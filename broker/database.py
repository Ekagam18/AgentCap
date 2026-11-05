"""SQLite storage for AgentCap tasks, single-use leases, and secure audit events."""

from __future__ import annotations

import hashlib
import math
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from policy.checks import ALLOWED_ACTION, parse_and_validate_s3_uri

DEFAULT_DB = Path(__file__).with_name("agentcap.db")

TASK_APPROVED = "approved"
TASK_LEASED = "leased"

AWS_KEY_PATTERN = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
AWS_SECRET_PATTERN = re.compile(
    r"(?i)(aws_secret_access_key|aws_session_token|secret_key)\s*="
)
SAFE_DETAIL_PATTERN = re.compile(r"^[A-Za-z0-9_.:=+-]{1,128}$")

KNOWN_EVENT_TYPES = frozenset(
    {
        "task_registered",
        "lease_issued",
        "lease_consumed",
        "lease_denied",
        "execution_denied",
        "s3_execution_succeeded",
        "s3_execution_failed",
        "lease_execution_rejected",
    }
)

KNOWN_OUTCOMES = frozenset(
    {
        "success",
        "failure",
        "denied",
        # AWS S3 and Botocore sanitized error codes
        "NoSuchKey",
        "NoSuchBucket",
        "AccessDenied",
        "InvalidBucketName",
        "InvalidRange",
        "RequestTimeout",
        "ServiceUnavailable",
        "SlowDown",
        "InternalError",
        "EndpointConnectionError",
        "NoCredentialsError",
        "ConnectTimeoutError",
        "ReadTimeoutError",
        "ClientError",
        "BotoCoreError",
        "UnknownError",
        # Executor and service error types
        "S3ObjectTooLargeError",
        "S3ServiceError",
        "S3InvalidLeaseError",
        "PolicyViolationError",
        "StsAssumeRoleError",
        # Lease and policy rejection reason codes
        "invalid_token",
        "expired_lease",
        "lease_expired",
        "invalid_lease",
        "rejected_invalid_lease",
        "policy_violation",
        "unauthorized",
        "forbidden",
        "object_too_large",
        "executor_error",
        "task_not_found",
        "already_used",
        "agent_mismatch",
        "scope_mismatch",
        "expired",
    }
)


class TaskUnavailableError(Exception):
    """Raised when a task cannot issue a lease.

    ``reason`` is one of: not_found, agent_mismatch, scope_mismatch,
    expired, or already_used.
    """

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


class _ClosingConnection(sqlite3.Connection):
    """Connection that commits/rolls back and closes on context-manager exit."""

    def __exit__(self, exc_type, exc, tb):
        try:
            return super().__exit__(exc_type, exc, tb)
        finally:
            self.close()


def _ensure_column(
    conn: sqlite3.Connection, table: str, column: str, declaration: str
) -> None:
    """Add a column to an existing table if it is missing."""
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")


def _validate_audit_field(val: Any, field_name: str, max_len: int = 256) -> str:
    if not isinstance(val, str):
        raise ValueError(f"{field_name} must be a string, got {type(val).__name__}")
    if "\n" in val or "\r" in val:
        raise ValueError(f"{field_name} cannot contain newline characters or tracebacks")
    cleaned = val.strip()
    if not cleaned:
        raise ValueError(f"{field_name} cannot be empty or whitespace only")
    if len(cleaned) > max_len:
        raise ValueError(f"{field_name} exceeds maximum length of {max_len} characters")
    if AWS_KEY_PATTERN.search(cleaned):
        raise ValueError(f"{field_name} contains prohibited AWS credential pattern")
    if AWS_SECRET_PATTERN.search(cleaned):
        raise ValueError(f"{field_name} contains prohibited secret key pattern")
    return cleaned


def _extract_64_hex_candidates(val: str) -> set[str]:
    """Extract 64-character hexadecimal substrings, normalized to lowercase."""
    candidates: set[str] = set()
    for segment in re.findall(r"[0-9a-fA-F]{64,}", val):
        for i in range(len(segment) - 64 + 1):
            candidates.add(segment[i : i + 64].lower())
    return candidates


def _extract_43_char_candidates(val: str) -> set[str]:
    """Extract 43-character URL-safe substrings (the format of our lease tokens)."""
    candidates: set[str] = set()
    for segment in re.findall(r"[A-Za-z0-9_-]{43,}", val):
        for i in range(len(segment) - 43 + 1):
            candidates.add(segment[i : i + 43])
    return candidates


def _check_tokens_and_hashes_in_connection(
    conn: sqlite3.Connection, fields: dict[str, str | None]
) -> None:
    """Reject actual plaintext lease tokens and token hashes in audit fields."""
    has_leases = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='leases'"
    ).fetchone()
    if not has_leases:
        return

    hex_hash_to_field: dict[str, str] = {}
    for field_name, val in fields.items():
        if not val or not isinstance(val, str) or len(val) < 64:
            continue
        for candidate in _extract_64_hex_candidates(val):
            hex_hash_to_field[candidate] = field_name

    if hex_hash_to_field:
        candidates = list(hex_hash_to_field)
        for offset in range(0, len(candidates), 500):
            chunk = candidates[offset : offset + 500]
            placeholders = ",".join("?" for _ in chunk)
            row = conn.execute(
                f"SELECT token_hash FROM leases WHERE token_hash IN ({placeholders}) LIMIT 1",
                chunk,
            ).fetchone()
            if row:
                raise ValueError(
                    f"{hex_hash_to_field[row[0]]} contains prohibited lease token hash"
                )

    candidate_hash_to_field: dict[str, str] = {}
    for field_name, val in fields.items():
        if not val or not isinstance(val, str) or len(val) < 43:
            continue
        for candidate in _extract_43_char_candidates(val):
            digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
            candidate_hash_to_field[digest] = field_name

    if candidate_hash_to_field:
        candidates = list(candidate_hash_to_field)
        for offset in range(0, len(candidates), 500):
            chunk = candidates[offset : offset + 500]
            placeholders = ",".join("?" for _ in chunk)
            row = conn.execute(
                f"SELECT token_hash FROM leases WHERE token_hash IN ({placeholders}) LIMIT 1",
                chunk,
            ).fetchone()
            if row:
                raise ValueError(
                    f"{candidate_hash_to_field[row[0]]} contains prohibited plaintext lease token"
                )


# Backward-compatible name used by the original audit tests.
_check_plaintext_tokens_in_connection = _check_tokens_and_hashes_in_connection


def _migrate_audit_events_on_connection(conn: sqlite3.Connection) -> bool:
    """Make task/action/resource nullable while preserving existing audit history."""
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_events'"
    ).fetchone()
    if not exists:
        return False

    columns = conn.execute("PRAGMA table_info(audit_events)").fetchall()
    needs_migration = any(
        row[1] in ("task_id", "action", "resource") and row[3] == 1
        for row in columns
    )
    if not needs_migration:
        return False

    existing_names = {row[1] for row in columns}
    agent_expr = "agent_id" if "agent_id" in existing_names else "NULL"
    detail_expr = "detail" if "detail" in existing_names else "NULL"

    in_transaction = conn.in_transaction
    savepoint = "audit_migration_sp"
    if in_transaction:
        conn.execute(f"SAVEPOINT {savepoint}")
    else:
        conn.execute("BEGIN IMMEDIATE")

    try:
        conn.execute("DROP TABLE IF EXISTS audit_events_new")
        conn.execute(
            """
            CREATE TABLE audit_events_new (
                event_id TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                timestamp_utc TEXT NOT NULL,
                event_type TEXT NOT NULL,
                task_id TEXT,
                action TEXT,
                resource TEXT,
                outcome TEXT NOT NULL,
                lease_id TEXT,
                agent_id TEXT,
                detail TEXT
            )
            """
        )
        conn.execute(
            f"""
            INSERT INTO audit_events_new (
                rowid, event_id, timestamp, timestamp_utc, event_type,
                task_id, action, resource, outcome, lease_id, agent_id, detail
            )
            SELECT
                rowid, event_id, timestamp, timestamp_utc, event_type,
                task_id, action, resource, outcome, lease_id,
                {agent_expr}, {detail_expr}
            FROM audit_events
            ORDER BY rowid ASC
            """
        )

        conn.execute("DROP TRIGGER IF EXISTS prevent_audit_update")
        conn.execute("DROP TRIGGER IF EXISTS prevent_audit_delete")
        conn.execute("DROP INDEX IF EXISTS idx_audit_events_task_id")
        conn.execute("DROP INDEX IF EXISTS idx_audit_events_timestamp")
        conn.execute("DROP TABLE audit_events")
        conn.execute("ALTER TABLE audit_events_new RENAME TO audit_events")

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_events_task_id ON audit_events (task_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events (timestamp)"
        )
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS prevent_audit_update
            BEFORE UPDATE ON audit_events
            BEGIN
                SELECT RAISE(FAIL, 'audit_events is append-only');
            END;
            """
        )
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
            BEFORE DELETE ON audit_events
            BEGIN
                SELECT RAISE(FAIL, 'audit_events is append-only');
            END;
            """
        )

        if in_transaction:
            conn.execute(f"RELEASE SAVEPOINT {savepoint}")
        else:
            conn.commit()
    except Exception:
        if in_transaction:
            conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
            conn.execute(f"RELEASE SAVEPOINT {savepoint}")
        else:
            conn.rollback()
        raise

    return True


def migrate_audit_events_table(db_path_or_conn=DEFAULT_DB) -> bool:
    """Migrate an old NOT NULL audit schema; preserve rows, IDs, rowids and protections."""
    if isinstance(db_path_or_conn, sqlite3.Connection):
        return _migrate_audit_events_on_connection(db_path_or_conn)

    if str(db_path_or_conn) != ":memory:":
        Path(db_path_or_conn).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path_or_conn, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        return _migrate_audit_events_on_connection(conn)
    finally:
        conn.close()


def _init_schema(conn: sqlite3.Connection) -> None:
    """Create or migrate all broker tables on an existing connection."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS tasks (
            task_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            created_at REAL NOT NULL,
            expires_at REAL,
            status TEXT NOT NULL DEFAULT 'approved'
        )
        """
    )
    _ensure_column(conn, "tasks", "expires_at", "REAL")
    _ensure_column(conn, "tasks", "status", "TEXT NOT NULL DEFAULT 'approved'")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS leases (
            lease_id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE,
            task_id TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            expires_at REAL NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('issued', 'consumed')),
            agent_id TEXT
        )
        """
    )
    _ensure_column(conn, "leases", "agent_id", "TEXT")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_events (
            event_id TEXT PRIMARY KEY,
            timestamp REAL NOT NULL,
            timestamp_utc TEXT NOT NULL,
            event_type TEXT NOT NULL,
            task_id TEXT,
            action TEXT,
            resource TEXT,
            outcome TEXT NOT NULL,
            lease_id TEXT,
            agent_id TEXT,
            detail TEXT
        )
        """
    )
    _migrate_audit_events_on_connection(conn)
    _ensure_column(conn, "audit_events", "agent_id", "TEXT")
    _ensure_column(conn, "audit_events", "detail", "TEXT")

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_events_task_id ON audit_events (task_id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events (timestamp)"
    )
    conn.execute(
        """
        CREATE TRIGGER IF NOT EXISTS prevent_audit_update
        BEFORE UPDATE ON audit_events
        BEGIN
            SELECT RAISE(FAIL, 'audit_events is append-only');
        END;
        """
    )
    conn.execute(
        """
        CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
        BEFORE DELETE ON audit_events
        BEGIN
            SELECT RAISE(FAIL, 'audit_events is append-only');
        END;
        """
    )


def connect(db_path=DEFAULT_DB) -> sqlite3.Connection:
    """Open a broker database connection and ensure the current schema exists."""
    if str(db_path) != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(
        db_path, timeout=10, factory=_ClosingConnection
    )
    conn.row_factory = sqlite3.Row
    _init_schema(conn)
    conn.commit()
    return conn


def _prepare_audit_fields(
    event_type: str,
    outcome: str,
    task_id: str | None = None,
    action: str | None = None,
    resource: str | None = None,
    lease_id: str | None = None,
    agent_id: str | None = None,
    detail: str | None = None,
) -> dict[str, str | None]:
    clean_event_type = _validate_audit_field(event_type, "event_type", max_len=64)
    if clean_event_type not in KNOWN_EVENT_TYPES:
        raise ValueError(
            f"Invalid event_type '{clean_event_type}'. "
            f"Must be one of {sorted(KNOWN_EVENT_TYPES)}"
        )

    clean_outcome = _validate_audit_field(outcome, "outcome", max_len=128)
    if clean_outcome not in KNOWN_OUTCOMES:
        raise ValueError(
            "outcome must be a known sanitized status code, not raw exception messages "
            "or object content"
        )

    clean_task_id = (
        _validate_audit_field(task_id, "task_id", max_len=128)
        if task_id is not None
        else None
    )
    clean_action = (
        _validate_audit_field(action, "action", max_len=64)
        if action is not None
        else None
    )
    if clean_action is not None and clean_action != ALLOWED_ACTION:
        raise ValueError(
            f"Invalid action '{clean_action}'. Supported policy action is '{ALLOWED_ACTION}'"
        )

    clean_resource = (
        _validate_audit_field(resource, "resource", max_len=1024)
        if resource is not None
        else None
    )
    if clean_resource is not None:
        parse_and_validate_s3_uri(clean_resource)

    clean_lease_id = (
        _validate_audit_field(lease_id, "lease_id", max_len=64)
        if lease_id is not None
        else None
    )
    clean_agent_id = (
        _validate_audit_field(agent_id, "agent_id", max_len=128)
        if agent_id is not None
        else None
    )
    clean_detail = None
    if detail is not None:
        clean_detail = _validate_audit_field(detail, "detail", max_len=128)
        if not SAFE_DETAIL_PATTERN.fullmatch(clean_detail):
            raise ValueError("detail must be a short sanitized code, not free-form text")

    return {
        "event_type": clean_event_type,
        "task_id": clean_task_id,
        "action": clean_action,
        "resource": clean_resource,
        "outcome": clean_outcome,
        "lease_id": clean_lease_id,
        "agent_id": clean_agent_id,
        "detail": clean_detail,
    }


def _audit_fields_to_check(clean: dict[str, str | None]) -> dict[str, str | None]:
    return {key: clean.get(key) for key in clean}


def _insert_prepared_audit_event(
    conn: sqlite3.Connection,
    clean: dict[str, str | None],
    event_id: str,
    timestamp: float,
    timestamp_utc: str,
) -> None:
    conn.execute(
        """
        INSERT INTO audit_events (
            event_id, timestamp, timestamp_utc, event_type,
            task_id, action, resource, outcome, lease_id, agent_id, detail
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            timestamp,
            timestamp_utc,
            clean["event_type"],
            clean["task_id"],
            clean["action"],
            clean["resource"],
            clean["outcome"],
            clean["lease_id"],
            clean["agent_id"],
            clean["detail"],
        ),
    )


def _insert_audit_event(
    conn: sqlite3.Connection,
    event_type: str,
    task_id: str | None,
    action: str | None,
    resource: str | None,
    outcome: str,
    lease_id: str | None = None,
    agent_id: str | None = None,
    detail: str | None = None,
) -> str:
    """Insert one validated audit event inside the caller's transaction."""
    clean = _prepare_audit_fields(
        event_type=event_type,
        outcome=outcome,
        task_id=task_id,
        action=action,
        resource=resource,
        lease_id=lease_id,
        agent_id=agent_id,
        detail=detail,
    )
    _check_plaintext_tokens_in_connection(conn, _audit_fields_to_check(clean))
    event_id = f"evt_{secrets.token_urlsafe(16)}"
    _insert_prepared_audit_event(
        conn,
        clean,
        event_id,
        time.time(),
        datetime.now(timezone.utc).isoformat(),
    )
    return event_id


def record_audit_event(
    event_type: str,
    outcome: str,
    task_id: str | None = None,
    action: str | None = None,
    resource: str | None = None,
    lease_id: str | None = None,
    db_path=DEFAULT_DB,
    *,
    agent_id: str | None = None,
    detail: str | None = None,
) -> dict:
    """Append a validated, secret-screened audit event.

    ``db_path`` may be a filesystem path or an already-open SQLite connection.
    The connection form participates in an existing transaction when one is active.
    """
    clean = _prepare_audit_fields(
        event_type=event_type,
        outcome=outcome,
        task_id=task_id,
        action=action,
        resource=resource,
        lease_id=lease_id,
        agent_id=agent_id,
        detail=detail,
    )
    now = time.time()
    now_utc = datetime.now(timezone.utc).isoformat()
    event_id = f"evt_{secrets.token_urlsafe(16)}"
    event = {
        "event_id": event_id,
        "timestamp": now,
        "timestamp_utc": now_utc,
        **clean,
    }

    if isinstance(db_path, sqlite3.Connection):
        conn = db_path
        if conn.in_transaction:
            _check_plaintext_tokens_in_connection(conn, _audit_fields_to_check(clean))
            _insert_prepared_audit_event(conn, clean, event_id, now, now_utc)
        else:
            conn.execute("BEGIN IMMEDIATE")
            try:
                _check_plaintext_tokens_in_connection(conn, _audit_fields_to_check(clean))
                _insert_prepared_audit_event(conn, clean, event_id, now, now_utc)
                conn.commit()
            except Exception:
                conn.rollback()
                raise
    else:
        with connect(db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            _check_plaintext_tokens_in_connection(conn, _audit_fields_to_check(clean))
            _insert_prepared_audit_event(conn, clean, event_id, now, now_utc)

    return event


def _validate_lease_inputs(task_id, action, resource, ttl_seconds) -> None:
    if not task_id or not action or not resource:
        raise ValueError("task_id, action, and resource are required")
    if (
        isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, (int, float))
        or not math.isfinite(ttl_seconds)
        or ttl_seconds <= 0
    ):
        raise ValueError("ttl_seconds must be positive and finite")


def _insert_lease(
    conn: sqlite3.Connection,
    task_id: str,
    action: str,
    resource: str,
    ttl_seconds: float,
    agent_id: str | None,
) -> tuple[str, str]:
    """Insert a lease and its audit event using the caller's transaction."""
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    lease_id = secrets.token_urlsafe(12)
    expires_at = time.time() + ttl_seconds

    conn.execute(
        """
        INSERT INTO leases (
            lease_id, token_hash, task_id, action, resource,
            expires_at, status, agent_id
        )
        VALUES (?, ?, ?, ?, ?, ?, 'issued', ?)
        """,
        (lease_id, token_hash, task_id, action, resource, expires_at, agent_id),
    )
    # Route through the public audit API while passing the active connection.
    # This keeps the audit insert in the lease transaction and ensures audit
    # failures propagate so the lease insert is rolled back.
    record_audit_event(
        event_type="lease_issued",
        outcome="success",
        task_id=task_id,
        action=action,
        resource=resource,
        lease_id=lease_id,
        db_path=conn,
        agent_id=agent_id,
    )
    return token, lease_id


def issue_lease(
    task_id,
    action,
    resource,
    ttl_seconds=60,
    db_path=DEFAULT_DB,
    agent_id=None,
):
    """Low-level lease primitive; stores only a token hash and records issuance."""
    _validate_lease_inputs(task_id, action, resource, ttl_seconds)
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        token, _ = _insert_lease(
            conn, task_id, action, resource, ttl_seconds, agent_id
        )
    return token


def issue_lease_for_task(
    task_id,
    agent_id,
    action,
    resource,
    ttl_seconds=60,
    db_path=DEFAULT_DB,
):
    """Atomically claim an approved task and issue its one agent-bound lease."""
    if not agent_id:
        raise ValueError("agent_id is required")
    _validate_lease_inputs(task_id, action, resource, ttl_seconds)

    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        task = conn.execute(
            """
            SELECT agent_id, action, resource, expires_at, status
            FROM tasks WHERE task_id = ?
            """,
            (task_id,),
        ).fetchone()

        if task is None:
            raise TaskUnavailableError("not_found", "Task not found")
        if task["agent_id"] != agent_id:
            raise TaskUnavailableError(
                "agent_mismatch", "Authenticated agent does not own this task"
            )
        if task["action"] != action or task["resource"] != resource:
            raise TaskUnavailableError(
                "scope_mismatch", "Requested scope does not match approved task"
            )
        if task["expires_at"] is None or task["expires_at"] <= time.time():
            raise TaskUnavailableError("expired", "Task approval has expired")

        claimed = conn.execute(
            "UPDATE tasks SET status = ? WHERE task_id = ? AND status = ?",
            (TASK_LEASED, task_id, TASK_APPROVED),
        ).rowcount
        if claimed != 1:
            raise TaskUnavailableError(
                "already_used", "Task has already been used to issue a lease"
            )

        token, _ = _insert_lease(
            conn, task_id, action, resource, ttl_seconds, agent_id
        )

    return token


def consume_lease(token, db_path=DEFAULT_DB, agent_id=None):
    """Consume a valid lease once; optionally bind consumption to its owning agent."""
    if not isinstance(token, str) or token == "":
        return None

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    query = """
        UPDATE leases
        SET status = 'consumed'
        WHERE token_hash = ?
          AND status = 'issued'
          AND expires_at > ?
    """
    params: list[Any] = [token_hash, time.time()]
    if agent_id is not None:
        query += " AND agent_id = ?"
        params.append(agent_id)
    query += """
        RETURNING lease_id, task_id, action, resource, expires_at, agent_id
    """

    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(query, params).fetchone()
        if row is None:
            return None

        # Keep consumption and its audit event atomic. If the audit write fails,
        # the enclosing transaction rolls the status update back to issued.
        record_audit_event(
            event_type="lease_consumed",
            outcome="success",
            task_id=row["task_id"],
            action=row["action"],
            resource=row["resource"],
            lease_id=row["lease_id"],
            db_path=conn,
            agent_id=row["agent_id"],
        )
        return dict(row)


def get_audit_events(task_id=None, event_type=None, db_path=DEFAULT_DB):
    """Retrieve audit events, optionally filtered by task ID or event type."""
    query = """
        SELECT event_id, timestamp, timestamp_utc, event_type,
               task_id, action, resource, outcome, lease_id, agent_id, detail
        FROM audit_events
    """
    conditions = []
    params = []
    if task_id:
        conditions.append("task_id = ?")
        params.append(task_id)
    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY timestamp ASC, rowid ASC"

    if isinstance(db_path, sqlite3.Connection):
        cursor = db_path.execute(query, params)
        rows = cursor.fetchall()
        if db_path.row_factory == sqlite3.Row:
            return [dict(row) for row in rows]
        columns = [description[0] for description in cursor.description]
        return [dict(zip(columns, row)) for row in rows]

    with connect(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]
