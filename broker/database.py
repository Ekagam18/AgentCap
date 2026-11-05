import hashlib
import math
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from policy.checks import ALLOWED_ACTION, parse_and_validate_s3_uri

DEFAULT_DB = Path(__file__).with_name("agentcap.db")

AWS_KEY_PATTERN = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
AWS_SECRET_PATTERN = re.compile(r"(?i)(aws_secret_access_key|aws_session_token|secret_key)\s*=")

KNOWN_EVENT_TYPES = frozenset({
    "lease_issued",
    "lease_consumed",
    "s3_execution_succeeded",
    "s3_execution_failed",
    "lease_execution_rejected",
})

KNOWN_OUTCOMES = frozenset({
    "success",
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
    # Executor domain error types
    "S3ObjectTooLargeError",
    "S3ServiceError",
    "S3InvalidLeaseError",
    "PolicyViolationError",
    # Lease and policy rejection reason codes
    "invalid_token",
    "expired_lease",
    "lease_expired",
    "invalid_lease",
    "rejected_invalid_lease",
    "policy_violation",
    "unauthorized",
    "forbidden",
})


def _validate_audit_field(val: str, field_name: str, max_len: int = 256) -> str:
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
    """Extract all 64-character hexadecimal candidate substrings from val, normalized to lowercase."""
    candidates = set()
    for segment in re.findall(r"[0-9a-fA-F]{64,}", val):
        for i in range(len(segment) - 64 + 1):
            candidates.add(segment[i : i + 64].lower())
    return candidates


def _extract_43_char_candidates(val: str) -> set[str]:
    """Extract all 43-character URL-safe candidate substrings from val."""
    candidates = set()
    for segment in re.findall(r"[A-Za-z0-9_-]{43,}", val):
        for i in range(len(segment) - 43 + 1):
            candidates.add(segment[i : i + 43])
    return candidates


def _check_tokens_and_hashes_in_connection(
    conn: sqlite3.Connection, fields: dict[str, str | None]
) -> None:
    """Detect actual plaintext lease tokens and token hashes in fields against leases."""
    has_leases = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='leases'"
    ).fetchone()
    if not has_leases:
        return

    # 1. Detect actual 64-character hexadecimal lease token hashes
    hex_hash_to_field: dict[str, str] = {}
    for field_name, val in fields.items():
        if not val or not isinstance(val, str) or len(val) < 64:
            continue
        for cand in _extract_64_hex_candidates(val):
            hex_hash_to_field[cand] = field_name

    if hex_hash_to_field:
        all_hex = list(hex_hash_to_field.keys())
        chunk_size = 500
        for i in range(0, len(all_hex), chunk_size):
            chunk = all_hex[i : i + chunk_size]
            placeholders = ",".join("?" for _ in chunk)
            row = conn.execute(
                f"SELECT token_hash FROM leases WHERE token_hash IN ({placeholders}) LIMIT 1",
                chunk,
            ).fetchone()
            if row:
                matched_hash = row[0]
                field_name = hex_hash_to_field[matched_hash]
                raise ValueError(f"{field_name} contains prohibited lease token hash")

    # 2. Detect actual 43-character plaintext lease tokens
    cand_hash_to_field: dict[str, str] = {}
    for field_name, val in fields.items():
        if not val or not isinstance(val, str) or len(val) < 43:
            continue
        for cand in _extract_43_char_candidates(val):
            cand_hash = hashlib.sha256(cand.encode("utf-8")).hexdigest()
            cand_hash_to_field[cand_hash] = field_name

    if cand_hash_to_field:
        all_cand_hashes = list(cand_hash_to_field.keys())
        chunk_size = 500
        for i in range(0, len(all_cand_hashes), chunk_size):
            chunk = all_cand_hashes[i : i + chunk_size]
            placeholders = ",".join("?" for _ in chunk)
            row = conn.execute(
                f"SELECT token_hash FROM leases WHERE token_hash IN ({placeholders}) LIMIT 1",
                chunk,
            ).fetchone()
            if row:
                matched_hash = row[0]
                field_name = cand_hash_to_field[matched_hash]
                raise ValueError(f"{field_name} contains prohibited plaintext lease token")


_check_plaintext_tokens_in_connection = _check_tokens_and_hashes_in_connection


def _migrate_audit_events_on_connection(conn: sqlite3.Connection) -> bool:
    cur = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_events'"
    )
    if not cur.fetchone():
        return False

    columns = conn.execute("PRAGMA table_info(audit_events)").fetchall()
    needs_migration = any(
        col[1] in ("task_id", "action", "resource") and col[3] == 1
        for col in columns
    )
    if not needs_migration:
        return False

    in_txn = conn.in_transaction
    sp_name = "audit_migration_sp"
    if in_txn:
        conn.execute(f"SAVEPOINT {sp_name}")
    else:
        conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DROP TABLE IF EXISTS audit_events_new")
        conn.execute("""
            CREATE TABLE audit_events_new (
                event_id TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                timestamp_utc TEXT NOT NULL,
                event_type TEXT NOT NULL,
                task_id TEXT,
                action TEXT,
                resource TEXT,
                outcome TEXT NOT NULL,
                lease_id TEXT
            )
        """)
        conn.execute("""
            INSERT INTO audit_events_new (
                rowid, event_id, timestamp, timestamp_utc,
                event_type, task_id, action, resource, outcome, lease_id
            )
            SELECT
                rowid, event_id, timestamp, timestamp_utc,
                event_type, task_id, action, resource, outcome, lease_id
            FROM audit_events
            ORDER BY rowid ASC
        """)
        conn.execute("DROP TRIGGER IF EXISTS prevent_audit_update")
        conn.execute("DROP TRIGGER IF EXISTS prevent_audit_delete")
        conn.execute("DROP INDEX IF EXISTS idx_audit_events_task_id")
        conn.execute("DROP INDEX IF EXISTS idx_audit_events_timestamp")
        conn.execute("DROP TABLE audit_events")
        conn.execute("ALTER TABLE audit_events_new RENAME TO audit_events")
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_events_task_id
            ON audit_events (task_id)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp
            ON audit_events (timestamp)
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS prevent_audit_update
            BEFORE UPDATE ON audit_events
            BEGIN
                SELECT RAISE(FAIL, 'audit_events is append-only');
            END;
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
            BEFORE DELETE ON audit_events
            BEGIN
                SELECT RAISE(FAIL, 'audit_events is append-only');
            END;
        """)
        if in_txn:
            conn.execute(f"RELEASE SAVEPOINT {sp_name}")
        else:
            conn.commit()
    except Exception:
        if in_txn:
            conn.execute(f"ROLLBACK TO SAVEPOINT {sp_name}")
            conn.execute(f"RELEASE SAVEPOINT {sp_name}")
        else:
            conn.rollback()
        raise

    return True


def migrate_audit_events_table(db_path_or_conn=DEFAULT_DB) -> bool:
    """Migrate audit_events table if task_id, action, or resource have NOT NULL constraints.

    Preserves all records, event IDs, timestamps, rowids, indexes, and append-only triggers.
    Returns True if migration was performed, False if migration was not needed.
    """
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


def connect(db_path=DEFAULT_DB):
    """Create a database connection and ensure tables exist."""
    if str(db_path) != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS leases (
            lease_id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE,
            task_id TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            expires_at REAL NOT NULL,
            status TEXT NOT NULL
                CHECK(status IN ('issued', 'consumed'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_events (
            event_id TEXT PRIMARY KEY,
            timestamp REAL NOT NULL,
            timestamp_utc TEXT NOT NULL,
            event_type TEXT NOT NULL,
            task_id TEXT,
            action TEXT,
            resource TEXT,
            outcome TEXT NOT NULL,
            lease_id TEXT
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_events_task_id
        ON audit_events (task_id)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp
        ON audit_events (timestamp)
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS prevent_audit_update
        BEFORE UPDATE ON audit_events
        BEGIN
            SELECT RAISE(FAIL, 'audit_events is append-only');
        END;
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
        BEFORE DELETE ON audit_events
        BEGIN
            SELECT RAISE(FAIL, 'audit_events is append-only');
        END;
    """)
    migrate_audit_events_table(conn)
    return conn


def issue_lease(task_id, action, resource, ttl_seconds=60, db_path=DEFAULT_DB):
    """Create a random lease token and store only its hash, recording an audit event."""
    if not task_id or not action or not resource:
        raise ValueError("task_id, action, and resource are required")
    if not math.isfinite(ttl_seconds) or ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive and finite")

    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    lease_id = secrets.token_urlsafe(12)
    now = time.time()

    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """INSERT INTO leases
            (lease_id, token_hash, task_id, action, resource,
             expires_at, status)
            VALUES (?, ?, ?, ?, ?, ?, 'issued')""",
            (
                lease_id,
                token_hash,
                task_id,
                action,
                resource,
                now + ttl_seconds,
            ),
        )
        record_audit_event(
            event_type="lease_issued",
            outcome="success",
            task_id=task_id,
            action=action,
            resource=resource,
            lease_id=lease_id,
            db_path=conn,
        )

    return token


def consume_lease(token, db_path=DEFAULT_DB):
    """Consume a valid lease once, or return None, recording an audit event on success."""
    if not token:
        return None

    token_hash = hashlib.sha256(token.encode()).hexdigest()

    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """UPDATE leases
            SET status = 'consumed'
            WHERE token_hash = ?
              AND status = 'issued'
              AND expires_at > ?
            RETURNING lease_id, task_id, action, resource, expires_at""",
            (token_hash, time.time()),
        ).fetchone()

        if not row:
            return None

        record_audit_event(
            event_type="lease_consumed",
            outcome="success",
            task_id=row["task_id"],
            action=row["action"],
            resource=row["resource"],
            lease_id=row["lease_id"],
            db_path=conn,
        )

        return dict(row)


def record_audit_event(
    event_type: str,
    outcome: str,
    task_id: str | None = None,
    action: str | None = None,
    resource: str | None = None,
    lease_id: str | None = None,
    db_path=DEFAULT_DB,
) -> dict:
    """Record an audit event into audit_events in an append-only manner.

    Parameters:
        event_type: Non-empty string identifying event type (e.g., 's3_execution_succeeded',
                    's3_execution_failed', 'lease_execution_rejected').
        outcome: Non-empty string representing sanitized outcome status code (e.g., 'success',
                 'invalid_token', 'policy_violation', 'access_denied').
        task_id: Optional task identifier.
        action: Optional action (e.g., 's3:GetObject').
        resource: Optional target resource (e.g., 's3://bucket/key').
        lease_id: Optional lease identifier.
        db_path: Database path or active sqlite3 connection.

    Returns:
        dict: The recorded audit event record.
    """
    clean_event_type = _validate_audit_field(event_type, "event_type", max_len=64)
    if clean_event_type not in KNOWN_EVENT_TYPES:
        raise ValueError(
            f"Invalid event_type '{clean_event_type}'. Must be one of {sorted(KNOWN_EVENT_TYPES)}"
        )

    clean_outcome = _validate_audit_field(outcome, "outcome", max_len=128)
    if clean_outcome not in KNOWN_OUTCOMES:
        raise ValueError(
            f"Invalid outcome '{clean_outcome}'. Must be a known sanitized status code, "
            f"not raw exception messages or object content."
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

    now = time.time()
    now_utc = datetime.now(timezone.utc).isoformat()
    event_id = f"evt_{secrets.token_urlsafe(16)}"

    event = {
        "event_id": event_id,
        "timestamp": now,
        "timestamp_utc": now_utc,
        "event_type": clean_event_type,
        "task_id": clean_task_id,
        "action": clean_action,
        "resource": clean_resource,
        "outcome": clean_outcome,
        "lease_id": clean_lease_id,
    }

    insert_sql = """
        INSERT INTO audit_events
        (event_id, timestamp, timestamp_utc, event_type,
         task_id, action, resource, outcome, lease_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    insert_params = (
        event_id,
        now,
        now_utc,
        clean_event_type,
        clean_task_id,
        clean_action,
        clean_resource,
        clean_outcome,
        clean_lease_id,
    )

    fields_to_check = {
        "task_id": clean_task_id,
        "action": clean_action,
        "resource": clean_resource,
        "outcome": clean_outcome,
        "lease_id": clean_lease_id,
        "event_type": clean_event_type,
    }

    if isinstance(db_path, sqlite3.Connection):
        conn = db_path
        if conn.in_transaction:
            _check_plaintext_tokens_in_connection(conn, fields_to_check)
            conn.execute(insert_sql, insert_params)
        else:
            with conn:
                conn.execute("BEGIN IMMEDIATE")
                _check_plaintext_tokens_in_connection(conn, fields_to_check)
                conn.execute(insert_sql, insert_params)
    else:
        with connect(db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            _check_plaintext_tokens_in_connection(conn, fields_to_check)
            conn.execute(insert_sql, insert_params)

    return event


def get_audit_events(task_id=None, event_type=None, db_path=DEFAULT_DB):
    """Retrieve audit events, optionally filtered by task_id or event_type."""
    query = """
        SELECT event_id, timestamp, timestamp_utc, event_type,
               task_id, action, resource, outcome, lease_id
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
        if db_path.row_factory == sqlite3.Row:
            return [dict(row) for row in cursor.fetchall()]
        col_names = [d[0] for d in cursor.description]
        return [dict(zip(col_names, row)) for row in cursor.fetchall()]

    with connect(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]
