"""SQLite storage for AgentCap: tasks, single-use leases, and the append-only audit log."""

import hashlib
import math
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB = Path(__file__).with_name("agentcap.db")

# Task lifecycle states.
TASK_APPROVED = "approved"  # approved by an admin, no lease issued yet
TASK_LEASED = "leased"  # its one lease has been issued; it cannot be reused


class TaskUnavailableError(Exception):
    """Raised when a lease is requested for a task that cannot issue one.

    ``reason`` is one of: ``not_found``, ``agent_mismatch``, ``expired``, ``already_used``.
    """

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


class _ClosingConnection(sqlite3.Connection):
    """sqlite3 connection that also closes itself when its ``with`` block ends.

    The standard ``with sqlite3.connect(...) as conn`` only commits or rolls back;
    it leaves the connection open. Every ``connect()`` call here is used as a
    context manager, so closing on exit prevents leaking file handles.
    """

    def __exit__(self, exc_type, exc, tb):
        try:
            return super().__exit__(exc_type, exc, tb)
        finally:
            self.close()


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, declaration: str) -> None:
    """Add a column to an existing table if it is missing (lightweight migration)."""
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            task_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            created_at REAL NOT NULL,
            expires_at REAL,
            status TEXT NOT NULL DEFAULT 'approved'
        )
    """)
    # Databases created before task expiry existed get the new columns.
    # Legacy rows have expires_at = NULL, which is treated as expired (fail closed).
    _ensure_column(conn, "tasks", "expires_at", "REAL")
    _ensure_column(conn, "tasks", "status", "TEXT NOT NULL DEFAULT 'approved'")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS leases (
            lease_id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE,
            task_id TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            expires_at REAL NOT NULL,
            status TEXT NOT NULL
                CHECK(status IN ('issued', 'consumed')),
            agent_id TEXT
        )
    """)
    _ensure_column(conn, "leases", "agent_id", "TEXT")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_events (
            event_id TEXT PRIMARY KEY,
            timestamp REAL NOT NULL,
            timestamp_utc TEXT NOT NULL,
            event_type TEXT NOT NULL,
            task_id TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            outcome TEXT NOT NULL,
            lease_id TEXT,
            agent_id TEXT,
            detail TEXT
        )
    """)
    _ensure_column(conn, "audit_events", "agent_id", "TEXT")
    _ensure_column(conn, "audit_events", "detail", "TEXT")

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


def connect(db_path=DEFAULT_DB):
    """Create a database connection and ensure tables exist.

    Use it as a context manager: the transaction is committed (or rolled back)
    and the connection is closed when the block ends.
    """
    if str(db_path) != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path, timeout=10, factory=_ClosingConnection)
    conn.row_factory = sqlite3.Row
    _init_schema(conn)
    conn.commit()
    return conn


def _insert_audit_event(
    conn: sqlite3.Connection,
    event_type: str,
    task_id: str,
    action: str,
    resource: str,
    outcome: str,
    lease_id: str | None = None,
    agent_id: str | None = None,
    detail: str | None = None,
) -> str:
    """Insert one audit event using an existing connection/transaction."""
    event_id = f"evt_{secrets.token_urlsafe(16)}"
    conn.execute(
        """INSERT INTO audit_events
        (event_id, timestamp, timestamp_utc, event_type,
         task_id, action, resource, outcome, lease_id, agent_id, detail)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            event_id,
            time.time(),
            datetime.now(timezone.utc).isoformat(),
            event_type,
            task_id,
            action,
            resource,
            outcome,
            lease_id,
            agent_id,
            detail,
        ),
    )
    return event_id


def record_audit_event(
    event_type: str,
    task_id: str,
    action: str,
    resource: str,
    outcome: str,
    lease_id: str | None = None,
    agent_id: str | None = None,
    detail: str | None = None,
    db_path=DEFAULT_DB,
) -> str:
    """Append a standalone audit event (e.g. denied requests, S3 execution outcomes).

    Never pass lease tokens, token hashes, or credentials in any field.
    """
    with connect(db_path) as conn:
        return _insert_audit_event(
            conn,
            event_type,
            task_id or "unknown",
            action or "unknown",
            resource or "unknown",
            outcome,
            lease_id=lease_id,
            agent_id=agent_id,
            detail=detail,
        )


def _validate_lease_inputs(task_id, action, resource, ttl_seconds) -> None:
    if not task_id or not action or not resource:
        raise ValueError("task_id, action, and resource are required")
    if not math.isfinite(ttl_seconds) or ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive and finite")


def _insert_lease(conn, task_id, action, resource, ttl_seconds, agent_id) -> tuple[str, str]:
    """Insert a lease row plus its lease_issued audit event. Returns (token, lease_id)."""
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    lease_id = secrets.token_urlsafe(12)
    now = time.time()

    conn.execute(
        """INSERT INTO leases
        (lease_id, token_hash, task_id, action, resource,
         expires_at, status, agent_id)
        VALUES (?, ?, ?, ?, ?, ?, 'issued', ?)""",
        (lease_id, token_hash, task_id, action, resource, now + ttl_seconds, agent_id),
    )
    _insert_audit_event(
        conn, "lease_issued", task_id, action, resource, "success",
        lease_id=lease_id, agent_id=agent_id,
    )
    return token, lease_id


def issue_lease(task_id, action, resource, ttl_seconds=60, db_path=DEFAULT_DB, agent_id=None):
    """Create a random lease token and store only its hash, recording an audit event.

    Low-level primitive: it does not check the task. The broker API uses
    ``issue_lease_for_task`` so that task ownership, expiry, and single use are
    enforced in the same transaction.
    """
    _validate_lease_inputs(task_id, action, resource, ttl_seconds)

    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        token, _ = _insert_lease(conn, task_id, action, resource, ttl_seconds, agent_id)

    return token


def issue_lease_for_task(task_id, agent_id, action, resource, ttl_seconds=60, db_path=DEFAULT_DB):
    """Atomically claim an approved task and issue its single lease.

    Within one ``BEGIN IMMEDIATE`` transaction this checks the task exists, belongs
    to ``agent_id``, matches action/resource, has not expired, and has not already
    issued a lease; then it marks the task as leased and inserts the lease.

    Raises:
        TaskUnavailableError: the task cannot issue a lease (see ``reason``).
        ValueError: invalid inputs.
    Returns:
        The plaintext lease token (returned once, never stored).
    """
    if not agent_id:
        raise ValueError("agent_id is required")
    _validate_lease_inputs(task_id, action, resource, ttl_seconds)

    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        task = conn.execute(
            "SELECT agent_id, action, resource, expires_at, status FROM tasks WHERE task_id = ?",
            (task_id,),
        ).fetchone()

        if task is None:
            raise TaskUnavailableError("not_found", "Task not found")
        if task["agent_id"] != agent_id:
            raise TaskUnavailableError("agent_mismatch", "Authenticated agent does not own this task")
        if task["action"] != action or task["resource"] != resource:
            raise TaskUnavailableError("scope_mismatch", "Requested scope does not match approved task")
        if task["expires_at"] is None or task["expires_at"] <= time.time():
            raise TaskUnavailableError("expired", "Task approval has expired")

        claimed = conn.execute(
            "UPDATE tasks SET status = ? WHERE task_id = ? AND status = ?",
            (TASK_LEASED, task_id, TASK_APPROVED),
        ).rowcount
        if claimed != 1:
            raise TaskUnavailableError("already_used", "Task has already been used to issue a lease")

        token, _ = _insert_lease(conn, task_id, action, resource, ttl_seconds, agent_id)

    return token


def consume_lease(token, db_path=DEFAULT_DB, agent_id=None):
    """Consume a valid lease once, or return None, recording an audit event on success.

    If ``agent_id`` is given, the lease must have been issued to that agent;
    a token presented by any other agent is treated as invalid and stays unused.
    """
    if not token:
        return None

    token_hash = hashlib.sha256(token.encode()).hexdigest()

    query = """UPDATE leases
        SET status = 'consumed'
        WHERE token_hash = ?
          AND status = 'issued'
          AND expires_at > ?"""
    params: list = [token_hash, time.time()]
    if agent_id is not None:
        query += " AND agent_id = ?"
        params.append(agent_id)
    query += " RETURNING lease_id, task_id, action, resource, expires_at, agent_id"

    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(query, params).fetchone()

        if not row:
            return None

        _insert_audit_event(
            conn, "lease_consumed", row["task_id"], row["action"], row["resource"], "success",
            lease_id=row["lease_id"], agent_id=row["agent_id"],
        )

        return dict(row)


def get_audit_events(task_id=None, event_type=None, db_path=DEFAULT_DB):
    """Retrieve audit events, optionally filtered by task_id or event_type."""
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

    with connect(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]
