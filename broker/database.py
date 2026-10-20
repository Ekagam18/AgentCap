import hashlib
import math
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB = Path(__file__).with_name("agentcap.db")


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
            task_id TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
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
    now_utc = datetime.now(timezone.utc).isoformat()
    event_id = f"evt_{secrets.token_urlsafe(16)}"

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
        conn.execute(
            """INSERT INTO audit_events
            (event_id, timestamp, timestamp_utc, event_type,
             task_id, action, resource, outcome, lease_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id,
                now,
                now_utc,
                "lease_issued",
                task_id,
                action,
                resource,
                "success",
                lease_id,
            ),
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

        event_id = f"evt_{secrets.token_urlsafe(16)}"
        now = time.time()
        now_utc = datetime.now(timezone.utc).isoformat()

        conn.execute(
            """INSERT INTO audit_events
            (event_id, timestamp, timestamp_utc, event_type,
             task_id, action, resource, outcome, lease_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id,
                now,
                now_utc,
                "lease_consumed",
                row["task_id"],
                row["action"],
                row["resource"],
                "success",
                row["lease_id"],
            ),
        )

        return dict(row)


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

    with connect(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]
