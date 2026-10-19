
import hashlib
import math
import secrets
import sqlite3
import time
from pathlib import Path

DEFAULT_DB = Path(__file__).with_name("agentcap.db")


def connect(db_path=DEFAULT_DB):
    """Create a database connection and the leases table."""
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
    return conn


def issue_lease(task_id, action, resource, ttl_seconds=60, db_path=DEFAULT_DB):
    """Create a random lease token and store only its hash."""
    if not task_id or not action or not resource:
        raise ValueError("task_id, action, and resource are required")
    if not math.isfinite(ttl_seconds) or ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive and finite")

    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    lease_id = secrets.token_urlsafe(12)

    with connect(db_path) as conn:
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
                time.time() + ttl_seconds,
            ),
        )

    return token


def consume_lease(token, db_path=DEFAULT_DB):
    """Consume a valid lease once, or return None."""
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

        return dict(row) if row else None

