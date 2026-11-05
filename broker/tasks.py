"""Task storage and retrieval using SQLite."""

import math
import secrets
import sqlite3
import time
from pathlib import Path

from broker.database import DEFAULT_DB, TASK_APPROVED, _init_schema, _insert_audit_event, connect

DEFAULT_TASK_TTL_SECONDS = 900  # an approval is valid for 15 minutes unless configured otherwise


def init_tasks_table(conn: sqlite3.Connection) -> None:
    """Ensure the tasks table exists in the database (kept for backward compatibility)."""
    _init_schema(conn)


def create_task(
    agent_id: str,
    action: str,
    resource: str,
    db_path: Path | str = DEFAULT_DB,
    ttl_seconds: float = DEFAULT_TASK_TTL_SECONDS,
) -> dict:
    """Register an approved task in SQLite and record a task_registered audit event.

    The task can issue exactly one lease, and only before ``expires_at``.
    """
    if not agent_id or not action or not resource:
        raise ValueError("agent_id, action, and resource are required")
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)):
        raise ValueError("ttl_seconds must be a number")
    if not math.isfinite(ttl_seconds) or ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive and finite")

    task_id = f"task_{secrets.token_urlsafe(16)}"
    created_at = time.time()
    expires_at = created_at + ttl_seconds

    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """INSERT INTO tasks (task_id, agent_id, action, resource, created_at, expires_at, status)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (task_id, agent_id, action, resource, created_at, expires_at, TASK_APPROVED),
        )
        _insert_audit_event(
            conn, "task_registered", task_id, action, resource, "success", agent_id=agent_id,
        )

    return {
        "task_id": task_id,
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "created_at": created_at,
        "expires_at": expires_at,
        "status": TASK_APPROVED,
    }


def get_task(task_id: str, db_path: Path | str = DEFAULT_DB) -> dict | None:
    """Retrieve an approved task by its task_id."""
    if not task_id:
        return None

    with connect(db_path) as conn:
        row = conn.execute(
            """SELECT task_id, agent_id, action, resource, created_at, expires_at, status
               FROM tasks WHERE task_id = ?""",
            (task_id,),
        ).fetchone()

        return dict(row) if row else None
