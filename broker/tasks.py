"""Task storage and retrieval using SQLite."""

import secrets
import sqlite3
import time
from pathlib import Path

from broker.database import DEFAULT_DB, connect


def init_tasks_table(conn: sqlite3.Connection) -> None:
    """Ensure the tasks table exists in the database."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            task_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            created_at REAL NOT NULL
        )
    """)


def create_task(
    agent_id: str,
    action: str,
    resource: str,
    db_path: Path | str = DEFAULT_DB,
) -> dict:
    """Register and store an approved task in SQLite."""
    if not agent_id or not action or not resource:
        raise ValueError("agent_id, action, and resource are required")

    task_id = f"task_{secrets.token_urlsafe(16)}"
    created_at = time.time()

    with connect(db_path) as conn:
        init_tasks_table(conn)
        conn.execute(
            """INSERT INTO tasks (task_id, agent_id, action, resource, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (task_id, agent_id, action, resource, created_at),
        )

    return {
        "task_id": task_id,
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "created_at": created_at,
    }


def get_task(task_id: str, db_path: Path | str = DEFAULT_DB) -> dict | None:
    """Retrieve an approved task by its task_id."""
    if not task_id:
        return None

    with connect(db_path) as conn:
        init_tasks_table(conn)
        row = conn.execute(
            """SELECT task_id, agent_id, action, resource, created_at
               FROM tasks WHERE task_id = ?""",
            (task_id,),
        ).fetchone()

        return dict(row) if row else None
