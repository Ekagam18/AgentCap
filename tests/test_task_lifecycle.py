"""Tests for single-use, expiring tasks and agent-bound leases."""

import sqlite3
import threading
import time

import pytest
from fastapi.testclient import TestClient

from broker.database import (
    TaskUnavailableError,
    connect,
    consume_lease,
    get_audit_events,
    issue_lease,
    issue_lease_for_task,
)
from broker.main import app
from broker.tasks import create_task, get_task

ADMIN_KEY = "test-admin-secret-key-12345"
AGENT_KEY = "test-agent-secret-key-67890"
AGENT_ID = "agent-1"
ACTION = "s3:GetObject"
RESOURCE = "s3://agentcap-demo/reports/q3-report.txt"


@pytest.fixture
def client_env(tmp_path, monkeypatch):
    db_file = tmp_path / "lifecycle.db"
    monkeypatch.setenv("ADMIN_API_KEY", ADMIN_KEY)
    monkeypatch.setenv("AGENT_API_KEY", AGENT_KEY)
    monkeypatch.setenv("AGENT_ID", AGENT_ID)
    monkeypatch.setenv("ALLOWED_S3_BUCKET", "agentcap-demo")
    monkeypatch.setenv("ALLOWED_S3_PREFIX", "reports/")
    monkeypatch.setenv("DATABASE_PATH", str(db_file))
    with TestClient(app) as client:
        yield client, db_file


def _approve(client):
    res = client.post(
        "/tasks",
        json={"action": ACTION, "resource": RESOURCE},
        headers={"X-Admin-Key": ADMIN_KEY},
    )
    assert res.status_code == 201
    return res.json()


def _request_lease(client, task_id):
    return client.post(
        "/leases",
        json={"task_id": task_id, "action": ACTION, "resource": RESOURCE},
        headers={"X-Agent-Key": AGENT_KEY},
    )


# --- Task expiry and single use (API) ---------------------------------------


def test_task_response_reports_expiry(client_env):
    client, _ = client_env
    task = _approve(client)
    assert task["expires_in"] == 900


def test_task_can_issue_only_one_lease(client_env):
    client, db_file = client_env
    task_id = _approve(client)["task_id"]

    assert _request_lease(client, task_id).status_code == 201
    second = _request_lease(client, task_id)
    assert second.status_code == 409

    with connect(db_file) as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM leases").fetchone()["n"] == 1
    assert get_task(task_id, db_path=db_file)["status"] == "leased"


def test_expired_task_cannot_issue_lease(client_env, monkeypatch):
    client, db_file = client_env
    monkeypatch.setenv("TASK_TTL_SECONDS", "1")
    task_id = _approve(client)["task_id"]

    with connect(db_file) as conn:
        conn.execute("UPDATE tasks SET expires_at = ? WHERE task_id = ?", (time.time() - 1, task_id))

    res = _request_lease(client, task_id)
    assert res.status_code == 403
    assert "expired" in res.json()["detail"].lower()


@pytest.mark.parametrize("bad_ttl", ["0", "-5", "abc"])
def test_invalid_task_ttl_config_fails_closed(client_env, monkeypatch, bad_ttl):
    client, _ = client_env
    monkeypatch.setenv("TASK_TTL_SECONDS", bad_ttl)
    res = client.post(
        "/tasks",
        json={"action": ACTION, "resource": RESOURCE},
        headers={"X-Admin-Key": ADMIN_KEY},
    )
    assert res.status_code == 500


def test_denied_lease_requests_are_audited(client_env):
    client, db_file = client_env
    task_id = _approve(client)["task_id"]
    _request_lease(client, task_id)
    _request_lease(client, task_id)  # replayed approval -> denied
    _request_lease(client, "task_does_not_exist")

    denied = get_audit_events(event_type="lease_denied", db_path=db_file)
    assert [e["detail"] for e in denied] == ["already_used", "task_not_found"]
    assert all(e["outcome"] == "denied" for e in denied)


def test_task_registration_is_audited(client_env):
    client, db_file = client_env
    task_id = _approve(client)["task_id"]
    events = get_audit_events(task_id=task_id, db_path=db_file)
    assert events[0]["event_type"] == "task_registered"
    assert events[0]["agent_id"] == AGENT_ID


# --- Atomic claim (library) -------------------------------------------------


def test_concurrent_lease_requests_for_one_task_allow_one_winner(tmp_path):
    db = tmp_path / "race.db"
    task = create_task(AGENT_ID, ACTION, RESOURCE, db_path=db)
    results = []
    lock = threading.Lock()

    def worker():
        try:
            token = issue_lease_for_task(task["task_id"], AGENT_ID, ACTION, RESOURCE, db_path=db)
            outcome = ("ok", token)
        except TaskUnavailableError as err:
            outcome = ("denied", err.reason)
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(1 for r in results if r[0] == "ok") == 1
    assert all(r == ("denied", "already_used") for r in results if r[0] != "ok")


@pytest.mark.parametrize(
    "agent_id, action, resource, reason",
    [
        ("agent-2", ACTION, RESOURCE, "agent_mismatch"),
        (AGENT_ID, ACTION, "s3://agentcap-demo/reports/other.txt", "scope_mismatch"),
    ],
)
def test_issue_lease_for_task_rejects_mismatches(tmp_path, agent_id, action, resource, reason):
    db = tmp_path / "mismatch.db"
    task = create_task(AGENT_ID, ACTION, RESOURCE, db_path=db)
    with pytest.raises(TaskUnavailableError) as exc:
        issue_lease_for_task(task["task_id"], agent_id, action, resource, db_path=db)
    assert exc.value.reason == reason
    assert get_task(task["task_id"], db_path=db)["status"] == "approved"


def test_legacy_task_without_expiry_is_treated_as_expired(tmp_path):
    db = tmp_path / "legacy.db"
    task = create_task(AGENT_ID, ACTION, RESOURCE, db_path=db)
    with connect(db) as conn:
        conn.execute("UPDATE tasks SET expires_at = NULL WHERE task_id = ?", (task["task_id"],))
    with pytest.raises(TaskUnavailableError) as exc:
        issue_lease_for_task(task["task_id"], AGENT_ID, ACTION, RESOURCE, db_path=db)
    assert exc.value.reason == "expired"


@pytest.mark.parametrize("bad_ttl", [0, -1, float("inf"), float("nan"), True])
def test_create_task_rejects_invalid_ttl(tmp_path, bad_ttl):
    with pytest.raises(ValueError):
        create_task(AGENT_ID, ACTION, RESOURCE, db_path=tmp_path / "t.db", ttl_seconds=bad_ttl)


# --- Agent-bound leases -----------------------------------------------------


def test_lease_records_owning_agent(tmp_path):
    db = tmp_path / "owner.db"
    task = create_task(AGENT_ID, ACTION, RESOURCE, db_path=db)
    issue_lease_for_task(task["task_id"], AGENT_ID, ACTION, RESOURCE, db_path=db)
    with connect(db) as conn:
        assert conn.execute("SELECT agent_id FROM leases").fetchone()["agent_id"] == AGENT_ID


def test_other_agent_cannot_consume_lease_and_it_stays_usable(tmp_path):
    db = tmp_path / "steal.db"
    task = create_task(AGENT_ID, ACTION, RESOURCE, db_path=db)
    token = issue_lease_for_task(task["task_id"], AGENT_ID, ACTION, RESOURCE, db_path=db)

    assert consume_lease(token, db_path=db, agent_id="agent-2") is None
    record = consume_lease(token, db_path=db, agent_id=AGENT_ID)
    assert record is not None
    assert record["agent_id"] == AGENT_ID


def test_consume_without_agent_check_still_works_for_backward_compatibility(tmp_path):
    db = tmp_path / "compat.db"
    token = issue_lease("task-x", ACTION, RESOURCE, db_path=db)
    assert consume_lease(token, db_path=db) is not None


# --- Schema migration and connection handling -------------------------------


def test_old_database_is_migrated_in_place(tmp_path):
    db = tmp_path / "old.db"
    raw = sqlite3.connect(db)
    raw.execute(
        "CREATE TABLE tasks (task_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, action TEXT NOT NULL,"
        " resource TEXT NOT NULL, created_at REAL NOT NULL)"
    )
    raw.execute(
        "CREATE TABLE leases (lease_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, task_id TEXT NOT NULL,"
        " action TEXT NOT NULL, resource TEXT NOT NULL, expires_at REAL NOT NULL, status TEXT NOT NULL)"
    )
    raw.commit()
    raw.close()

    with connect(db) as conn:
        task_cols = {r["name"] for r in conn.execute("PRAGMA table_info(tasks)")}
        lease_cols = {r["name"] for r in conn.execute("PRAGMA table_info(leases)")}
    assert {"expires_at", "status"} <= task_cols
    assert "agent_id" in lease_cols


def test_connection_is_closed_after_with_block(tmp_path):
    with connect(tmp_path / "close.db") as conn:
        conn.execute("SELECT 1")
    with pytest.raises(sqlite3.ProgrammingError):
        conn.execute("SELECT 1")
