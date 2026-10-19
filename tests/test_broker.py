"""Integration tests for the AgentCap broker API."""

import sqlite3
import pytest
from fastapi.testclient import TestClient

from broker.database import connect, consume_lease
from broker.main import app

ADMIN_KEY = "test-admin-secret-key-12345"
AGENT_KEY = "test-agent-secret-key-67890"
AGENT_ID = "agent-1"
ALLOWED_BUCKET = "agentcap-demo"
ALLOWED_PREFIX = "reports/"
VALID_RESOURCE = "s3://agentcap-demo/reports/q3-report.txt"
VALID_ACTION = "s3:GetObject"


@pytest.fixture
def client_env(tmp_path, monkeypatch):
    db_file = tmp_path / "broker_test.db"
    monkeypatch.setenv("ADMIN_API_KEY", ADMIN_KEY)
    monkeypatch.setenv("AGENT_API_KEY", AGENT_KEY)
    monkeypatch.setenv("AGENT_ID", AGENT_ID)
    monkeypatch.setenv("ALLOWED_S3_BUCKET", ALLOWED_BUCKET)
    monkeypatch.setenv("ALLOWED_S3_PREFIX", ALLOWED_PREFIX)
    monkeypatch.setenv("DATABASE_PATH", str(db_file))

    with TestClient(app) as client:
        yield client, db_file


def _register_task(client, action=VALID_ACTION, resource=VALID_RESOURCE, admin_key=ADMIN_KEY):
    headers = {"X-Admin-Key": admin_key} if admin_key else {}
    return client.post("/tasks", json={"action": action, "resource": resource}, headers=headers)


def test_health_check(client_env):
    client, _ = client_env
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_1_approved_action_and_resource_lease_issued(client_env):
    client, _ = client_env
    task_res = _register_task(client)
    assert task_res.status_code == 201
    task_id = task_res.json()["task_id"]

    lease_res = client.post(
        "/leases",
        json={"task_id": task_id, "action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert lease_res.status_code == 201
    data = lease_res.json()
    assert "lease_token" in data
    assert data["expires_in"] == 60
    assert data["token_type"] == "Bearer"


def test_2_unknown_task_denied(client_env):
    client, _ = client_env
    lease_res = client.post(
        "/leases",
        json={
            "task_id": "non-existent-task-id",
            "action": VALID_ACTION,
            "resource": VALID_RESOURCE,
        },
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert lease_res.status_code == 404


def test_3_different_resource_denied(client_env):
    client, _ = client_env
    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]

    lease_res = client.post(
        "/leases",
        json={
            "task_id": task_id,
            "action": VALID_ACTION,
            "resource": "s3://agentcap-demo/reports/other-file.txt",
        },
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert lease_res.status_code == 403


def test_4_s3_delete_object_denied(client_env):
    client, _ = client_env
    # Task registration with s3:DeleteObject should be rejected
    task_res = _register_task(client, action="s3:DeleteObject")
    assert task_res.status_code == 403

    # Direct lease request with s3:DeleteObject should also be rejected
    valid_task = _register_task(client)
    task_id = valid_task.json()["task_id"]
    lease_res = client.post(
        "/leases",
        json={
            "task_id": task_id,
            "action": "s3:DeleteObject",
            "resource": VALID_RESOURCE,
        },
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert lease_res.status_code == 403


def test_5_wrong_s3_bucket_denied(client_env):
    client, _ = client_env
    wrong_bucket_resource = "s3://unauthorized-bucket/reports/q3-report.txt"
    task_res = _register_task(client, resource=wrong_bucket_resource)
    assert task_res.status_code == 403


def test_6_wrong_key_prefix_denied(client_env):
    client, _ = client_env
    wrong_prefix_resource = "s3://agentcap-demo/confidential/secret.txt"
    task_res = _register_task(client, resource=wrong_prefix_resource)
    assert task_res.status_code == 403


def test_7_missing_or_invalid_agent_api_key_denied(client_env):
    client, _ = client_env
    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]

    # Missing agent key
    res_missing = client.post(
        "/leases",
        json={"task_id": task_id, "action": VALID_ACTION, "resource": VALID_RESOURCE},
    )
    assert res_missing.status_code == 401

    # Invalid agent key
    res_invalid = client.post(
        "/leases",
        json={"task_id": task_id, "action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Agent-Key": "incorrect-agent-key"},
    )
    assert res_invalid.status_code == 401


def test_8_missing_or_invalid_admin_api_key_denied(client_env):
    client, _ = client_env
    # Missing admin key
    res_missing = client.post(
        "/tasks",
        json={"action": VALID_ACTION, "resource": VALID_RESOURCE},
    )
    assert res_missing.status_code == 401

    # Invalid admin key
    res_invalid = client.post(
        "/tasks",
        json={"action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Admin-Key": "wrong-admin-key"},
    )
    assert res_invalid.status_code == 401


def test_9_agent_cannot_register_its_own_approved_task(client_env):
    client, _ = client_env
    # Agent tries using X-Agent-Key on /tasks
    res_agent_header = client.post(
        "/tasks",
        json={"action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert res_agent_header.status_code == 401

    # Agent tries using its agent key in X-Admin-Key
    res_agent_key_in_admin = client.post(
        "/tasks",
        json={"action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Admin-Key": AGENT_KEY},
    )
    assert res_agent_key_in_admin.status_code == 401


def test_10_rejected_request_creates_no_lease(client_env):
    client, db_file = client_env
    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]

    # Rejected attempt due to wrong resource
    res = client.post(
        "/leases",
        json={
            "task_id": task_id,
            "action": VALID_ACTION,
            "resource": "s3://agentcap-demo/reports/different.txt",
        },
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert res.status_code == 403

    # Verify no lease row exists in SQLite
    with connect(db_file) as conn:
        count = conn.execute("SELECT COUNT(*) AS cnt FROM leases").fetchone()["cnt"]
        assert count == 0


def test_11_correct_task_identity_and_scope_successful_authorization(client_env, monkeypatch):
    client, _ = client_env
    # Register task for agent-1
    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]

    # Same agent succeeds
    lease_res = client.post(
        "/leases",
        json={"task_id": task_id, "action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert lease_res.status_code == 201

    # Switch configured agent identity to agent-2 while keeping key or using different key
    monkeypatch.setenv("AGENT_ID", "agent-2")
    mismatch_res = client.post(
        "/leases",
        json={"task_id": task_id, "action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert mismatch_res.status_code == 403


def test_12_issued_token_works_with_consume_lease(client_env):
    client, db_file = client_env
    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]

    lease_res = client.post(
        "/leases",
        json={"task_id": task_id, "action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert lease_res.status_code == 201
    token = lease_res.json()["lease_token"]

    # Consume lease using Ekagamjot's consume_lease function
    record = consume_lease(token, db_path=db_file)
    assert record is not None
    assert record["task_id"] == task_id
    assert record["action"] == VALID_ACTION
    assert record["resource"] == VALID_RESOURCE

    # Cannot be consumed again (single use)
    second_record = consume_lease(token, db_path=db_file)
    assert second_record is None


def test_unexpected_request_fields_rejected(client_env):
    client, _ = client_env
    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]

    # Extra field in /tasks
    bad_task = client.post(
        "/tasks",
        json={"action": VALID_ACTION, "resource": VALID_RESOURCE, "extra_field": "disallowed"},
        headers={"X-Admin-Key": ADMIN_KEY},
    )
    assert bad_task.status_code == 422

    # Extra field (e.g. attempting to set TTL or agent_id) in /leases
    bad_lease = client.post(
        "/leases",
        json={
            "task_id": task_id,
            "action": VALID_ACTION,
            "resource": VALID_RESOURCE,
            "ttl": 9999,
            "agent_id": "malicious",
        },
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert bad_lease.status_code == 422


def test_fail_safely_when_configuration_missing(client_env, monkeypatch):
    client, _ = client_env
    # Unset admin key
    monkeypatch.delenv("ADMIN_API_KEY", raising=False)
    admin_res = client.post(
        "/tasks",
        json={"action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Admin-Key": "some-key"},
    )
    assert admin_res.status_code == 500

    # Unset agent key
    monkeypatch.delenv("AGENT_API_KEY", raising=False)
    agent_res = client.post(
        "/leases",
        json={"task_id": "any-id", "action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Agent-Key": "some-key"},
    )
    assert agent_res.status_code == 500
