"""Integration tests for the AgentCap broker API."""

import base64
import io
import sqlite3
import time
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

import broker.main
from broker.database import connect, consume_lease, get_audit_events
from broker.execution_service import (
    DEFAULT_MAX_OBJECT_BYTES,
    execute_lease_token as real_execute_lease_token,
)
from broker.main import app

ADMIN_KEY = "test-admin-secret-key-12345"
AGENT_KEY = "test-agent-secret-key-67890"
AGENT_ID = "agent-1"
ALLOWED_BUCKET = "agentcap-demo"
ALLOWED_PREFIX = "reports/"
VALID_RESOURCE = "s3://agentcap-demo/reports/q3-report.txt"
VALID_ACTION = "s3:GetObject"


class MockStreamingBody:
    """Mock for botocore.response.StreamingBody supporting chunked reads and close tracking."""

    def __init__(self, data: bytes):
        self._bio = io.BytesIO(data)
        self.closed = False

    def read(self, amt: int | None = None) -> bytes:
        return self._bio.read(amt)

    def close(self) -> None:
        self.closed = True
        self._bio.close()


def make_mock_s3_client(
    payload: bytes = b"Report content",
    content_type: str = "text/plain",
    etag: str = '"etag-12345"',
) -> tuple[MagicMock, MockStreamingBody]:
    """Helper to create a mocked S3 client returning predefined payload and metadata."""
    mock_body = MockStreamingBody(payload)
    mock_client = MagicMock()
    mock_client.get_object.return_value = {
        "Body": mock_body,
        "ContentLength": len(payload),
        "ContentType": content_type,
        "ETag": etag,
        "VersionId": "v1",
        "LastModified": "2026-11-05T00:00:00Z",
        "Metadata": {},
    }
    return mock_client, mock_body


def mock_s3_for_broker(monkeypatch, mock_client):
    """Wrap broker.main.execute_lease_token to inject mock_client and mock boto3."""
    def wrapper(
        token,
        allowed_bucket,
        allowed_prefix,
        db_path=None,
        s3_client=None,
        max_object_bytes=DEFAULT_MAX_OBJECT_BYTES,
        **kwargs,
    ):
        return real_execute_lease_token(
            token,
            allowed_bucket,
            allowed_prefix,
            db_path=db_path,
            s3_client=mock_client if s3_client is None else s3_client,
            max_object_bytes=max_object_bytes,
            **kwargs,
        )

    monkeypatch.setattr(broker.main, "execute_lease_token", wrapper)
    monkeypatch.setattr("broker.s3_executor.boto3.client", lambda *args, **kwargs: mock_client)


@pytest.fixture
def mock_s3(monkeypatch):
    """Fixture providing a mock S3 client attached to the broker."""
    mock_client, mock_body = make_mock_s3_client()
    mock_s3_for_broker(monkeypatch, mock_client)
    return mock_client, mock_body


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
    assert lease_res.headers.get("Cache-Control") == "no-store"
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


# ==============================================================================
# Phase 2: POST /leases/execute Integration Tests
# ==============================================================================


def test_execute_lease_endpoint_success(client_env, mock_s3):
    client, db_file = client_env
    mock_client, mock_body = mock_s3

    # 1. Admin registers task
    task_res = _register_task(client)
    assert task_res.status_code == 201
    task_id = task_res.json()["task_id"]

    # 2. Agent requests single-use lease
    lease_res = client.post(
        "/leases",
        json={"task_id": task_id, "action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert lease_res.status_code == 201
    token = lease_res.json()["lease_token"]

    # 3. Agent executes lease
    exec_res = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert exec_res.status_code == 200
    data = exec_res.json()

    # Verify response body structure
    expected_bytes = b"Report content"
    assert data["content_base64"] == base64.b64encode(expected_bytes).decode("ascii")
    assert base64.b64decode(data["content_base64"]) == expected_bytes
    assert data["content_length"] == len(expected_bytes)
    assert data["content_type"] == "text/plain"
    assert data["etag"] == "etag-12345"
    assert "lease_token" not in data

    # Verify S3 client was called properly
    mock_client.get_object.assert_called_once_with(
        Bucket=ALLOWED_BUCKET,
        Key="reports/q3-report.txt",
    )
    assert mock_body.closed is True

    # Verify DB lease status is now 'consumed'
    with connect(db_file) as conn:
        row = conn.execute("SELECT status FROM leases WHERE task_id = ?", (task_id,)).fetchone()
        assert row["status"] == "consumed"

    # Verify audit events recorded (both lease_issued and s3_execution_succeeded)
    events = get_audit_events(db_path=db_file)
    exec_events = [e for e in events if e["event_type"] == "s3_execution_succeeded"]
    assert len(exec_events) == 1
    assert exec_events[0]["outcome"] == "success"
    assert exec_events[0]["task_id"] == task_id
    assert exec_events[0]["action"] == VALID_ACTION
    assert exec_events[0]["resource"] == VALID_RESOURCE


def test_execute_lease_endpoint_auth_failures(client_env, mock_s3):
    client, _ = client_env
    mock_client, _ = mock_s3

    # Missing X-Agent-Key header
    res_no_key = client.post(
        "/leases/execute",
        json={"lease_token": "some-token"},
    )
    assert res_no_key.status_code == 401

    # Invalid X-Agent-Key header
    res_bad_key = client.post(
        "/leases/execute",
        json={"lease_token": "some-token"},
        headers={"X-Agent-Key": "incorrect-secret-key"},
    )
    assert res_bad_key.status_code == 401

    # Admin key supplied in X-Admin-Key instead of X-Agent-Key
    res_admin_header = client.post(
        "/leases/execute",
        json={"lease_token": "some-token"},
        headers={"X-Admin-Key": ADMIN_KEY},
    )
    assert res_admin_header.status_code == 401

    # Admin key supplied in X-Agent-Key
    res_admin_as_agent = client.post(
        "/leases/execute",
        json={"lease_token": "some-token"},
        headers={"X-Agent-Key": ADMIN_KEY},
    )
    assert res_admin_as_agent.status_code == 401

    mock_client.get_object.assert_not_called()


def test_execute_lease_endpoint_invalid_token(client_env, mock_s3):
    client, db_file = client_env
    mock_client, _ = mock_s3

    res = client.post(
        "/leases/execute",
        json={"lease_token": "non_existent_fake_token_123456789012345678"},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert res.status_code == 403
    assert res.json() == {"detail": "Invalid, expired, or already consumed lease token"}
    mock_client.get_object.assert_not_called()

    # Verify rejection audit event recorded
    events = get_audit_events(db_path=db_file)
    assert len(events) == 1
    assert events[0]["event_type"] == "lease_execution_rejected"
    assert events[0]["outcome"] == "invalid_token"


def test_execute_lease_endpoint_expired_token(client_env, mock_s3):
    client, db_file = client_env
    mock_client, _ = mock_s3

    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]

    lease_res = client.post(
        "/leases",
        json={"task_id": task_id, "action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    token = lease_res.json()["lease_token"]

    # Expire the lease in SQLite
    with connect(db_file) as conn:
        conn.execute("UPDATE leases SET expires_at = ?", (int(time.time()) - 30,))

    res = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert res.status_code == 403
    assert res.json() == {"detail": "Invalid, expired, or already consumed lease token"}
    mock_client.get_object.assert_not_called()

    # Verify rejection audit event
    events = get_audit_events(db_path=db_file)
    assert events[-1]["event_type"] == "lease_execution_rejected"
    assert events[-1]["outcome"] == "invalid_token"


def test_execute_lease_endpoint_replay_protection(client_env, mock_s3):
    client, db_file = client_env
    mock_client, _ = mock_s3

    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]

    lease_res = client.post(
        "/leases",
        json={"task_id": task_id, "action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    token = lease_res.json()["lease_token"]

    # First execution succeeds
    res1 = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert res1.status_code == 200
    assert mock_client.get_object.call_count == 1

    # Second execution (replay) fails with 403
    res2 = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert res2.status_code == 403
    assert res2.json() == {"detail": "Invalid, expired, or already consumed lease token"}

    # S3 must NOT be called again
    assert mock_client.get_object.call_count == 1

    # Verify audit trail has lease_execution_rejected
    events = get_audit_events(db_path=db_file)
    assert events[-1]["event_type"] == "lease_execution_rejected"
    assert events[-1]["outcome"] == "invalid_token"


def test_execute_lease_endpoint_whitespace_padded_token_rejected_without_consuming(client_env, mock_s3):
    client, db_file = client_env
    mock_client, _ = mock_s3

    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]

    lease_res = client.post(
        "/leases",
        json={"task_id": task_id, "action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    token = lease_res.json()["lease_token"]

    # Whitespace-padded token is rejected with 403
    padded_res = client.post(
        "/leases/execute",
        json={"lease_token": f" {token} "},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert padded_res.status_code == 403
    assert padded_res.json() == {"detail": "Invalid, expired, or already consumed lease token"}
    mock_client.get_object.assert_not_called()

    # The lease must still be issued in DB
    with connect(db_file) as conn:
        row = conn.execute("SELECT status FROM leases WHERE task_id = ?", (task_id,)).fetchone()
        assert row["status"] == "issued"

    # Exact token execution succeeds
    valid_res = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert valid_res.status_code == 200
    assert mock_client.get_object.call_count == 1


@pytest.mark.parametrize("extra_key", ["action", "resource", "bucket", "key", "agent_id", "extra_field"])
def test_execute_lease_endpoint_extra_fields_rejected(client_env, mock_s3, extra_key):
    client, db_file = client_env
    mock_client, _ = mock_s3

    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]

    lease_res = client.post(
        "/leases",
        json={"task_id": task_id, "action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    token = lease_res.json()["lease_token"]

    bad_res = client.post(
        "/leases/execute",
        json={"lease_token": token, extra_key: "disallowed-value"},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert bad_res.status_code == 422
    mock_client.get_object.assert_not_called()

    # The lease must still remain issued
    with connect(db_file) as conn:
        row = conn.execute("SELECT status FROM leases WHERE task_id = ?", (task_id,)).fetchone()
        assert row["status"] == "issued"


def test_execute_lease_endpoint_empty_and_missing_token_rejected(client_env, mock_s3):
    client, _ = client_env
    mock_client, _ = mock_s3

    # Empty string token
    res_empty = client.post(
        "/leases/execute",
        json={"lease_token": ""},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert res_empty.status_code == 422

    # Missing lease_token
    res_missing = client.post(
        "/leases/execute",
        json={},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert res_missing.status_code == 422

    mock_client.get_object.assert_not_called()


def test_execute_lease_endpoint_s3_service_error_sanitized(client_env, monkeypatch):
    client, db_file = client_env
    mock_client = MagicMock()
    mock_client.get_object.side_effect = ClientError(
        {"Error": {"Code": "NoSuchKey", "Message": "Internal secret key path /var/data/private"}},
        "GetObject",
    )
    mock_s3_for_broker(monkeypatch, mock_client)

    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]

    lease_res = client.post(
        "/leases",
        json={"task_id": task_id, "action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    token = lease_res.json()["lease_token"]

    exec_res = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert exec_res.status_code == 502
    assert exec_res.json() == {"detail": "S3 service execution failed"}
    assert "Internal secret key" not in exec_res.text
    assert "NoSuchKey" not in exec_res.text

    # Verify lease is consumed in DB
    with connect(db_file) as conn:
        row = conn.execute("SELECT status FROM leases WHERE task_id = ?", (task_id,)).fetchone()
        assert row["status"] == "consumed"

    # Verify failure audit event recorded
    events = get_audit_events(db_path=db_file)
    assert events[-1]["event_type"] == "s3_execution_failed"
    assert events[-1]["outcome"] == "S3ServiceError"

    # Replay cannot be attempted
    replay_res = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert replay_res.status_code == 403


def test_execute_lease_endpoint_oversized_object(client_env, monkeypatch):
    client, db_file = client_env
    mock_client = MagicMock()
    # ContentLength exceeding 1 MiB limit
    mock_client.get_object.return_value = {
        "Body": MockStreamingBody(b"payload"),
        "ContentLength": 2 * 1024 * 1024,
        "ContentType": "text/plain",
        "ETag": '"etag-oversized"',
    }
    mock_s3_for_broker(monkeypatch, mock_client)

    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]

    lease_res = client.post(
        "/leases",
        json={"task_id": task_id, "action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    token = lease_res.json()["lease_token"]

    exec_res = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert exec_res.status_code == 413
    assert exec_res.json() == {"detail": "Object size exceeds maximum allowed limit"}

    # Lease is consumed
    with connect(db_file) as conn:
        row = conn.execute("SELECT status FROM leases WHERE task_id = ?", (task_id,)).fetchone()
        assert row["status"] == "consumed"

    # Audit event recorded
    events = get_audit_events(db_path=db_file)
    assert events[-1]["event_type"] == "s3_execution_failed"
    assert events[-1]["outcome"] == "S3ObjectTooLargeError"


def test_execute_lease_endpoint_audit_failure_fails_closed(client_env, monkeypatch):
    client, db_file = client_env
    mock_client, _ = make_mock_s3_client()
    mock_s3_for_broker(monkeypatch, mock_client)

    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]

    lease_res = client.post(
        "/leases",
        json={"task_id": task_id, "action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    token = lease_res.json()["lease_token"]

    # Force record_audit_event in broker.execution_service to fail for s3_execution_succeeded
    from broker import execution_service

    orig_record_audit_event = execution_service.record_audit_event

    def failing_audit_event(**kwargs):
        if kwargs.get("event_type") == "s3_execution_succeeded":
            raise sqlite3.OperationalError("simulated database lock")
        return orig_record_audit_event(**kwargs)

    monkeypatch.setattr(execution_service, "record_audit_event", failing_audit_event)

    exec_res = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert exec_res.status_code == 503
    assert exec_res.json() == {"detail": "Execution audit logging failed"}
    assert "simulated database lock" not in exec_res.text


def test_execute_lease_endpoint_policy_violation(client_env, mock_s3):
    client, db_file = client_env
    mock_client, _ = mock_s3

    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]

    lease_res = client.post(
        "/leases",
        json={"task_id": task_id, "action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    token = lease_res.json()["lease_token"]

    # Tamper with the issued lease in SQLite so its resource violates prefix policy
    with connect(db_file) as conn:
        conn.execute(
            "UPDATE leases SET resource = ? WHERE task_id = ?",
            ("s3://agentcap-demo/forbidden/secret.txt", task_id),
        )

    exec_res = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert exec_res.status_code == 403
    assert exec_res.json() == {"detail": "Access denied: policy violation"}
    mock_client.get_object.assert_not_called()


def test_execute_lease_endpoint_unexpected_error(client_env, monkeypatch):
    client, _ = client_env

    def raise_unexpected(*args, **kwargs):
        raise RuntimeError("Sensitive internal database connection string: db://user:pass@host")

    monkeypatch.setattr(broker.main, "execute_lease_token", raise_unexpected)

    exec_res = client.post(
        "/leases/execute",
        json={"lease_token": "some-token"},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert exec_res.status_code == 500
    assert exec_res.json() == {"detail": "Internal server error"}
    assert "Sensitive" not in exec_res.text
    assert "user:pass" not in exec_res.text


def test_execute_lease_endpoint_missing_agent_api_key(client_env, monkeypatch):
    client, _ = client_env
    monkeypatch.delenv("AGENT_API_KEY", raising=False)

    exec_res = client.post(
        "/leases/execute",
        json={"lease_token": "some-token"},
        headers={"X-Agent-Key": "some-key"},
    )
    assert exec_res.status_code == 500
    assert exec_res.json() == {"detail": "Server configuration error: AGENT_API_KEY is not configured"}


def test_execute_lease_endpoint_empty_policy_config_fails(client_env, monkeypatch):
    client, _ = client_env
    # Empty string allowed bucket causes configuration error
    monkeypatch.setenv("ALLOWED_S3_BUCKET", "")

    exec_res = client.post(
        "/leases/execute",
        json={"lease_token": "some-token"},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert exec_res.status_code == 500
    assert exec_res.json() == {"detail": "Server configuration error: ALLOWED_S3_BUCKET is not configured"}


def test_lease_issuance_response_has_no_store_cache_control(client_env):
    """Verify POST /leases response includes Cache-Control: no-store without leaking token."""
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
    assert lease_res.headers.get("Cache-Control") == "no-store"
    assert "lease_token" in lease_res.json()


def test_policy_config_missing_bucket_fails_closed(client_env, monkeypatch):
    """Verify missing ALLOWED_S3_BUCKET fails closed with HTTP 500 across endpoints."""
    client, _ = client_env
    task_res = _register_task(client)
    assert task_res.status_code == 201
    task_id = task_res.json()["task_id"]

    monkeypatch.delenv("ALLOWED_S3_BUCKET", raising=False)

    t_res = client.post(
        "/tasks",
        json={"action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Admin-Key": ADMIN_KEY},
    )
    assert t_res.status_code == 500
    assert t_res.json() == {"detail": "Server configuration error: ALLOWED_S3_BUCKET is not configured"}

    lease_res = client.post(
        "/leases",
        json={"task_id": task_id, "action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert lease_res.status_code == 500
    assert lease_res.json() == {"detail": "Server configuration error: ALLOWED_S3_BUCKET is not configured"}

    exec_res = client.post(
        "/leases/execute",
        json={"lease_token": "any-token"},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert exec_res.status_code == 500
    assert exec_res.json() == {"detail": "Server configuration error: ALLOWED_S3_BUCKET is not configured"}


def test_policy_config_empty_bucket_fails_closed(client_env, monkeypatch):
    """Verify empty/whitespace ALLOWED_S3_BUCKET fails closed with HTTP 500."""
    client, _ = client_env
    task_res = _register_task(client)
    assert task_res.status_code == 201
    task_id = task_res.json()["task_id"]

    monkeypatch.setenv("ALLOWED_S3_BUCKET", "   ")

    t_res = client.post(
        "/tasks",
        json={"action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Admin-Key": ADMIN_KEY},
    )
    assert t_res.status_code == 500
    assert t_res.json() == {"detail": "Server configuration error: ALLOWED_S3_BUCKET is not configured"}

    lease_res = client.post(
        "/leases",
        json={"task_id": task_id, "action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert lease_res.status_code == 500
    assert lease_res.json() == {"detail": "Server configuration error: ALLOWED_S3_BUCKET is not configured"}


def test_policy_config_missing_prefix_fails_closed(client_env, monkeypatch):
    """Verify missing ALLOWED_S3_PREFIX fails closed with HTTP 500 across endpoints."""
    client, _ = client_env
    task_res = _register_task(client)
    assert task_res.status_code == 201
    task_id = task_res.json()["task_id"]

    monkeypatch.delenv("ALLOWED_S3_PREFIX", raising=False)

    t_res = client.post(
        "/tasks",
        json={"action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Admin-Key": ADMIN_KEY},
    )
    assert t_res.status_code == 500
    assert t_res.json() == {"detail": "Server configuration error: ALLOWED_S3_PREFIX is not configured"}

    lease_res = client.post(
        "/leases",
        json={"task_id": task_id, "action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert lease_res.status_code == 500
    assert lease_res.json() == {"detail": "Server configuration error: ALLOWED_S3_PREFIX is not configured"}

    exec_res = client.post(
        "/leases/execute",
        json={"lease_token": "any-token"},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert exec_res.status_code == 500
    assert exec_res.json() == {"detail": "Server configuration error: ALLOWED_S3_PREFIX is not configured"}


def test_policy_config_empty_prefix_fails_closed(client_env, monkeypatch):
    """Verify empty/whitespace ALLOWED_S3_PREFIX fails closed with HTTP 500."""
    client, _ = client_env
    monkeypatch.setenv("ALLOWED_S3_PREFIX", "   ")

    task_res = client.post(
        "/tasks",
        json={"action": VALID_ACTION, "resource": VALID_RESOURCE},
        headers={"X-Admin-Key": ADMIN_KEY},
    )
    assert task_res.status_code == 500
    assert task_res.json() == {"detail": "Server configuration error: ALLOWED_S3_PREFIX is not configured"}


def test_policy_config_explicitly_configured_succeeds(client_env, monkeypatch):
    """Verify endpoints operate normally when both bucket and prefix are explicitly set."""
    client, _ = client_env
    custom_bucket = "custom-prod-bucket"
    custom_prefix = "custom-prefix/"
    custom_resource = f"s3://{custom_bucket}/{custom_prefix}data.txt"

    monkeypatch.setenv("ALLOWED_S3_BUCKET", custom_bucket)
    monkeypatch.setenv("ALLOWED_S3_PREFIX", custom_prefix)

    task_res = client.post(
        "/tasks",
        json={"action": VALID_ACTION, "resource": custom_resource},
        headers={"X-Admin-Key": ADMIN_KEY},
    )
    assert task_res.status_code == 201
    task_id = task_res.json()["task_id"]

    lease_res = client.post(
        "/leases",
        json={"task_id": task_id, "action": VALID_ACTION, "resource": custom_resource},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert lease_res.status_code == 201
    assert lease_res.headers.get("Cache-Control") == "no-store"
