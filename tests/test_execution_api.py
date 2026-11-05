"""Dedicated End-to-End HTTP Execution Integration Tests (Phase 3).

Validates the full HTTP execution workflow for AgentCap:
- Successful authorized execution and base64 payload delivery.
- Real HTTP concurrency handling with single-use lease guarantees.
- Expired, invalid, whitespace-padded, and replayed token rejection.
- Agent authentication enforcement (missing, invalid, or mismatched keys).
- Explicit AWS S3 AccessDenied and NoSuchKey error handling and sanitization.
- Oversized S3 object protection (ContentLength header and streaming body).
- Strict request body validation (forbidding extra fields).
- Fail-closed behavior on audit write failures.
- Non-leakage of tokens, hashes, and internal credentials in errors and audit logs.
"""

from __future__ import annotations

import base64
import io
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

import broker.main
from broker.database import connect, get_audit_events
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
        self.close_called_count = 0

    def read(self, amt: int | None = None) -> bytes:
        return self._bio.read(amt)

    def close(self) -> None:
        self.closed = True
        self.close_called_count += 1
        self._bio.close()


class OversizedStreamingBody:
    """Mock streaming body producing chunks exceeding size limit without high memory usage."""

    def __init__(self, total_bytes: int = 2 * 1024 * 1024):
        self.total_bytes = total_bytes
        self.bytes_read = 0
        self.closed = False

    def read(self, amt: int | None = None) -> bytes:
        if self.bytes_read >= self.total_bytes:
            return b""
        chunk_size = 64 * 1024 if amt is None else min(amt, self.total_bytes - self.bytes_read)
        self.bytes_read += chunk_size
        return b"Z" * chunk_size

    def close(self) -> None:
        self.closed = True


def make_mock_s3_client(
    payload: bytes = b"Report content",
    content_type: str = "text/plain",
    etag: str = '"etag-12345"',
) -> tuple[MagicMock, MockStreamingBody]:
    """Create a mocked S3 client returning predefined payload and metadata."""
    mock_body = MockStreamingBody(payload)
    mock_client = MagicMock()
    mock_client.get_object.return_value = {
        "Body": mock_body,
        "ContentLength": len(payload),
        "ContentType": content_type,
        "ETag": etag,
        "VersionId": "v1",
        "LastModified": "2026-11-05T00:00:00Z",
        "Metadata": {"project": "agentcap"},
    }
    return mock_client, mock_body


def mock_s3_for_broker(monkeypatch: pytest.MonkeyPatch, mock_client: Any) -> None:
    """Safely inject mock_client into broker execution logic and boto3."""
    def wrapper(
        token: str,
        allowed_bucket: str,
        allowed_prefix: str,
        db_path: Any = None,
        s3_client: Any = None,
        max_object_bytes: int = DEFAULT_MAX_OBJECT_BYTES,
        **kwargs: Any,
    ) -> Any:
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
def mock_s3(monkeypatch: pytest.MonkeyPatch) -> tuple[MagicMock, MockStreamingBody]:
    """Fixture providing a mock S3 client attached to the broker."""
    mock_client, mock_body = make_mock_s3_client()
    mock_s3_for_broker(monkeypatch, mock_client)
    return mock_client, mock_body


@pytest.fixture
def client_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Fixture providing an isolated database and configured TestClient."""
    db_file = tmp_path / "execution_api_test.db"
    monkeypatch.setenv("ADMIN_API_KEY", ADMIN_KEY)
    monkeypatch.setenv("AGENT_API_KEY", AGENT_KEY)
    monkeypatch.setenv("AGENT_ID", AGENT_ID)
    monkeypatch.setenv("ALLOWED_S3_BUCKET", ALLOWED_BUCKET)
    monkeypatch.setenv("ALLOWED_S3_PREFIX", ALLOWED_PREFIX)
    monkeypatch.setenv("DATABASE_PATH", str(db_file))

    with TestClient(app) as client:
        yield client, db_file


def _register_task(
    client: TestClient,
    action: str = VALID_ACTION,
    resource: str = VALID_RESOURCE,
    admin_key: str = ADMIN_KEY,
):
    """Helper to register an approved task via POST /tasks."""
    headers = {"X-Admin-Key": admin_key} if admin_key else {}
    return client.post("/tasks", json={"action": action, "resource": resource}, headers=headers)


def _issue_lease(
    client: TestClient,
    task_id: str,
    action: str = VALID_ACTION,
    resource: str = VALID_RESOURCE,
    agent_key: str = AGENT_KEY,
):
    """Helper to request a single-use lease via POST /leases."""
    headers = {"X-Agent-Key": agent_key} if agent_key else {}
    return client.post(
        "/leases",
        json={"task_id": task_id, "action": action, "resource": resource},
        headers=headers,
    )


# ==============================================================================
# 1. Successful HTTP Execution
# ==============================================================================


def test_successful_http_lease_execution(client_env, mock_s3):
    """Verify end-to-end authorized execution returns Base64 payload and logs audit events."""
    client, db_file = client_env
    mock_client, mock_body = mock_s3

    task_res = _register_task(client)
    assert task_res.status_code == 201
    task_id = task_res.json()["task_id"]

    lease_res = _issue_lease(client, task_id)
    assert lease_res.status_code == 201
    token = lease_res.json()["lease_token"]

    exec_res = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert exec_res.status_code == 200
    data = exec_res.json()

    # Validate response fields
    expected_bytes = b"Report content"
    assert data["content_base64"] == base64.b64encode(expected_bytes).decode("ascii")
    assert base64.b64decode(data["content_base64"]) == expected_bytes
    assert data["content_length"] == len(expected_bytes)
    assert data["content_type"] == "text/plain"
    assert data["etag"] == "etag-12345"
    assert "lease_token" not in data

    # Verify S3 call parameters
    mock_client.get_object.assert_called_once_with(
        Bucket=ALLOWED_BUCKET,
        Key="reports/q3-report.txt",
    )
    assert mock_body.closed is True

    # Verify lease is consumed in SQLite
    with connect(db_file) as conn:
        row = conn.execute("SELECT status FROM leases WHERE task_id = ?", (task_id,)).fetchone()
        assert row["status"] == "consumed"

    # Verify audit trail contains lease_issued, lease_consumed, and s3_execution_succeeded
    events = get_audit_events(db_path=db_file)
    event_types = [e["event_type"] for e in events]
    assert "lease_issued" in event_types
    assert "lease_consumed" in event_types
    assert "s3_execution_succeeded" in event_types

    succ_ev = next(e for e in events if e["event_type"] == "s3_execution_succeeded")
    assert succ_ev["outcome"] == "success"
    assert succ_ev["task_id"] == task_id
    assert succ_ev["action"] == VALID_ACTION
    assert succ_ev["resource"] == VALID_RESOURCE


# ==============================================================================
# 2. HTTP Concurrency Test
# ==============================================================================


def test_concurrent_http_lease_execution(client_env, mock_s3):
    """Verify two concurrent HTTP requests for the same lease allow exactly one execution."""
    client, db_file = client_env
    mock_client, mock_body = mock_s3

    task_res = _register_task(client)
    assert task_res.status_code == 201
    task_id = task_res.json()["task_id"]

    lease_res = _issue_lease(client, task_id)
    assert lease_res.status_code == 201
    token = lease_res.json()["lease_token"]

    barrier = threading.Barrier(2)

    def execute_lease():
        barrier.wait()
        return client.post(
            "/leases/execute",
            json={"lease_token": token},
            headers={"X-Agent-Key": AGENT_KEY},
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_a = executor.submit(execute_lease)
        future_b = executor.submit(execute_lease)
        res_a = future_a.result()
        res_b = future_b.result()

    status_codes = sorted([res_a.status_code, res_b.status_code])
    assert status_codes == [200, 403]

    success_res = res_a if res_a.status_code == 200 else res_b
    rejected_res = res_b if res_a.status_code == 200 else res_a

    # Verify success response payload
    assert base64.b64decode(success_res.json()["content_base64"]) == b"Report content"
    assert success_res.json()["content_length"] == len(b"Report content")

    # Verify rejected response details
    assert rejected_res.json()["detail"] == "Invalid, expired, or already consumed lease token"

    # S3 client must be called exactly once
    assert mock_client.get_object.call_count == 1
    assert mock_body.closed is True

    # Lease must be consumed in SQLite
    with connect(db_file) as conn:
        row = conn.execute("SELECT status FROM leases WHERE task_id = ?", (task_id,)).fetchone()
        assert row["status"] == "consumed"

    # Audit verification: 1 consumed, 1 succeeded, 1 rejected
    events = get_audit_events(db_path=db_file)
    event_types = [e["event_type"] for e in events]
    assert event_types.count("lease_issued") == 1
    assert event_types.count("lease_consumed") == 1
    assert event_types.count("s3_execution_succeeded") == 1
    assert event_types.count("lease_execution_rejected") == 1

    succ_ev = next(e for e in events if e["event_type"] == "s3_execution_succeeded")
    assert succ_ev["outcome"] == "success"
    assert succ_ev["task_id"] == task_id

    rej_ev = next(e for e in events if e["event_type"] == "lease_execution_rejected")
    assert rej_ev["outcome"] == "invalid_token"


# ==============================================================================
# 3. Explicit S3 AccessDenied & NoSuchKey Error Handling
# ==============================================================================


def test_s3_access_denied_returns_sanitized_502(client_env, monkeypatch):
    """Verify S3 AccessDenied returns sanitized 502, consumes lease, and prevents secret leaks."""
    client, db_file = client_env
    sensitive_iam_message = (
        "User: arn:aws:iam::123456789012:role/agentcap-broker-role is not authorized to "
        "perform: s3:GetObject on resource: arn:aws:s3:::agentcap-demo/reports/q3-report.txt "
        "because no identity-based policy allows the s3:GetObject action"
    )
    mock_client = MagicMock()
    mock_client.get_object.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": sensitive_iam_message}},
        "GetObject",
    )
    mock_s3_for_broker(monkeypatch, mock_client)

    task_res = _register_task(client)
    assert task_res.status_code == 201
    task_id = task_res.json()["task_id"]

    lease_res = _issue_lease(client, task_id)
    assert lease_res.status_code == 201
    token = lease_res.json()["lease_token"]

    exec_res = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )

    # 1. Sanitized 502 response
    assert exec_res.status_code == 502
    assert exec_res.json() == {"detail": "S3 service execution failed"}

    # 2. Confirm raw AWS error details and IAM role ARN are not returned
    assert "AccessDenied" not in exec_res.text
    assert "123456789012" not in exec_res.text
    assert "agentcap-broker-role" not in exec_res.text
    assert "arn:aws:iam" not in exec_res.text

    # 3. Verify lease remains consumed in SQLite
    with connect(db_file) as conn:
        row = conn.execute("SELECT status FROM leases WHERE task_id = ?", (task_id,)).fetchone()
        assert row["status"] == "consumed"

    # 4. Verify failure audit event recorded
    events = get_audit_events(db_path=db_file)
    fail_events = [e for e in events if e["event_type"] == "s3_execution_failed"]
    assert len(fail_events) == 1
    fail_ev = fail_events[0]
    assert fail_ev["outcome"] == "S3ServiceError"
    assert fail_ev["task_id"] == task_id
    assert fail_ev["action"] == VALID_ACTION
    assert fail_ev["resource"] == VALID_RESOURCE

    # Verify no raw IAM details or tokens leaked into audit table
    assert "123456789012" not in str(dict(fail_ev))
    assert token not in str(dict(fail_ev))

    # 5. Subsequent execution attempt with same token must be rejected
    replay_res = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert replay_res.status_code == 403


def test_s3_missing_object_nosuchkey_returns_sanitized_502(client_env, monkeypatch):
    """Verify S3 NoSuchKey returns sanitized 502, consumes lease, and hides internal key paths."""
    client, db_file = client_env
    sensitive_internal_message = "The specified key internal/hidden/secret.txt does not exist."
    mock_client = MagicMock()
    mock_client.get_object.side_effect = ClientError(
        {"Error": {"Code": "NoSuchKey", "Message": sensitive_internal_message}},
        "GetObject",
    )
    mock_s3_for_broker(monkeypatch, mock_client)

    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]

    lease_res = _issue_lease(client, task_id)
    token = lease_res.json()["lease_token"]

    exec_res = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )

    assert exec_res.status_code == 502
    assert exec_res.json() == {"detail": "S3 service execution failed"}
    assert "NoSuchKey" not in exec_res.text
    assert "secret.txt" not in exec_res.text
    assert "internal/hidden" not in exec_res.text

    with connect(db_file) as conn:
        row = conn.execute("SELECT status FROM leases WHERE task_id = ?", (task_id,)).fetchone()
        assert row["status"] == "consumed"

    events = get_audit_events(db_path=db_file)
    fail_events = [e for e in events if e["event_type"] == "s3_execution_failed"]
    assert len(fail_events) == 1
    assert fail_events[0]["outcome"] == "S3ServiceError"


# ==============================================================================
# 4. Token Validation, Replay, and Expiry Rejection
# ==============================================================================


def test_invalid_lease_token_rejection(client_env, mock_s3):
    """Verify non-existent or forged token is rejected with 403 without calling S3."""
    client, db_file = client_env
    mock_client, _ = mock_s3

    res = client.post(
        "/leases/execute",
        json={"lease_token": "invalid_forged_token_01234567890123456789012"},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert res.status_code == 403
    assert res.json() == {"detail": "Invalid, expired, or already consumed lease token"}
    mock_client.get_object.assert_not_called()

    events = get_audit_events(db_path=db_file)
    assert len(events) == 1
    assert events[0]["event_type"] == "lease_execution_rejected"
    assert events[0]["outcome"] == "invalid_token"


def test_expired_lease_token_rejection(client_env, mock_s3):
    """Verify expired token is rejected with 403 without calling S3."""
    client, db_file = client_env
    mock_client, _ = mock_s3

    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]
    lease_res = _issue_lease(client, task_id)
    token = lease_res.json()["lease_token"]

    # Expire the lease in SQLite
    with connect(db_file) as conn:
        conn.execute("UPDATE leases SET expires_at = ?", (int(time.time()) - 60,))

    res = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert res.status_code == 403
    assert res.json() == {"detail": "Invalid, expired, or already consumed lease token"}
    mock_client.get_object.assert_not_called()

    events = get_audit_events(db_path=db_file)
    assert events[-1]["event_type"] == "lease_execution_rejected"
    assert events[-1]["outcome"] == "invalid_token"


def test_whitespace_padded_token_rejected_without_consuming(client_env, mock_s3):
    """Verify whitespace-padded token is rejected with 403 and does not consume original lease."""
    client, db_file = client_env
    mock_client, _ = mock_s3

    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]
    lease_res = _issue_lease(client, task_id)
    token = lease_res.json()["lease_token"]

    padded_res = client.post(
        "/leases/execute",
        json={"lease_token": f"   {token}   "},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert padded_res.status_code == 403
    assert padded_res.json() == {"detail": "Invalid, expired, or already consumed lease token"}
    mock_client.get_object.assert_not_called()

    # The lease must still remain issued in SQLite
    with connect(db_file) as conn:
        row = conn.execute("SELECT status FROM leases WHERE task_id = ?", (task_id,)).fetchone()
        assert row["status"] == "issued"

    # Executing with exact original token must succeed
    valid_res = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert valid_res.status_code == 200
    assert mock_client.get_object.call_count == 1


def test_replay_rejection(client_env, mock_s3):
    """Verify executing the same lease token twice is rejected on the second call."""
    client, db_file = client_env
    mock_client, _ = mock_s3

    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]
    lease_res = _issue_lease(client, task_id)
    token = lease_res.json()["lease_token"]

    # First call succeeds
    res1 = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert res1.status_code == 200
    assert mock_client.get_object.call_count == 1

    # Replay call fails with 403
    res2 = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert res2.status_code == 403
    assert res2.json() == {"detail": "Invalid, expired, or already consumed lease token"}

    # S3 must NOT be called a second time
    assert mock_client.get_object.call_count == 1

    # Second call logged as lease_execution_rejected
    events = get_audit_events(db_path=db_file)
    assert events[-1]["event_type"] == "lease_execution_rejected"
    assert events[-1]["outcome"] == "invalid_token"


# ==============================================================================
# 5. Agent Authentication Enforcement
# ==============================================================================


def test_agent_authentication_missing_and_invalid(client_env, mock_s3):
    """Verify unauthorized requests without valid agent key are rejected with 401."""
    client, _ = client_env
    mock_client, _ = mock_s3

    # 1. Missing X-Agent-Key
    res_no_key = client.post(
        "/leases/execute",
        json={"lease_token": "sample-token"},
    )
    assert res_no_key.status_code == 401
    assert res_no_key.json() == {"detail": "Invalid or missing agent API key"}

    # 2. Invalid X-Agent-Key
    res_wrong_key = client.post(
        "/leases/execute",
        json={"lease_token": "sample-token"},
        headers={"X-Agent-Key": "completely-wrong-key"},
    )
    assert res_wrong_key.status_code == 401

    # 3. Admin key supplied in X-Admin-Key header
    res_admin_header = client.post(
        "/leases/execute",
        json={"lease_token": "sample-token"},
        headers={"X-Admin-Key": ADMIN_KEY},
    )
    assert res_admin_header.status_code == 401

    # 4. Admin key passed in X-Agent-Key header
    res_admin_as_agent = client.post(
        "/leases/execute",
        json={"lease_token": "sample-token"},
        headers={"X-Agent-Key": ADMIN_KEY},
    )
    assert res_admin_as_agent.status_code == 401

    mock_client.get_object.assert_not_called()


# ==============================================================================
# 6. Oversized S3 Object Protection
# ==============================================================================


def test_oversized_object_content_length_header_rejected_413(client_env, monkeypatch):
    """Verify object with ContentLength header exceeding limit is rejected with 413."""
    client, db_file = client_env
    mock_client = MagicMock()
    mock_client.get_object.return_value = {
        "Body": MockStreamingBody(b"payload"),
        "ContentLength": 5 * 1024 * 1024,  # 5 MiB > 1 MiB default
        "ContentType": "text/plain",
        "ETag": '"etag-oversized"',
    }
    mock_s3_for_broker(monkeypatch, mock_client)

    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]
    lease_res = _issue_lease(client, task_id)
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

    events = get_audit_events(db_path=db_file)
    assert events[-1]["event_type"] == "s3_execution_failed"
    assert events[-1]["outcome"] == "S3ObjectTooLargeError"


def test_oversized_object_streaming_body_rejected_413(client_env, monkeypatch):
    """Verify streaming object without ContentLength exceeding limit is rejected with 413."""
    client, db_file = client_env
    oversized_body = OversizedStreamingBody(total_bytes=2 * 1024 * 1024)
    mock_client = MagicMock()
    mock_client.get_object.return_value = {
        "Body": oversized_body,
        "ContentLength": None,  # Missing or untrusted header
        "ContentType": "application/octet-stream",
        "ETag": '"etag-stream-large"',
    }
    mock_s3_for_broker(monkeypatch, mock_client)

    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]
    lease_res = _issue_lease(client, task_id)
    token = lease_res.json()["lease_token"]

    exec_res = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert exec_res.status_code == 413
    assert exec_res.json() == {"detail": "Object size exceeds maximum allowed limit"}
    assert oversized_body.closed is True

    # Lease is consumed
    with connect(db_file) as conn:
        row = conn.execute("SELECT status FROM leases WHERE task_id = ?", (task_id,)).fetchone()
        assert row["status"] == "consumed"

    events = get_audit_events(db_path=db_file)
    assert events[-1]["event_type"] == "s3_execution_failed"
    assert events[-1]["outcome"] == "S3ObjectTooLargeError"


# ==============================================================================
# 7. Strict Request Validation & Sanitized Error Protection
# ==============================================================================


@pytest.mark.parametrize("disallowed_field", ["action", "resource", "bucket", "key", "agent_id", "malicious"])
def test_strict_request_body_validation_extra_fields_rejected_422(client_env, mock_s3, disallowed_field):
    """Verify request containing any extra fields is rejected with 422 before lease consumption."""
    client, db_file = client_env
    mock_client, _ = mock_s3

    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]
    lease_res = _issue_lease(client, task_id)
    token = lease_res.json()["lease_token"]

    bad_res = client.post(
        "/leases/execute",
        json={"lease_token": token, disallowed_field: "injected-value"},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert bad_res.status_code == 422
    mock_client.get_object.assert_not_called()

    # The lease must remain unconsumed in SQLite
    with connect(db_file) as conn:
        row = conn.execute("SELECT status FROM leases WHERE task_id = ?", (task_id,)).fetchone()
        assert row["status"] == "issued"


def test_empty_and_missing_token_rejected_422(client_env, mock_s3):
    """Verify empty string or missing lease_token payload returns 422."""
    client, _ = client_env
    mock_client, _ = mock_s3

    res_empty = client.post(
        "/leases/execute",
        json={"lease_token": ""},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert res_empty.status_code == 422

    res_missing = client.post(
        "/leases/execute",
        json={},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert res_missing.status_code == 422

    mock_client.get_object.assert_not_called()


def test_audit_write_failure_fails_closed_503(client_env, monkeypatch):
    """Verify that if recording execution audit fails, 503 is returned without payload."""
    client, _ = client_env
    mock_client, _ = make_mock_s3_client(b"Top secret document content")
    mock_s3_for_broker(monkeypatch, mock_client)

    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]
    lease_res = _issue_lease(client, task_id)
    token = lease_res.json()["lease_token"]

    from broker import execution_service
    orig_record_audit_event = execution_service.record_audit_event

    def failing_record_audit(**kwargs: Any):
        if kwargs.get("event_type") == "s3_execution_succeeded":
            raise sqlite3.OperationalError("database disk image is full")
        return orig_record_audit_event(**kwargs)

    monkeypatch.setattr(execution_service, "record_audit_event", failing_record_audit)

    exec_res = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert exec_res.status_code == 503
    assert exec_res.json() == {"detail": "Execution audit logging failed"}
    # Verify content was NOT leaked
    assert "Top secret document" not in exec_res.text
    assert "database disk image" not in exec_res.text


def test_policy_violation_on_tampered_lease_returns_403(client_env, mock_s3):
    """Verify tampered lease violating policy raises sanitized 403."""
    client, db_file = client_env
    mock_client, _ = mock_s3

    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]
    lease_res = _issue_lease(client, task_id)
    token = lease_res.json()["lease_token"]

    # Tamper with the issued lease in SQLite so its resource violates prefix policy
    with connect(db_file) as conn:
        conn.execute(
            "UPDATE leases SET resource = ? WHERE task_id = ?",
            ("s3://agentcap-demo/sensitive/salaries.csv", task_id),
        )

    exec_res = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert exec_res.status_code == 403
    assert exec_res.json() == {"detail": "Access denied: policy violation"}
    mock_client.get_object.assert_not_called()


def test_no_secret_or_token_leakage_in_error_responses_and_audit(client_env, mock_s3):
    """Verify neither lease tokens, SHA hashes, nor secrets leak into error bodies or audit events."""
    client, db_file = client_env
    mock_client, _ = mock_s3

    task_res = _register_task(client)
    task_id = task_res.json()["task_id"]
    lease_res = _issue_lease(client, task_id)
    token = lease_res.json()["lease_token"]

    # Generate an error (e.g. replay)
    client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    replay_res = client.post(
        "/leases/execute",
        json={"lease_token": token},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert replay_res.status_code == 403

    # Assert neither token nor secrets appear in response
    assert token not in replay_res.text
    assert AGENT_KEY not in replay_res.text
    assert ADMIN_KEY not in replay_res.text

    # Assert audit trail does not store plaintext token
    events = get_audit_events(db_path=db_file)
    for event in events:
        event_dict_str = str(dict(event))
        assert token not in event_dict_str
        assert AGENT_KEY not in event_dict_str
        assert ADMIN_KEY not in event_dict_str
