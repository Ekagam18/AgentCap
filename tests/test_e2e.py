"""End-to-end tests: admin approves a task, agent gets a lease, agent spends it on S3.

S3 is replaced by a fake client through FastAPI's dependency overrides,
so these tests never touch AWS.
"""

import base64
import io
import time

import pytest
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

from broker.database import connect, get_audit_events
from broker.main import app, get_s3_client

ADMIN_KEY = "test-admin-secret-key-12345"
AGENT_KEY = "test-agent-secret-key-67890"
AGENT_ID = "agent-1"
ACTION = "s3:GetObject"
BUCKET = "agentcap-demo"
KEY = "reports/q3-report.txt"
RESOURCE = f"s3://{BUCKET}/{KEY}"
CONTENT = b"Q3 revenue: 42\n"


class FakeS3:
    """Records every call and returns whatever object it was given."""

    def __init__(self, body=CONTENT, content_type="text/plain", error_code=None, content_length=None):
        self.body = body
        self.content_type = content_type
        self.error_code = error_code
        self.content_length = content_length
        self.calls = []

    def get_object(self, Bucket, Key):
        self.calls.append((Bucket, Key))
        if self.error_code:
            raise ClientError({"Error": {"Code": self.error_code, "Message": "secret detail"}}, "GetObject")
        response = {"Body": io.BytesIO(self.body), "ContentType": self.content_type, "ETag": '"abc"'}
        if self.content_length is not None:
            response["ContentLength"] = self.content_length
        return response

    def __getattr__(self, name):
        # Any S3 call other than get_object is a bug in the executor.
        raise AssertionError(f"unexpected S3 call: {name}")


@pytest.fixture
def env(tmp_path, monkeypatch):
    db_file = tmp_path / "e2e.db"
    monkeypatch.setenv("ADMIN_API_KEY", ADMIN_KEY)
    monkeypatch.setenv("AGENT_API_KEY", AGENT_KEY)
    monkeypatch.setenv("AGENT_ID", AGENT_ID)
    monkeypatch.setenv("ALLOWED_S3_BUCKET", BUCKET)
    monkeypatch.setenv("ALLOWED_S3_PREFIX", "reports/")
    monkeypatch.setenv("DATABASE_PATH", str(db_file))
    monkeypatch.delenv("S3_MAX_OBJECT_BYTES", raising=False)

    fake = FakeS3()
    app.dependency_overrides[get_s3_client] = lambda: fake
    with TestClient(app) as client:
        yield client, fake, db_file
    app.dependency_overrides.clear()


def _approve(client):
    res = client.post("/tasks", json={"action": ACTION, "resource": RESOURCE}, headers={"X-Admin-Key": ADMIN_KEY})
    assert res.status_code == 201
    return res.json()["task_id"]


def _lease(client, task_id):
    return client.post(
        "/leases",
        json={"task_id": task_id, "action": ACTION, "resource": RESOURCE},
        headers={"X-Agent-Key": AGENT_KEY},
    )


def _execute(client, token, agent_key=AGENT_KEY):
    return client.post("/leases/execute", json={"lease_token": token}, headers={"X-Agent-Key": agent_key})


def _approve_and_lease(client):
    task_id = _approve(client)
    res = _lease(client, task_id)
    assert res.status_code == 201
    return task_id, res.json()["lease_token"]


# --- Happy path -------------------------------------------------------------


def test_full_flow_returns_object_bytes(env):
    client, fake, _ = env
    _, token = _approve_and_lease(client)

    res = _execute(client, token)

    assert res.status_code == 200
    assert base64.b64decode(res.json()["content_base64"]) == CONTENT
    assert res.json()["content_type"].startswith("text/plain")
    assert res.headers["cache-control"] == "no-store"
    assert res.headers["x-content-type-options"] == "nosniff"
    assert fake.calls == [(BUCKET, KEY)]


def test_full_flow_writes_complete_audit_trail(env):
    client, _, db_file = env
    task_id, token = _approve_and_lease(client)
    _execute(client, token)

    events = [e["event_type"] for e in get_audit_events(task_id=task_id, db_path=db_file)]
    assert events == ["task_registered", "lease_issued", "lease_consumed", "s3_execution_succeeded"]

    success = get_audit_events(event_type="s3_execution_succeeded", db_path=db_file)[0]
    assert success["outcome"] == "success"
    assert success["agent_id"] == AGENT_ID
    assert success["detail"] == f"bytes={len(CONTENT)}"


def test_token_never_appears_in_audit_log(env):
    client, _, db_file = env
    _, token = _approve_and_lease(client)
    _execute(client, token)
    _execute(client, token)

    for event in get_audit_events(db_path=db_file):
        assert token not in str(event)


def test_unsafe_content_type_falls_back_to_octet_stream(env):
    client, fake, _ = env
    fake.content_type = "text/html\r\nSet-Cookie: x=1"
    _, token = _approve_and_lease(client)

    res = _execute(client, token)

    assert res.status_code == 200
    assert res.json()["content_type"] == "application/octet-stream"
    assert "set-cookie" not in res.headers


# --- Replay and reuse -------------------------------------------------------


def test_replayed_lease_is_rejected(env):
    client, fake, db_file = env
    _, token = _approve_and_lease(client)

    assert _execute(client, token).status_code == 200
    replay = _execute(client, token)

    assert replay.status_code == 403
    assert len(fake.calls) == 1
    denied = get_audit_events(
        event_type="lease_execution_rejected",
        db_path=db_file,
    )
    assert len(denied) == 1 and denied[0]["detail"] == "invalid_token"


def test_second_lease_for_same_task_is_conflict(env):
    client, _, _ = env
    task_id, _ = _approve_and_lease(client)

    assert _lease(client, task_id).status_code == 409


def test_unknown_token_is_rejected(env):
    client, fake, _ = env
    res = _execute(client, "not-a-real-token")
    assert res.status_code == 403
    assert fake.calls == []


def test_expired_lease_is_rejected(env):
    client, fake, db_file = env
    task_id, token = _approve_and_lease(client)
    with connect(db_file) as conn:
        conn.execute("UPDATE leases SET expires_at = ? WHERE task_id = ?", (time.time() - 1, task_id))

    res = _execute(client, token)

    assert res.status_code == 403
    assert fake.calls == []


def test_lease_bound_to_other_agent_is_rejected_and_stays_unused(env, monkeypatch):
    client, fake, _ = env
    _, token = _approve_and_lease(client)

    # Same key, different configured identity: simulates another agent holding the token.
    monkeypatch.setenv("AGENT_ID", "agent-2")
    assert _execute(client, token).status_code == 403
    assert fake.calls == []

    monkeypatch.setenv("AGENT_ID", AGENT_ID)
    assert _execute(client, token).status_code == 200


# --- Authentication and input -----------------------------------------------


def test_execute_requires_agent_key(env):
    client, fake, _ = env
    _, token = _approve_and_lease(client)

    assert client.post("/leases/execute", json={"lease_token": token}).status_code == 401
    assert _execute(client, token, agent_key="wrong").status_code == 401
    assert fake.calls == []
    # A rejected key must not burn the lease.
    assert _execute(client, token).status_code == 200


def test_execute_rejects_extra_fields(env):
    client, fake, _ = env
    _, token = _approve_and_lease(client)

    res = client.post(
        "/leases/execute",
        json={"lease_token": token, "resource": "s3://agentcap-demo/reports/other.txt"},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    assert res.status_code == 422
    assert fake.calls == []


# --- Execution failures -----------------------------------------------------


def test_oversized_object_returns_413_and_burns_lease(env, monkeypatch):
    client, fake, db_file = env
    monkeypatch.setenv("S3_MAX_OBJECT_BYTES", "8")
    _, token = _approve_and_lease(client)

    res = _execute(client, token)

    assert res.status_code == 413
    failed = get_audit_events(event_type="s3_execution_failed", db_path=db_file)
    assert failed[0]["detail"] == "object_too_large"
    assert _execute(client, token).status_code == 403


def test_reported_content_length_over_limit_is_rejected(env):
    client, fake, _ = env
    fake.content_length = 10 * 1024 * 1024
    _, token = _approve_and_lease(client)

    assert _execute(client, token).status_code == 413


def test_s3_error_returns_502_without_leaking_details(env):
    client, fake, db_file = env
    fake.error_code = "AccessDenied"
    _, token = _approve_and_lease(client)

    res = _execute(client, token)

    assert res.status_code == 502
    assert "secret detail" not in res.text
    failed = get_audit_events(event_type="s3_execution_failed", db_path=db_file)[0]
    assert "AccessDenied" in failed["detail"]
    assert "secret detail" not in failed["detail"]


def test_policy_tightened_after_lease_blocks_execution(env, monkeypatch):
    client, fake, _ = env
    _, token = _approve_and_lease(client)

    monkeypatch.setenv("ALLOWED_S3_PREFIX", "public/")
    res = _execute(client, token)

    assert res.status_code == 403
    assert fake.calls == []


def test_invalid_max_object_bytes_fails_closed(env, monkeypatch):
    client, fake, _ = env
    _, token = _approve_and_lease(client)
    monkeypatch.setenv("S3_MAX_OBJECT_BYTES", "lots")

    assert _execute(client, token).status_code == 500
    assert fake.calls == []
    # Config errors are raised before the lease is consumed, so it is still usable.
    monkeypatch.delenv("S3_MAX_OBJECT_BYTES")
    assert _execute(client, token).status_code == 200
