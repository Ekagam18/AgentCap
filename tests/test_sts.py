"""Tests for per-lease STS AssumeRole credentials (no AWS calls are made)."""

import io
import json

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from fastapi.testclient import TestClient

from broker.database import get_audit_events
from broker.main import app, get_s3_client_builder, get_sts_client
from broker.sts import (
    DEFAULT_SESSION_SECONDS,
    StsAssumeRoleError,
    build_session_policy,
    role_session_name,
    scoped_s3_client_for_lease,
    validate_role_arn,
)
from policy.checks import PolicyViolationError

ROLE_ARN = "arn:aws:iam::123456789012:role/agentcap-executor"
ADMIN_KEY = "test-admin-secret-key-12345"
AGENT_KEY = "test-agent-secret-key-67890"
AGENT_ID = "agent-1"
ACTION = "s3:GetObject"
RESOURCE = "s3://agentcap-demo/reports/q3-report.txt"
CONTENT = b"Q3 revenue: 42\n"
CREDS = {"AccessKeyId": "ASIATEST", "SecretAccessKey": "secret-xyz", "SessionToken": "session-xyz"}
LEASE = {"lease_id": "abc_DEF-123", "resource": RESOURCE}


class FakeSTS:
    def __init__(self, error_code=None, response=None, exc=None):
        self.error_code = error_code
        self.response = response
        self.exc = exc
        self.calls = []

    def assume_role(self, **kwargs):
        self.calls.append(kwargs)
        if self.exc:
            raise self.exc
        if self.error_code:
            raise ClientError({"Error": {"Code": self.error_code, "Message": "arn and account leak"}}, "AssumeRole")
        return self.response if self.response is not None else {"Credentials": dict(CREDS)}


class FakeS3:
    def __init__(self):
        self.calls = []

    def get_object(self, Bucket, Key):
        self.calls.append((Bucket, Key))
        return {"Body": io.BytesIO(CONTENT), "ContentType": "text/plain"}


class Builder:
    """Stands in for boto3.client('s3', ...) and remembers which credentials it got."""

    def __init__(self):
        self.credentials = []
        self.s3 = FakeS3()

    def __call__(self, credentials):
        self.credentials.append(credentials)
        return self.s3


# --- Session policy -----------------------------------------------------------


def test_session_policy_allows_one_action_on_one_object():
    policy = build_session_policy(RESOURCE)
    assert policy["Version"] == "2012-10-17"
    assert len(policy["Statement"]) == 1
    stmt = policy["Statement"][0]
    assert stmt["Effect"] == "Allow"
    assert stmt["Action"] == "s3:GetObject"
    assert stmt["Resource"] == "arn:aws:s3:::agentcap-demo/reports/q3-report.txt"


def test_session_policy_uses_role_partition():
    policy = build_session_policy(RESOURCE, partition="aws-cn")
    assert policy["Statement"][0]["Resource"].startswith("arn:aws-cn:s3:::")


@pytest.mark.parametrize("bad", ["s3://agentcap-demo/reports/*", "s3://agentcap-demo/reports/q?.txt"])
def test_session_policy_rejects_wildcards(bad):
    with pytest.raises((PolicyViolationError, ValueError)):
        build_session_policy(bad)


@pytest.mark.parametrize(
    "arn",
    [
        "",
        "arn:aws:iam::123:role/x",
        "arn:aws:iam::123456789012:user/alice",
        "arn:aws:s3:::bucket",
        "arn:aws:iam::123456789012:role/",
        "arn:aws:iam::123456789012:role/x y",
    ],
)
def test_invalid_role_arn_rejected(arn):
    with pytest.raises(ValueError):
        validate_role_arn(arn)


def test_valid_role_arns_accepted():
    assert validate_role_arn(ROLE_ARN) == "aws"
    assert validate_role_arn("arn:aws-us-gov:iam::123456789012:role/path/to/role") == "aws-us-gov"


def test_session_name_uses_lease_id_and_fits_sts_limits():
    assert role_session_name(LEASE) == "agentcap-abc_DEF-123"
    long_name = role_session_name({"lease_id": "x" * 200})
    assert len(long_name) == 64
    assert role_session_name({"lease_id": "a/b c"}) == "agentcap-a-b-c"


# --- AssumeRole call ----------------------------------------------------------


def test_assume_role_called_with_scoped_policy():
    sts, builder = FakeSTS(), Builder()

    client = scoped_s3_client_for_lease(LEASE, ROLE_ARN, sts_client=sts, s3_client_builder=builder)

    assert client is builder.s3
    assert builder.credentials == [CREDS]
    call = sts.calls[0]
    assert call["RoleArn"] == ROLE_ARN
    assert call["RoleSessionName"] == "agentcap-abc_DEF-123"
    assert call["DurationSeconds"] == DEFAULT_SESSION_SECONDS
    assert json.loads(call["Policy"]) == build_session_policy(RESOURCE)


def test_sts_client_error_is_sanitized():
    with pytest.raises(StsAssumeRoleError) as err:
        scoped_s3_client_for_lease(LEASE, ROLE_ARN, sts_client=FakeSTS(error_code="AccessDenied"), s3_client_builder=Builder())
    assert "AccessDenied" in str(err.value)
    assert "leak" not in str(err.value)


def test_sts_network_error_is_sanitized():
    sts = FakeSTS(exc=EndpointConnectionError(endpoint_url="https://sts.amazonaws.com"))
    with pytest.raises(StsAssumeRoleError) as err:
        scoped_s3_client_for_lease(LEASE, ROLE_ARN, sts_client=sts, s3_client_builder=Builder())
    assert "amazonaws" not in str(err.value)


@pytest.mark.parametrize("response", [{}, {"Credentials": {"AccessKeyId": "A"}}, {"Credentials": None}])
def test_missing_credentials_rejected(response):
    builder = Builder()
    with pytest.raises(StsAssumeRoleError):
        scoped_s3_client_for_lease(LEASE, ROLE_ARN, sts_client=FakeSTS(response=response), s3_client_builder=builder)
    assert builder.credentials == []


# --- Through the API ----------------------------------------------------------


@pytest.fixture
def env(tmp_path, monkeypatch):
    db_file = tmp_path / "sts.db"
    for name, value in {
        "ADMIN_API_KEY": ADMIN_KEY,
        "AGENT_API_KEY": AGENT_KEY,
        "AGENT_ID": AGENT_ID,
        "ALLOWED_S3_BUCKET": "agentcap-demo",
        "ALLOWED_S3_PREFIX": "reports/",
        "DATABASE_PATH": str(db_file),
        "AWS_ROLE_ARN": ROLE_ARN,
    }.items():
        monkeypatch.setenv(name, value)

    sts, builder = FakeSTS(), Builder()
    app.dependency_overrides[get_sts_client] = lambda: sts
    app.dependency_overrides[get_s3_client_builder] = lambda: builder
    with TestClient(app) as client:
        yield client, sts, builder, db_file
    app.dependency_overrides.clear()


def _get_token(client):
    task = client.post("/tasks", json={"action": ACTION, "resource": RESOURCE}, headers={"X-Admin-Key": ADMIN_KEY})
    lease = client.post(
        "/leases",
        json={"task_id": task.json()["task_id"], "action": ACTION, "resource": RESOURCE},
        headers={"X-Agent-Key": AGENT_KEY},
    )
    return lease.json()["lease_token"]


def _execute(client, token):
    return client.post("/leases/execute", json={"lease_token": token}, headers={"X-Agent-Key": AGENT_KEY})


def test_execute_uses_scoped_sts_credentials(env):
    client, sts, builder, _ = env
    res = _execute(client, _get_token(client))

    assert res.status_code == 200
    assert res.content == CONTENT
    assert len(sts.calls) == 1
    assert json.loads(sts.calls[0]["Policy"])["Statement"][0]["Resource"] == (
        "arn:aws:s3:::agentcap-demo/reports/q3-report.txt"
    )
    assert builder.credentials == [CREDS]
    assert builder.s3.calls == [("agentcap-demo", "reports/q3-report.txt")]


def test_credentials_never_reach_agent_or_audit_log(env):
    client, _, _, db_file = env
    res = _execute(client, _get_token(client))

    for secret in CREDS.values():
        assert secret not in res.text
        assert secret not in str(dict(res.headers))
        assert all(secret not in str(e) for e in get_audit_events(db_path=db_file))


def test_sts_failure_returns_502_and_burns_lease(env):
    client, sts, builder, db_file = env
    sts.error_code = "AccessDenied"
    token = _get_token(client)

    res = _execute(client, token)

    assert res.status_code == 502
    assert "leak" not in res.text
    assert builder.s3.calls == []
    failed = get_audit_events(event_type="s3_execution_failed", db_path=db_file)[0]
    assert "AccessDenied" in failed["detail"]
    assert _execute(client, token).status_code == 403


def test_invalid_role_arn_fails_closed_before_consuming(env, monkeypatch):
    client, sts, _, _ = env
    token = _get_token(client)
    monkeypatch.setenv("AWS_ROLE_ARN", "not-an-arn")

    assert _execute(client, token).status_code == 500
    assert sts.calls == []

    monkeypatch.setenv("AWS_ROLE_ARN", ROLE_ARN)
    assert _execute(client, token).status_code == 200


def test_no_role_arn_skips_sts(env, monkeypatch):
    client, sts, builder, _ = env
    monkeypatch.delenv("AWS_ROLE_ARN")
    fake = FakeS3()
    from broker.main import get_s3_client

    app.dependency_overrides[get_s3_client] = lambda: fake
    res = _execute(client, _get_token(client))

    assert res.status_code == 200
    assert sts.calls == []
    assert fake.calls == [("agentcap-demo", "reports/q3-report.txt")]
