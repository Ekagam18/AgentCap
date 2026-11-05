"""Unit tests for broker.execution_service."""

from __future__ import annotations

import io
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from broker.database import connect, get_audit_events, issue_lease
from broker.execution_service import (
    DEFAULT_MAX_OBJECT_BYTES,
    ExecutionAuditError,
    InvalidLeaseTokenError,
    PolicyViolationError,
    S3ExecutionResult,
    S3ObjectTooLargeError,
    S3ServiceError,
    execute_lease_token,
)

ALLOWED_BUCKET = "agentcap-demo"
ALLOWED_PREFIX = "reports/"


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


def make_mock_s3_client(payload: bytes = b"Report content", content_type: str = "text/plain") -> tuple[MagicMock, MockStreamingBody]:
    """Helper to create a mocked S3 client returning payload."""
    mock_body = MockStreamingBody(payload)
    mock_client = MagicMock()
    mock_client.get_object.return_value = {
        "Body": mock_body,
        "ContentLength": len(payload),
        "ContentType": content_type,
        "ETag": '"etag12345"',
        "VersionId": "v1.0",
        "LastModified": "2026-11-05T00:00:00Z",
        "Metadata": {"department": "finance"},
    }
    return mock_client, mock_body


def test_successful_lease_consumption_and_s3_retrieval(tmp_path):
    db = tmp_path / "exec_success.db"
    payload = b"Q3 Financial Summary Report"
    mock_client, mock_body = make_mock_s3_client(payload)

    token = issue_lease(
        task_id="task-fin-1",
        action="s3:GetObject",
        resource="s3://agentcap-demo/reports/q3_summary.txt",
        db_path=db,
    )

    result = execute_lease_token(
        token=token,
        allowed_bucket=ALLOWED_BUCKET,
        allowed_prefix=ALLOWED_PREFIX,
        db_path=db,
        s3_client=mock_client,
    )

    # 1. Assert structured result
    assert isinstance(result, S3ExecutionResult)
    assert result.bucket == "agentcap-demo"
    assert result.key == "reports/q3_summary.txt"
    assert result.content_bytes == payload
    assert result.content_length == len(payload)
    assert result.content_type == "text/plain"
    assert result.etag == "etag12345"
    assert result.metadata == {"department": "finance"}
    assert result["content_bytes"] == payload

    # 2. Verify S3 client was called with correct arguments
    mock_client.get_object.assert_called_once_with(
        Bucket="agentcap-demo",
        Key="reports/q3_summary.txt",
    )
    assert mock_body.closed is True

    # 3. Verify audit trail in SQLite
    events = get_audit_events(db_path=db)
    event_types = [e["event_type"] for e in events]
    assert event_types == ["lease_issued", "lease_consumed", "s3_execution_succeeded"]

    success_ev = events[2]
    assert success_ev["event_type"] == "s3_execution_succeeded"
    assert success_ev["outcome"] == "success"
    assert success_ev["task_id"] == "task-fin-1"
    assert success_ev["action"] == "s3:GetObject"
    assert success_ev["resource"] == "s3://agentcap-demo/reports/q3_summary.txt"
    assert success_ev["lease_id"] is not None

    # 4. Verify lease status in SQLite is consumed
    with connect(db) as conn:
        row = conn.execute("SELECT status FROM leases").fetchone()
        assert row["status"] == "consumed"


@pytest.mark.parametrize(
    "invalid_tok",
    [
        "invalid_token_does_not_exist_at_all_12345678",
        "",
        "   ",
        None,
        12345,
    ],
)
def test_invalid_token_rejection(tmp_path, invalid_tok):
    db = tmp_path / "exec_invalid.db"
    mock_client, _ = make_mock_s3_client()

    with pytest.raises(InvalidLeaseTokenError, match="Invalid, expired, or already consumed lease token"):
        execute_lease_token(
            token=invalid_tok,
            allowed_bucket=ALLOWED_BUCKET,
            allowed_prefix=ALLOWED_PREFIX,
            db_path=db,
            s3_client=mock_client,
        )

    # S3 was never called
    mock_client.get_object.assert_not_called()

    # Rejection audit event recorded
    events = get_audit_events(db_path=db)
    assert len(events) == 1
    rej_ev = events[0]
    assert rej_ev["event_type"] == "lease_execution_rejected"
    assert rej_ev["outcome"] == "invalid_token"
    assert rej_ev["task_id"] is None
    assert rej_ev["action"] is None
    assert rej_ev["resource"] is None
    assert rej_ev["lease_id"] is None

    # The supplied invalid token must not appear in any audit field
    if isinstance(invalid_tok, str) and invalid_tok.strip():
        for val in rej_ev.values():
            assert invalid_tok not in str(val)


def test_expired_lease_rejection(tmp_path):
    db = tmp_path / "exec_expired.db"
    mock_client, _ = make_mock_s3_client()

    token = issue_lease(
        task_id="task-exp",
        action="s3:GetObject",
        resource="s3://agentcap-demo/reports/exp.txt",
        ttl_seconds=0.01,
        db_path=db,
    )

    # Wait for lease to expire
    time.sleep(0.05)

    with pytest.raises(InvalidLeaseTokenError, match="Invalid, expired, or already consumed lease token"):
        execute_lease_token(
            token=token,
            allowed_bucket=ALLOWED_BUCKET,
            allowed_prefix=ALLOWED_PREFIX,
            db_path=db,
            s3_client=mock_client,
        )

    # S3 client never called
    mock_client.get_object.assert_not_called()

    # Audit trail: lease_issued then lease_execution_rejected (no lease_consumed)
    events = get_audit_events(db_path=db)
    event_types = [e["event_type"] for e in events]
    assert event_types == ["lease_issued", "lease_execution_rejected"]
    assert events[1]["outcome"] == "invalid_token"

    # Lease status remains 'issued' (was never consumed)
    with connect(db) as conn:
        row = conn.execute("SELECT status FROM leases").fetchone()
        assert row["status"] == "issued"


def test_replayed_token_rejection(tmp_path):
    db = tmp_path / "exec_replay.db"
    mock_client, _ = make_mock_s3_client(b"Single Use Secret")

    token = issue_lease(
        task_id="task-replay",
        action="s3:GetObject",
        resource="s3://agentcap-demo/reports/doc.txt",
        db_path=db,
    )

    # 1. First execution succeeds
    res1 = execute_lease_token(
        token=token,
        allowed_bucket=ALLOWED_BUCKET,
        allowed_prefix=ALLOWED_PREFIX,
        db_path=db,
        s3_client=mock_client,
    )
    assert res1.content_bytes == b"Single Use Secret"
    assert mock_client.get_object.call_count == 1

    # 2. Replay with the same token fails
    with pytest.raises(InvalidLeaseTokenError, match="Invalid, expired, or already consumed lease token"):
        execute_lease_token(
            token=token,
            allowed_bucket=ALLOWED_BUCKET,
            allowed_prefix=ALLOWED_PREFIX,
            db_path=db,
            s3_client=mock_client,
        )

    # S3 client was not called a second time
    assert mock_client.get_object.call_count == 1

    # Audit events verify 1 success and 1 rejection
    events = get_audit_events(db_path=db)
    event_types = [e["event_type"] for e in events]
    assert event_types == [
        "lease_issued",
        "lease_consumed",
        "s3_execution_succeeded",
        "lease_execution_rejected",
    ]
    assert events[3]["outcome"] == "invalid_token"


def test_concurrent_attempts_using_same_lease_only_one_succeeds(tmp_path):
    db = tmp_path / "exec_concurrent.db"
    payload = b"Concurrent Secret Data"

    mock_body = MockStreamingBody(payload)
    mock_client = MagicMock()

    def slow_get_object(*args, **kwargs):
        time.sleep(0.01)
        return {
            "Body": mock_body,
            "ContentLength": len(payload),
            "ContentType": "text/plain",
            "ETag": '"etag_conc"',
        }

    mock_client.get_object.side_effect = slow_get_object

    token = issue_lease(
        task_id="task-conc-1",
        action="s3:GetObject",
        resource="s3://agentcap-demo/reports/annual.csv",
        ttl_seconds=60,
        db_path=db,
    )

    num_threads = 10
    success_results = []
    rejected_errors = []

    def run_worker():
        try:
            res = execute_lease_token(
                token=token,
                allowed_bucket=ALLOWED_BUCKET,
                allowed_prefix=ALLOWED_PREFIX,
                db_path=db,
                s3_client=mock_client,
            )
            success_results.append(res)
        except InvalidLeaseTokenError as err:
            rejected_errors.append(err)

    with ThreadPoolExecutor(max_workers=num_threads) as pool:
        futures = [pool.submit(run_worker) for _ in range(num_threads)]
        for f in futures:
            f.result()

    # Exactly 1 success, 9 rejections
    assert len(success_results) == 1
    assert len(rejected_errors) == num_threads - 1

    # S3 client was called at most once
    assert mock_client.get_object.call_count == 1

    # Audit verification: 1 consumed, 1 succeeded, 9 rejected
    events = get_audit_events(db_path=db)
    consumed_count = sum(1 for e in events if e["event_type"] == "lease_consumed")
    succeeded_count = sum(1 for e in events if e["event_type"] == "s3_execution_succeeded")
    rejected_count = sum(1 for e in events if e["event_type"] == "lease_execution_rejected")

    assert consumed_count == 1
    assert succeeded_count == 1
    assert rejected_count == num_threads - 1


def test_s3_service_failure_and_sanitized_failure_audit(tmp_path):
    db = tmp_path / "exec_s3_fail.db"

    mock_client = MagicMock()
    mock_client.get_object.side_effect = ClientError(
        {"Error": {"Code": "NoSuchKey", "Message": "The specified key does not exist."}},
        "GetObject",
    )

    token = issue_lease(
        task_id="task-s3-fail",
        action="s3:GetObject",
        resource="s3://agentcap-demo/reports/missing.txt",
        db_path=db,
    )

    # Execution fails with S3ServiceError
    with pytest.raises(S3ServiceError, match="AWS S3 error \\(NoSuchKey\\)"):
        execute_lease_token(
            token=token,
            allowed_bucket=ALLOWED_BUCKET,
            allowed_prefix=ALLOWED_PREFIX,
            db_path=db,
            s3_client=mock_client,
        )

    # Audit trail verifies lease was consumed and failure was audited safely
    events = get_audit_events(db_path=db)
    event_types = [e["event_type"] for e in events]
    assert event_types == ["lease_issued", "lease_consumed", "s3_execution_failed"]

    fail_ev = events[2]
    assert fail_ev["outcome"] == "S3ServiceError"
    assert fail_ev["task_id"] == "task-s3-fail"
    assert fail_ev["resource"] == "s3://agentcap-demo/reports/missing.txt"
    assert fail_ev["lease_id"] is not None

    # The lease REMAINS consumed and cannot be reused
    with connect(db) as conn:
        row = conn.execute("SELECT status FROM leases").fetchone()
        assert row["status"] == "consumed"

    # Attempting to call again with the same token must fail
    with pytest.raises(InvalidLeaseTokenError):
        execute_lease_token(
            token=token,
            allowed_bucket=ALLOWED_BUCKET,
            allowed_prefix=ALLOWED_PREFIX,
            db_path=db,
            s3_client=mock_client,
        )


def test_oversized_object_rejection_and_failure_audit(tmp_path):
    db = tmp_path / "exec_oversize.db"

    # 250 bytes data when limit is 100 bytes
    payload = b"x" * 250
    mock_client, mock_body = make_mock_s3_client(payload)

    token = issue_lease(
        task_id="task-oversize",
        action="s3:GetObject",
        resource="s3://agentcap-demo/reports/big.bin",
        db_path=db,
    )

    with pytest.raises(S3ObjectTooLargeError):
        execute_lease_token(
            token=token,
            allowed_bucket=ALLOWED_BUCKET,
            allowed_prefix=ALLOWED_PREFIX,
            db_path=db,
            s3_client=mock_client,
            max_object_bytes=100,
        )

    # Response body was closed despite oversize error
    assert mock_body.closed is True

    # Audit verification: s3_execution_failed with outcome S3ObjectTooLargeError
    events = get_audit_events(db_path=db)
    event_types = [e["event_type"] for e in events]
    assert event_types == ["lease_issued", "lease_consumed", "s3_execution_failed"]
    assert events[2]["outcome"] == "S3ObjectTooLargeError"

    # Lease remains consumed
    with connect(db) as conn:
        row = conn.execute("SELECT status FROM leases").fetchone()
        assert row["status"] == "consumed"


def test_policy_violation_rejection_and_failure_audit(tmp_path):
    db = tmp_path / "exec_policy_viol.db"
    mock_client, _ = make_mock_s3_client()

    # Resource in disallowed prefix "secrets/"
    token = issue_lease(
        task_id="task-pol-viol",
        action="s3:GetObject",
        resource="s3://agentcap-demo/secrets/keys.txt",
        db_path=db,
    )

    with pytest.raises(PolicyViolationError):
        execute_lease_token(
            token=token,
            allowed_bucket=ALLOWED_BUCKET,
            allowed_prefix=ALLOWED_PREFIX,  # "reports/"
            db_path=db,
            s3_client=mock_client,
        )

    # S3 client was not called
    mock_client.get_object.assert_not_called()

    # Audit verification: s3_execution_failed with PolicyViolationError
    events = get_audit_events(db_path=db)
    event_types = [e["event_type"] for e in events]
    assert event_types == ["lease_issued", "lease_consumed", "s3_execution_failed"]
    assert events[2]["outcome"] == "PolicyViolationError"

    # Lease remains consumed
    with connect(db) as conn:
        assert conn.execute("SELECT status FROM leases").fetchone()["status"] == "consumed"


def test_no_lease_token_or_object_contents_in_audit_records(tmp_path):
    db = tmp_path / "exec_secrets_check.db"
    secret_payload = b"CLASSIFIED_FINANCIAL_DATA_NEVER_LOG_987654321"
    mock_client, _ = make_mock_s3_client(secret_payload)

    token = issue_lease(
        task_id="task-secret-check",
        action="s3:GetObject",
        resource="s3://agentcap-demo/reports/classified.txt",
        db_path=db,
    )

    execute_lease_token(
        token=token,
        allowed_bucket=ALLOWED_BUCKET,
        allowed_prefix=ALLOWED_PREFIX,
        db_path=db,
        s3_client=mock_client,
    )

    with connect(db) as conn:
        rows = conn.execute("SELECT * FROM audit_events").fetchall()

    assert len(rows) == 3

    # Check every column of every audit row
    for row in rows:
        for val in row:
            if val is not None:
                val_str = str(val)
                # Plaintext token must never be in any audit field
                assert token not in val_str
                # Secret object payload must never be in any audit field
                assert "CLASSIFIED_FINANCIAL_DATA" not in val_str
                assert "987654321" not in val_str


def test_audit_write_failure_does_not_result_in_reported_success(tmp_path, monkeypatch):
    import broker.execution_service

    db = tmp_path / "exec_audit_fail.db"
    mock_client, _ = make_mock_s3_client(b"Critical Document")

    token = issue_lease(
        task_id="task-audit-fail",
        action="s3:GetObject",
        resource="s3://agentcap-demo/reports/doc.txt",
        db_path=db,
    )

    real_record_audit_event = broker.database.record_audit_event

    def fail_on_success_audit(event_type, *args, **kwargs):
        if event_type == "s3_execution_succeeded":
            raise RuntimeError("Simulated audit disk full error")
        return real_record_audit_event(event_type, *args, **kwargs)

    monkeypatch.setattr(broker.execution_service, "record_audit_event", fail_on_success_audit)

    # Must raise ExecutionAuditError and fail closed (never report success)
    with pytest.raises(ExecutionAuditError, match="failing closed"):
        execute_lease_token(
            token=token,
            allowed_bucket=ALLOWED_BUCKET,
            allowed_prefix=ALLOWED_PREFIX,
            db_path=db,
            s3_client=mock_client,
        )

    # S3 was called, but execution failed closed
    assert mock_client.get_object.call_count == 1

    # Lease is consumed in database
    with connect(db) as conn:
        assert conn.execute("SELECT status FROM leases").fetchone()["status"] == "consumed"


def test_audit_write_failure_on_rejection_fails_closed(tmp_path, monkeypatch):
    import broker.execution_service

    db = tmp_path / "exec_audit_rej_fail.db"

    def fail_on_rejection(event_type, *args, **kwargs):
        if event_type == "lease_execution_rejected":
            raise RuntimeError("Simulated audit failure during rejection")
        return broker.database.record_audit_event(event_type, *args, **kwargs)

    monkeypatch.setattr(broker.execution_service, "record_audit_event", fail_on_rejection)

    with pytest.raises(ExecutionAuditError, match="Failed to record lease rejection audit event"):
        execute_lease_token(
            token="invalid_token_123",
            allowed_bucket=ALLOWED_BUCKET,
            allowed_prefix=ALLOWED_PREFIX,
            db_path=db,
        )


def test_audit_write_failure_on_s3_failure_fails_closed(tmp_path, monkeypatch):
    import broker.execution_service

    db = tmp_path / "exec_audit_s3_fail.db"
    mock_client = MagicMock()
    mock_client.get_object.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
        "GetObject",
    )

    token = issue_lease(
        task_id="task-audit-s3-fail",
        action="s3:GetObject",
        resource="s3://agentcap-demo/reports/doc.txt",
        db_path=db,
    )

    def fail_on_s3_fail_audit(event_type, *args, **kwargs):
        if event_type == "s3_execution_failed":
            raise RuntimeError("Simulated audit disk failure during s3_execution_failed")
        return broker.database.record_audit_event(event_type, *args, **kwargs)

    monkeypatch.setattr(broker.execution_service, "record_audit_event", fail_on_s3_fail_audit)

    with pytest.raises(ExecutionAuditError, match="Failed to record execution failure audit event"):
        execute_lease_token(
            token=token,
            allowed_bucket=ALLOWED_BUCKET,
            allowed_prefix=ALLOWED_PREFIX,
            db_path=db,
            s3_client=mock_client,
        )


@pytest.mark.parametrize(
    "bucket,prefix,max_bytes,err_match",
    [
        ("", "reports/", DEFAULT_MAX_OBJECT_BYTES, "allowed_bucket must be a non-empty string"),
        ("   ", "reports/", DEFAULT_MAX_OBJECT_BYTES, "allowed_bucket must be a non-empty string"),
        (None, "reports/", DEFAULT_MAX_OBJECT_BYTES, "allowed_bucket must be a non-empty string"),
        ("agentcap-demo", "", DEFAULT_MAX_OBJECT_BYTES, "allowed_prefix must be a non-empty string"),
        ("agentcap-demo", "   ", DEFAULT_MAX_OBJECT_BYTES, "allowed_prefix must be a non-empty string"),
        ("agentcap-demo", None, DEFAULT_MAX_OBJECT_BYTES, "allowed_prefix must be a non-empty string"),
        ("agentcap-demo", "reports/", -1, "max_object_bytes must be a non-negative integer"),
        ("agentcap-demo", "reports/", True, "max_object_bytes must be a non-negative integer"),
        ("agentcap-demo", "reports/", False, "max_object_bytes must be a non-negative integer"),
        ("agentcap-demo", "reports/", "100", "max_object_bytes must be a non-negative integer"),
    ],
)
def test_config_parameter_validation(tmp_path, bucket, prefix, max_bytes, err_match):
    db = tmp_path / "config_val.db"
    token = issue_lease("task-cfg", "s3:GetObject", "s3://agentcap-demo/reports/doc.txt", db_path=db)

    with pytest.raises(ValueError, match=err_match):
        execute_lease_token(
            token=token,
            allowed_bucket=bucket,
            allowed_prefix=prefix,
            max_object_bytes=max_bytes,
            db_path=db,
        )

    # Lease was NOT consumed because validation failed upfront
    with connect(db) as conn:
        assert conn.execute("SELECT status FROM leases").fetchone()["status"] == "issued"


def test_keyword_alias_lease_token(tmp_path):
    db = tmp_path / "keyword_alias.db"
    mock_client, _ = make_mock_s3_client(b"Keyword Alias Data")

    token = issue_lease("task-kw", "s3:GetObject", "s3://agentcap-demo/reports/kw.txt", db_path=db)

    result = execute_lease_token(
        lease_token=token,
        allowed_bucket=ALLOWED_BUCKET,
        allowed_prefix=ALLOWED_PREFIX,
        db_path=db,
        s3_client=mock_client,
    )

    assert result.content_bytes == b"Keyword Alias Data"


def test_whitespace_padded_valid_token_is_rejected_without_consuming_lease(tmp_path):
    db = tmp_path / "exec_padded_token.db"
    mock_client, _ = make_mock_s3_client()

    token = issue_lease(
        task_id="task-padded",
        action="s3:GetObject",
        resource="s3://agentcap-demo/reports/padded.txt",
        db_path=db,
    )

    with pytest.raises(InvalidLeaseTokenError):
        execute_lease_token(
            token=f" {token} ",
            allowed_bucket=ALLOWED_BUCKET,
            allowed_prefix=ALLOWED_PREFIX,
            db_path=db,
            s3_client=mock_client,
        )

    mock_client.get_object.assert_not_called()

    # The padded token must not consume the original lease.
    with connect(db) as conn:
        row = conn.execute("SELECT status FROM leases").fetchone()
        assert row["status"] == "issued"

    # The exact original token must still work.
    result = execute_lease_token(
        token=token,
        allowed_bucket=ALLOWED_BUCKET,
        allowed_prefix=ALLOWED_PREFIX,
        db_path=db,
        s3_client=mock_client,
    )

    assert result.content_bytes == b"Report content"
    mock_client.get_object.assert_called_once()
