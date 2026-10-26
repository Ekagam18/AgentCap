"""Unit tests for the isolated AWS S3 Executor."""

import io
import math
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import BotoCoreError, ClientError, EndpointConnectionError, NoCredentialsError

from broker.s3_executor import (
    DEFAULT_MAX_OBJECT_BYTES,
    S3ExecutionResult,
    S3ExecutorError,
    S3InvalidLeaseError,
    S3ObjectTooLargeError,
    S3ServiceError,
    execute_consumed_lease,
)
from policy.checks import PolicyViolationError

ALLOWED_BUCKET = "agentcap-demo"
ALLOWED_PREFIX = "reports/"

_DEFAULT = object()


def make_valid_lease(
    action: str = "s3:GetObject",
    resource: str = "s3://agentcap-demo/reports/q3-report.txt",
    lease_id: str = "lease_test123",
    task_id: str = "task_test456",
    expires_at: object = _DEFAULT,
    **extra,
) -> dict:
    """Helper to construct a valid consumed_lease dictionary."""
    record = {
        "lease_id": lease_id,
        "task_id": task_id,
        "action": action,
        "resource": resource,
        "expires_at": time.time() + 60.0 if expires_at is _DEFAULT else expires_at,
    }
    record.update(extra)
    return record


class MockStreamingBody:
    """Mock for botocore.response.StreamingBody supporting chunked reads and close tracking."""

    def __init__(self, data: bytes):
        self._bio = io.BytesIO(data)
        self.closed = False
        self.close_called_count = 0
        self.bytes_read_at_close = 0

    def read(self, amt: int | None = None) -> bytes:
        return self._bio.read(amt)

    def close(self) -> None:
        self.closed = True
        self.close_called_count += 1
        try:
            self.bytes_read_at_close = self._bio.tell()
        except ValueError:
            pass
        self._bio.close()


# ---------------------------------------------------------------------------
# 1. Successful object retrieval & parameter validation
# ---------------------------------------------------------------------------

def test_successful_object_retrieval():
    """Verify successful GetObject execution returns structured metadata and bytes."""
    payload = b"Confidential Quarterly Report Contents"
    mock_body = MockStreamingBody(payload)
    mock_client = MagicMock()
    mock_client.get_object.return_value = {
        "Body": mock_body,
        "ContentLength": len(payload),
        "ContentType": "text/plain",
        "ETag": '"0123456789abcdef"',
        "VersionId": "v1.0",
        "LastModified": datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc),
        "Metadata": {"author": "agent-1"},
    }

    lease = make_valid_lease()
    result = execute_consumed_lease(
        consumed_lease=lease,
        allowed_bucket=ALLOWED_BUCKET,
        allowed_prefix=ALLOWED_PREFIX,
        s3_client=mock_client,
    )

    # Validate correct arguments passed to AWS S3 client
    mock_client.get_object.assert_called_once_with(
        Bucket="agentcap-demo",
        Key="reports/q3-report.txt",
    )

    # Validate structured result
    assert isinstance(result, S3ExecutionResult)
    assert isinstance(result, dict)
    assert result.bucket == "agentcap-demo"
    assert result.key == "reports/q3-report.txt"
    assert result.content_bytes == payload
    assert result.content_length == len(payload)
    assert result.content_type == "text/plain"
    assert result.etag == "0123456789abcdef"  # quotes stripped
    assert result.version_id == "v1.0"
    assert result.metadata == {"author": "agent-1"}

    # Dict-like access
    assert result["bucket"] == "agentcap-demo"
    assert result["key"] == "reports/q3-report.txt"
    assert result["content_bytes"] == payload
    assert result["content_length"] == len(payload)
    assert result["body"] == payload
    assert result["data"] == payload

    # Body closure verified
    assert mock_body.closed is True
    assert mock_body.close_called_count == 1


def test_correct_bucket_and_key_passed_to_aws():
    """Ensure exact parsed bucket and key are passed to AWS without modification."""
    mock_client = MagicMock()
    mock_client.get_object.return_value = {
        "Body": MockStreamingBody(b"data"),
        "ContentLength": 4,
    }

    lease = make_valid_lease(resource="s3://agentcap-demo/reports/2026/oct/summary.csv")
    execute_consumed_lease(
        consumed_lease=lease,
        allowed_bucket=ALLOWED_BUCKET,
        allowed_prefix=ALLOWED_PREFIX,
        s3_client=mock_client,
    )

    mock_client.get_object.assert_called_once_with(
        Bucket="agentcap-demo",
        Key="reports/2026/oct/summary.csv",
    )


# ---------------------------------------------------------------------------
# 2. Unsupported actions and missing/invalid lease fields
# ---------------------------------------------------------------------------

def test_missing_or_invalid_lease_record():
    """Reject non-dictionary or None lease arguments."""
    mock_client = MagicMock()
    for bad_lease in [None, "string-lease", 12345, [], ()]:
        with pytest.raises(S3InvalidLeaseError, match="consumed_lease must be a valid dictionary"):
            execute_consumed_lease(
                bad_lease,
                ALLOWED_BUCKET,
                ALLOWED_PREFIX,
                s3_client=mock_client,
            )


@pytest.mark.parametrize(
    "missing_field",
    ["lease_id", "task_id", "action", "resource", "expires_at"],
)
def test_missing_required_lease_fields(missing_field):
    """Reject leases missing any mandatory database record field."""
    lease = make_valid_lease()
    del lease[missing_field]
    mock_client = MagicMock()

    with pytest.raises(S3InvalidLeaseError, match=f"Missing required lease field: '{missing_field}'"):
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
        )


@pytest.mark.parametrize(
    "empty_field",
    ["lease_id", "task_id", "action", "resource"],
)
def test_empty_string_lease_fields(empty_field):
    """Reject empty strings or whitespace-only strings in required lease fields."""
    for bad_val in ["", "   "]:
        lease = make_valid_lease(**{empty_field: bad_val})
        mock_client = MagicMock()
        with pytest.raises(S3InvalidLeaseError, match=f"Lease field '{empty_field}' must be a non-empty string"):
            execute_consumed_lease(
                lease,
                ALLOWED_BUCKET,
                ALLOWED_PREFIX,
                s3_client=mock_client,
            )


@pytest.mark.parametrize(
    "bad_expires",
    ["tomorrow", None, -1.0, 0, float("inf"), float("-inf"), float("nan")],
)
def test_invalid_expires_at(bad_expires):
    """Reject non-numeric, negative, zero, or non-finite expires_at timestamps."""
    lease = make_valid_lease(expires_at=bad_expires)
    mock_client = MagicMock()
    with pytest.raises(S3InvalidLeaseError, match="Lease field 'expires_at' must be a positive finite number"):
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
        )


@pytest.mark.parametrize(
    "disallowed_action",
    [
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket",
        "s3:GetObjectVersion",
        "s3:*",
        "iam:PassRole",
    ],
)
def test_unsupported_actions_rejected(disallowed_action):
    """Permit only s3:GetObject; reject any other AWS actions."""
    lease = make_valid_lease(action=disallowed_action)
    mock_client = MagicMock()

    with pytest.raises(PolicyViolationError, match="is not permitted; only 's3:GetObject' is allowed"):
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
        )
    mock_client.get_object.assert_not_called()


# ---------------------------------------------------------------------------
# 3. Malformed URIs, fragments, wildcards, and path traversal
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "fragment_uri",
    [
        "s3://agentcap-demo/reports/q3-report.txt#section1",
        "s3://agentcap-demo/reports/#root",
        "s3://agentcap-demo/reports/report.txt#",
        "s3://agentcap-demo/reports/sub#dir/file.txt",
    ],
)
def test_fragment_delimiters_rejected(fragment_uri):
    """Explicitly reject resources containing literal URI fragment delimiters ('#')."""
    lease = make_valid_lease(resource=fragment_uri)
    mock_client = MagicMock()

    with pytest.raises(PolicyViolationError, match="must not contain fragment delimiters"):
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
        )
    mock_client.get_object.assert_not_called()


@pytest.mark.parametrize(
    "wildcard_uri",
    [
        "s3://agentcap-demo/reports/*.txt",
        "s3://agentcap-demo/reports/q?-report.txt",
        "s3://agentcap-demo/reports/*",
    ],
)
def test_wildcard_uris_rejected(wildcard_uri):
    """Reject wildcard patterns in resource URIs."""
    lease = make_valid_lease(resource=wildcard_uri)
    mock_client = MagicMock()

    with pytest.raises(PolicyViolationError, match="Wildcard resource authorization is not allowed"):
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
        )
    mock_client.get_object.assert_not_called()


@pytest.mark.parametrize(
    "traversal_uri",
    [
        "s3://agentcap-demo/reports/../secrets.txt",
        "s3://agentcap-demo/reports/./q3.txt",
        "s3://agentcap-demo/reports/subdir/../../etc/passwd",
    ],
)
def test_path_traversal_rejected(traversal_uri):
    """Reject directory traversal segments (.. and .)."""
    lease = make_valid_lease(resource=traversal_uri)
    mock_client = MagicMock()

    with pytest.raises(PolicyViolationError, match="path traversal segments"):
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
        )
    mock_client.get_object.assert_not_called()


@pytest.mark.parametrize(
    "dir_uri",
    [
        "s3://agentcap-demo/reports/",
        "s3://agentcap-demo/reports/subdir/",
    ],
)
def test_directory_only_resources_rejected(dir_uri):
    """Reject directory-only prefixes that do not point to a specific object."""
    lease = make_valid_lease(resource=dir_uri)
    mock_client = MagicMock()

    with pytest.raises(PolicyViolationError, match="specify an object, not a directory prefix"):
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
        )
    mock_client.get_object.assert_not_called()


@pytest.mark.parametrize(
    "malformed_uri",
    [
        "https://agentcap-demo/reports/file.txt",
        "file:///etc/passwd",
        "s3://",
        "s3://agentcap-demo",
        "s3://agentcap-demo/",
        "s3://agentcap-demo//reports/file.txt",
        "s3://agentcap-demo\\reports\\file.txt",
    ],
)
def test_malformed_s3_uris_rejected(malformed_uri):
    """Reject malformed, invalid-scheme, or ambiguous S3 URIs."""
    lease = make_valid_lease(resource=malformed_uri)
    mock_client = MagicMock()

    with pytest.raises(PolicyViolationError):
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
        )
    mock_client.get_object.assert_not_called()


# ---------------------------------------------------------------------------
# 4. Disallowed buckets and prefixes
# ---------------------------------------------------------------------------

def test_disallowed_bucket_rejected():
    """Reject requests targeting buckets other than the configured allowed bucket."""
    lease = make_valid_lease(resource="s3://unauthorized-bucket/reports/q3.txt")
    mock_client = MagicMock()

    with pytest.raises(PolicyViolationError, match="Bucket 'unauthorized-bucket' is not permitted"):
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
        )
    mock_client.get_object.assert_not_called()


def test_disallowed_prefix_rejected():
    """Reject requests targeting keys outside the configured allowed prefix."""
    lease = make_valid_lease(resource="s3://agentcap-demo/private-data/keys.txt")
    mock_client = MagicMock()

    with pytest.raises(PolicyViolationError, match="must be an object inside prefix"):
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
        )
    mock_client.get_object.assert_not_called()


def test_prefix_boundary_bypass_rejected():
    """Ensure 'reports-internal' cannot bypass prefix 'reports'."""
    lease = make_valid_lease(resource="s3://agentcap-demo/reports-internal/file.txt")
    mock_client = MagicMock()

    with pytest.raises(PolicyViolationError, match="must be an object inside prefix"):
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            "reports",
            s3_client=mock_client,
        )
    mock_client.get_object.assert_not_called()


def test_invalid_executor_configuration_parameters():
    """Ensure invalid allowed_bucket, allowed_prefix, or negative max_object_bytes raise ValueError."""
    lease = make_valid_lease()
    mock_client = MagicMock()

    with pytest.raises(ValueError, match="allowed_bucket must be a non-empty string"):
        execute_consumed_lease(lease, "", ALLOWED_PREFIX, s3_client=mock_client)

    with pytest.raises(ValueError, match="allowed_prefix must be a non-empty string"):
        execute_consumed_lease(lease, ALLOWED_BUCKET, "", s3_client=mock_client)

    with pytest.raises(ValueError, match="max_object_bytes must be a non-negative integer"):
        execute_consumed_lease(lease, ALLOWED_BUCKET, ALLOWED_PREFIX, s3_client=mock_client, max_object_bytes=-1)


@pytest.mark.parametrize("bool_limit", [True, False])
def test_boolean_max_object_bytes_rejected(bool_limit):
    """Ensure boolean size limits (True and False) raise ValueError."""
    lease = make_valid_lease()
    mock_client = MagicMock()
    with pytest.raises(ValueError, match="max_object_bytes must be a non-negative integer"):
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
            max_object_bytes=bool_limit,
        )
    mock_client.get_object.assert_not_called()


# ---------------------------------------------------------------------------
# 5. Oversized objects and limit enforcement
# ---------------------------------------------------------------------------

def test_oversized_object_rejected_via_content_length_header():
    """Check that an oversized object is rejected early via ContentLength before reading."""
    mock_body = MockStreamingBody(b"X" * 200)
    mock_client = MagicMock()
    mock_client.get_object.return_value = {
        "Body": mock_body,
        "ContentLength": 200,
    }

    lease = make_valid_lease()
    with pytest.raises(S3ObjectTooLargeError, match="Reported ContentLength \\(200 bytes\\) exceeds maximum allowed size \\(100 bytes\\)"):
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
            max_object_bytes=100,
        )

    # Body must be closed even on early rejection
    assert mock_body.closed is True
    # The stream should not have been read
    assert mock_body.bytes_read_at_close == 0


def test_oversized_object_rejected_via_actual_stream_read():
    """Check that an oversized object is rejected when reading, even if ContentLength is missing/misleading."""
    stream_data = b"Y" * 150
    mock_body = MockStreamingBody(stream_data)
    mock_client = MagicMock()
    mock_client.get_object.return_value = {
        "Body": mock_body,
        "ContentLength": None,  # ContentLength header absent
    }

    lease = make_valid_lease()
    with pytest.raises(S3ObjectTooLargeError, match="Object byte stream exceeded maximum allowed size \\(100 bytes\\)"):
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
            max_object_bytes=100,
        )

    assert mock_body.closed is True


def test_oversized_object_rejected_with_inaccurate_understated_content_length():
    """Ensure an object is rejected when reported ContentLength is below limit but actual stream exceeds it."""
    # ContentLength is reported as 50 bytes (below 100-byte limit), but actual stream delivers 150 bytes
    stream_data = b"M" * 150
    mock_body = MockStreamingBody(stream_data)
    mock_client = MagicMock()
    mock_client.get_object.return_value = {
        "Body": mock_body,
        "ContentLength": 50,
    }

    lease = make_valid_lease()
    with pytest.raises(S3ObjectTooLargeError, match="Object byte stream exceeded maximum allowed size \\(100 bytes\\)"):
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
            max_object_bytes=100,
        )

    assert mock_body.closed is True
    assert mock_body.close_called_count == 1


def test_object_size_exactly_at_limit_allowed():
    """Objects exactly equal to max_object_bytes must succeed."""
    limit = 50
    data = b"Z" * limit
    mock_body = MockStreamingBody(data)
    mock_client = MagicMock()
    mock_client.get_object.return_value = {
        "Body": mock_body,
        "ContentLength": limit,
    }

    lease = make_valid_lease()
    result = execute_consumed_lease(
        lease,
        ALLOWED_BUCKET,
        ALLOWED_PREFIX,
        s3_client=mock_client,
        max_object_bytes=limit,
    )

    assert result.content_length == limit
    assert result.content_bytes == data
    assert mock_body.closed is True


def test_object_size_one_byte_over_limit_rejected():
    """Objects 1 byte over max_object_bytes must be rejected."""
    limit = 50
    data = b"Z" * (limit + 1)
    mock_body = MockStreamingBody(data)
    mock_client = MagicMock()
    mock_client.get_object.return_value = {
        "Body": mock_body,
        "ContentLength": limit + 1,
    }

    lease = make_valid_lease()
    with pytest.raises(S3ObjectTooLargeError):
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
            max_object_bytes=limit,
        )
    assert mock_body.closed is True


def test_default_max_object_bytes_is_one_mebibyte():
    """Ensure the default limit is 1 MiB (1048576 bytes)."""
    assert DEFAULT_MAX_OBJECT_BYTES == 1048576


def test_zero_byte_object_succeeds_and_body_closed():
    """Confirm a legitimate zero-byte object succeeds and its body is reliably closed."""
    mock_body = MockStreamingBody(b"")
    mock_client = MagicMock()
    mock_client.get_object.return_value = {
        "Body": mock_body,
        "ContentLength": 0,
        "ContentType": "text/plain",
    }

    lease = make_valid_lease()
    result = execute_consumed_lease(
        lease,
        ALLOWED_BUCKET,
        ALLOWED_PREFIX,
        s3_client=mock_client,
        max_object_bytes=0,
    )

    assert result.content_bytes == b""
    assert result.content_length == 0
    assert mock_body.closed is True
    assert mock_body.close_called_count == 1


@pytest.mark.parametrize("missing_body_response", [{}, {"Body": None, "ContentLength": 0}])
def test_missing_response_body_rejected(missing_body_response):
    """Confirm a response with no Body or Body=None is rejected with a sanitized executor exception."""
    mock_client = MagicMock()
    mock_client.get_object.return_value = missing_body_response

    lease = make_valid_lease()
    with pytest.raises(S3ExecutorError, match="missing Body"):
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
        )


# ---------------------------------------------------------------------------
# 6. AWS errors and safe error handling
# ---------------------------------------------------------------------------

def test_aws_client_error_sanitized():
    """Ensure botocore ClientError is safely mapped to S3ServiceError with sanitized code."""
    mock_client = MagicMock()
    mock_client.get_object.side_effect = ClientError(
        error_response={
            "Error": {
                "Code": "NoSuchKey",
                "Message": "The specified key does not exist. (Internal path: /var/aws/s3/key)",
            },
            "ResponseMetadata": {
                "HTTPHeaders": {"x-amz-request-id": "SECRET_ID_123"},
            },
        },
        operation_name="GetObject",
    )

    lease = make_valid_lease()
    with pytest.raises(S3ServiceError) as exc_info:
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
        )

    err_msg = str(exc_info.value)
    assert "NoSuchKey" in err_msg
    assert "SECRET_ID_123" not in err_msg
    assert "/var/aws" not in err_msg
    # Ensure cause is suppressed (from None)
    assert exc_info.value.__cause__ is None


def test_aws_access_denied_sanitized():
    """Ensure AccessDenied is sanitized and does not leak IAM ARN or policy details."""
    mock_client = MagicMock()
    mock_client.get_object.side_effect = ClientError(
        error_response={
            "Error": {
                "Code": "AccessDenied",
                "Message": "User arn:aws:iam::123456789012:user/secret-agent is not authorized",
            },
        },
        operation_name="GetObject",
    )

    lease = make_valid_lease()
    with pytest.raises(S3ServiceError) as exc_info:
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
        )

    err_msg = str(exc_info.value)
    assert "AccessDenied" in err_msg
    assert "123456789012" not in err_msg
    assert "secret-agent" not in err_msg
    assert exc_info.value.__cause__ is None


def test_aws_endpoint_connection_error_sanitized():
    """Ensure EndpointConnectionError does not leak internal VPC endpoint URLs."""
    mock_client = MagicMock()
    mock_client.get_object.side_effect = EndpointConnectionError(
        endpoint_url="https://internal-s3-vpc-privatelink.local:8443",
    )

    lease = make_valid_lease()
    with pytest.raises(S3ServiceError) as exc_info:
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
        )

    err_msg = str(exc_info.value)
    assert "EndpointConnectionError" in err_msg
    assert "internal-s3-vpc-privatelink.local" not in err_msg
    assert exc_info.value.__cause__ is None


def test_aws_no_credentials_error_sanitized():
    """Ensure NoCredentialsError does not leak environment or local credentials file paths."""
    mock_client = MagicMock()
    mock_client.get_object.side_effect = NoCredentialsError()

    lease = make_valid_lease()
    with pytest.raises(S3ServiceError) as exc_info:
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
        )

    err_msg = str(exc_info.value)
    assert "NoCredentialsError" in err_msg
    assert exc_info.value.__cause__ is None


# ---------------------------------------------------------------------------
# 7. Response-body closure on all code paths
# ---------------------------------------------------------------------------

def test_body_closed_on_stream_read_exception():
    """Ensure body is closed even if stream reading raises an unexpected error."""
    mock_body = MagicMock()
    mock_body.read.side_effect = RuntimeError("Socket read timed out")
    mock_client = MagicMock()
    mock_client.get_object.return_value = {
        "Body": mock_body,
        "ContentLength": 50,
    }

    lease = make_valid_lease()
    with pytest.raises(S3ServiceError):
        execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
        )

    mock_body.close.assert_called_once()


def test_body_close_exception_handled_cleanly():
    """Ensure an exception inside body.close() does not mask previous execution or cause crash."""
    mock_body = MockStreamingBody(b"success-content")
    mock_close = MagicMock(side_effect=OSError("Connection already reset"))
    mock_body.close = mock_close
    mock_client = MagicMock()
    mock_client.get_object.return_value = {
        "Body": mock_body,
        "ContentLength": 15,
    }

    lease = make_valid_lease()
    result = execute_consumed_lease(
        lease,
        ALLOWED_BUCKET,
        ALLOWED_PREFIX,
        s3_client=mock_client,
    )

    assert result.content_bytes == b"success-content"
    mock_close.assert_called_once()


# ---------------------------------------------------------------------------
# 8. No tokens or secrets in results or error messages
# ---------------------------------------------------------------------------

def test_no_tokens_or_secrets_in_result_or_errors():
    """Verify that sensitive lease tokens, hashes, or secret keys never appear in results or errors."""
    secret_token = "SECRET_PLAINTEXT_TOKEN_abc123"
    token_hash = "f" * 64
    agent_api_key = "sk_live_very_secret_agent_key"
    sensitive_values = [secret_token, token_hash, agent_api_key]

    mock_client = MagicMock()
    mock_client.get_object.return_value = {
        "Body": MockStreamingBody(b"safe-content"),
        "ContentLength": 12,
        "ContentType": "text/plain",
        "Metadata": {"report_tag": "public-release"},
    }

    # Pass lease containing sensitive extra fields
    lease = make_valid_lease(
        token=secret_token,
        token_hash=token_hash,
        api_key=agent_api_key,
    )

    result = execute_consumed_lease(
        lease,
        ALLOWED_BUCKET,
        ALLOWED_PREFIX,
        s3_client=mock_client,
    )

    # Inspect result.to_dict() directly rather than relying on custom __repr__
    result_dict = result.to_dict()
    expected_keys = {
        "bucket",
        "key",
        "content_bytes",
        "content_length",
        "content_type",
        "etag",
        "version_id",
        "last_modified",
        "metadata",
    }
    assert set(result_dict.keys()) == expected_keys

    # Verify secrets are NOT in result fields or metadata
    for secret in sensitive_values:
        assert secret not in result_dict
        assert secret not in result_dict.values()
        assert secret not in result_dict["metadata"].keys()
        assert secret not in result_dict["metadata"].values()
        assert secret not in repr(result_dict)

    # Test that an error message when lease is invalid also does not echo the dictionary or secrets
    bad_lease = {
        "token": secret_token,
        "token_hash": token_hash,
        # missing action and resource
    }
    with pytest.raises(S3InvalidLeaseError) as exc_info:
        execute_consumed_lease(
            bad_lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=mock_client,
        )

    err_text = str(exc_info.value)
    assert secret_token not in err_text
    assert token_hash not in err_text


# ---------------------------------------------------------------------------
# 9. Default boto3 client resolution
# ---------------------------------------------------------------------------

def test_default_boto3_client_resolution():
    """Verify that when s3_client is None, boto3.client('s3') is called."""
    mock_client = MagicMock()
    mock_client.get_object.return_value = {
        "Body": MockStreamingBody(b"resolved-via-boto3"),
        "ContentLength": 19,
    }

    lease = make_valid_lease()
    with patch("broker.s3_executor.boto3.client", return_value=mock_client) as mock_boto_client:
        result = execute_consumed_lease(
            lease,
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
            s3_client=None,
        )

        mock_boto_client.assert_called_once_with("s3")
        assert result.content_bytes == b"resolved-via-boto3"
