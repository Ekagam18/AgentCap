"""Isolated AWS S3 Executor for AgentCap.

Executes authorized actions (only s3:GetObject) using a consumed lease record,
validating action and resource policies, enforcing object size limits,
and safely communicating with AWS S3 without leaking credentials or tokens.
"""

from __future__ import annotations

import math
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from policy.checks import (
    PolicyViolationError,
    parse_and_validate_s3_uri,
    validate_action_and_resource,
)

DEFAULT_MAX_OBJECT_BYTES = 1048576  # 1 MiB (1024 * 1024 bytes)
REQUIRED_LEASE_FIELDS = ("lease_id", "task_id", "action", "resource", "expires_at")
CHUNK_SIZE = 64 * 1024  # 64 KiB chunks for streaming reads

__all__ = [
    "DEFAULT_MAX_OBJECT_BYTES",
    "S3ExecutionResult",
    "S3ExecutorError",
    "S3InvalidLeaseError",
    "S3ObjectTooLargeError",
    "S3ServiceError",
    "execute_consumed_lease",
]


class S3ExecutorError(Exception):
    """Base exception for all S3 executor errors."""


class S3InvalidLeaseError(S3ExecutorError, ValueError):
    """Raised when the consumed lease record is invalid or missing required fields."""


class S3ObjectTooLargeError(S3ExecutorError):
    """Raised when the target S3 object exceeds the maximum allowed byte size."""


class S3ServiceError(S3ExecutorError):
    """Raised when an AWS S3 client or service operation fails (sanitized)."""


class S3ExecutionResult(dict):
    """Structured result of a successful S3 GetObject execution.

    Inherits from dict for full backward and mapping compatibility,
    while also exposing typed property attributes.
    """

    def __init__(
        self,
        *,
        bucket: str,
        key: str,
        content_bytes: bytes,
        content_length: int,
        content_type: str | None = None,
        etag: str | None = None,
        version_id: str | None = None,
        last_modified: Any = None,
        metadata: dict[str, str] | None = None,
    ) -> None:
        clean_metadata = dict(metadata) if isinstance(metadata, dict) else {}
        super().__init__(
            bucket=bucket,
            key=key,
            content_bytes=content_bytes,
            content_length=content_length,
            content_type=content_type,
            etag=etag,
            version_id=version_id,
            last_modified=last_modified,
            metadata=clean_metadata,
        )

    @property
    def bucket(self) -> str:
        """The S3 bucket name."""
        return self["bucket"]

    @property
    def key(self) -> str:
        """The S3 object key."""
        return self["key"]

    @property
    def content_bytes(self) -> bytes:
        """The raw bytes of the retrieved object."""
        return self["content_bytes"]

    @property
    def content_length(self) -> int:
        """The length of the retrieved object in bytes."""
        return self["content_length"]

    @property
    def content_type(self) -> str | None:
        """The Content-Type of the object, if reported by S3."""
        return self["content_type"]

    @property
    def etag(self) -> str | None:
        """The ETag of the object, if reported by S3."""
        return self["etag"]

    @property
    def version_id(self) -> str | None:
        """The S3 object version ID, if available."""
        return self["version_id"]

    @property
    def last_modified(self) -> Any:
        """The last modified timestamp of the object, if available."""
        return self["last_modified"]

    @property
    def metadata(self) -> dict[str, str]:
        """User-defined S3 object metadata."""
        return self["metadata"]

    @property
    def body(self) -> bytes:
        """Alias for content_bytes."""
        return self["content_bytes"]

    @property
    def data(self) -> bytes:
        """Alias for content_bytes."""
        return self["content_bytes"]

    def __getitem__(self, key: str) -> Any:
        if key in ("body", "data"):
            return self["content_bytes"]
        return super().__getitem__(key)

    def to_dict(self) -> dict[str, Any]:
        """Return a copy as a plain Python dictionary."""
        return dict(self)

    def __repr__(self) -> str:
        return (
            f"S3ExecutionResult(bucket={self.bucket!r}, key={self.key!r}, "
            f"content_length={self.content_length}, content_type={self.content_type!r})"
        )


def _validate_consumed_lease(consumed_lease: Any) -> None:
    """Validate that consumed_lease is a valid record returned by consume_lease()."""
    if not isinstance(consumed_lease, dict):
        raise S3InvalidLeaseError("consumed_lease must be a valid dictionary returned by consume_lease()")

    for field in REQUIRED_LEASE_FIELDS:
        if field not in consumed_lease:
            raise S3InvalidLeaseError(f"Missing required lease field: '{field}'")
        val = consumed_lease[field]
        if field in ("lease_id", "task_id", "action", "resource"):
            if not isinstance(val, str) or not val.strip():
                raise S3InvalidLeaseError(f"Lease field '{field}' must be a non-empty string")
        elif field == "expires_at":
            if not isinstance(val, (int, float)) or not math.isfinite(val) or val <= 0:
                raise S3InvalidLeaseError("Lease field 'expires_at' must be a positive finite number")


def _validate_policy(
    action: str,
    resource: str,
    allowed_bucket: str,
    allowed_prefix: str,
) -> tuple[str, str]:
    """Validate action and resource against configured authorization policy and URI safety rules."""
    if not isinstance(allowed_bucket, str) or not allowed_bucket.strip():
        raise ValueError("allowed_bucket must be a non-empty string")
    if not isinstance(allowed_prefix, str) or not allowed_prefix.strip():
        raise ValueError("allowed_prefix must be a non-empty string")

    # Reject literal fragment delimiters ('#') explicitly
    if "#" in resource:
        raise PolicyViolationError("Resource must not contain fragment delimiters ('#')")

    # Permit only s3:GetObject and enforce allowed bucket/prefix via policy.checks
    validate_action_and_resource(
        action=action,
        resource=resource,
        allowed_bucket=allowed_bucket,
        allowed_prefix=allowed_prefix,
    )

    # Extract parsed bucket and key
    bucket, key = parse_and_validate_s3_uri(resource)
    return bucket, key


def _read_body_with_limit(body: Any, max_object_bytes: int) -> bytes:
    """Read the response body up to max_object_bytes, raising S3ObjectTooLargeError if exceeded."""
    if body is None:
        raise S3ServiceError("S3 response is missing Body")

    if isinstance(body, (bytes, bytearray)):
        if len(body) > max_object_bytes:
            raise S3ObjectTooLargeError(
                f"Object size ({len(body)} bytes) exceeds maximum allowed size ({max_object_bytes} bytes)"
            )
        return bytes(body)

    if not hasattr(body, "read") or not callable(body.read):
        raise S3ExecutorError("Response body is not readable")

    chunks: list[bytes] = []
    total_read = 0

    while True:
        # Read at most CHUNK_SIZE or enough remaining to detect if limit is exceeded
        to_read = min(CHUNK_SIZE, max_object_bytes - total_read + 1)
        chunk = body.read(to_read)
        if not chunk:
            break
        if not isinstance(chunk, (bytes, bytearray)):
            raise S3ExecutorError("Unexpected non-bytes data read from response body")
        total_read += len(chunk)
        if total_read > max_object_bytes:
            raise S3ObjectTooLargeError(
                f"Object byte stream exceeded maximum allowed size ({max_object_bytes} bytes)"
            )
        chunks.append(bytes(chunk))

    return b"".join(chunks)


def _sanitize_error_code(code: Any) -> str:
    """Sanitize error code to prevent log injection or information leakage."""
    if not code:
        return "UnknownError"
    code_str = str(code).strip()
    sanitized = "".join(c for c in code_str if c.isalnum() or c in ("-", "_", "."))
    return sanitized or "UnknownError"


def execute_consumed_lease(
    consumed_lease: dict,
    allowed_bucket: str,
    allowed_prefix: str,
    s3_client: Any = None,
    max_object_bytes: int = DEFAULT_MAX_OBJECT_BYTES,
) -> S3ExecutionResult:
    """Execute s3:GetObject for a consumed lease.

    Args:
        consumed_lease: The record dictionary returned by a successful consume_lease() call.
        allowed_bucket: The configured allowed S3 bucket name.
        allowed_prefix: The configured allowed S3 key prefix.
        s3_client: Optional injected boto3 S3 client (creates default boto3 client if None).
        max_object_bytes: Configurable maximum object size limit in bytes (defaults to 1 MiB).

    Returns:
        S3ExecutionResult: A structured, documented result containing object metadata and bytes.

    Raises:
        S3InvalidLeaseError: If the lease record is invalid or missing required fields.
        PolicyViolationError: If action is not s3:GetObject, or URI/bucket/prefix violates policy.
        S3ObjectTooLargeError: If object exceeds max_object_bytes (header or actual stream).
        S3ServiceError: If AWS S3 returns an error (sanitized to avoid leaking sensitive details).
        ValueError: If configuration arguments (allowed_bucket, allowed_prefix, max_object_bytes) are invalid.
    """
    if isinstance(max_object_bytes, bool) or not isinstance(max_object_bytes, int) or max_object_bytes < 0:
        raise ValueError("max_object_bytes must be a non-negative integer")

    # 1. Validate consumed lease record and extract action & resource from record
    _validate_consumed_lease(consumed_lease)
    action = consumed_lease["action"]
    resource = consumed_lease["resource"]

    # 2. Validate policy and extract bucket & key
    bucket, key = _validate_policy(
        action=action,
        resource=resource,
        allowed_bucket=allowed_bucket,
        allowed_prefix=allowed_prefix,
    )

    # 3. Resolve S3 client (injectable or standard boto3 client)
    if s3_client is None:
        s3_client = boto3.client("s3")

    # 4. Execute only get_object using the validated bucket and key
    body = None
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        if not isinstance(response, dict):
            raise S3ServiceError("Invalid response format received from S3 client")

        body = response.get("Body")

        # 5. Check ContentLength header if present before reading stream
        content_length_header = response.get("ContentLength")
        if content_length_header is not None:
            try:
                reported_size = int(content_length_header)
                if reported_size > max_object_bytes:
                    raise S3ObjectTooLargeError(
                        f"Reported ContentLength ({reported_size} bytes) exceeds "
                        f"maximum allowed size ({max_object_bytes} bytes)"
                    )
            except (ValueError, TypeError):
                # Fall through to enforce during byte reading
                pass

        # 6. Read stream while enforcing size limit
        content_bytes = _read_body_with_limit(body, max_object_bytes)

    except S3ExecutorError:
        raise
    except ClientError as exc:
        error_code = _sanitize_error_code(
            exc.response.get("Error", {}).get("Code")
            if isinstance(getattr(exc, "response", None), dict)
            else None
        )
        raise S3ServiceError(f"AWS S3 error ({error_code}) during GetObject") from None
    except BotoCoreError as exc:
        client_err = _sanitize_error_code(exc.__class__.__name__)
        raise S3ServiceError(f"AWS client error ({client_err}) during GetObject") from None
    except Exception as exc:
        err_type = _sanitize_error_code(exc.__class__.__name__)
        raise S3ServiceError(f"Unexpected error ({err_type}) during S3 GetObject") from None
    finally:
        # 7. Close response body reliably in all circumstances (success or error)
        if body is not None and hasattr(body, "close") and callable(body.close):
            try:
                body.close()
            except Exception:
                pass

    # 8. Return structured result
    etag = response.get("ETag")
    if isinstance(etag, str):
        etag = etag.strip('"')

    return S3ExecutionResult(
        bucket=bucket,
        key=key,
        content_bytes=content_bytes,
        content_length=len(content_bytes),
        content_type=response.get("ContentType"),
        etag=etag,
        version_id=response.get("VersionId"),
        last_modified=response.get("LastModified"),
        metadata=response.get("Metadata"),
    )
