"""Execution service layer connecting single-use lease consumption to isolated S3 execution.

Coordinates:
1. Validating and consuming single-use lease tokens via broker.database.consume_lease.
2. Executing authorized S3 actions via broker.s3_executor.execute_consumed_lease.
3. Recording append-only audit events (s3_execution_succeeded, s3_execution_failed,
   or lease_execution_rejected) without leaking tokens, hashes, credentials, or object contents.
4. Enforcing fail-closed behavior on audit write failures.
"""

from __future__ import annotations

import logging
from typing import Any

from broker.database import DEFAULT_DB, consume_lease, record_audit_event
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

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_MAX_OBJECT_BYTES",
    "ExecutionAuditError",
    "ExecutionServiceError",
    "InvalidLeaseTokenError",
    "PolicyViolationError",
    "S3ExecutionResult",
    "S3ExecutorError",
    "S3InvalidLeaseError",
    "S3ObjectTooLargeError",
    "S3ServiceError",
    "execute_lease_token",
]


class ExecutionServiceError(Exception):
    """Base exception for execution service errors."""


class InvalidLeaseTokenError(ExecutionServiceError, ValueError):
    """Raised when a lease token is invalid, expired, or already consumed."""


class ExecutionAuditError(ExecutionServiceError):
    """Raised when writing the execution audit record fails, failing closed."""


def _map_exception_to_audit_outcome(exc: Exception) -> str:
    """Map an execution exception to an approved sanitized audit outcome code."""
    if isinstance(exc, S3ObjectTooLargeError):
        return "S3ObjectTooLargeError"
    if isinstance(exc, PolicyViolationError):
        return "PolicyViolationError"
    if isinstance(exc, S3InvalidLeaseError):
        return "S3InvalidLeaseError"
    if isinstance(exc, S3ServiceError):
        return "S3ServiceError"
    return "UnknownError"


def execute_lease_token(
    token: str = "",
    allowed_bucket: str = "",
    allowed_prefix: str = "",
    db_path: Any = DEFAULT_DB,
    s3_client: Any = None,
    max_object_bytes: int = DEFAULT_MAX_OBJECT_BYTES,
    *,
    lease_token: str | None = None,
) -> S3ExecutionResult:
    """Execute authorized S3 operation for a single-use lease token.

    Args:
        token: The plaintext lease token provided by the agent.
        allowed_bucket: Configured allowed S3 bucket.
        allowed_prefix: Configured allowed S3 prefix.
        db_path: Database path or active SQLite connection.
        s3_client: Optional injected S3 client (e.g. for testing).
        max_object_bytes: Maximum allowed S3 object size in bytes (default 1 MiB).
        lease_token: Optional keyword alias for token.

    Returns:
        S3ExecutionResult: The result of the S3 GetObject operation.

    Raises:
        InvalidLeaseTokenError: If the token is invalid, expired, or already consumed.
        PolicyViolationError: If action or resource violates configured policy.
        S3ObjectTooLargeError: If object exceeds max_object_bytes.
        S3ServiceError: If S3 client/service fails.
        ExecutionAuditError: If audit event writing fails (failing closed).
        ValueError: If configuration arguments are invalid.
    """
    if lease_token is not None:
        token = lease_token

    # Validate configuration parameters upfront
    if not isinstance(allowed_bucket, str) or not allowed_bucket.strip():
        raise ValueError("allowed_bucket must be a non-empty string")
    if not isinstance(allowed_prefix, str) or not allowed_prefix.strip():
        raise ValueError("allowed_prefix must be a non-empty string")
    if (
        isinstance(max_object_bytes, bool)
        or not isinstance(max_object_bytes, int)
        or max_object_bytes < 0
    ):
        raise ValueError("max_object_bytes must be a non-negative integer")

    # 1. Validate token input without logging or exposing it
    # 2. Call existing consume_lease() exactly once
    if not isinstance(token, str):
        consumed_lease = consume_lease("", db_path=db_path)
    else:
        consumed_lease = consume_lease(token, db_path=db_path)

    # 3. If consumption returns None, record lease_execution_rejected and raise safe custom exception
    if consumed_lease is None:
        try:
            record_audit_event(
                event_type="lease_execution_rejected",
                outcome="invalid_token",
                task_id=None,
                action=None,
                resource=None,
                lease_id=None,
                db_path=db_path,
            )
        except Exception as audit_exc:
            raise ExecutionAuditError("Failed to record lease rejection audit event") from audit_exc

        raise InvalidLeaseTokenError("Invalid, expired, or already consumed lease token")

    # 4. Use only the returned consumed-lease record when calling execute_consumed_lease()
    task_id = consumed_lease.get("task_id")
    action = consumed_lease.get("action")
    resource = consumed_lease.get("resource")
    lease_id = consumed_lease.get("lease_id")

    try:
        result = execute_consumed_lease(
            consumed_lease=consumed_lease,
            allowed_bucket=allowed_bucket,
            allowed_prefix=allowed_prefix,
            s3_client=s3_client,
            max_object_bytes=max_object_bytes,
        )
    except Exception as exec_exc:
        # 6. On execution failure, record s3_execution_failed using only approved sanitized outcomes
        # 7. Never store raw exception text, AWS credentials, lease tokens, or object contents in audit records
        # 8. Keep the lease consumed even if the S3 operation fails
        outcome = _map_exception_to_audit_outcome(exec_exc)
        try:
            record_audit_event(
                event_type="s3_execution_failed",
                outcome=outcome,
                task_id=task_id,
                action=action,
                resource=resource,
                lease_id=lease_id,
                db_path=db_path,
            )
        except Exception as audit_exc:
            raise ExecutionAuditError("Failed to record execution failure audit event") from audit_exc
        raise

    # 5. On successful execution, record s3_execution_succeeded with outcome success
    # 9. Fail closed if the required audit write fails. Never report a successful execution
    #    if its success audit record could not be written.
    try:
        record_audit_event(
            event_type="s3_execution_succeeded",
            outcome="success",
            task_id=task_id,
            action=action,
            resource=resource,
            lease_id=lease_id,
            db_path=db_path,
        )
    except Exception as audit_exc:
        raise ExecutionAuditError(
            "Failed to record execution success audit event; failing closed"
        ) from audit_exc

    return result
