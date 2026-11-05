"""Fail-closed orchestration for single-use lease execution."""

from __future__ import annotations

import logging
import re
from typing import Any, Callable

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
    """Raised when a lease token is invalid, expired, already used, or agent-mismatched."""


class ExecutionAuditError(ExecutionServiceError):
    """Raised when a required execution audit write fails; execution fails closed."""


def _map_exception_to_audit_outcome(exc: Exception) -> str:
    """Map an execution exception to a fixed, sanitized audit outcome."""
    if isinstance(exc, S3ObjectTooLargeError):
        return "S3ObjectTooLargeError"
    if isinstance(exc, PolicyViolationError):
        return "PolicyViolationError"
    if isinstance(exc, S3InvalidLeaseError):
        return "S3InvalidLeaseError"
    if isinstance(exc, S3ServiceError):
        return "S3ServiceError"
    return "UnknownError"


def _map_exception_to_audit_detail(exc: Exception) -> str:
    """Return only a short sanitized error code; never store exception text wholesale."""
    if isinstance(exc, S3ObjectTooLargeError):
        return "object_too_large"
    if isinstance(exc, PolicyViolationError):
        return "policy_violation"
    if isinstance(exc, S3InvalidLeaseError):
        return "invalid_lease_record"
    if isinstance(exc, S3ServiceError):
        match = re.search(r"\(([A-Za-z0-9_.-]{1,64})\)", str(exc))
        return match.group(1) if match else "S3ServiceError"
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
    agent_id: str | None = None,
    s3_client_factory: Callable[[dict], Any] | None = None,
) -> S3ExecutionResult:
    """Consume and execute one lease, optionally bound to an agent and scoped STS client.

    Configuration is validated before token consumption. The lease is then consumed
    atomically exactly once. ``s3_client_factory`` is invoked only with the trusted
    database lease record returned by ``consume_lease``.
    """
    if lease_token is not None:
        token = lease_token

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

    # Do not strip or normalize tokens: a padded token must not consume a valid lease.
    if not isinstance(token, str):
        consumed_lease = consume_lease("", db_path=db_path, agent_id=agent_id)
    else:
        consumed_lease = consume_lease(token, db_path=db_path, agent_id=agent_id)

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
                agent_id=agent_id,
                detail="invalid_token",
            )
        except Exception as audit_exc:
            raise ExecutionAuditError(
                "Failed to record lease rejection audit event"
            ) from audit_exc
        raise InvalidLeaseTokenError(
            "Invalid, expired, or already consumed lease token"
        )

    task_id = consumed_lease.get("task_id")
    action = consumed_lease.get("action")
    resource = consumed_lease.get("resource")
    lease_id = consumed_lease.get("lease_id")
    lease_agent_id = consumed_lease.get("agent_id")

    try:
        resolved_s3_client = s3_client
        if resolved_s3_client is None and s3_client_factory is not None:
            resolved_s3_client = s3_client_factory(consumed_lease)

        result = execute_consumed_lease(
            consumed_lease=consumed_lease,
            allowed_bucket=allowed_bucket,
            allowed_prefix=allowed_prefix,
            s3_client=resolved_s3_client,
            max_object_bytes=max_object_bytes,
        )
    except Exception as execution_exc:
        try:
            record_audit_event(
                event_type="s3_execution_failed",
                outcome=_map_exception_to_audit_outcome(execution_exc),
                task_id=task_id,
                action=action,
                resource=resource,
                lease_id=lease_id,
                db_path=db_path,
                agent_id=lease_agent_id or agent_id,
                detail=_map_exception_to_audit_detail(execution_exc),
            )
        except Exception as audit_exc:
            raise ExecutionAuditError(
                "Failed to record execution failure audit event"
            ) from audit_exc
        raise

    try:
        record_audit_event(
            event_type="s3_execution_succeeded",
            outcome="success",
            task_id=task_id,
            action=action,
            resource=resource,
            lease_id=lease_id,
            db_path=db_path,
            agent_id=lease_agent_id or agent_id,
            detail=f"bytes={result.content_length}",
        )
    except Exception as audit_exc:
        raise ExecutionAuditError(
            "Failed to record execution success audit event; failing closed"
        ) from audit_exc

    return result
