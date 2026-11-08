"""Minimal authorization broker service with task lifecycle and scoped execution."""

from __future__ import annotations

import base64
import hmac
import logging
import os
from pathlib import Path
from typing import Any, Callable

from fastapi import Depends, FastAPI, Header, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field

from broker.database import (
    DEFAULT_DB,
    TaskUnavailableError,
    issue_lease_for_task,
    record_audit_event,
)
from broker.execution_service import (
    ExecutionAuditError,
    InvalidLeaseTokenError,
    execute_lease_token,
)
from broker.s3_executor import (
    DEFAULT_MAX_OBJECT_BYTES,
    S3ExecutorError,
    S3ObjectTooLargeError,
    S3ServiceError,
)
from broker.sts import scoped_s3_client_for_lease, validate_role_arn
from broker.tasks import DEFAULT_TASK_TTL_SECONDS, create_task, get_task
from policy.checks import (
    PolicyViolationError,
    validate_action_and_resource,
    validate_task_match,
)

logger = logging.getLogger(__name__)

app = FastAPI(title="AgentCap Authorization Broker")

LEASE_TTL_SECONDS = 60


class TaskCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = Field(..., description="Action to approve, e.g. s3:GetObject")
    resource: str = Field(..., description="S3 resource URI")


class TaskResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task_id: str
    agent_id: str
    action: str
    resource: str
    expires_in: int


class LeaseCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task_id: str = Field(..., min_length=1, max_length=128)
    action: str = Field(..., description="Requested action")
    resource: str = Field(..., description="Requested resource")


class LeaseResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    lease_token: str
    expires_in: int
    token_type: str = "Bearer"


class LeaseExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Keep the token opaque: do not strip or normalize it.
    lease_token: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Single-use lease token",
    )


class LeaseExecuteResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content_base64: str
    content_length: int
    content_type: str | None = None
    etag: str | None = None


def get_db_path() -> Path:
    env_path = os.getenv("DATABASE_PATH")
    return Path(env_path) if env_path else DEFAULT_DB


def get_configured_agent_id() -> str:
    return os.getenv("AGENT_ID", "agent-default")


def get_task_ttl_seconds() -> int:
    """How long an admin approval remains valid before a lease is requested."""
    raw = os.getenv("TASK_TTL_SECONDS", str(DEFAULT_TASK_TTL_SECONDS))
    try:
        ttl_seconds = int(raw)
    except (TypeError, ValueError):
        ttl_seconds = 0
    if ttl_seconds <= 0:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error: TASK_TTL_SECONDS must be a positive integer",
        )
    return ttl_seconds


def get_s3_client() -> Any:
    """Optional injected S3 client; None uses the executor's default boto3 client."""
    return None


def get_sts_client() -> Any:
    """Optional injected STS client; None uses boto3."""
    return None


def get_s3_client_builder() -> Callable[[dict], Any] | None:
    """Optional builder for an S3 client using temporary STS credentials."""
    return None


def get_role_arn() -> str | None:
    """Enable per-lease STS credentials when AWS_ROLE_ARN is configured."""
    role_arn = os.getenv("AWS_ROLE_ARN", "").strip()
    if not role_arn:
        return None
    try:
        validate_role_arn(role_arn)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error: AWS_ROLE_ARN is not a valid IAM role ARN",
        )
    return role_arn


def get_max_object_bytes() -> int:
    raw = os.getenv("S3_MAX_OBJECT_BYTES", str(DEFAULT_MAX_OBJECT_BYTES))
    try:
        max_bytes = int(raw)
    except (TypeError, ValueError):
        max_bytes = -1
    if max_bytes <= 0:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error: S3_MAX_OBJECT_BYTES must be a positive integer",
        )
    return max_bytes


def get_policy_config() -> tuple[str, str]:
    raw_bucket = os.getenv("ALLOWED_S3_BUCKET")
    raw_prefix = os.getenv("ALLOWED_S3_PREFIX")

    bucket = raw_bucket.strip() if raw_bucket else ""
    prefix = raw_prefix.strip() if raw_prefix else ""

    if not bucket:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error: ALLOWED_S3_BUCKET is not configured",
        )
    if not prefix:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error: ALLOWED_S3_PREFIX is not configured",
        )
    return bucket, prefix


def authenticate_admin(
    x_admin_key: str | None = Header(None, alias="X-Admin-Key"),
) -> None:
    expected_key = os.getenv("ADMIN_API_KEY")
    if not expected_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error: ADMIN_API_KEY is not configured",
        )
    if not x_admin_key or not hmac.compare_digest(x_admin_key, expected_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing admin API key",
        )


def authenticate_agent(
    x_agent_key: str | None = Header(None, alias="X-Agent-Key"),
) -> str:
    expected_key = os.getenv("AGENT_API_KEY")
    if not expected_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error: AGENT_API_KEY is not configured",
        )
    if not x_agent_key or not hmac.compare_digest(x_agent_key, expected_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing agent API key",
        )
    return get_configured_agent_id()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/tasks", response_model=TaskResponse, status_code=status.HTTP_201_CREATED)
def register_task(
    payload: TaskCreateRequest,
    _: None = Depends(authenticate_admin),
    db_path: Path = Depends(get_db_path),
) -> TaskResponse:
    allowed_bucket, allowed_prefix = get_policy_config()
    try:
        validate_action_and_resource(
            payload.action,
            payload.resource,
            allowed_bucket,
            allowed_prefix,
        )
    except PolicyViolationError as err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(err),
        )

    agent_id = get_configured_agent_id()
    ttl_seconds = get_task_ttl_seconds()
    task = create_task(
        agent_id,
        payload.action,
        payload.resource,
        db_path=db_path,
        ttl_seconds=ttl_seconds,
    )
    return TaskResponse(
        task_id=task["task_id"],
        agent_id=task["agent_id"],
        action=task["action"],
        resource=task["resource"],
        expires_in=ttl_seconds,
    )


def _audit_lease_denied(
    payload: LeaseCreateRequest,
    agent_id: str,
    reason: str,
    db_path: Path,
) -> None:
    """Record only a short denial code; do not log arbitrary request scope."""
    try:
        record_audit_event(
            event_type="lease_denied",
            outcome="denied",
            task_id=payload.task_id,
            agent_id=agent_id,
            detail=reason,
            db_path=db_path,
        )
    except Exception as audit_exc:
        logger.error("Lease denial audit write failed: %s", type(audit_exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Audit logging failed",
        ) from None


@app.post("/leases", response_model=LeaseResponse, status_code=status.HTTP_201_CREATED)
def issue_lease_endpoint(
    payload: LeaseCreateRequest,
    response: Response,
    agent_id: str = Depends(authenticate_agent),
    db_path: Path = Depends(get_db_path),
) -> LeaseResponse:
    task = get_task(payload.task_id, db_path=db_path)
    if not task:
        _audit_lease_denied(payload, agent_id, "task_not_found", db_path)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )

    allowed_bucket, allowed_prefix = get_policy_config()
    try:
        validate_task_match(
            task,
            agent_id,
            payload.action,
            payload.resource,
        )
        validate_action_and_resource(
            payload.action,
            payload.resource,
            allowed_bucket,
            allowed_prefix,
        )
    except PolicyViolationError as err:
        _audit_lease_denied(payload, agent_id, "policy_violation", db_path)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(err),
        )

    try:
        token = issue_lease_for_task(
            payload.task_id,
            agent_id,
            payload.action,
            payload.resource,
            ttl_seconds=LEASE_TTL_SECONDS,
            db_path=db_path,
        )
    except TaskUnavailableError as err:
        _audit_lease_denied(payload, agent_id, err.reason, db_path)
        status_code = {
            "not_found": status.HTTP_404_NOT_FOUND,
            "already_used": status.HTTP_409_CONFLICT,
        }.get(err.reason, status.HTTP_403_FORBIDDEN)
        raise HTTPException(status_code=status_code, detail=str(err))

    response.headers["Cache-Control"] = "no-store"

    return LeaseResponse(
        lease_token=token,
        expires_in=LEASE_TTL_SECONDS,
        token_type="Bearer",
    )


@app.post(
    "/leases/execute",
    response_model=LeaseExecuteResponse,
    status_code=status.HTTP_200_OK,
)
def execute_lease_endpoint(
    payload: LeaseExecuteRequest,
    response: Response,
    agent_id: str = Depends(authenticate_agent),
    db_path: Path = Depends(get_db_path),
    s3_client: Any = Depends(get_s3_client),
    max_object_bytes: int = Depends(get_max_object_bytes),
    role_arn: str | None = Depends(get_role_arn),
    sts_client: Any = Depends(get_sts_client),
    s3_client_builder: Any = Depends(get_s3_client_builder),
) -> LeaseExecuteResponse:
    """Execute a lease through the fail-closed service; STS scope is lease-derived."""
    allowed_bucket, allowed_prefix = get_policy_config()

    s3_client_factory = None
    if role_arn and s3_client is None:
        # This callback receives only the trusted lease row returned by consume_lease().
        s3_client_factory = lambda lease: scoped_s3_client_for_lease(
            lease,
            role_arn,
            sts_client=sts_client,
            s3_client_builder=s3_client_builder,
        )

    try:
        result = execute_lease_token(
            payload.lease_token,
            allowed_bucket,
            allowed_prefix,
            db_path=db_path,
            s3_client=s3_client,
            max_object_bytes=max_object_bytes,
            agent_id=agent_id,
            s3_client_factory=s3_client_factory,
        )
    except InvalidLeaseTokenError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid, expired, or already consumed lease token",
        )
    except PolicyViolationError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: policy violation",
        )
    except S3ObjectTooLargeError:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="Object size exceeds maximum allowed limit",
        )
    except S3ServiceError:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="S3 service execution failed",
        )
    except ExecutionAuditError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Execution audit logging failed",
        )
    except (S3ExecutorError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )
    except Exception as exc:
        # Never log exception messages, tokens, object data, or AWS credentials.
        logger.error(
            "Unexpected error during lease execution: %s",
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )

    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"

    return LeaseExecuteResponse(
        content_base64=base64.b64encode(result.content_bytes).decode("ascii"),
        content_length=result.content_length,
        content_type=result.content_type,
        etag=result.etag,
    )
