"""Minimal authorization broker service."""

import hmac
import os
import re
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field

from broker.database import (
    DEFAULT_DB,
    TaskUnavailableError,
    consume_lease,
    issue_lease_for_task,
    record_audit_event,
)
from broker.s3_executor import (
    DEFAULT_MAX_OBJECT_BYTES,
    S3ExecutorError,
    S3ObjectTooLargeError,
    S3ServiceError,
    execute_consumed_lease,
)
from broker.sts import StsAssumeRoleError, scoped_s3_client_for_lease, validate_role_arn
from broker.tasks import DEFAULT_TASK_TTL_SECONDS, create_task, get_task
from policy.checks import (
    PolicyViolationError,
    validate_action_and_resource,
    validate_task_match,
)

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
    task_id: str = Field(..., description="ID of the approved task")
    action: str = Field(..., description="Requested action")
    resource: str = Field(..., description="Requested resource")


class LeaseExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    lease_token: str = Field(..., min_length=1, max_length=256, description="Lease token from POST /leases")


class LeaseResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    lease_token: str
    expires_in: int
    token_type: str = "Bearer"


def get_db_path() -> Path:
    env_path = os.getenv("DATABASE_PATH")
    if env_path:
        return Path(env_path)
    return DEFAULT_DB


def get_configured_agent_id() -> str:
    return os.getenv("AGENT_ID", "agent-default")


def get_task_ttl_seconds() -> int:
    """How long an admin approval stays valid before its lease must be requested."""
    raw = os.getenv("TASK_TTL_SECONDS", str(DEFAULT_TASK_TTL_SECONDS))
    try:
        ttl = int(raw)
    except ValueError:
        ttl = 0
    if ttl <= 0:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error: TASK_TTL_SECONDS must be a positive integer",
        )
    return ttl


def get_s3_client() -> Any:
    """S3 client used by the executor. None lets the executor build a default boto3 client.

    Tests override this dependency with a fake client so no AWS call is made.
    """
    return None


def get_sts_client() -> Any:
    """STS client used to assume the execution role. None means a default boto3 client."""
    return None


def get_s3_client_builder() -> Any:
    """Builds an S3 client from temporary credentials. None means boto3. Tests override this."""
    return None


def get_role_arn() -> str | None:
    """AWS_ROLE_ARN enables per-lease STS credentials. Invalid value -> 500, fail closed.

    Unset means local/dev mode: the executor uses the broker's default boto3 credentials.
    """
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
        limit = int(raw)
    except ValueError:
        limit = -1
    if limit <= 0:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error: S3_MAX_OBJECT_BYTES must be a positive integer",
        )
    return limit


def get_policy_config() -> tuple[str, str]:
    bucket = os.getenv("ALLOWED_S3_BUCKET", "agentcap-demo")
    prefix = os.getenv("ALLOWED_S3_PREFIX", "reports/")
    return bucket, prefix


def authenticate_admin(x_admin_key: str | None = Header(None, alias="X-Admin-Key")) -> None:
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


def authenticate_agent(x_agent_key: str | None = Header(None, alias="X-Agent-Key")) -> str:
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
        validate_action_and_resource(payload.action, payload.resource, allowed_bucket, allowed_prefix)
    except PolicyViolationError as err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(err))

    agent_id = get_configured_agent_id()
    ttl_seconds = get_task_ttl_seconds()
    task = create_task(agent_id, payload.action, payload.resource, db_path=db_path, ttl_seconds=ttl_seconds)
    return TaskResponse(
        task_id=task["task_id"],
        agent_id=task["agent_id"],
        action=task["action"],
        resource=task["resource"],
        expires_in=ttl_seconds,
    )


@app.post("/leases", response_model=LeaseResponse, status_code=status.HTTP_201_CREATED)
def issue_lease_endpoint(
    payload: LeaseCreateRequest,
    agent_id: str = Depends(authenticate_agent),
    db_path: Path = Depends(get_db_path),
) -> LeaseResponse:
    task = get_task(payload.task_id, db_path=db_path)
    if not task:
        _audit_lease_denied(payload, agent_id, "task_not_found", db_path)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")

    allowed_bucket, allowed_prefix = get_policy_config()
    try:
        validate_task_match(task, agent_id, payload.action, payload.resource)
        validate_action_and_resource(payload.action, payload.resource, allowed_bucket, allowed_prefix)
    except PolicyViolationError as err:
        _audit_lease_denied(payload, agent_id, "policy_violation", db_path)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(err))

    # Claim the task and issue its single lease in one transaction, so two
    # concurrent requests can never both get a lease for the same approval.
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

    return LeaseResponse(lease_token=token, expires_in=LEASE_TTL_SECONDS, token_type="Bearer")


def _audit_lease_denied(payload: LeaseCreateRequest, agent_id: str, reason: str, db_path: Path) -> None:
    """Record a refused lease request. Never raises, so auditing can't mask the denial."""
    try:
        record_audit_event(
            "lease_denied",
            payload.task_id,
            payload.action,
            payload.resource,
            "denied",
            agent_id=agent_id,
            detail=reason,
            db_path=db_path,
        )
    except Exception:
        pass


INVALID_LEASE_DETAIL = "Lease is invalid, expired, already used, or not issued to this agent"
_SAFE_CONTENT_TYPE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+(\s*;\s*[A-Za-z0-9_.-]+=[A-Za-z0-9_.\"-]+)*$")


@app.post("/leases/execute")
def execute_lease_endpoint(
    payload: LeaseExecuteRequest,
    agent_id: str = Depends(authenticate_agent),
    db_path: Path = Depends(get_db_path),
    s3_client: Any = Depends(get_s3_client),
    max_object_bytes: int = Depends(get_max_object_bytes),
    role_arn: str | None = Depends(get_role_arn),
    sts_client: Any = Depends(get_sts_client),
    s3_client_builder: Any = Depends(get_s3_client_builder),
) -> Response:
    """Spend a lease: consume it once, then run its single S3 GetObject."""
    # Consuming first means a lease is spent even if S3 then fails; it can never be replayed.
    lease = consume_lease(payload.lease_token, db_path=db_path, agent_id=agent_id)
    if lease is None:
        # Same answer for unknown, expired, replayed, or another agent's token.
        _audit_safely(
            "execution_denied", None, None, None, "denied",
            agent_id=agent_id, detail="invalid_lease", db_path=db_path,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=INVALID_LEASE_DETAIL)

    allowed_bucket, allowed_prefix = get_policy_config()
    try:
        if role_arn and s3_client is None:
            # Temporary credentials that can read only this lease's object.
            s3_client = scoped_s3_client_for_lease(
                lease, role_arn, sts_client=sts_client, s3_client_builder=s3_client_builder
            )
        result = execute_consumed_lease(
            lease,
            allowed_bucket=allowed_bucket,
            allowed_prefix=allowed_prefix,
            s3_client=s3_client,
            max_object_bytes=max_object_bytes,
        )
    except PolicyViolationError:
        _audit_execution_failed(lease, agent_id, "policy_violation", db_path)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Lease scope is no longer allowed by policy")
    except S3ObjectTooLargeError:
        _audit_execution_failed(lease, agent_id, "object_too_large", db_path)
        raise HTTPException(
            status_code=413,  # Content Too Large
            detail=f"Object exceeds the {max_object_bytes} byte limit",
        )
    except StsAssumeRoleError as err:
        _audit_execution_failed(lease, agent_id, str(err)[:200], db_path)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Could not obtain scoped AWS credentials")
    except S3ServiceError as err:
        # Executor messages are already sanitized (error code only, no credentials).
        _audit_execution_failed(lease, agent_id, str(err)[:200], db_path)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="S3 request failed")
    except (S3ExecutorError, ValueError):
        _audit_execution_failed(lease, agent_id, "executor_error", db_path)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Execution failed")

    _audit_safely(
        "s3_execution_succeeded", lease["task_id"], lease["action"], lease["resource"], "success",
        lease_id=lease["lease_id"], agent_id=agent_id,
        detail=f"bytes={result.content_length}", db_path=db_path,
    )

    content_type = result.content_type or ""
    if not _SAFE_CONTENT_TYPE.match(content_type):
        content_type = "application/octet-stream"
    return Response(
        content=result.content_bytes,
        media_type=content_type,
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": "attachment",
            "X-AgentCap-Task-Id": lease["task_id"],
        },
    )


def _audit_execution_failed(lease: dict, agent_id: str, reason: str, db_path: Path) -> None:
    _audit_safely(
        "s3_execution_failed", lease["task_id"], lease["action"], lease["resource"], "failure",
        lease_id=lease["lease_id"], agent_id=agent_id, detail=reason, db_path=db_path,
    )


def _audit_safely(event_type, task_id, action, resource, outcome, *, db_path, **kwargs) -> None:
    """Write an audit event without letting an audit failure change the response."""
    try:
        record_audit_event(event_type, task_id, action, resource, outcome, db_path=db_path, **kwargs)
    except Exception:
        pass
