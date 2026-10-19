"""Minimal authorization broker service."""

import hmac
import os
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from broker.database import DEFAULT_DB, issue_lease
from broker.tasks import create_task, get_task
from policy.checks import (
    PolicyViolationError,
    validate_action_and_resource,
    validate_task_match,
)

app = FastAPI(title="AgentCap Authorization Broker")


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


class LeaseCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task_id: str = Field(..., description="ID of the approved task")
    action: str = Field(..., description="Requested action")
    resource: str = Field(..., description="Requested resource")


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
    task = create_task(agent_id, payload.action, payload.resource, db_path=db_path)
    return TaskResponse(
        task_id=task["task_id"],
        agent_id=task["agent_id"],
        action=task["action"],
        resource=task["resource"],
    )


@app.post("/leases", response_model=LeaseResponse, status_code=status.HTTP_201_CREATED)
def issue_lease_endpoint(
    payload: LeaseCreateRequest,
    agent_id: str = Depends(authenticate_agent),
    db_path: Path = Depends(get_db_path),
) -> LeaseResponse:
    task = get_task(payload.task_id, db_path=db_path)
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")

    allowed_bucket, allowed_prefix = get_policy_config()
    try:
        validate_task_match(task, agent_id, payload.action, payload.resource)
        validate_action_and_resource(payload.action, payload.resource, allowed_bucket, allowed_prefix)
    except PolicyViolationError as err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(err))

    token = issue_lease(
        payload.task_id,
        payload.action,
        payload.resource,
        ttl_seconds=60,
        db_path=db_path,
    )
    return LeaseResponse(lease_token=token, expires_in=60, token_type="Bearer")
