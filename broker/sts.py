"""Per-lease AWS credentials via STS AssumeRole.

For every executed lease the broker assumes a configured IAM role and passes an
inline session policy that allows exactly one action on exactly one object:

    s3:GetObject on arn:aws:s3:::<bucket>/<key>

AWS grants the *intersection* of the role's own permissions and the session
policy, so even if the role is broader (e.g. the whole reports/ prefix), the
temporary credentials can read only the leased object. The credentials live in
memory for one request and are never returned to the agent or written to logs.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from broker.s3_executor import S3ServiceError
from policy.checks import parse_and_validate_s3_uri

# STS minimum. Our lease TTL is 60s, but AssumeRole cannot issue less than 15 minutes.
DEFAULT_SESSION_SECONDS = 900

ROLE_ARN_PATTERN = re.compile(r"^arn:(aws|aws-cn|aws-us-gov):iam::\d{12}:role/[\w+=,.@/-]{1,512}$")
_SESSION_NAME_ALLOWED = re.compile(r"[^\w+=,.@-]")

__all__ = [
    "DEFAULT_SESSION_SECONDS",
    "StsAssumeRoleError",
    "build_session_policy",
    "role_session_name",
    "scoped_s3_client_for_lease",
    "validate_role_arn",
]


class StsAssumeRoleError(S3ServiceError):
    """AssumeRole failed. Message carries only a sanitized AWS error code."""


def validate_role_arn(role_arn: str) -> str:
    """Return the ARN's partition (aws, aws-cn, aws-us-gov), or raise ValueError."""
    match = ROLE_ARN_PATTERN.match(role_arn or "")
    if not match:
        raise ValueError("AWS_ROLE_ARN must look like arn:aws:iam::123456789012:role/name")
    return match.group(1)


def build_session_policy(resource: str, partition: str = "aws") -> dict:
    """Inline policy allowing s3:GetObject on one exact object and nothing else."""
    bucket, key = parse_and_validate_s3_uri(resource)
    # IAM treats * and ? in a Resource ARN as wildcards. parse_and_validate_s3_uri
    # already rejects them; check again so a future change can't widen the grant.
    if any(ch in bucket + key for ch in "*?"):
        raise ValueError("Wildcards are not allowed in a session policy resource")
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AgentCapSingleObjectRead",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": f"arn:{partition}:s3:::{bucket}/{key}",
            }
        ],
    }


def role_session_name(lease: dict) -> str:
    """CloudTrail-visible session name tying AWS activity back to the lease.

    Uses the lease_id (not the token). STS allows [\\w+=,.@-], 2 to 64 chars.
    """
    lease_id = _SESSION_NAME_ALLOWED.sub("-", str(lease.get("lease_id", "")))
    return f"agentcap-{lease_id}"[:64]


def _sanitize_code(code: Any) -> str:
    cleaned = "".join(c for c in str(code or "") if c.isalnum() or c in "-_.")
    return cleaned[:64] or "UnknownError"


def _default_s3_builder(credentials: dict) -> Any:
    return boto3.client(
        "s3",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def scoped_s3_client_for_lease(
    lease: dict,
    role_arn: str,
    sts_client: Any = None,
    s3_client_builder: Callable[[dict], Any] | None = None,
    duration_seconds: int = DEFAULT_SESSION_SECONDS,
) -> Any:
    """Assume ``role_arn`` scoped to the lease's single object and return an S3 client.

    Raises:
        ValueError: bad role ARN or resource (configuration / policy problem).
        StsAssumeRoleError: STS refused or failed (sanitized, no AWS message text).
    """
    partition = validate_role_arn(role_arn)
    policy = build_session_policy(lease["resource"], partition)

    if sts_client is None:
        sts_client = boto3.client("sts")
    if s3_client_builder is None:
        s3_client_builder = _default_s3_builder

    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=role_session_name(lease),
            Policy=json.dumps(policy, separators=(",", ":")),
            DurationSeconds=duration_seconds,
        )
        credentials = response["Credentials"]
        for field in ("AccessKeyId", "SecretAccessKey", "SessionToken"):
            if not credentials.get(field):
                raise KeyError(field)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code") if isinstance(getattr(exc, "response", None), dict) else None
        raise StsAssumeRoleError(f"STS AssumeRole failed ({_sanitize_code(code)})") from None
    except BotoCoreError as exc:
        raise StsAssumeRoleError(f"STS client error ({_sanitize_code(type(exc).__name__)})") from None
    except (KeyError, TypeError):
        raise StsAssumeRoleError("STS AssumeRole returned no usable credentials") from None
    except Exception as exc:
        raise StsAssumeRoleError(f"Unexpected STS error ({_sanitize_code(type(exc).__name__)})") from None

    return s3_client_builder(credentials)
