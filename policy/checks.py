"""Authorization policy engine for AgentCap broker."""

from urllib.parse import urlparse

ALLOWED_ACTION = "s3:GetObject"


class PolicyViolationError(ValueError):
    """Raised when an action or resource violates authorization policy."""


def parse_and_validate_s3_uri(resource: str) -> tuple[str, str]:
    """Parse an S3 URI and validate that it is well-formed, unambiguous, and without wildcards."""
    if not isinstance(resource, str) or not resource.strip():
        raise PolicyViolationError("Resource must be a non-empty string")

    if not resource.startswith("s3://"):
        raise PolicyViolationError("Resource must start with 's3://'")

    if "*" in resource or "?" in resource:
        raise PolicyViolationError("Wildcard resource authorization is not allowed")

    if "\\" in resource:
        raise PolicyViolationError("Resource must not contain backslashes")

    parsed = urlparse(resource)
    if parsed.scheme != "s3":
        raise PolicyViolationError("Resource must use the 's3' scheme")

    bucket = parsed.netloc
    if not bucket:
        raise PolicyViolationError("Resource is missing a bucket name")

    path = parsed.path
    if not path or path == "/":
        raise PolicyViolationError("Resource is missing an object key")

    raw_path = resource[len("s3://") + len(bucket):]
    if raw_path.startswith("//") or "//" in raw_path:
        raise PolicyViolationError("Resource contains malformed consecutive slashes")

    key = path.lstrip("/")
    segments = key.split("/")
    if any(segment in ("..", ".") for segment in segments):
        raise PolicyViolationError("Resource must not contain path traversal segments")

    if key.endswith("/"):
        raise PolicyViolationError("Resource must specify an object, not a directory prefix")

    return bucket, key


def validate_action_and_resource(
    action: str,
    resource: str,
    allowed_bucket: str,
    allowed_prefix: str,
) -> None:
    """Validate action and resource against configured authorization policy."""
    if action != ALLOWED_ACTION:
        raise PolicyViolationError(f"Action '{action}' is not permitted; only '{ALLOWED_ACTION}' is allowed")

    bucket, key = parse_and_validate_s3_uri(resource)

    if bucket != allowed_bucket:
        raise PolicyViolationError(f"Bucket '{bucket}' is not permitted; only '{allowed_bucket}' is allowed")

    normalized_prefix = allowed_prefix if allowed_prefix.endswith("/") else f"{allowed_prefix}/"
    if not key.startswith(normalized_prefix) or len(key) <= len(normalized_prefix):
        raise PolicyViolationError(
            f"Key '{key}' is not permitted; must be an object inside prefix '{normalized_prefix}'"
        )


def validate_task_match(
    task: dict,
    agent_id: str,
    action: str,
    resource: str,
) -> None:
    """Validate that requested operation exactly matches the approved task."""
    if task.get("agent_id") != agent_id:
        raise PolicyViolationError("Authenticated agent does not own this task")

    if task.get("action") != action:
        raise PolicyViolationError("Requested action does not match approved task")

    if task.get("resource") != resource:
        raise PolicyViolationError("Requested resource does not match approved task")
