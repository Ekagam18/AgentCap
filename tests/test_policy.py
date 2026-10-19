"""Unit tests for the policy engine."""

import pytest

from policy.checks import (
    PolicyViolationError,
    parse_and_validate_s3_uri,
    validate_action_and_resource,
    validate_task_match,
)

ALLOWED_BUCKET = "agentcap-demo"
ALLOWED_PREFIX = "reports/"


def test_valid_action_and_resource():
    validate_action_and_resource(
        "s3:GetObject",
        "s3://agentcap-demo/reports/q3-report.txt",
        ALLOWED_BUCKET,
        ALLOWED_PREFIX,
    )


def test_valid_with_prefix_without_trailing_slash():
    validate_action_and_resource(
        "s3:GetObject",
        "s3://agentcap-demo/reports/sub/report.pdf",
        ALLOWED_BUCKET,
        "reports",
    )


def test_disallowed_actions():
    for bad_action in ["s3:DeleteObject", "s3:PutObject", "s3:ListBucket", "s3:*", ""]:
        with pytest.raises(PolicyViolationError, match="is not permitted"):
            validate_action_and_resource(
                bad_action,
                "s3://agentcap-demo/reports/q3-report.txt",
                ALLOWED_BUCKET,
                ALLOWED_PREFIX,
            )


def test_disallowed_bucket():
    with pytest.raises(PolicyViolationError, match="Bucket 'other-bucket' is not permitted"):
        validate_action_and_resource(
            "s3:GetObject",
            "s3://other-bucket/reports/q3-report.txt",
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
        )


def test_disallowed_prefix():
    with pytest.raises(PolicyViolationError, match="must be an object inside prefix"):
        validate_action_and_resource(
            "s3:GetObject",
            "s3://agentcap-demo/confidential/secret.txt",
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
        )


def test_prefix_boundary_leak_prevented():
    # reports-confidential should not match prefix reports/
    with pytest.raises(PolicyViolationError, match="must be an object inside prefix"):
        validate_action_and_resource(
            "s3:GetObject",
            "s3://agentcap-demo/reports-confidential/file.txt",
            ALLOWED_BUCKET,
            "reports",
        )


def test_directory_resource_rejected():
    with pytest.raises(PolicyViolationError, match="specify an object, not a directory prefix"):
        validate_action_and_resource(
            "s3:GetObject",
            "s3://agentcap-demo/reports/",
            ALLOWED_BUCKET,
            ALLOWED_PREFIX,
        )


def test_wildcard_resource_rejected():
    with pytest.raises(PolicyViolationError, match="Wildcard resource authorization is not allowed"):
        parse_and_validate_s3_uri("s3://agentcap-demo/reports/*.txt")

    with pytest.raises(PolicyViolationError, match="Wildcard resource authorization is not allowed"):
        parse_and_validate_s3_uri("s3://agentcap-demo/reports/?3-report.txt")


def test_traversal_resource_rejected():
    with pytest.raises(PolicyViolationError, match="path traversal"):
        parse_and_validate_s3_uri("s3://agentcap-demo/reports/../secrets.txt")

    with pytest.raises(PolicyViolationError, match="path traversal"):
        parse_and_validate_s3_uri("s3://agentcap-demo/reports/./test.txt")


def test_malformed_s3_uri():
    for malformed in [
        "",
        "http://agentcap-demo/reports/q3.txt",
        "s3://",
        "s3://agentcap-demo",
        "s3://agentcap-demo/",
        "s3://agentcap-demo//reports/q3.txt",
        "s3://agentcap-demo\\reports\\q3.txt",
    ]:
        with pytest.raises(PolicyViolationError):
            parse_and_validate_s3_uri(malformed)


def test_validate_task_match_success():
    task = {
        "task_id": "task-123",
        "agent_id": "agent-1",
        "action": "s3:GetObject",
        "resource": "s3://agentcap-demo/reports/q3-report.txt",
    }
    validate_task_match(
        task,
        "agent-1",
        "s3:GetObject",
        "s3://agentcap-demo/reports/q3-report.txt",
    )


def test_validate_task_match_agent_mismatch():
    task = {
        "task_id": "task-123",
        "agent_id": "agent-1",
        "action": "s3:GetObject",
        "resource": "s3://agentcap-demo/reports/q3-report.txt",
    }
    with pytest.raises(PolicyViolationError, match="Authenticated agent does not own this task"):
        validate_task_match(
            task,
            "agent-2",
            "s3:GetObject",
            "s3://agentcap-demo/reports/q3-report.txt",
        )


def test_validate_task_match_action_mismatch():
    task = {
        "task_id": "task-123",
        "agent_id": "agent-1",
        "action": "s3:GetObject",
        "resource": "s3://agentcap-demo/reports/q3-report.txt",
    }
    with pytest.raises(PolicyViolationError, match="Requested action does not match approved task"):
        validate_task_match(
            task,
            "agent-1",
            "s3:PutObject",
            "s3://agentcap-demo/reports/q3-report.txt",
        )


def test_validate_task_match_resource_mismatch():
    task = {
        "task_id": "task-123",
        "agent_id": "agent-1",
        "action": "s3:GetObject",
        "resource": "s3://agentcap-demo/reports/q3-report.txt",
    }
    with pytest.raises(PolicyViolationError, match="Requested resource does not match approved task"):
        validate_task_match(
            task,
            "agent-1",
            "s3:GetObject",
            "s3://agentcap-demo/reports/other.txt",
        )
