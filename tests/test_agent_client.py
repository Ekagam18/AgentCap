import base64
import json

import httpx
import pytest

from agent.client import (
    AgentCapClient,
    BrokerHTTPError,
    InvalidBrokerResponseError,
)


def make_client(handler, max_object_bytes=1024 * 1024):
    transport = httpx.MockTransport(handler)
    return AgentCapClient(
        base_url="http://127.0.0.1:8000",
        api_key="test-agent-key",
        max_object_bytes=max_object_bytes,
        transport=transport,
    )


def execution_handler(payload=b"AgentCap test content", encoded=None, content_length=None):
    if encoded is None:
        encoded = base64.b64encode(payload).decode("ascii")

    if content_length is None:
        content_length = len(payload)

    def handler(request):
        if request.url.path == "/leases":
            return httpx.Response(
                201,
                json={
                    "lease_token": "test-single-use-token",
                    "expires_in": 60,
                    "token_type": "Bearer",
                },
            )

        if request.url.path == "/leases/execute":
            return httpx.Response(
                200,
                json={
                    "content_base64": encoded,
                    "content_length": content_length,
                    "content_type": "text/plain",
                    "etag": "test-etag",
                },
            )

        return httpx.Response(404)

    return handler


def test_execute_task_successfully_decodes_content():
    payload = b"AgentCap test content"
    requests = []

    def handler(request):
        requests.append(request)

        if request.url.path == "/leases":
            return httpx.Response(
                201,
                json={
                    "lease_token": "test-single-use-token",
                    "expires_in": 60,
                    "token_type": "Bearer",
                },
            )

        if request.url.path == "/leases/execute":
            return httpx.Response(
                200,
                json={
                    "content_base64": base64.b64encode(payload).decode("ascii"),
                    "content_length": len(payload),
                    "content_type": "text/plain",
                    "etag": "test-etag",
                },
            )

        return httpx.Response(404)

    client = make_client(handler)

    result = client.execute_task(
        task_id="task-test-123",
        action="s3:GetObject",
        resource="s3://test-bucket/reports/test.txt",
    )

    assert result.content_bytes == payload
    assert result.content_length == len(payload)
    assert result.content_type == "text/plain"
    assert len(requests) == 2

    assert requests[0].url.path == "/leases"
    assert requests[0].headers["X-Agent-Key"] == "test-agent-key"
    assert json.loads(requests[0].content) == {
        "task_id": "task-test-123",
        "action": "s3:GetObject",
        "resource": "s3://test-bucket/reports/test.txt",
    }

    assert requests[1].url.path == "/leases/execute"
    assert json.loads(requests[1].content) == {
        "lease_token": "test-single-use-token"
    }

    assert "test-single-use-token" not in repr(result)


def test_broker_http_error_is_reported_without_response_body():
    def handler(request):
        return httpx.Response(
            403,
            json={"detail": "sensitive internal information"},
        )

    client = make_client(handler)

    with pytest.raises(BrokerHTTPError) as exc:
        client.execute_task(
            "task-test-123",
            "s3:GetObject",
            "s3://test-bucket/reports/test.txt",
        )

    assert exc.value.status_code == 403
    assert "sensitive internal information" not in str(exc.value)


def test_invalid_base64_is_rejected():
    client = make_client(
        execution_handler(
            encoded="@@not-valid-base64@@",
            content_length=10,
        )
    )

    with pytest.raises(InvalidBrokerResponseError):
        client.execute_task(
            "task-test-123",
            "s3:GetObject",
            "s3://test-bucket/reports/test.txt",
        )


def test_content_length_mismatch_is_rejected():
    payload = b"AgentCap test content"

    client = make_client(
        execution_handler(
            payload=payload,
            content_length=len(payload) + 5,
        )
    )

    with pytest.raises(InvalidBrokerResponseError):
        client.execute_task(
            "task-test-123",
            "s3:GetObject",
            "s3://test-bucket/reports/test.txt",
        )


def test_object_exceeding_configured_limit_is_rejected():
    payload = b"12345"

    client = make_client(
        execution_handler(payload=payload),
        max_object_bytes=4,
    )

    with pytest.raises(InvalidBrokerResponseError):
        client.execute_task(
            "task-test-123",
            "s3:GetObject",
            "s3://test-bucket/reports/test.txt",
        )
