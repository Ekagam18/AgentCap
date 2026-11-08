"""HTTP client for executing administrator-approved AgentCap tasks."""

from __future__ import annotations

import base64
import binascii
import json
import math
from dataclasses import dataclass, field
from pathlib import Path

import httpx


class AgentClientError(Exception):
    """Base exception for safe agent-client errors."""


class BrokerConnectionError(AgentClientError):
    """The broker could not be reached."""


class InvalidBrokerResponseError(AgentClientError):
    """The broker returned an invalid or unsafe response."""


class BrokerHTTPError(AgentClientError):
    """The broker rejected a request."""

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__(f"Broker returned HTTP {status_code}.")


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    # Keep object bytes out of the default representation.
    content_bytes: bytes = field(repr=False)
    content_length: int
    content_type: str | None = None
    etag: str | None = None

    def save(self, destination: str | Path) -> Path:
        """Save without overwriting an existing file."""
        path = Path(destination)
        with path.open("xb") as output:
            output.write(self.content_bytes)
        return path


class AgentCapClient:
    """Request a lease and execute it without exposing the lease token."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = 10.0,
        max_object_bytes: int = 1_048_576,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not isinstance(base_url, str) or not base_url.strip():
            raise ValueError("base_url must be a non-empty URL.")

        try:
            parsed_url = httpx.URL(base_url)
        except (TypeError, httpx.InvalidURL):
            raise ValueError("base_url must be a valid HTTP(S) URL.") from None

        if (
            parsed_url.scheme not in {"http", "https"}
            or not parsed_url.host
            or parsed_url.username
            or parsed_url.password
            or parsed_url.query
            or parsed_url.fragment
        ):
            raise ValueError("base_url must be a valid HTTP(S) URL without credentials, query, or fragment.")

        # Plain HTTP is permitted only for local development.
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if parsed_url.scheme == "http" and parsed_url.host not in local_hosts:
            raise ValueError("HTTPS is required for non-local broker addresses.")

        if not isinstance(api_key, str) or not api_key.strip():
            raise ValueError("api_key must be a non-empty string.")

        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("timeout must be a positive finite number.")

        if (
            isinstance(max_object_bytes, bool)
            or not isinstance(max_object_bytes, int)
            or max_object_bytes <= 0
        ):
            raise ValueError("max_object_bytes must be a positive integer.")

        self._max_object_bytes = max_object_bytes
        self._max_response_bytes = ((max_object_bytes + 2) // 3) * 4 + 65_536

        self._http = httpx.Client(
            base_url=str(parsed_url).rstrip("/") + "/",
            headers={
                "X-Agent-Key": api_key,
                "Accept": "application/json",
            },
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            transport=transport,
        )

    def __enter__(self) -> AgentCapClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

    def _post_json(self, path: str, payload: dict) -> dict:
        """POST JSON while bounding the response and hiding response bodies on errors."""
        try:
            with self._http.stream("POST", path, json=payload) as response:
                if not response.is_success:
                    raise BrokerHTTPError(response.status_code)

                declared_length = response.headers.get("content-length")
                if declared_length is not None:
                    try:
                        declared_size = int(declared_length)
                    except ValueError:
                        raise InvalidBrokerResponseError(
                            "Broker returned an invalid response length."
                        ) from None

                    if declared_size < 0 or declared_size > self._max_response_bytes:
                        raise InvalidBrokerResponseError(
                            "Broker response exceeded the configured size limit."
                        )

                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > self._max_response_bytes:
                        raise InvalidBrokerResponseError(
                            "Broker response exceeded the configured size limit."
                        )

        except (BrokerHTTPError, InvalidBrokerResponseError):
            raise
        except httpx.TimeoutException:
            raise BrokerConnectionError("The broker request timed out.") from None
        except httpx.RequestError:
            raise BrokerConnectionError(
                "Could not communicate with the AgentCap broker."
            ) from None

        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise InvalidBrokerResponseError(
                "Broker returned invalid JSON."
            ) from None

        if not isinstance(data, dict):
            raise InvalidBrokerResponseError(
                "Broker returned an unexpected response format."
            )

        return data

    @staticmethod
    def _validate_task_field(name: str, value: str) -> None:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string.")

    def execute_task(
        self,
        task_id: str,
        action: str,
        resource: str,
    ) -> ExecutionResult:
        """Request a lease and immediately execute the approved task.

        The lease token remains local to this method. It is never returned,
        printed, or written to disk.
        """
        self._validate_task_field("task_id", task_id)
        self._validate_task_field("action", action)
        self._validate_task_field("resource", resource)

        lease = self._post_json(
            "leases",
            {
                "task_id": task_id,
                "action": action,
                "resource": resource,
            },
        )

        lease_token = lease.get("lease_token")
        expires_in = lease.get("expires_in")

        if (
            not isinstance(lease_token, str)
            or not lease_token
            or len(lease_token) > 256
            or isinstance(expires_in, bool)
            or not isinstance(expires_in, int)
            or expires_in <= 0
        ):
            raise InvalidBrokerResponseError(
                "Broker returned an invalid lease response."
            )

        execution = self._post_json(
            "leases/execute",
            {"lease_token": lease_token},
        )

        encoded_content = execution.get("content_base64")
        content_length = execution.get("content_length")

        if (
            not isinstance(encoded_content, str)
            or isinstance(content_length, bool)
            or not isinstance(content_length, int)
            or content_length < 0
            or content_length > self._max_object_bytes
        ):
            raise InvalidBrokerResponseError(
                "Broker returned invalid object metadata."
            )

        try:
            content_bytes = base64.b64decode(
                encoded_content,
                validate=True,
            )
        except (binascii.Error, ValueError):
            raise InvalidBrokerResponseError(
                "Broker returned invalid Base64 object content."
            ) from None

        if len(content_bytes) != content_length:
            raise InvalidBrokerResponseError(
                "Downloaded object length did not match broker metadata."
            )

        content_type = execution.get("content_type")
        etag = execution.get("etag")

        if content_type is not None and not isinstance(content_type, str):
            raise InvalidBrokerResponseError("Invalid content-type metadata.")

        if etag is not None and not isinstance(etag, str):
            raise InvalidBrokerResponseError("Invalid ETag metadata.")

        return ExecutionResult(
            content_bytes=content_bytes,
            content_length=content_length,
            content_type=content_type,
            etag=etag,
        )
