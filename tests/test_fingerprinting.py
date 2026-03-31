"""Agent fingerprinting integration tests for the MCP Honeypot.

These tests run against the **live Docker Compose stack**.  Before running,
bring the stack up with::

    docker-compose up --build -d

Required services: mcp-honeypot (port 8000), jaeger (port 16686).

Run with::

    pytest tests/test_fingerprinting.py -v

The tests are marked ``integration`` so they can be excluded from fast unit
test runs::

    pytest -m "not integration"
"""

from __future__ import annotations

import re
import socket
import time
import uuid
from typing import Any

import httpx
import pytest

# ---------------------------------------------------------------------------
# Reachability guard -- skip the entire module when the stack is down
# ---------------------------------------------------------------------------

MCP_BASE = "http://localhost:8000"
JAEGER_API = "http://localhost:16686/api"
JAEGER_POLL_TIMEOUT = 30  # seconds
JAEGER_POLL_INTERVAL = 2  # seconds


def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Return True if *host*:*port* accepts a TCP connection."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


_stack_up = _port_open("localhost", 8000) and _port_open("localhost", 16686)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not _stack_up, reason="Docker Compose stack not running on localhost:8000/16686"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _jsonrpc(method: str, params: dict[str, Any] | None = None, id: int = 1) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 request dict."""
    msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "id": id}
    if params is not None:
        msg["params"] = params
    return msg


def _poll_jaeger_for_attribute(
    service: str,
    attribute_key: str,
    expected_value: str | None = None,
    timeout: float = JAEGER_POLL_TIMEOUT,
) -> str | None:
    """Poll Jaeger until a span with *attribute_key* (optionally matching
    *expected_value*) appears for *service*.  Returns the attribute value
    found, or ``None`` on timeout.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(
                f"{JAEGER_API}/traces",
                params={
                    "service": service,
                    "limit": 20,
                    "lookback": "1m",
                },
                timeout=5.0,
            )
            if resp.status_code == 200:
                traces = resp.json().get("data", [])
                for trace in traces:
                    for span in trace.get("spans", []):
                        for tag in span.get("tags", []):
                            if tag.get("key") == attribute_key:
                                val = tag.get("value")
                                if expected_value is None or val == expected_value:
                                    return val
        except httpx.RequestError:
            pass
        time.sleep(JAEGER_POLL_INTERVAL)
    return None


class _SSESession:
    """Minimal helper to drive an MCP SSE session via httpx.

    Opens ``GET /sse`` to receive the messages endpoint URL, then sends
    JSON-RPC messages via ``POST /messages``.
    """

    def __init__(self, extra_headers: dict[str, str] | None = None) -> None:
        self._extra_headers = extra_headers or {}
        self._messages_url: str | None = None
        self._client = httpx.Client(timeout=30.0)

    def connect(self) -> None:
        """Establish the SSE connection and retrieve the messages endpoint."""
        headers = {**self._extra_headers, "Accept": "text/event-stream"}
        # We stream the SSE endpoint just long enough to grab the first
        # ``endpoint`` event that tells us the POST URL.
        with self._client.stream("GET", f"{MCP_BASE}/sse", headers=headers) as resp:
            for line in resp.iter_lines():
                # SSE lines: ``event: endpoint\ndata: /messages?session_id=...``
                if line.startswith("data:") and "messages" in line:
                    path = line.split("data:", 1)[1].strip()
                    if path.startswith("/"):
                        self._messages_url = f"{MCP_BASE}{path}"
                    else:
                        self._messages_url = path
                    break
        if not self._messages_url:
            raise RuntimeError("Failed to obtain messages endpoint from /sse")

    def send(self, payload: dict[str, Any]) -> httpx.Response:
        """POST a JSON-RPC message to the session messages endpoint."""
        assert self._messages_url is not None, "call connect() first"
        return self._client.post(
            self._messages_url,
            json=payload,
            headers={"Content-Type": "application/json"},
        )

    def close(self) -> None:
        self._client.close()


def _run_session_with_tool_call(
    *,
    extra_headers: dict[str, str] | None = None,
    send_initialize: bool = True,
    client_info: dict[str, str] | None = None,
) -> None:
    """Open an SSE session, optionally send ``initialize``, then call a tool."""
    sess = _SSESession(extra_headers=extra_headers)
    try:
        sess.connect()

        if send_initialize:
            init_params: dict[str, Any] = {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
            }
            if client_info is not None:
                init_params["clientInfo"] = client_info
            resp = sess.send(_jsonrpc("initialize", init_params, id=1))
            # Accept any 2xx -- the server may return 200 or 202
            assert resp.status_code < 300, f"initialize failed: {resp.status_code} {resp.text}"

        # Call a lightweight tool so the server generates an instrumented span.
        resp = sess.send(
            _jsonrpc(
                "tools/call",
                {"name": "list_directory", "arguments": {"path": "/tmp"}},
                id=2,
            )
        )
        assert resp.status_code < 300, f"tools/call failed: {resp.status_code} {resp.text}"
    finally:
        sess.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAgentFingerprinting:
    """Verify that the honeypot correctly tags spans with the agent identity."""

    def test_custom_user_agent_header(self) -> None:
        """A custom User-Agent header should appear as ``agent.id`` in Jaeger."""
        ua = f"FakeAgent/1.0-{uuid.uuid4().hex[:8]}"

        _run_session_with_tool_call(
            extra_headers={"User-Agent": ua},
            send_initialize=True,
            client_info=None,
        )

        found = _poll_jaeger_for_attribute("mcp-honeypot", "agent.id", expected_value=ua)
        assert found == ua, (
            f"Expected agent.id=={ua!r} in Jaeger spans but got {found!r}"
        )

    def test_mcp_initialize_client_info(self) -> None:
        """clientInfo in the MCP initialize message should override the
        User-Agent and appear as ``agent.id``."""
        unique = uuid.uuid4().hex[:8]
        client_info_name = f"TestBot-{unique}"
        client_info_version = "2.0"
        expected_agent_id = f"{client_info_name}/{client_info_version}"

        _run_session_with_tool_call(
            extra_headers=None,
            send_initialize=True,
            client_info={"name": client_info_name, "version": client_info_version},
        )

        found = _poll_jaeger_for_attribute(
            "mcp-honeypot", "agent.id", expected_value=expected_agent_id,
        )
        assert found == expected_agent_id, (
            f"Expected agent.id=={expected_agent_id!r} in Jaeger spans but got {found!r}"
        )

    def test_fallback_to_session_id(self) -> None:
        """Without User-Agent or clientInfo the agent.id should fall back to
        a session-ID-derived hex string."""
        _run_session_with_tool_call(
            extra_headers={"User-Agent": ""},  # empty to suppress default UA
            send_initialize=True,
            client_info=None,
        )

        # We don't know the exact session ID, so just look for any agent.id
        # value that looks like a hex string (the derive_session_id output).
        found = _poll_jaeger_for_attribute("mcp-honeypot", "agent.id")
        assert found is not None, "No agent.id attribute found in Jaeger spans"
        # Session IDs are 16-char hex strings produced by derive_session_id.
        assert re.fullmatch(r"[0-9a-f]{16}", found), (
            f"Expected a 16-char hex session ID fallback, got {found!r}"
        )
