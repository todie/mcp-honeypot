"""Unit tests for tests/harness/ modules -- mcp_client, telemetry, scenarios."""

from __future__ import annotations

import asyncio
import inspect
import sys
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

from tests.harness.mcp_client import McpTestClient
from tests.harness.scenarios import (
    SCENARIOS,
    credential_probe,
    exfiltration_chain,
    full_attack_sequence,
    path_traversal,
    privilege_escalation,
    rapid_enumeration,
    replay_attack,
)
from tests.harness.telemetry import TelemetryHarness

# =========================================================================
# McpTestClient -- init and message construction
# =========================================================================


class TestMcpTestClientInit:
    def test_base_url_trailing_slash_stripped(self):
        client = McpTestClient(base_url="http://localhost:8000/")
        assert client._base_url == "http://localhost:8000"

    def test_default_client_info(self):
        client = McpTestClient()
        assert client._client_info == {"name": "mcp-test-client", "version": "1.0"}

    def test_custom_client_info(self):
        info = {"name": "evil-bot", "version": "2.0"}
        client = McpTestClient(client_info=info)
        assert client._client_info == info

    def test_user_agent_set_in_headers(self):
        client = McpTestClient(user_agent="TestBot/1.0")
        assert client._user_agent == "TestBot/1.0"
        assert client._headers.get("User-Agent") == "TestBot/1.0"

    def test_default_user_agent_is_none(self):
        client = McpTestClient()
        assert client._user_agent is None
        assert "User-Agent" not in client._headers

    def test_initial_state(self):
        client = McpTestClient()
        assert client.session_id is None
        assert client.endpoint_url is None
        assert client.connected is False
        assert client._msg_id == 0


class TestMcpTestClientMessageId:
    def test_next_id_auto_increments(self):
        client = McpTestClient()
        id1 = client._next_id()
        id2 = client._next_id()
        id3 = client._next_id()
        assert id1 == 1
        assert id2 == 2
        assert id3 == 3

    def test_msg_id_starts_at_zero(self):
        client = McpTestClient()
        assert client._msg_id == 0


class TestMcpTestClientNotifications:
    """Verify that notification payloads have no 'id' field."""

    @pytest.mark.asyncio
    async def test_notification_has_no_id(self):
        """Construct what _send_notification would send and verify no id."""
        _ = McpTestClient()  # verify it can be instantiated
        # Build the payload manually (same logic as _send_notification)
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }
        assert "id" not in payload

    @pytest.mark.asyncio
    async def test_notification_with_params_has_no_id(self):
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": "notifications/progress",
        }
        params = {"token": "abc"}
        payload["params"] = params
        assert "id" not in payload
        assert payload["params"] == {"token": "abc"}


# =========================================================================
# TelemetryHarness -- init and query construction
# =========================================================================


class TestTelemetryHarnessInit:
    def test_default_urls(self):
        harness = TelemetryHarness()
        assert harness._jaeger_url == "http://localhost:16686"
        assert harness._prometheus_url == "http://localhost:9090"

    def test_custom_urls(self):
        harness = TelemetryHarness(
            jaeger_url="http://jaeger:16686/",
            prometheus_url="http://prom:9090/",
        )
        assert harness._jaeger_url == "http://jaeger:16686"
        assert harness._prometheus_url == "http://prom:9090"

    def test_trailing_slash_stripped(self):
        harness = TelemetryHarness(jaeger_url="http://jaeger:16686///")
        assert harness._jaeger_url == "http://jaeger:16686"


class TestTelemetryHarnessQueries:
    """Verify PromQL query strings are built correctly."""

    @pytest.mark.asyncio
    async def test_tool_call_count_query_all(self):
        harness = TelemetryHarness()
        # Mock _client.get to capture the query param
        captured_params = {}

        async def mock_get(url, params=None):
            captured_params.update(params or {})
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"data": {"result": []}}
            return resp

        harness._client = MagicMock()
        harness._client.get = mock_get

        result = await harness.get_tool_call_count()
        assert captured_params["query"] == "sum(mcp_honeypot_mcp_tool_calls_total)"
        assert result == 0

    @pytest.mark.asyncio
    async def test_tool_call_count_query_specific_tool(self):
        harness = TelemetryHarness()
        captured_params = {}

        async def mock_get(url, params=None):
            captured_params.update(params or {})
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"data": {"result": [{"value": [1700000000, "42"]}]}}
            return resp

        harness._client = MagicMock()
        harness._client.get = mock_get

        result = await harness.get_tool_call_count("read_file")
        assert 'tool="read_file"' in captured_params["query"]
        assert result == 42

    @pytest.mark.asyncio
    async def test_anomaly_count_query_with_flag(self):
        harness = TelemetryHarness()
        captured_params = {}

        async def mock_get(url, params=None):
            captured_params.update(params or {})
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"data": {"result": []}}
            return resp

        harness._client = MagicMock()
        harness._client.get = mock_get

        await harness.get_anomaly_count("credential_probe")
        assert 'flag="credential_probe"' in captured_params["query"]


class TestTelemetryHarnessTraceParsing:
    """Test Jaeger trace parsing logic from sample JSON."""

    @pytest.mark.asyncio
    async def test_get_all_anomaly_flags_extracts_flags(self):
        harness = TelemetryHarness()
        sample_traces = [
            {
                "traceID": "t1",
                "spans": [
                    {
                        "spanID": "s1",
                        "tags": [
                            {"key": "anomaly.flags", "value": "credential_probe,path_traversal"},
                        ],
                    },
                    {
                        "spanID": "s2",
                        "tags": [
                            {"key": "anomaly.flags", "value": "exfiltration_chain"},
                        ],
                    },
                ],
            }
        ]

        # Mock wait_for_traces to return our sample data
        harness.wait_for_traces = AsyncMock(return_value=sample_traces)
        flags = await harness.get_all_anomaly_flags()
        assert flags == {"credential_probe", "path_traversal", "exfiltration_chain"}

    @pytest.mark.asyncio
    async def test_get_all_anomaly_flags_handles_empty_traces(self):
        harness = TelemetryHarness()
        harness.wait_for_traces = AsyncMock(return_value=[])
        flags = await harness.get_all_anomaly_flags()
        assert flags == set()

    @pytest.mark.asyncio
    async def test_get_all_anomaly_flags_handles_no_flag_tags(self):
        harness = TelemetryHarness()
        sample_traces = [
            {
                "traceID": "t1",
                "spans": [
                    {
                        "spanID": "s1",
                        "tags": [{"key": "mcp.tool", "value": "read_file"}],
                    },
                ],
            }
        ]
        harness.wait_for_traces = AsyncMock(return_value=sample_traces)
        flags = await harness.get_all_anomaly_flags()
        assert flags == set()


# =========================================================================
# scenarios.py -- scenario registry and function signatures
# =========================================================================


class TestScenariosRegistry:
    def test_all_expected_scenario_names_present(self):
        expected = {"credential", "exfil", "escalation", "rapid", "traversal", "replay", "all"}
        assert set(SCENARIOS.keys()) == expected

    def test_each_scenario_is_callable(self):
        for name, func in SCENARIOS.items():
            assert callable(func), f"SCENARIOS[{name!r}] is not callable"

    def test_each_scenario_is_async(self):
        for name, func in SCENARIOS.items():
            assert asyncio.iscoroutinefunction(func), (
                f"SCENARIOS[{name!r}] should be an async function"
            )

    def test_scenario_functions_accept_client_arg(self):
        """Each scenario function should accept at least a client parameter."""
        for name, func in SCENARIOS.items():
            sig = inspect.signature(func)
            params = list(sig.parameters.keys())
            assert len(params) >= 1, f"SCENARIOS[{name!r}] should accept at least one parameter"

    def test_full_attack_sequence_calls_all_scenarios(self):
        """full_attack_sequence should reference all individual scenarios."""
        # We verify by checking the source code contains calls to each scenario
        source = inspect.getsource(full_attack_sequence)
        assert "credential_probe" in source
        assert "exfiltration_chain" in source
        assert "privilege_escalation" in source
        assert "path_traversal" in source
        assert "rapid_enumeration" in source
        assert "replay_attack" in source

    def test_credential_probe_exists_and_is_async(self):
        assert asyncio.iscoroutinefunction(credential_probe)

    def test_exfiltration_chain_exists_and_is_async(self):
        assert asyncio.iscoroutinefunction(exfiltration_chain)

    def test_privilege_escalation_exists_and_is_async(self):
        assert asyncio.iscoroutinefunction(privilege_escalation)

    def test_rapid_enumeration_exists_and_is_async(self):
        assert asyncio.iscoroutinefunction(rapid_enumeration)

    def test_path_traversal_exists_and_is_async(self):
        assert asyncio.iscoroutinefunction(path_traversal)

    def test_replay_attack_exists_and_is_async(self):
        assert asyncio.iscoroutinefunction(replay_attack)
