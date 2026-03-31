"""Unit tests for tools/adversarial_agent.py -- persona phases, CLI, SSE parsing."""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path setup so imports resolve without installing the package
# ---------------------------------------------------------------------------
_project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_project_root))
sys.path.insert(0, str(_project_root / "server"))

# Import the top-level tools/adversarial_agent.py via importlib to avoid
# collision with server/tools/ package already on sys.path.
_adv_spec = importlib.util.spec_from_file_location(
    "adversarial_agent", _project_root / "tools" / "adversarial_agent.py"
)
_adv_mod = importlib.util.module_from_spec(_adv_spec)
sys.modules["adversarial_agent"] = _adv_mod  # register so dataclasses can resolve __module__
_adv_spec.loader.exec_module(_adv_mod)

PERSONAS = _adv_mod.PERSONAS
AdversarialAgent = _adv_mod.AdversarialAgent
CallResult = _adv_mod.CallResult
MCPSession = _adv_mod.MCPSession
PhaseResult = _adv_mod.PhaseResult
SessionResult = _adv_mod.SessionResult
_bruteforce_phases = _adv_mod._bruteforce_phases
_build_parser = _adv_mod._build_parser
_chaos_phases = _adv_mod._chaos_phases
_exfiltrator_phases = _adv_mod._exfiltrator_phases
_lateral_phases = _adv_mod._lateral_phases
_recon_phases = _adv_mod._recon_phases

from tools.registry import TOOL_REGISTRY

# =========================================================================
# Persona phase generation (no network needed)
# =========================================================================


class TestReconPhases:
    def test_returns_three_phases(self):
        phases = _recon_phases()
        assert len(phases) == 3

    def test_phase_names(self):
        phases = _recon_phases()
        names = [p[0] for p in phases]
        assert "Filesystem Mapping" in names
        assert "Config Harvesting" in names
        assert "Environment Probing" in names


class TestExfiltratorPhases:
    def test_returns_three_phases(self):
        phases = _exfiltrator_phases()
        assert len(phases) == 3

    def test_contains_read_file_and_fetch_url(self):
        """Exfiltrator should use read tools and network tools."""
        phases = _exfiltrator_phases()
        all_tools = {tool for _, _, calls in phases for tool, _ in calls}
        assert "read_file" in all_tools
        assert "fetch_url" in all_tools

    def test_contains_secret_tools(self):
        phases = _exfiltrator_phases()
        all_tools = {tool for _, _, calls in phases for tool, _ in calls}
        assert "list_secrets" in all_tools
        assert "read_secret" in all_tools


class TestBruteforcePhases:
    def test_returns_four_phases(self):
        phases = _bruteforce_phases()
        assert len(phases) == 4

    def test_has_rapid_phase_with_many_calls(self):
        """At least one phase should have >10 calls (rapid_enumeration trigger)."""
        phases = _bruteforce_phases()
        max_calls = max(len(calls) for _, _, calls in phases)
        assert max_calls > 10

    def test_replay_phase_overlaps_with_earlier_phases(self):
        """The replay phase should repeat calls from earlier phases (triggering replay_attempt)."""
        phases = _bruteforce_phases()
        earlier_calls = set()
        for phase in phases[:-1]:
            for t, p in phase[2]:
                earlier_calls.add((t, json.dumps(p, sort_keys=True)))
        replay_calls = {(t, json.dumps(p, sort_keys=True)) for t, p in phases[-1][2]}
        overlap = earlier_calls & replay_calls
        assert len(overlap) > 0, "Replay phase should repeat calls from earlier phases"


class TestLateralPhases:
    def test_returns_four_phases(self):
        phases = _lateral_phases()
        assert len(phases) == 4

    def test_spans_all_four_categories(self):
        """Lateral movement should touch filesystem, exec, web, and secrets."""
        phases = _lateral_phases()
        all_tools = {tool for _, _, calls in phases for tool, _ in calls}

        # filesystem
        assert all_tools & {"read_file", "list_directory", "write_file", "delete_file"}
        # exec
        assert all_tools & {"run_command", "run_python"}
        # web
        assert all_tools & {"fetch_url", "search_web", "screenshot"}
        # secrets
        assert all_tools & {"get_env_var", "read_secret", "list_secrets", "get_api_key"}


class TestChaosPhases:
    def test_returns_three_phases(self):
        phases = _chaos_phases()
        assert len(phases) == 3

    def test_contains_base64_encoded_params(self):
        """Chaos persona should include base64-encoded parameters."""
        phases = _chaos_phases()
        all_params = []
        for _, _, calls in phases:
            for _, params in calls:
                all_params.extend(str(v) for v in params.values())

        base64_values = []
        for val in all_params:
            try:
                decoded = base64.b64decode(val, validate=True)
                if len(decoded) > 5:  # non-trivial base64
                    base64_values.append(val)
            except Exception:
                pass

        assert len(base64_values) > 0, "Chaos phases should have base64-encoded params"

    def test_base64_params_are_long_enough(self):
        """base64 params should be >20 chars to trigger param_obfuscation."""
        phases = _chaos_phases()
        found_long_b64 = False
        for _, _, calls in phases:
            for _, params in calls:
                for val in params.values():
                    val_str = str(val)
                    if len(val_str) > 20:
                        try:
                            base64.b64decode(val_str, validate=True)
                            found_long_b64 = True
                        except Exception:
                            pass
        assert found_long_b64, "Should have base64 param >20 chars"


# =========================================================================
# Phase structure validation
# =========================================================================


class TestPhaseStructure:
    @pytest.mark.parametrize(
        "phases_fn",
        [
            _recon_phases,
            _exfiltrator_phases,
            _bruteforce_phases,
            _lateral_phases,
            _chaos_phases,
        ],
    )
    def test_each_phase_has_name_and_nonempty_calls(self, phases_fn):
        phases = phases_fn()
        for name, intent, calls in phases:
            assert isinstance(name, str) and len(name) > 0
            assert isinstance(intent, str) and len(intent) > 0
            assert isinstance(calls, list) and len(calls) > 0

    @pytest.mark.parametrize(
        "phases_fn",
        [
            _recon_phases,
            _exfiltrator_phases,
            _bruteforce_phases,
            _lateral_phases,
            _chaos_phases,
        ],
    )
    def test_call_tuples_have_tool_name_and_params(self, phases_fn):
        phases = phases_fn()
        for _, _, calls in phases:
            for item in calls:
                assert len(item) == 2
                tool_name, params = item
                assert isinstance(tool_name, str)
                assert isinstance(params, dict)

    @pytest.mark.parametrize(
        "phases_fn",
        [
            _recon_phases,
            _exfiltrator_phases,
            _bruteforce_phases,
            _lateral_phases,
        ],
    )
    def test_all_tool_names_in_registry(self, phases_fn):
        """Every tool referenced by a persona should be in the TOOL_REGISTRY."""
        phases = phases_fn()
        for _, _, calls in phases:
            for tool_name, _ in calls:
                assert tool_name in TOOL_REGISTRY, f"Tool {tool_name!r} not found in TOOL_REGISTRY"

    def test_chaos_tool_names_mostly_in_registry(self):
        """Chaos includes tools from all personas; most should be in registry."""
        phases = _chaos_phases()
        all_tools = {tool for _, _, calls in phases for tool, _ in calls}
        registered = all_tools & set(TOOL_REGISTRY.keys())
        # At least 10 of the 13 tools should appear
        assert len(registered) >= 10


# =========================================================================
# CLI argument parsing
# =========================================================================


class TestCLIParsing:
    def test_parse_persona_recon(self):
        parser = _build_parser()
        args = parser.parse_args(["--persona", "recon"])
        assert args.persona == "recon"

    def test_parse_persona_all(self):
        parser = _build_parser()
        args = parser.parse_args(["--persona", "all"])
        assert args.persona == "all"

    def test_parse_sessions_and_delay(self):
        parser = _build_parser()
        args = parser.parse_args(["--persona", "chaos", "--sessions", "3", "--delay", "0.1"])
        assert args.sessions == 3
        assert args.delay == pytest.approx(0.1)

    def test_default_values(self):
        parser = _build_parser()
        args = parser.parse_args(["--persona", "recon"])
        assert args.url == "http://localhost:8000"
        assert args.sessions == 1
        assert args.delay == 0.5
        assert args.verbose is False
        assert args.no_color is False
        assert args.user_agent is None

    def test_list_flag(self):
        parser = _build_parser()
        args = parser.parse_args(["--list"])
        assert args.list_personas is True


# =========================================================================
# PERSONAS registry
# =========================================================================


class TestPersonasRegistry:
    def test_all_five_personas_present(self):
        assert set(PERSONAS.keys()) == {"recon", "exfiltrator", "bruteforce", "lateral", "chaos"}

    def test_each_persona_has_required_keys(self):
        for key, info in PERSONAS.items():
            assert "name" in info, f"{key} missing 'name'"
            assert "description" in info, f"{key} missing 'description'"
            assert "phases_fn" in info, f"{key} missing 'phases_fn'"
            assert "expected_flags" in info, f"{key} missing 'expected_flags'"
            assert callable(info["phases_fn"]), f"{key} phases_fn not callable"

    def test_chaos_expects_all_seven_flags(self):
        chaos_flags = set(PERSONAS["chaos"]["expected_flags"])
        assert "credential_probe" in chaos_flags
        assert "param_obfuscation" in chaos_flags
        assert "rapid_enumeration" in chaos_flags
        assert "replay_attempt" in chaos_flags
        assert "exfiltration_chain" in chaos_flags
        assert "privilege_escalation" in chaos_flags
        assert "path_traversal" in chaos_flags


# =========================================================================
# MCPSession SSE parsing (mock network)
# =========================================================================


class TestMCPSessionSSEParsing:
    def test_handle_endpoint_event_absolute_path(self):
        session = MCPSession("http://localhost:8000")
        session._handle_sse_event("endpoint", "/messages?session_id=abc123")
        assert session._endpoint == "http://localhost:8000/messages?session_id=abc123"

    def test_handle_endpoint_event_full_url(self):
        session = MCPSession("http://localhost:8000")
        session._handle_sse_event("endpoint", "http://other:9000/messages?session_id=xyz")
        assert session._endpoint == "http://other:9000/messages?session_id=xyz"

    def test_handle_endpoint_event_relative_path(self):
        session = MCPSession("http://localhost:8000")
        session._handle_sse_event("endpoint", "messages?session_id=rel")
        assert session._endpoint == "http://localhost:8000/messages?session_id=rel"

    def test_handle_endpoint_sets_connected_event(self):
        session = MCPSession("http://localhost:8000")
        assert not session._sse_connected.is_set()
        session._handle_sse_event("endpoint", "/messages?session_id=test")
        assert session._sse_connected.is_set()

    def test_handle_message_event_dispatches_to_future(self):
        session = MCPSession("http://localhost:8000")
        loop = asyncio.new_event_loop()
        try:
            future = loop.create_future()
            session._pending[1] = future
            data = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})
            session._handle_sse_event("message", data)
            assert future.done()
            assert future.result() == {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
        finally:
            loop.close()

    def test_handle_message_event_ignores_invalid_json(self):
        session = MCPSession("http://localhost:8000")
        # Should not raise
        session._handle_sse_event("message", "not valid json{{{")

    def test_handle_message_event_ignores_unmatched_id(self):
        session = MCPSession("http://localhost:8000")
        loop = asyncio.new_event_loop()
        try:
            future = loop.create_future()
            session._pending[1] = future
            data = json.dumps({"jsonrpc": "2.0", "id": 999, "result": {}})
            session._handle_sse_event("message", data)
            assert not future.done(), "Future for id=1 should not be resolved by id=999"
        finally:
            loop.close()


# =========================================================================
# Data classes
# =========================================================================


class TestDataClasses:
    def test_call_result_defaults(self):
        cr = CallResult(tool="read_file", params={"path": "/etc/passwd"})
        assert cr.response is None
        assert cr.error is None
        assert cr.elapsed_ms == 0.0

    def test_session_result_defaults(self):
        sr = SessionResult(session_id="abc", persona="recon")
        assert sr.phases == []
        assert sr.total_calls == 0
        assert sr.unique_tools == set()
        assert sr.elapsed_s == 0.0

    def test_phase_result_defaults(self):
        pr = PhaseResult(name="test", intent="testing")
        assert pr.calls == []
        assert pr.elapsed_s == 0.0
