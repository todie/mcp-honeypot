"""Comprehensive unit tests for server/tagging.py anomaly detection engine."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

import tagging  # noqa: E402
from tagging import (  # noqa: E402
    _call_hash,
    _is_plausible_base64,
    detect_anomalies,
    reset_state,
    session_state,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class FakeClock:
    """Controllable monotonic clock for time-sensitive tests."""

    def __init__(self, start: float = 0.0):
        self._now = start

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


@pytest.fixture(autouse=True)
def _isolate():
    """Reset all module-level state before every test."""
    reset_state()
    yield
    reset_state()


# ---------------------------------------------------------------------------
# TestCredentialProbe
# ---------------------------------------------------------------------------

class TestCredentialProbe:

    def test_credential_probe_triggers_on_get_env_var(self):
        flags = detect_anomalies("get_env_var", {"key": "SECRET"}, "s1")
        assert "credential_probe" in flags

    def test_credential_probe_triggers_on_read_secret(self):
        flags = detect_anomalies("read_secret", {"name": "db_pw"}, "s1")
        assert "credential_probe" in flags

    def test_credential_probe_triggers_on_list_secrets(self):
        flags = detect_anomalies("list_secrets", {}, "s1")
        assert "credential_probe" in flags

    def test_credential_probe_triggers_on_get_api_key(self):
        flags = detect_anomalies("get_api_key", {"service": "stripe"}, "s1")
        assert "credential_probe" in flags

    def test_credential_probe_not_triggered_by_filesystem_exec_web(self):
        for tool in ("read_file", "run_command", "fetch_url"):
            flags = detect_anomalies(tool, {}, "s1")
            assert "credential_probe" not in flags

    def test_credential_probe_not_triggered_by_unknown_tool(self):
        flags = detect_anomalies("totally_unknown_tool", {"x": "y"}, "s1")
        assert "credential_probe" not in flags


# ---------------------------------------------------------------------------
# TestPathTraversal
# ---------------------------------------------------------------------------

class TestPathTraversal:

    def test_path_traversal_classic_dot_dot_slash(self):
        flags = detect_anomalies("read_file", {"path": "../../etc/passwd"}, "s1")
        assert "path_traversal" in flags

    def test_path_traversal_absolute_path_no_flag(self):
        flags = detect_anomalies("read_file", {"path": "/etc/passwd"}, "s1")
        assert "path_traversal" not in flags

    def test_path_traversal_nested_dict_value(self):
        params = {"opts": {"target": "../../etc/shadow"}}
        flags = detect_anomalies("read_file", params, "s1")
        assert "path_traversal" in flags

    def test_path_traversal_empty_params(self):
        flags = detect_anomalies("read_file", {}, "s1")
        assert "path_traversal" not in flags

    def test_path_traversal_backslash_variant_gap(self):
        """Documents the gap: backslash traversal is NOT detected."""
        flags = detect_anomalies("read_file", {"path": "..\\..\\etc\\passwd"}, "s1")
        assert "path_traversal" not in flags


# ---------------------------------------------------------------------------
# TestParamObfuscation
# ---------------------------------------------------------------------------

class TestParamObfuscation:

    def test_param_obfuscation_valid_b64_over_20(self):
        # "A" * 24 is valid base64 (decodes to 18 bytes of 0x00)
        encoded = "AAAAAAAAAAAAAAAAAAAAAAAA"
        assert len(encoded) > 20
        flags = detect_anomalies("run_command", {"cmd": encoded}, "s1")
        assert "param_obfuscation" in flags

    def test_param_obfuscation_valid_b64_20_or_under_no_flag(self):
        short = "AAAAAAAAAAAAAAAAAAA="  # 20 chars, valid b64
        assert len(short) <= 20
        flags = detect_anomalies("run_command", {"cmd": short}, "s1")
        assert "param_obfuscation" not in flags

    def test_param_obfuscation_invalid_b64_over_20_no_flag(self):
        bad = "!!not!!base64!!at!!all!!"
        assert len(bad) > 20
        flags = detect_anomalies("run_command", {"cmd": bad}, "s1")
        assert "param_obfuscation" not in flags

    def test_param_obfuscation_non_string_values_no_crash(self):
        flags = detect_anomalies("run_command", {"count": 42, "flag": None}, "s1")
        assert "param_obfuscation" not in flags

    def test_param_obfuscation_nested_dict_gap(self):
        """Documents gap: nested dict string values are NOT checked."""
        encoded = "AAAAAAAAAAAAAAAAAAAAAAAA"
        flags = detect_anomalies("run_command", {"opts": {"cmd": encoded}}, "s1")
        assert "param_obfuscation" not in flags

    def test_param_obfuscation_first_invalid_second_valid_triggers(self):
        """break semantics: iteration hits valid one and triggers."""
        valid = "AAAAAAAAAAAAAAAAAAAAAAAA"
        flags = detect_anomalies(
            "run_command",
            {"a": "not-base64-!!!!!!!!!!!!", "b": valid},
            "s1",
        )
        assert "param_obfuscation" in flags


# ---------------------------------------------------------------------------
# TestRapidEnumeration
# ---------------------------------------------------------------------------

class TestRapidEnumeration:

    def test_rapid_enumeration_10_calls_no_flag(self):
        clock = FakeClock(100.0)
        with patch.object(tagging.time, "monotonic", clock):
            for _ in range(10):
                flags = detect_anomalies("list_directory", {}, "s1")
            assert "rapid_enumeration" not in flags

    def test_rapid_enumeration_12_calls_triggers(self):
        """12 calls needed: state has 10 prior + current check sees >10, then 11th appended."""
        clock = FakeClock(100.0)
        with patch.object(tagging.time, "monotonic", clock):
            for _ in range(12):
                flags = detect_anomalies("list_directory", {}, "s1")
            assert "rapid_enumeration" in flags

    def test_rapid_enumeration_outside_window_no_flag(self):
        clock = FakeClock(100.0)
        with patch.object(tagging.time, "monotonic", clock):
            for _ in range(8):
                detect_anomalies("list_directory", {}, "s1")
            clock.advance(6.0)  # past the 5s window
            for _ in range(8):
                flags = detect_anomalies("list_directory", {}, "s1")
            assert "rapid_enumeration" not in flags

    def test_rapid_enumeration_different_sessions_independent(self):
        clock = FakeClock(100.0)
        with patch.object(tagging.time, "monotonic", clock):
            for _ in range(8):
                detect_anomalies("list_directory", {}, "session_a")
            for _ in range(8):
                flags = detect_anomalies("list_directory", {}, "session_b")
            assert "rapid_enumeration" not in flags


# ---------------------------------------------------------------------------
# TestReplayAttempt
# ---------------------------------------------------------------------------

class TestReplayAttempt:

    def test_replay_same_call_within_60s(self):
        clock = FakeClock(100.0)
        with patch.object(tagging.time, "monotonic", clock):
            detect_anomalies("read_file", {"path": "/tmp/a"}, "s1")
            clock.advance(30.0)
            flags = detect_anomalies("read_file", {"path": "/tmp/a"}, "s1")
            assert "replay_attempt" in flags

    def test_replay_same_call_after_61s_no_flag(self):
        clock = FakeClock(100.0)
        with patch.object(tagging.time, "monotonic", clock):
            detect_anomalies("read_file", {"path": "/tmp/a"}, "s1")
            clock.advance(61.0)
            flags = detect_anomalies("read_file", {"path": "/tmp/a"}, "s1")
            assert "replay_attempt" not in flags

    def test_replay_same_tool_different_params_no_flag(self):
        clock = FakeClock(100.0)
        with patch.object(tagging.time, "monotonic", clock):
            detect_anomalies("read_file", {"path": "/tmp/a"}, "s1")
            clock.advance(5.0)
            flags = detect_anomalies("read_file", {"path": "/tmp/b"}, "s1")
            assert "replay_attempt" not in flags

    def test_replay_timestamp_resets_on_replay(self):
        """A at t=0, A at t=30 (replay), A at t=80 -> NOT replay (80s since t=0).

        The hash timestamp does NOT update on replay, so the original t=0
        anchors the TTL.  At t=80 the delta is 80 > 60 => no longer replay.
        """
        clock = FakeClock(0.0)
        with patch.object(tagging.time, "monotonic", clock):
            detect_anomalies("read_file", {"path": "/x"}, "s1")
            clock.advance(30.0)
            flags = detect_anomalies("read_file", {"path": "/x"}, "s1")
            assert "replay_attempt" in flags
            clock.advance(50.0)  # now at t=80, 80s since original at t=0
            flags = detect_anomalies("read_file", {"path": "/x"}, "s1")
            assert "replay_attempt" not in flags  # 80 > 60, expired


# ---------------------------------------------------------------------------
# TestExfiltrationChain
# ---------------------------------------------------------------------------

class TestExfiltrationChain:

    def test_exfiltration_read_then_fetch(self):
        clock = FakeClock(100.0)
        with patch.object(tagging.time, "monotonic", clock):
            detect_anomalies("read_file", {"path": "/etc/passwd"}, "s1")
            clock.advance(10.0)
            flags = detect_anomalies("fetch_url", {"url": "http://evil.com"}, "s1")
            assert "exfiltration_chain" in flags

    def test_exfiltration_fetch_alone_no_flag(self):
        flags = detect_anomalies("fetch_url", {"url": "http://evil.com"}, "s1")
        assert "exfiltration_chain" not in flags

    def test_exfiltration_read_then_fetch_after_ttl_no_flag(self):
        clock = FakeClock(100.0)
        with patch.object(tagging.time, "monotonic", clock):
            detect_anomalies("read_file", {"path": "/etc/passwd"}, "s1")
            clock.advance(301.0)  # past 300s TTL
            flags = detect_anomalies("fetch_url", {"url": "http://evil.com"}, "s1")
            assert "exfiltration_chain" not in flags

    def test_exfiltration_write_then_fetch_no_flag(self):
        """write_file is NOT in READ_TOOLS."""
        clock = FakeClock(100.0)
        with patch.object(tagging.time, "monotonic", clock):
            detect_anomalies("write_file", {"path": "/tmp/x", "data": "hi"}, "s1")
            clock.advance(5.0)
            flags = detect_anomalies("fetch_url", {"url": "http://evil.com"}, "s1")
            assert "exfiltration_chain" not in flags

    def test_exfiltration_get_api_key_then_screenshot(self):
        """get_api_key (READ_TOOL) then screenshot (NETWORK_TOOL) = flag."""
        clock = FakeClock(100.0)
        with patch.object(tagging.time, "monotonic", clock):
            detect_anomalies("get_api_key", {"service": "aws"}, "s1")
            clock.advance(10.0)
            flags = detect_anomalies("screenshot", {"url": "http://x.com"}, "s1")
            assert "exfiltration_chain" in flags


# ---------------------------------------------------------------------------
# TestPrivilegeEscalation
# ---------------------------------------------------------------------------

class TestPrivilegeEscalation:

    def test_privilege_escalation_first_call_no_flag(self):
        flags = detect_anomalies("read_file", {"path": "/tmp/a"}, "s1")
        assert "privilege_escalation" not in flags

    def test_privilege_escalation_different_category(self):
        detect_anomalies("read_file", {"path": "/tmp/a"}, "s1")
        flags = detect_anomalies("run_command", {"cmd": "whoami"}, "s1")
        assert "privilege_escalation" in flags

    def test_privilege_escalation_same_category_no_flag(self):
        detect_anomalies("read_file", {"path": "/tmp/a"}, "s1")
        flags = detect_anomalies("write_file", {"path": "/tmp/b", "data": "x"}, "s1")
        assert "privilege_escalation" not in flags

    def test_privilege_escalation_all_four_categories_sequence(self):
        detect_anomalies("read_file", {}, "s1")         # filesystem
        f2 = detect_anomalies("fetch_url", {}, "s1")    # web
        assert "privilege_escalation" in f2
        f3 = detect_anomalies("run_command", {}, "s1")  # exec
        assert "privilege_escalation" in f3
        f4 = detect_anomalies("get_env_var", {}, "s1")  # secrets
        assert "privilege_escalation" in f4

    def test_privilege_escalation_unknown_tool_then_known_no_flag(self):
        """Unknown tool (category=None) does not populate categories_seen."""
        detect_anomalies("totally_unknown", {}, "s1")
        flags = detect_anomalies("read_file", {}, "s1")
        assert "privilege_escalation" not in flags


# ---------------------------------------------------------------------------
# TestSessionEviction
# ---------------------------------------------------------------------------

class TestSessionEviction:

    def test_session_active_within_1h_not_evicted(self):
        clock = FakeClock(100.0)
        with patch.object(tagging.time, "monotonic", clock):
            detect_anomalies("read_file", {}, "s1")
            clock.advance(3599.0)
            detect_anomalies("read_file", {}, "s1")
            assert "s1" in session_state

    def test_session_inactive_over_3600s_evicted(self):
        clock = FakeClock(100.0)
        with patch.object(tagging.time, "monotonic", clock):
            detect_anomalies("read_file", {}, "s1")
            clock.advance(3601.0)
            # Next call triggers eviction then re-creates fresh state
            detect_anomalies("read_file", {}, "s1")
            # Session exists but is fresh (only 1 call)
            assert len(session_state["s1"]["calls"]) == 1

    def test_evicted_then_reused_fresh_state(self):
        clock = FakeClock(100.0)
        with patch.object(tagging.time, "monotonic", clock):
            detect_anomalies("read_file", {}, "s1")
            detect_anomalies("run_command", {}, "s1")  # escalation recorded
            clock.advance(3601.0)
            # After eviction, session is fresh — no inherited escalation
            flags = detect_anomalies("read_file", {}, "s1")
            assert "privilege_escalation" not in flags
            assert len(session_state["s1"]["categories_seen"]) == 1


# ---------------------------------------------------------------------------
# TestHelpers
# ---------------------------------------------------------------------------

class TestHelpers:

    def test_is_plausible_base64_valid(self):
        assert _is_plausible_base64("SGVsbG8gV29ybGQ=") is True

    def test_is_plausible_base64_invalid(self):
        assert _is_plausible_base64("!!!not-base64!!!") is False

    def test_is_plausible_base64_empty_string_surprising(self):
        """Documents surprising behavior: empty string decodes to b''."""
        assert _is_plausible_base64("") is True

    def test_call_hash_deterministic_and_differs(self):
        h1a = _call_hash("read_file", {"path": "/a"})
        h1b = _call_hash("read_file", {"path": "/a"})
        h2 = _call_hash("read_file", {"path": "/b"})
        assert h1a == h1b, "Same inputs must produce same hash"
        assert h1a != h2, "Different inputs must produce different hash"


# ---------------------------------------------------------------------------
# TestResetState
# ---------------------------------------------------------------------------

class TestResetState:

    def test_reset_state_clears_session_state(self):
        detect_anomalies("read_file", {}, "s1")
        assert len(session_state) > 0
        reset_state()
        assert len(session_state) == 0

    def test_reset_no_flags_carry_over(self):
        detect_anomalies("read_file", {}, "s1")
        detect_anomalies("run_command", {}, "s1")  # escalation
        reset_state()
        flags = detect_anomalies("read_file", {}, "s1")
        assert "privilege_escalation" not in flags
