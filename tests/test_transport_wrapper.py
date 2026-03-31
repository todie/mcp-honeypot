"""Unit tests for server.transport_wrapper module."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

from transport_wrapper import (
    InstrumentedTransport,
    _extract_agent_from_initialize,
    _extract_agent_from_user_agent,
    derive_session_id,
)

# ======================================================================
# derive_session_id
# ======================================================================


class TestDeriveSessionId:
    """Tests for derive_session_id."""

    def test_returns_16_char_hex(self):
        sid = derive_session_id("192.168.1.1", 1700000000.0)
        assert len(sid) == 16
        assert all(c in "0123456789abcdef" for c in sid)

    def test_deterministic(self):
        a = derive_session_id("10.0.0.1", 1700000000.0)
        b = derive_session_id("10.0.0.1", 1700000000.0)
        assert a == b

    def test_different_ip_different_id(self):
        a = derive_session_id("10.0.0.1", 1700000000.0)
        b = derive_session_id("10.0.0.2", 1700000000.0)
        assert a != b

    def test_different_ts_different_id(self):
        a = derive_session_id("10.0.0.1", 1700000000.0)
        b = derive_session_id("10.0.0.1", 1700000001.0)
        assert a != b

    def test_empty_ip(self):
        sid = derive_session_id("", 0.0)
        assert len(sid) == 16


# ======================================================================
# _extract_agent_from_user_agent
# ======================================================================


class TestExtractAgentFromUserAgent:
    """Tests for _extract_agent_from_user_agent."""

    def test_returns_user_agent_value(self):
        headers = [(b"user-agent", b"MyCLI/1.0")]
        assert _extract_agent_from_user_agent(headers) == "MyCLI/1.0"

    def test_case_insensitive_header_name(self):
        headers = [(b"User-Agent", b"AgentX/2.0")]
        assert _extract_agent_from_user_agent(headers) == "AgentX/2.0"

    def test_returns_none_when_no_user_agent(self):
        headers = [(b"content-type", b"application/json")]
        assert _extract_agent_from_user_agent(headers) is None

    def test_returns_none_for_empty_headers(self):
        assert _extract_agent_from_user_agent([]) is None

    def test_returns_none_for_blank_user_agent(self):
        headers = [(b"user-agent", b"   ")]
        assert _extract_agent_from_user_agent(headers) is None

    def test_strips_whitespace(self):
        headers = [(b"user-agent", b"  Trimmed/1.0  ")]
        assert _extract_agent_from_user_agent(headers) == "Trimmed/1.0"


# ======================================================================
# _extract_agent_from_initialize
# ======================================================================


class TestExtractAgentFromInitialize:
    """Tests for _extract_agent_from_initialize."""

    def test_name_and_version(self):
        msg = {"params": {"clientInfo": {"name": "Claude", "version": "3.5"}}}
        assert _extract_agent_from_initialize(msg) == "Claude/3.5"

    def test_name_only_no_version(self):
        msg = {"params": {"clientInfo": {"name": "Claude"}}}
        assert _extract_agent_from_initialize(msg) == "Claude"

    def test_returns_none_when_no_client_info(self):
        msg = {"params": {"somethingElse": True}}
        assert _extract_agent_from_initialize(msg) is None

    def test_returns_none_when_no_params(self):
        msg = {"method": "initialize"}
        assert _extract_agent_from_initialize(msg) is None

    def test_returns_none_for_empty_name(self):
        msg = {"params": {"clientInfo": {"name": "", "version": "1.0"}}}
        assert _extract_agent_from_initialize(msg) is None

    def test_client_info_snake_case_key(self):
        msg = {"params": {"client_info": {"name": "Alt", "version": "0.1"}}}
        assert _extract_agent_from_initialize(msg) == "Alt/0.1"


# ======================================================================
# InstrumentedTransport.__init__
# ======================================================================


class TestInstrumentedTransportInit:
    """Tests for InstrumentedTransport construction."""

    def test_session_id_is_16_char_hex(self):
        t = InstrumentedTransport("1.2.3.4", [])
        assert len(t.session_id) == 16
        assert all(c in "0123456789abcdef" for c in t.session_id)

    def test_agent_id_from_user_agent(self):
        headers = [(b"user-agent", b"TestAgent/1.0")]
        t = InstrumentedTransport("1.2.3.4", headers)
        assert t.agent_id == "TestAgent/1.0"

    def test_agent_id_falls_back_to_session_id(self):
        t = InstrumentedTransport("1.2.3.4", [])
        assert t.agent_id == t.session_id
