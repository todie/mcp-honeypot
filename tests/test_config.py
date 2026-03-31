"""Comprehensive unit tests for server.config module."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure the server package is importable without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

import config  # noqa: E402  (after path manipulation)
from config import Settings, _get, _get_int, _require  # noqa: E402


# ======================================================================
# Helpers — build env dicts for patch.dict
# ======================================================================

_MINIMAL_ENV: dict[str, str] = {}
"""Empty env — every setting should fall back to its default."""


def _env(**overrides: str) -> dict[str, str]:
    """Return a clean env dict with only the given overrides."""
    return {k: v for k, v in overrides.items()}


# ======================================================================
# TestDefaults
# ======================================================================

class TestDefaults:
    """All defaults with empty / minimal env produce valid Settings."""

    @patch.dict(os.environ, _MINIMAL_ENV, clear=True)
    def test_all_defaults(self):
        s = Settings.from_env()
        assert s.mcp_host == "0.0.0.0"
        assert s.mcp_port == 8000
        assert s.service_name == "mcp-honeypot"
        assert s.honeypot_phase == "research"
        assert s.log_level == "INFO"
        assert s.otlp_insecure is True
        assert s.webhook_secret is None

    @patch.dict(os.environ, _MINIMAL_ENV, clear=True)
    def test_service_name_default(self):
        s = Settings.from_env()
        assert s.service_name == "mcp-honeypot"

    @patch.dict(os.environ, _MINIMAL_ENV, clear=True)
    def test_otlp_endpoint_default(self):
        s = Settings.from_env()
        assert s.otlp_endpoint == "otel-collector:4317"


# ======================================================================
# TestPhaseValidation
# ======================================================================

class TestPhaseValidation:
    """HONEYPOT_PHASE must be a recognized value; 'public' needs a secret."""

    @patch.dict(os.environ, _env(HONEYPOT_PHASE="research"), clear=True)
    def test_research_phase_succeeds(self):
        s = Settings.from_env()
        assert s.honeypot_phase == "research"

    @patch.dict(os.environ, _env(HONEYPOT_PHASE="public"), clear=True)
    def test_public_phase_without_secret_raises(self):
        with pytest.raises(ValueError, match="HONEYPOT_WEBHOOK_SECRET"):
            Settings.from_env()

    @patch.dict(
        os.environ,
        _env(HONEYPOT_PHASE="public", HONEYPOT_WEBHOOK_SECRET="mysecret"),
        clear=True,
    )
    def test_public_phase_with_secret_succeeds(self):
        s = Settings.from_env()
        assert s.honeypot_phase == "public"
        assert s.webhook_secret == "mysecret"

    @patch.dict(os.environ, _env(HONEYPOT_PHASE="staging"), clear=True)
    def test_invalid_phase_raises(self):
        with pytest.raises(ValueError, match="HONEYPOT_PHASE"):
            Settings.from_env()


# ======================================================================
# TestWebhookSecret
# ======================================================================

class TestWebhookSecret:
    """webhook_secret is populated only in public phase."""

    @patch.dict(os.environ, _env(HONEYPOT_PHASE="research"), clear=True)
    def test_research_phase_secret_is_none(self):
        s = Settings.from_env()
        assert s.webhook_secret is None

    @patch.dict(
        os.environ,
        _env(HONEYPOT_PHASE="public", HONEYPOT_WEBHOOK_SECRET="s3cret"),
        clear=True,
    )
    def test_public_phase_secret_stored(self):
        s = Settings.from_env()
        assert s.webhook_secret == "s3cret"


# ======================================================================
# TestLogLevel
# ======================================================================

class TestLogLevel:
    """LOG_LEVEL is uppercased and validated."""

    @patch.dict(os.environ, _env(LOG_LEVEL="debug"), clear=True)
    def test_lowercase_uppercased(self):
        s = Settings.from_env()
        assert s.log_level == "DEBUG"

    @patch.dict(os.environ, _env(LOG_LEVEL="INFO"), clear=True)
    def test_info_succeeds(self):
        s = Settings.from_env()
        assert s.log_level == "INFO"

    @patch.dict(os.environ, _env(LOG_LEVEL="VERBOSE"), clear=True)
    def test_invalid_level_raises(self):
        with pytest.raises(ValueError, match="LOG_LEVEL"):
            Settings.from_env()


# ======================================================================
# TestPortValidation
# ======================================================================

class TestPortValidation:
    """MCP_PORT must be a valid integer in [1, 65535]."""

    @patch.dict(os.environ, _env(MCP_PORT="8080"), clear=True)
    def test_valid_port(self):
        s = Settings.from_env()
        assert s.mcp_port == 8080

    @patch.dict(os.environ, _env(MCP_PORT="abc"), clear=True)
    def test_non_integer_raises(self):
        with pytest.raises(ValueError, match="not a valid integer"):
            Settings.from_env()

    @patch.dict(os.environ, _env(MCP_PORT="0"), clear=True)
    def test_zero_port_raises(self):
        with pytest.raises(ValueError, match="out of range"):
            Settings.from_env()

    @patch.dict(os.environ, _env(MCP_PORT="65536"), clear=True)
    def test_above_max_raises(self):
        with pytest.raises(ValueError, match="out of range"):
            Settings.from_env()

    @patch.dict(os.environ, _env(MCP_PORT="65535"), clear=True)
    def test_boundary_max_succeeds(self):
        s = Settings.from_env()
        assert s.mcp_port == 65535

    @patch.dict(os.environ, _env(MCP_PORT=""), clear=True)
    def test_empty_falls_back_to_default(self):
        s = Settings.from_env()
        assert s.mcp_port == 8000


# ======================================================================
# TestOtlpInsecure
# ======================================================================

class TestOtlpInsecure:
    """OTLP_INSECURE is True unless explicitly set to 'false'."""

    @patch.dict(os.environ, _env(OTLP_INSECURE="true"), clear=True)
    def test_true_string(self):
        s = Settings.from_env()
        assert s.otlp_insecure is True

    @patch.dict(os.environ, _env(OTLP_INSECURE="false"), clear=True)
    def test_false_string(self):
        s = Settings.from_env()
        assert s.otlp_insecure is False

    @patch.dict(os.environ, _env(OTLP_INSECURE="FALSE"), clear=True)
    def test_false_case_insensitive(self):
        s = Settings.from_env()
        assert s.otlp_insecure is False

    @patch.dict(os.environ, _env(OTLP_INSECURE="0"), clear=True)
    def test_zero_is_truthy(self):
        """Only the literal word 'false' disables — '0' does NOT."""
        s = Settings.from_env()
        assert s.otlp_insecure is True

    @patch.dict(os.environ, _MINIMAL_ENV, clear=True)
    def test_not_set_defaults_true(self):
        s = Settings.from_env()
        assert s.otlp_insecure is True


# ======================================================================
# TestGetHelper
# ======================================================================

class TestGetHelper:
    """Tests for the ``_get`` env-var helper."""

    @patch.dict(os.environ, {"MY_KEY": "hello"}, clear=True)
    def test_key_present_returns_value(self):
        assert _get("MY_KEY", "default") == "hello"

    @patch.dict(os.environ, {"MY_KEY": "  spaced  "}, clear=True)
    def test_key_present_strips_whitespace(self):
        assert _get("MY_KEY", "default") == "spaced"

    @patch.dict(os.environ, {"MY_KEY": "   "}, clear=True)
    def test_empty_after_strip_returns_default(self):
        assert _get("MY_KEY", "fallback") == "fallback"


# ======================================================================
# TestGetIntHelper
# ======================================================================

class TestGetIntHelper:
    """Tests for the ``_get_int`` env-var helper."""

    @patch.dict(os.environ, {"NUM": "42"}, clear=True)
    def test_valid_int(self):
        assert _get_int("NUM", 0) == 42

    @patch.dict(os.environ, {"NUM": "xyz"}, clear=True)
    def test_non_int_raises(self):
        with pytest.raises(ValueError, match="not a valid integer"):
            _get_int("NUM", 0)

    @patch.dict(os.environ, {"NUM": ""}, clear=True)
    def test_empty_returns_default(self):
        assert _get_int("NUM", 99) == 99


# ======================================================================
# TestRequireHelper
# ======================================================================

class TestRequireHelper:
    """Tests for the ``_require`` env-var helper."""

    @patch.dict(os.environ, {"REQ": "value"}, clear=True)
    def test_present_returns_value(self):
        assert _require("REQ") == "value"

    @patch.dict(os.environ, {}, clear=True)
    def test_missing_raises(self):
        with pytest.raises(ValueError, match="REQ"):
            _require("REQ")

    @patch.dict(os.environ, {"REQ": "   "}, clear=True)
    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="REQ"):
            _require("REQ")
