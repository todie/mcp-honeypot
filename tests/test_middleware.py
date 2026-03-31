"""Unit tests for server.middleware module."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

from middleware import SecurityHeadersMiddleware, _client_ip

# ======================================================================
# _client_ip
# ======================================================================


class TestClientIp:
    """Tests for the _client_ip key function."""

    def test_returns_peer_ip_from_client(self):
        request = MagicMock()
        request.headers = {}
        request.client.host = "192.168.1.10"
        with patch("middleware.get_remote_address", return_value="192.168.1.10"):
            assert _client_ip(request) == "192.168.1.10"

    def test_extracts_first_ip_from_x_forwarded_for(self):
        request = MagicMock()
        request.headers = {"x-forwarded-for": "10.0.0.1, 10.0.0.2, 10.0.0.3"}
        assert _client_ip(request) == "10.0.0.1"

    def test_falls_back_to_get_remote_address(self):
        request = MagicMock()
        request.headers = {}
        with patch("middleware.get_remote_address", return_value="127.0.0.1") as mock_gra:
            result = _client_ip(request)
            mock_gra.assert_called_once_with(request)
            assert result == "127.0.0.1"

    def test_strips_whitespace_from_forwarded(self):
        request = MagicMock()
        request.headers = {"x-forwarded-for": "  10.0.0.5 , 10.0.0.6"}
        assert _client_ip(request) == "10.0.0.5"


# ======================================================================
# SecurityHeadersMiddleware
# ======================================================================


class TestSecurityHeadersMiddleware:
    """Tests for the SecurityHeadersMiddleware ASGI middleware."""

    @pytest.fixture()
    def recorded_messages(self):
        """Collect messages passed to the ASGI send callable."""
        messages: list[dict] = []
        return messages

    def _make_app(self, status: int = 200, body: bytes = b"OK"):
        """Return a minimal ASGI app that sends a complete HTTP response."""

        async def app(scope, receive, send):
            await send(
                {
                    "type": "http.response.start",
                    "status": status,
                    "headers": [
                        (b"content-type", b"text/plain"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})

        return app

    async def test_adds_security_headers(self, recorded_messages):
        inner = self._make_app()
        mw = SecurityHeadersMiddleware(inner)

        messages = recorded_messages

        async def mock_send(msg):
            messages.append(msg)

        scope = {"type": "http", "path": "/healthz"}
        await mw(scope, None, mock_send)

        start_msg = messages[0]
        header_dict = {k.decode(): v.decode() for k, v in start_msg["headers"]}
        assert header_dict["X-Content-Type-Options"] == "nosniff"
        assert header_dict["X-Frame-Options"] == "DENY"
        assert header_dict["Referrer-Policy"] == "no-referrer"
        assert header_dict["Server"] == "mcp-honeypot"

    async def test_skips_sse_path(self, recorded_messages):
        inner = self._make_app()
        mw = SecurityHeadersMiddleware(inner)

        messages = recorded_messages

        async def mock_send(msg):
            messages.append(msg)

        scope = {"type": "http", "path": "/sse"}
        await mw(scope, None, mock_send)

        start_msg = messages[0]
        header_dict = {k.decode(): v.decode() for k, v in start_msg["headers"]}
        # Should NOT have security headers injected
        assert "X-Content-Type-Options" not in header_dict

    async def test_skips_messages_path(self, recorded_messages):
        inner = self._make_app()
        mw = SecurityHeadersMiddleware(inner)

        messages = recorded_messages

        async def mock_send(msg):
            messages.append(msg)

        scope = {"type": "http", "path": "/messages"}
        await mw(scope, None, mock_send)

        start_msg = messages[0]
        header_dict = {k.decode(): v.decode() for k, v in start_msg["headers"]}
        assert "X-Content-Type-Options" not in header_dict

    async def test_passes_through_non_http(self, recorded_messages):
        """Non-http scope types pass through without modification."""
        called = []

        async def fake_app(scope, receive, send):
            called.append(scope["type"])

        mw_non_http = SecurityHeadersMiddleware(fake_app)
        scope = {"type": "lifespan"}
        await mw_non_http(scope, None, None)
        assert called == ["lifespan"]

    async def test_replaces_existing_server_header(self, recorded_messages):
        """Existing Server header is replaced, not duplicated."""

        async def app_with_server(scope, receive, send):
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [
                        (b"server", b"uvicorn"),
                        (b"content-type", b"text/plain"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": b"OK"})

        mw = SecurityHeadersMiddleware(app_with_server)
        messages = recorded_messages

        async def mock_send(msg):
            messages.append(msg)

        scope = {"type": "http", "path": "/healthz"}
        await mw(scope, None, mock_send)

        start_msg = messages[0]
        server_values = [v.decode() for k, v in start_msg["headers"] if k.lower() == b"server"]
        assert server_values == ["mcp-honeypot"]


# ======================================================================
# Integration via httpx.AsyncClient + ASGI transport
# ======================================================================


class TestMiddlewareIntegration:
    """Integration tests using the actual Starlette app with httpx."""

    async def test_healthz_has_security_headers(self):
        from httpx import ASGITransport, AsyncClient
        from main import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/healthz")
            assert resp.status_code == 200
            assert resp.headers.get("x-content-type-options") == "nosniff"
            assert resp.headers.get("x-frame-options") == "DENY"
            assert resp.headers.get("server") == "mcp-honeypot"
