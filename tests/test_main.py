"""Unit tests for server.main module (Starlette app, healthz, list_tools)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))


# ======================================================================
# healthz endpoint
# ======================================================================


class TestHealthz:
    """Tests for the /healthz liveness probe."""

    async def test_returns_200_ok(self):
        from httpx import ASGITransport, AsyncClient
        from main import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/healthz")
            assert resp.status_code == 200
            data = resp.json()
            assert data == {"status": "ok"}

    async def test_has_security_headers(self):
        from httpx import ASGITransport, AsyncClient
        from main import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/healthz")
            assert resp.headers.get("x-content-type-options") == "nosniff"
            assert resp.headers.get("x-frame-options") == "DENY"
            assert resp.headers.get("referrer-policy") == "no-referrer"
            assert resp.headers.get("server") == "mcp-honeypot"


# ======================================================================
# App structure
# ======================================================================


class TestAppStructure:
    """Tests that the Starlette app is configured correctly."""

    def test_is_starlette_instance(self):
        from main import app
        from starlette.applications import Starlette

        assert isinstance(app, Starlette)

    def test_has_healthz_route(self):
        from main import app

        paths = [route.path for route in app.routes]
        assert "/healthz" in paths

    def test_has_sse_route(self):
        from main import app

        paths = [route.path for route in app.routes]
        assert "/sse" in paths

    def test_has_messages_route(self):
        from main import app

        paths = [route.path for route in app.routes]
        assert "/messages" in paths


# ======================================================================
# list_tools
# ======================================================================


class TestListTools:
    """Tests for the MCP list_tools handler."""

    async def test_returns_13_tools(self):
        from main import list_tools

        tools = await list_tools()
        assert len(tools) == 13

    async def test_each_tool_has_required_fields(self):
        from main import list_tools

        tools = await list_tools()
        for tool in tools:
            assert hasattr(tool, "name") and tool.name
            assert hasattr(tool, "description") and tool.description
            assert hasattr(tool, "inputSchema")

    async def test_known_tool_names_present(self):
        from main import list_tools

        tools = await list_tools()
        names = {t.name for t in tools}
        expected = {
            "read_file",
            "write_file",
            "fetch_url",
            "run_command",
            "get_env_var",
            "read_secret",
        }
        assert expected.issubset(names)
