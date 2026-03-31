"""MCP Honeypot server — stub for T01 scaffolding.

Full implementation in T07.
"""
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


async def healthz(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


app = Starlette(routes=[Route("/healthz", healthz)])
