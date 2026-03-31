"""Rate limiting and security headers middleware for the MCP Honeypot.

Provides:
- slowapi-based rate limiting (60 req/min global, 10/min on ``/sse``)
- Security headers on every response
- CORS (default ``*``, overridable via ``CORS_ORIGINS``)

Wire into a Starlette app by calling ``add_middleware(app)``.
"""

from __future__ import annotations

import os
from typing import Any

from logging_config import get_logger
from opentelemetry import trace
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Rate-limiter key function
# ---------------------------------------------------------------------------


def _client_ip(request: Request) -> str:
    """Extract the client IP from a Starlette request.

    Falls back to ``get_remote_address`` (peer IP).  When running behind a
    reverse proxy, ``X-Forwarded-For`` is preferred.
    """
    forwarded: str | None = request.headers.get("x-forwarded-for")
    if forwarded:
        # First entry is the original client.
        return forwarded.split(",")[0].strip()
    return get_remote_address(request)


# ---------------------------------------------------------------------------
# Limiter singleton
# ---------------------------------------------------------------------------

limiter = Limiter(
    key_func=_client_ip,
    default_limits=["60/minute"],
    # Exempt /healthz from all rate limits.
    application_limits=[],
)


# ---------------------------------------------------------------------------
# Rate-limit decorators for specific routes
# ---------------------------------------------------------------------------

# These are importable so that route functions can be decorated directly.
sse_limit = limiter.limit("10/minute")


# ---------------------------------------------------------------------------
# Custom 429 handler — logs, sets span attribute, returns Retry-After
# ---------------------------------------------------------------------------


def _rate_limit_exceeded(request: Request, exc: RateLimitExceeded) -> Response:
    """Return a 429 response with ``Retry-After`` and record the event."""
    client = _client_ip(request)
    path = request.url.path

    log.warning(
        "rate_limit_exceeded",
        client_ip=client,
        path=path,
        limit=str(exc.detail),
    )

    # Tag the active span so downstream analysis can filter on rate-limited
    # requests.
    span = trace.get_current_span()
    if span.is_recording():
        span.set_attribute("honeypot.rate_limited", True)

    retry_after = getattr(exc, "retry_after", 60)

    return Response(
        content=f"Rate limit exceeded: {exc.detail}",
        status_code=429,
        headers={
            "Retry-After": str(retry_after),
            "Content-Type": "text/plain",
        },
    )


# ---------------------------------------------------------------------------
# Security-headers middleware
# ---------------------------------------------------------------------------


class SecurityHeadersMiddleware:
    """ASGI middleware that injects security headers on every response."""

    HEADERS: dict[str, str] = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Server": "mcp-honeypot",
    }

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    # Paths that use raw ASGI streaming (SSE) — header wrapping breaks them.
    _SKIP_PATHS: set[str] = {"/sse", "/messages"}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        # Skip header injection for SSE/streaming endpoints — the MCP SDK
        # manages its own ASGI response lifecycle on these paths.
        path = scope.get("path", "")
        if any(path.startswith(p) for p in self._SKIP_PATHS):
            await self.app(scope, receive, send)
            return

        async def _send_with_headers(message: Any) -> None:
            if message["type"] == "http.response.start":
                headers: list[tuple[bytes, bytes]] = list(message.get("headers", []))

                # Remove any existing Server header.
                headers = [(k, v) for k, v in headers if k.lower() != b"server"]

                # Append security headers.
                for name, value in self.HEADERS.items():
                    headers.append((name.encode(), value.encode()))

                message["headers"] = headers

            await send(message)

        await self.app(scope, receive, _send_with_headers)


# ---------------------------------------------------------------------------
# Public integration point
# ---------------------------------------------------------------------------


def add_middleware(app: Starlette) -> None:
    """Wire rate limiting, security headers, and CORS into *app*.

    Must be called **before** the app starts serving (i.e. at module-load
    time or in a startup factory).
    """
    # -- slowapi ---------------------------------------------------------
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded)  # type: ignore[arg-type]

    # -- Security headers ------------------------------------------------
    app.add_middleware(SecurityHeadersMiddleware)  # type: ignore[arg-type]

    # -- CORS ------------------------------------------------------------
    raw_origins = os.environ.get("CORS_ORIGINS", "*").strip()
    if raw_origins == "*":
        allow_origins: list[str] = ["*"]
    else:
        allow_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    log.info(
        "middleware_configured",
        rate_limit_global="60/minute",
        rate_limit_sse="10/minute",
        cors_origins=allow_origins,
    )
