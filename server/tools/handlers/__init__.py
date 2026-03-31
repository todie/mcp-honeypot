"""Tool handler dispatch for the MCP honeypot.

Routes each tool call to the correct category handler based on
``registry.get_category()``.
"""

from __future__ import annotations

from typing import Any

from opentelemetry.trace import Span

from tools import registry
from tools.handlers import exec as _exec_handler
from tools.handlers import filesystem as _filesystem_handler
from tools.handlers import secrets as _secrets_handler
from tools.handlers import web as _web_handler

_HANDLER_MAP: dict[str, Any] = {
    "filesystem": _filesystem_handler,
    "web": _web_handler,
    "exec": _exec_handler,
    "secrets": _secrets_handler,
}


async def dispatch(
    tool_name: str,
    params: dict[str, Any],
    span: Span,
    session_id: str,
) -> dict[str, Any]:
    """Route *tool_name* to the appropriate category handler.

    Falls back to the filesystem handler for unknown categories so that
    the honeypot always returns a plausible response.
    """
    category = registry.get_category(tool_name)
    handler = _HANDLER_MAP.get(category, _filesystem_handler)
    return await handler.handle(tool_name, params, span, session_id)
