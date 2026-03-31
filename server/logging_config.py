"""Structured JSON logging configuration for the MCP Honeypot.

Call ``setup_logging()`` once at process startup — before any logger is
created — to wire structlog and stdlib logging into a single JSON pipeline.

Every log record automatically carries ``timestamp``, ``level``, ``logger``,
``service``, and (when set) ``session_id``.
"""

from __future__ import annotations

import logging
import sys
from contextvars import ContextVar
from typing import Any

import structlog

# ---------------------------------------------------------------------------
# Context variable — handlers bind this per-request / per-session
# ---------------------------------------------------------------------------
session_id_var: ContextVar[str | None] = ContextVar("session_id", default=None)

# Guard so the function is safe to call more than once.
_configured: bool = False


def _add_session_id(
    logger: Any,
    method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Inject ``session_id`` from the current context, if present."""
    sid = session_id_var.get()
    if sid is not None:
        event_dict["session_id"] = sid
    return event_dict


def _add_service_name(
    logger: Any,
    method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Inject the ``service`` field from settings."""
    # Import lazily to avoid circular imports (config.py is evaluated at import
    # time, and this module may be imported before config is fully ready in
    # some test harnesses).
    from config import settings  # noqa: WPS433

    event_dict["service"] = settings.service_name
    return event_dict


# ---------------------------------------------------------------------------
# Shared processor chain (used by both structlog *and* stdlib foreign loggers)
# ---------------------------------------------------------------------------
def _shared_processors() -> list[structlog.types.Processor]:
    return [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        _add_service_name,
        _add_session_id,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def setup_logging() -> None:
    """Configure structlog + stdlib logging for structured JSON output.

    Idempotent — subsequent calls are no-ops.
    """
    global _configured  # noqa: WPS420
    if _configured:
        return
    _configured = True

    from config import settings  # noqa: WPS433

    log_level = getattr(logging, settings.log_level, logging.INFO)

    shared = _shared_processors()

    # --- structlog configuration -------------------------------------------
    structlog.configure(
        processors=[
            *shared,
            # Prep for stdlib's ProcessorFormatter (structlog -> stdlib bridge)
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # --- stdlib handler that renders JSON ----------------------------------
    formatter = structlog.stdlib.ProcessorFormatter(
        # ``foreign_pre_chain`` handles log records that originate from plain
        # stdlib loggers (uvicorn, third-party libs, etc.) so they go through
        # the same enrichment pipeline.
        foreign_pre_chain=shared,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    # Root logger — catches everything
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(log_level)

    # --- Tame uvicorn ------------------------------------------------------
    # Uvicorn installs its own handlers on first import; remove them so all
    # output funnels through the JSON formatter above.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uv_logger = logging.getLogger(name)
        uv_logger.handlers.clear()
        uv_logger.propagate = True


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a structlog logger bound to *name*.

    Must be called **after** ``setup_logging()``; if called before, structlog
    falls back to its defaults (still functional, just not JSON).
    """
    return structlog.get_logger(name)
