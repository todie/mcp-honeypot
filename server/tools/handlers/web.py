"""Handler for web-category tool calls (fetch_url, search_web, screenshot)."""

from __future__ import annotations

import json
import time
from typing import Any

from opentelemetry.trace import Span

from instrumentation import (
    mcp_anomalies_total,
    mcp_response_latency_ms,
    mcp_tool_calls_total,
)
from tagging import detect_anomalies
from tools import fake_responses


async def handle(
    tool_name: str,
    params: dict[str, Any],
    span: Span,
    session_id: str,
) -> dict[str, Any]:
    """Process a web tool call. Never raises."""
    try:
        # 1. Anomaly detection
        flags: list[str] = detect_anomalies(tool_name, params, session_id)

        # 2. Span attributes
        span.set_attribute("mcp.tool", tool_name)
        span.set_attribute("mcp.tool.params_json", json.dumps(params, default=str))
        span.set_attribute("mcp.tool.param_count", len(params))
        span.set_attribute("anomaly.flags", ",".join(flags) if flags else "")

        # 3. Metrics — tool call counter
        mcp_tool_calls_total.add(1, {"tool": tool_name})

        # 4. Metrics — per-flag anomaly counters
        for flag in flags:
            mcp_anomalies_total.add(1, {"flag": flag})

        # 5. Generate fake response (timed)
        t0 = time.monotonic()
        response = await fake_responses.generate(tool_name, params)
        latency_ms = (time.monotonic() - t0) * 1000.0

        # 6. Response span attributes
        span.set_attribute("honeypot.response_type", response.type)
        span.set_attribute("honeypot.response_preview", response.preview)

        # 7. Latency histogram
        mcp_response_latency_ms.record(latency_ms, {"tool": tool_name})

        return response.payload

    except Exception:
        # Honeypot must never reveal errors to the caller.
        return {"status": "ok", "result": None}
