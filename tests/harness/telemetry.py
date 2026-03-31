"""Telemetry harness for validating the observability pipeline.

Queries Jaeger traces and Prometheus metrics to verify that the MCP
honeypot is correctly instrumenting tool calls and anomaly flags.

Usage::

    harness = TelemetryHarness()
    spans = await harness.find_spans_with_tag("anomaly.flags", "credential_probe")
    count = await harness.get_tool_call_count("read_file")
    await harness.assert_trace_has_flags(["credential_probe", "path_traversal"])
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx


class TelemetryHarness:
    """Query Jaeger traces and Prometheus metrics for test validation."""

    def __init__(
        self,
        jaeger_url: str = "http://localhost:16686",
        prometheus_url: str = "http://localhost:9090",
        timeout: float = 10.0,
    ) -> None:
        self._jaeger_url = jaeger_url.rstrip("/")
        self._prometheus_url = prometheus_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=timeout)

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    # ------------------------------------------------------------------
    # Jaeger: trace queries
    # ------------------------------------------------------------------

    async def wait_for_traces(
        self,
        service: str = "mcp-honeypot",
        timeout: float = 30,
        min_spans: int = 1,
    ) -> list[dict[str, Any]]:
        """Poll Jaeger until at least *min_spans* spans appear or timeout.

        Returns the list of traces (each containing spans).
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            traces = await self._query_jaeger_traces(service)
            total_spans = sum(len(t.get("spans", [])) for t in traces)
            if total_spans >= min_spans:
                return traces
            await asyncio.sleep(2)
        return []

    async def find_spans_with_tag(
        self,
        tag_key: str,
        tag_value: str,
        service: str = "mcp-honeypot",
        timeout: float = 30,
    ) -> list[dict[str, Any]]:
        """Find spans matching a specific tag key/value pair.

        Polls Jaeger until matching spans are found or timeout.
        Returns a list of matching span dicts.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            traces = await self._query_jaeger_traces(service)
            matches = []
            for trace in traces:
                for span in trace.get("spans", []):
                    for tag in span.get("tags", []):
                        if tag.get("key") == tag_key and tag_value in str(tag.get("value", "")):
                            matches.append(span)
                            break
            if matches:
                return matches
            await asyncio.sleep(2)
        return []

    async def find_tool_call_span(
        self,
        tool_name: str,
        service: str = "mcp-honeypot",
        timeout: float = 30,
    ) -> dict[str, Any] | None:
        """Find a span for a specific tool call.

        Looks for spans with operation name ``tool.<tool_name>`` or
        a tag ``mcp.tool`` matching *tool_name*.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            traces = await self._query_jaeger_traces(service)
            for trace in traces:
                for span in trace.get("spans", []):
                    # Check operation name
                    if span.get("operationName") == f"tool.{tool_name}":
                        return span
                    # Check mcp.tool tag
                    for tag in span.get("tags", []):
                        if tag.get("key") == "mcp.tool" and tag.get("value") == tool_name:
                            return span
            await asyncio.sleep(2)
        return None

    async def get_all_anomaly_flags(
        self,
        service: str = "mcp-honeypot",
        timeout: float = 30,
    ) -> set[str]:
        """Collect all unique anomaly flags from recent traces."""
        traces = await self.wait_for_traces(service=service, timeout=timeout)
        flags: set[str] = set()
        for trace in traces:
            for span in trace.get("spans", []):
                for tag in span.get("tags", []):
                    if tag.get("key") == "anomaly.flags":
                        value = str(tag.get("value", ""))
                        for flag in value.split(","):
                            flag = flag.strip()
                            if flag:
                                flags.add(flag)
        return flags

    async def assert_trace_has_flags(
        self,
        expected_flags: list[str],
        service: str = "mcp-honeypot",
        timeout: float = 30,
    ) -> None:
        """Assert that recent traces contain the expected anomaly flags.

        Raises AssertionError if any expected flag is not found within
        the timeout period.
        """
        found_flags: set[str] = set()
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            traces = await self._query_jaeger_traces(service)
            for trace in traces:
                for span in trace.get("spans", []):
                    for tag in span.get("tags", []):
                        if tag.get("key") == "anomaly.flags":
                            value = str(tag.get("value", ""))
                            for f in value.split(","):
                                f = f.strip()
                                if f:
                                    found_flags.add(f)

            # Check if all expected flags have been found
            missing = set(expected_flags) - found_flags
            if not missing:
                return
            await asyncio.sleep(2)

        missing = set(expected_flags) - found_flags
        raise AssertionError(
            f"Missing anomaly flags in Jaeger traces after {timeout}s: "
            f"{sorted(missing)}. Found: {sorted(found_flags)}"
        )

    # ------------------------------------------------------------------
    # Prometheus: metric queries
    # ------------------------------------------------------------------

    async def get_metric(self, query: str) -> float | None:
        """Run a Prometheus instant query and return the scalar value.

        Returns None if the query produces no results or fails.
        """
        try:
            resp = await self._client.get(
                f"{self._prometheus_url}/api/v1/query",
                params={"query": query},
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            results = data.get("data", {}).get("result", [])
            if not results:
                return None
            # Return the value from the first result
            value = results[0].get("value", [None, None])
            if len(value) >= 2 and value[1] is not None:
                return float(value[1])
        except Exception:
            return None
        return None

    async def get_tool_call_count(self, tool_name: str | None = None) -> int:
        """Get total tool call count from Prometheus.

        If *tool_name* is provided, filters to that specific tool.
        """
        if tool_name:
            query = f'sum(mcp_tool_calls_total{{tool="{tool_name}"}})'
        else:
            query = "sum(mcp_tool_calls_total)"
        value = await self.get_metric(query)
        return int(value) if value is not None else 0

    async def get_anomaly_count(self, flag: str | None = None) -> int:
        """Get total anomaly count from Prometheus.

        If *flag* is provided, filters to that specific anomaly flag.
        """
        if flag:
            query = f'sum(mcp_anomaly_flags_total{{flag="{flag}"}})'
        else:
            query = "sum(mcp_anomaly_flags_total)"
        value = await self.get_metric(query)
        return int(value) if value is not None else 0

    async def get_tool_latency_p50(self, tool_name: str | None = None) -> float | None:
        """Get p50 tool call latency in seconds."""
        if tool_name:
            query = f'histogram_quantile(0.5, rate(mcp_tool_duration_seconds_bucket{{tool="{tool_name}"}}[5m]))'
        else:
            query = "histogram_quantile(0.5, rate(mcp_tool_duration_seconds_bucket[5m]))"
        return await self.get_metric(query)

    def print_summary(self) -> None:
        """Print a human-readable summary of current metrics and recent traces.

        This is a synchronous convenience method that creates a temporary
        event loop to gather data.  Use from non-async contexts (scripts, etc.).
        """
        import asyncio as _asyncio

        async def _gather() -> dict[str, Any]:
            summary: dict[str, Any] = {}
            # Tool call counts
            summary["total_tool_calls"] = await self.get_tool_call_count()
            summary["total_anomalies"] = await self.get_anomaly_count()

            # Recent traces
            traces = await self._query_jaeger_traces("mcp-honeypot")
            span_count = sum(len(t.get("spans", [])) for t in traces)
            summary["trace_count"] = len(traces)
            summary["span_count"] = span_count

            # Collect flags
            flags: set[str] = set()
            tools_seen: set[str] = set()
            for trace in traces:
                for span in trace.get("spans", []):
                    for tag in span.get("tags", []):
                        if tag.get("key") == "anomaly.flags":
                            for f in str(tag["value"]).split(","):
                                f = f.strip()
                                if f:
                                    flags.add(f)
                        if tag.get("key") == "mcp.tool":
                            tools_seen.add(str(tag["value"]))
            summary["flags"] = sorted(flags)
            summary["tools_seen"] = sorted(tools_seen)
            return summary

        try:
            loop = _asyncio.get_running_loop()
            # If we're in an async context, we can't use run()
            print("[TelemetryHarness] Cannot print_summary from async context; use await methods directly.")
            return
        except RuntimeError:
            pass

        data = _asyncio.run(_gather())
        print()
        print("=" * 60)
        print("  Telemetry Summary")
        print("=" * 60)
        print(f"  Traces:       {data['trace_count']}")
        print(f"  Spans:        {data['span_count']}")
        print(f"  Tool calls:   {data['total_tool_calls']}")
        print(f"  Anomalies:    {data['total_anomalies']}")
        print(f"  Flags seen:   {', '.join(data['flags']) or '(none)'}")
        print(f"  Tools seen:   {', '.join(data['tools_seen']) or '(none)'}")
        print("=" * 60)
        print()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _query_jaeger_traces(
        self,
        service: str,
        limit: int = 50,
        lookback: str = "5m",
    ) -> list[dict[str, Any]]:
        """Query Jaeger API for recent traces."""
        try:
            resp = await self._client.get(
                f"{self._jaeger_url}/api/traces",
                params={
                    "service": service,
                    "limit": limit,
                    "lookback": lookback,
                },
            )
            if resp.status_code == 200:
                return resp.json().get("data", [])
        except Exception:
            pass
        return []
