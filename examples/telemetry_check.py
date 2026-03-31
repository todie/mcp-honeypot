#!/usr/bin/env python3
"""Query Jaeger + Prometheus to verify the telemetry pipeline works.

Run this AFTER sending some traffic (e.g. after running flag_triggers.py).
It checks that traces landed in Jaeger and metrics are flowing to Prometheus.

Usage:
    python examples/flag_triggers.py   # first, generate traffic
    python examples/telemetry_check.py  # then, verify telemetry

Requires: docker compose up, pip install httpx
"""

import asyncio
import json

import httpx

JAEGER_URL = "http://localhost:16686"
PROMETHEUS_URL = "http://localhost:9090"


async def check_jaeger(client: httpx.AsyncClient) -> None:
    """Query Jaeger for honeypot traces."""
    print("=== Jaeger Traces ===\n")

    # Check which services Jaeger knows about
    resp = await client.get(f"{JAEGER_URL}/api/services")
    services = resp.json().get("data", [])
    print(f"Services: {services}")
    assert "mcp-honeypot" in services, "mcp-honeypot service not found in Jaeger!"

    # Fetch recent traces
    resp = await client.get(f"{JAEGER_URL}/api/traces", params={
        "service": "mcp-honeypot",
        "limit": 20,
        "lookback": "1h",
    })
    traces = resp.json().get("data", [])
    print(f"Traces (last 1h): {len(traces)}")

    # Extract span details
    tools_seen: set[str] = set()
    flags_seen: set[str] = set()
    agents_seen: set[str] = set()

    for trace in traces:
        for span in trace.get("spans", []):
            tags = {t["key"]: t["value"] for t in span.get("tags", [])}

            tool = tags.get("mcp.tool", "")
            if tool:
                tools_seen.add(tool)

            flags = tags.get("anomaly.flags", "")
            if flags:
                for f in flags.split(","):
                    if f.strip():
                        flags_seen.add(f.strip())

            agent = tags.get("agent.id", "")
            if agent:
                agents_seen.add(agent)

    print(f"Tools seen:  {sorted(tools_seen) or '(none — run flag_triggers.py first)'}")
    print(f"Flags seen:  {sorted(flags_seen) or '(none)'}")
    print(f"Agents seen: {sorted(agents_seen) or '(none)'}")
    print()


async def check_prometheus(client: httpx.AsyncClient) -> None:
    """Query Prometheus for honeypot metrics."""
    print("=== Prometheus Metrics ===\n")

    queries = {
        "Tool calls": "sum(mcp_honeypot_mcp_tool_calls_total)",
        "Anomalies": "sum(mcp_honeypot_mcp_anomalies_total)",
        "Active sessions": "mcp_honeypot_mcp_sessions_active",
        "Tool calls by tool": "mcp_honeypot_mcp_tool_calls_total",
        "Anomalies by flag": "mcp_honeypot_mcp_anomalies_total",
    }

    for label, query in queries.items():
        resp = await client.get(f"{PROMETHEUS_URL}/api/v1/query", params={"query": query})
        data = resp.json()

        if data["status"] != "success":
            print(f"{label}: ERROR — {data}")
            continue

        results = data["data"]["result"]
        if not results:
            print(f"{label}: (no data)")
            continue

        if "by" in label.lower():
            # Multi-series: show each label
            for r in results:
                metric = r["metric"]
                value = r["value"][1]
                key = metric.get("tool") or metric.get("flag") or str(metric)
                print(f"  {label} [{key}]: {value}")
        else:
            value = results[0]["value"][1]
            print(f"{label}: {value}")

    print()


async def check_grafana() -> None:
    """Verify Grafana dashboards are loaded."""
    print("=== Grafana Dashboards ===\n")

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            "http://localhost:3000/api/search",
            auth=("admin", "honeypot"),
        )
        dashboards = resp.json()
        print(f"Dashboards loaded: {len(dashboards)}")
        for d in dashboards:
            print(f"  - {d['title']} ({d['url']})")
    print()


async def main() -> None:
    print("MCP Honeypot — Telemetry Pipeline Check\n")

    async with httpx.AsyncClient(timeout=10) as client:
        await check_jaeger(client)
        await check_prometheus(client)

    await check_grafana()

    print("Pipeline check complete.")


if __name__ == "__main__":
    asyncio.run(main())
