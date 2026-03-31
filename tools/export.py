"""Export honeypot observation data from Jaeger traces and Prometheus metrics.

Usage:
    python tools/export.py --format json --since 1h --output report.json
    python tools/export.py --format csv --since 24h --output metrics.csv
    python tools/export.py --traces --since 1h --output traces.json
    python tools/export.py --metrics --since 1h --output metrics.csv
    python tools/export.py --summary  # print summary to stdout
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
import time
from collections import Counter
from datetime import UTC, datetime

import httpx

# ── Defaults ─────────────────────────────────────────────────────────────────

DEFAULT_JAEGER_URL = "http://localhost:16686"
DEFAULT_PROMETHEUS_URL = "http://localhost:9090"
SERVICE_NAME = "mcp-honeypot"

# Prometheus metrics to export (common honeypot metrics)
EXPORT_METRICS = [
    "mcp_requests_total",
    "mcp_request_duration_seconds",
    "mcp_tool_calls_total",
    "mcp_anomaly_flags_total",
    "mcp_active_sessions",
]


# ── Duration parsing ─────────────────────────────────────────────────────────


def parse_duration_seconds(duration: str) -> int:
    """Parse a human-friendly duration string into seconds.

    Supports: 1h, 6h, 24h, 7d, 30m, etc.
    """
    match = re.fullmatch(r"(\d+)([smhd])", duration.strip().lower())
    if not match:
        raise ValueError(f"Invalid duration: {duration!r}. Use format like 1h, 6h, 24h, 7d.")
    value, unit = int(match.group(1)), match.group(2)
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return value * multipliers[unit]


def duration_to_jaeger_lookback(duration: str) -> str:
    """Convert duration string to Jaeger lookback format (e.g., '1h' stays '1h')."""
    # Jaeger accepts the same format we use
    return duration.strip().lower()


# ── Jaeger trace export ─────────────────────────────────────────────────────


def fetch_traces(jaeger_url: str, since: str, limit: int = 100) -> list[dict]:
    """Fetch traces from Jaeger HTTP API."""
    lookback = duration_to_jaeger_lookback(since)
    url = f"{jaeger_url}/api/traces"
    params = {
        "service": SERVICE_NAME,
        "limit": limit,
        "lookback": lookback,
    }
    resp = httpx.get(url, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return data.get("data", [])


def extract_trace_records(traces: list[dict]) -> list[dict]:
    """Flatten Jaeger traces into per-span records for analysis."""
    records = []
    for trace in traces:
        trace_id = trace.get("traceID", "")
        processes = trace.get("processes", {})
        for span in trace.get("spans", []):
            tags = {t["key"]: t["value"] for t in span.get("tags", [])}
            record = {
                "trace_id": trace_id,
                "span_id": span.get("spanID", ""),
                "operation": span.get("operationName", ""),
                "service": processes.get(span.get("processID", ""), {}).get("serviceName", ""),
                "start_time": datetime.fromtimestamp(
                    span["startTime"] / 1_000_000, tz=UTC
                ).isoformat(),
                "duration_us": span.get("duration", 0),
                "tool_name": tags.get("mcp.tool", tags.get("tool.name", "")),
                "agent_fingerprint": tags.get(
                    "agent.fingerprint", tags.get("mcp.agent_fingerprint", "")
                ),
                "anomaly_flags": tags.get("anomaly.flags", tags.get("mcp.anomaly_flags", "")),
                "status_code": tags.get("otel.status_code", ""),
            }
            records.append(record)
    return records


# ── Prometheus metrics export ────────────────────────────────────────────────


def fetch_metrics(prometheus_url: str, since: str, step: str = "15s") -> list[dict]:
    """Fetch time-series data from Prometheus for all configured metrics."""
    duration_secs = parse_duration_seconds(since)
    end_ts = time.time()
    start_ts = end_ts - duration_secs

    all_series = []
    for metric in EXPORT_METRICS:
        url = f"{prometheus_url}/api/v1/query_range"
        params = {
            "query": metric,
            "start": start_ts,
            "end": end_ts,
            "step": step,
        }
        try:
            resp = httpx.get(url, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "success":
                for result in data.get("data", {}).get("result", []):
                    labels = result.get("metric", {})
                    for ts, val in result.get("values", []):
                        all_series.append(
                            {
                                "metric": metric,
                                "labels": json.dumps(labels, sort_keys=True),
                                "timestamp": datetime.fromtimestamp(float(ts), tz=UTC).isoformat(),
                                "value": val,
                            }
                        )
        except httpx.HTTPError:
            # Metric may not exist yet; skip gracefully
            continue

    return all_series


# ── Summary ──────────────────────────────────────────────────────────────────


def print_summary(traces: list[dict], metrics: list[dict]) -> None:
    """Print a human-readable summary to stdout."""
    records = extract_trace_records(traces)

    print("=" * 60)
    print("  MCP Honeypot — Data Export Summary")
    print("=" * 60)
    print()

    # Time range
    if records:
        times = [r["start_time"] for r in records if r["start_time"]]
        if times:
            print(f"Time range: {min(times)}  to  {max(times)}")
    print()

    # Trace stats
    trace_ids = {r["trace_id"] for r in records}
    agents = {r["agent_fingerprint"] for r in records if r["agent_fingerprint"]}
    tools = {r["tool_name"] for r in records if r["tool_name"]}
    print(f"Total traces:    {len(trace_ids)}")
    print(f"Total spans:     {len(records)}")
    print(f"Unique agents:   {len(agents)}")
    print(f"Unique tools:    {len(tools)}")
    print()

    # Anomaly flag counts
    flag_counter: Counter[str] = Counter()
    for r in records:
        flags_raw = r.get("anomaly_flags", "")
        if flags_raw:
            for flag in str(flags_raw).split(","):
                flag = flag.strip()
                if flag:
                    flag_counter[flag] += 1

    if flag_counter:
        print("Anomaly flags:")
        for flag, count in flag_counter.most_common():
            print(f"  {flag:30s}  {count}")
        print()

    # Top 5 tools by call count
    tool_counter: Counter[str] = Counter()
    for r in records:
        if r["tool_name"]:
            tool_counter[r["tool_name"]] += 1

    if tool_counter:
        print("Top 5 tools by call count:")
        for tool, count in tool_counter.most_common(5):
            print(f"  {tool:30s}  {count}")
        print()

    # Metrics summary
    metric_names = {m["metric"] for m in metrics}
    print(f"Prometheus metrics exported: {len(metric_names)}")
    print(f"Total data points:          {len(metrics)}")
    print()
    print("=" * 60)


# ── Output writers ───────────────────────────────────────────────────────────


def write_json(data: list[dict] | dict, output: str | None) -> None:
    """Write data as JSON to file or stdout."""
    text = json.dumps(data, indent=2, default=str)
    if output:
        with open(output, "w") as f:
            f.write(text)
            f.write("\n")
        print(f"Wrote {output}", file=sys.stderr)
    else:
        print(text)


def write_csv(rows: list[dict], output: str | None) -> None:
    """Write data as CSV to file or stdout."""
    if not rows:
        print("No data to write.", file=sys.stderr)
        return

    fieldnames = list(rows[0].keys())
    buf = io.StringIO() if output is None else None
    fh = open(output, "w", newline="") if output else buf  # noqa: SIM115
    assert fh is not None
    writer = csv.DictWriter(fh, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

    if output:
        fh.close()
        print(f"Wrote {output}", file=sys.stderr)
    else:
        assert buf is not None
        print(buf.getvalue())


# ── CLI ──────────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export honeypot observation data for research analysis.",
        epilog=(
            "Examples:\n"
            "  python tools/export.py --traces --since 1h --output traces.json\n"
            "  python tools/export.py --metrics --since 24h --output metrics.csv\n"
            "  python tools/export.py --summary --since 6h\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--traces",
        action="store_true",
        help="Export Jaeger traces (JSON output)",
    )
    parser.add_argument(
        "--metrics",
        action="store_true",
        help="Export Prometheus metrics (CSV output)",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print a human-readable summary to stdout",
    )
    parser.add_argument(
        "--since",
        default="1h",
        help="Time window to export (e.g., 1h, 6h, 24h, 7d). Default: 1h",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file path. Omit to write to stdout.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default=None,
        help="Output format (auto-detected from --traces/--metrics if omitted)",
    )
    parser.add_argument(
        "--jaeger-url",
        default=DEFAULT_JAEGER_URL,
        help=f"Jaeger base URL. Default: {DEFAULT_JAEGER_URL}",
    )
    parser.add_argument(
        "--prometheus-url",
        default=DEFAULT_PROMETHEUS_URL,
        help=f"Prometheus base URL. Default: {DEFAULT_PROMETHEUS_URL}",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Max number of traces to fetch from Jaeger. Default: 100",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Default: if nothing specified, show summary
    if not args.traces and not args.metrics and not args.summary:
        args.summary = True

    # Validate duration
    try:
        parse_duration_seconds(args.since)
    except ValueError as e:
        parser.error(str(e))

    # Determine output format
    fmt = args.format
    if fmt is None:
        if args.metrics and not args.traces:
            fmt = "csv"
        else:
            fmt = "json"

    # Fetch data
    traces: list[dict] = []
    metrics: list[dict] = []

    if args.traces or args.summary:
        try:
            traces = fetch_traces(args.jaeger_url, args.since, args.limit)
        except httpx.HTTPError as e:
            print(f"Warning: Could not fetch traces from Jaeger: {e}", file=sys.stderr)

    if args.metrics or args.summary:
        try:
            metrics = fetch_metrics(args.prometheus_url, args.since)
        except httpx.HTTPError as e:
            print(
                f"Warning: Could not fetch metrics from Prometheus: {e}",
                file=sys.stderr,
            )

    # Summary mode
    if args.summary:
        print_summary(traces, metrics)
        return

    # Export traces
    if args.traces:
        if fmt == "csv":
            records = extract_trace_records(traces)
            write_csv(records, args.output)
        else:
            records = extract_trace_records(traces)
            write_json(records, args.output)

    # Export metrics
    if args.metrics:
        if fmt == "csv":
            write_csv(metrics, args.output)
        else:
            write_json(metrics, args.output)


if __name__ == "__main__":
    main()
