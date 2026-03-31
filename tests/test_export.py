"""Unit tests for tools/export.py -- duration parsing, trace flattening, CSV/summary."""

from __future__ import annotations

import csv
import importlib.util
import io
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_project_root))
sys.path.insert(0, str(_project_root / "server"))

# Import the top-level tools/export.py via importlib to avoid collision
# with server/tools/ package already on sys.path.
_export_spec = importlib.util.spec_from_file_location(
    "export_tool", _project_root / "tools" / "export.py"
)
_export_mod = importlib.util.module_from_spec(_export_spec)
_export_spec.loader.exec_module(_export_mod)

extract_trace_records = _export_mod.extract_trace_records
parse_duration_seconds = _export_mod.parse_duration_seconds
print_summary = _export_mod.print_summary
write_csv = _export_mod.write_csv


# =========================================================================
# Duration parsing
# =========================================================================


class TestParseDuration:
    def test_one_hour(self):
        assert parse_duration_seconds("1h") == 3600

    def test_twenty_four_hours(self):
        assert parse_duration_seconds("24h") == 86400

    def test_seven_days(self):
        assert parse_duration_seconds("7d") == 604800

    def test_thirty_minutes(self):
        assert parse_duration_seconds("30m") == 1800

    def test_sixty_seconds(self):
        assert parse_duration_seconds("60s") == 60

    def test_strips_whitespace(self):
        assert parse_duration_seconds("  1h  ") == 3600

    def test_case_insensitive(self):
        assert parse_duration_seconds("1H") == 3600
        assert parse_duration_seconds("7D") == 604800

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError, match="Invalid duration"):
            parse_duration_seconds("forever")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="Invalid duration"):
            parse_duration_seconds("")

    def test_missing_unit_raises(self):
        with pytest.raises(ValueError, match="Invalid duration"):
            parse_duration_seconds("100")


# =========================================================================
# Trace flattening
# =========================================================================


def _make_trace(spans, trace_id="abc123", processes=None):
    """Helper to build a Jaeger trace dict."""
    if processes is None:
        processes = {"p1": {"serviceName": "mcp-honeypot"}}
    return {"traceID": trace_id, "processes": processes, "spans": spans}


def _make_span(
    operation="tool.read_file",
    span_id="span1",
    process_id="p1",
    start_time=1700000000000000,
    duration=5000,
    tags=None,
):
    span = {
        "operationName": operation,
        "spanID": span_id,
        "processID": process_id,
        "startTime": start_time,
        "duration": duration,
        "tags": tags or [],
    }
    return span


class TestExtractTraceRecords:
    def test_extracts_basic_fields(self):
        span = _make_span(
            tags=[
                {"key": "mcp.tool", "value": "read_file"},
                {"key": "agent.fingerprint", "value": "agent-007"},
                {"key": "anomaly.flags", "value": "credential_probe"},
            ]
        )
        trace = _make_trace([span])
        records = extract_trace_records([trace])
        assert len(records) == 1
        r = records[0]
        assert r["trace_id"] == "abc123"
        assert r["span_id"] == "span1"
        assert r["operation"] == "tool.read_file"
        assert r["tool_name"] == "read_file"
        assert r["agent_fingerprint"] == "agent-007"
        assert r["anomaly_flags"] == "credential_probe"
        assert r["duration_us"] == 5000
        assert r["service"] == "mcp-honeypot"

    def test_handles_no_tags(self):
        span = _make_span(tags=[])
        trace = _make_trace([span])
        records = extract_trace_records([trace])
        assert len(records) == 1
        r = records[0]
        assert r["tool_name"] == ""
        assert r["agent_fingerprint"] == ""
        assert r["anomaly_flags"] == ""

    def test_handles_empty_trace_list(self):
        records = extract_trace_records([])
        assert records == []

    def test_handles_trace_with_no_spans(self):
        trace = _make_trace([])
        records = extract_trace_records([trace])
        assert records == []

    def test_multiple_spans_in_one_trace(self):
        span1 = _make_span(span_id="s1", operation="tool.read_file")
        span2 = _make_span(span_id="s2", operation="tool.fetch_url")
        trace = _make_trace([span1, span2])
        records = extract_trace_records([trace])
        assert len(records) == 2
        assert {r["span_id"] for r in records} == {"s1", "s2"}

    def test_fallback_tag_keys(self):
        """When primary tag keys are missing, fallback keys should be used."""
        span = _make_span(
            tags=[
                {"key": "tool.name", "value": "run_command"},
                {"key": "mcp.agent_fingerprint", "value": "bot-x"},
                {"key": "mcp.anomaly_flags", "value": "rapid_enumeration"},
            ]
        )
        trace = _make_trace([span])
        records = extract_trace_records([trace])
        r = records[0]
        assert r["tool_name"] == "run_command"
        assert r["agent_fingerprint"] == "bot-x"
        assert r["anomaly_flags"] == "rapid_enumeration"


# =========================================================================
# Metric CSV formatting
# =========================================================================


class TestWriteCsv:
    def test_csv_output_has_correct_headers(self, capsys):
        rows = [
            {
                "metric": "mcp_tool_calls_total",
                "labels": "{}",
                "timestamp": "2024-01-01T00:00:00Z",
                "value": "42",
            },
            {
                "metric": "mcp_tool_calls_total",
                "labels": "{}",
                "timestamp": "2024-01-01T00:00:15Z",
                "value": "43",
            },
        ]
        write_csv(rows, None)  # write to stdout
        output = capsys.readouterr().out
        reader = csv.DictReader(io.StringIO(output))
        headers = reader.fieldnames
        assert headers == ["metric", "labels", "timestamp", "value"]
        read_rows = list(reader)
        assert len(read_rows) == 2
        assert read_rows[0]["value"] == "42"

    def test_empty_results_prints_warning(self, capsys):
        write_csv([], None)
        output = capsys.readouterr().err
        assert "No data" in output


# =========================================================================
# Summary output
# =========================================================================


class TestPrintSummary:
    def test_summary_counts_are_correct(self, capsys):
        span1 = _make_span(
            span_id="s1",
            tags=[
                {"key": "mcp.tool", "value": "read_file"},
                {"key": "anomaly.flags", "value": "credential_probe,path_traversal"},
                {"key": "agent.fingerprint", "value": "agent-1"},
            ],
        )
        span2 = _make_span(
            span_id="s2",
            tags=[
                {"key": "mcp.tool", "value": "fetch_url"},
                {"key": "anomaly.flags", "value": "exfiltration_chain"},
                {"key": "agent.fingerprint", "value": "agent-2"},
            ],
        )
        traces = [_make_trace([span1, span2], trace_id="t1")]
        metrics = [
            {
                "metric": "mcp_tool_calls_total",
                "labels": "{}",
                "timestamp": "2024-01-01T00:00:00Z",
                "value": "10",
            },
        ]

        print_summary(traces, metrics)
        output = capsys.readouterr().out

        assert "Total traces:    1" in output
        assert "Total spans:     2" in output
        assert "Unique agents:   2" in output
        assert "Unique tools:    2" in output
        assert "credential_probe" in output
        assert "path_traversal" in output
        assert "exfiltration_chain" in output
        assert "Total data points:          1" in output

    def test_summary_handles_empty_data(self, capsys):
        print_summary([], [])
        output = capsys.readouterr().out
        assert "Total traces:    0" in output
        assert "Total spans:     0" in output
