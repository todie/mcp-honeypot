"""OpenTelemetry instrumentation for the MCP honeypot server.

Initialises tracer and meter providers with OTLP gRPC exporters,
and exposes three custom metrics for honeypot-specific observability.
"""

from __future__ import annotations

from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
    OTLPMetricExporter,
)
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
    OTLPSpanExporter,
)
from opentelemetry.metrics import Counter, Histogram, Meter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import Tracer

from config import settings

# ---------------------------------------------------------------------------
# Idempotency guard
# ---------------------------------------------------------------------------
_telemetry_initialised: bool = False

# ---------------------------------------------------------------------------
# Module-level metric instruments (populated by setup_telemetry)
# ---------------------------------------------------------------------------
mcp_tool_calls_total: Counter
mcp_anomalies_total: Counter
mcp_response_latency_ms: Histogram


def setup_telemetry() -> None:
    """Initialise OpenTelemetry tracer and meter providers.

    Safe to call multiple times; only the first invocation has an effect.
    Configuration is read from ``config.settings``.
    """
    global _telemetry_initialised
    global mcp_tool_calls_total, mcp_anomalies_total, mcp_response_latency_ms

    if _telemetry_initialised:
        return

    resource = Resource.create({"service.name": settings.service_name})

    # -- Traces ------------------------------------------------------------
    span_exporter = OTLPSpanExporter(
        endpoint=settings.otlp_endpoint,
        insecure=settings.otlp_insecure,
    )
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
    trace.set_tracer_provider(tracer_provider)

    # -- Metrics -----------------------------------------------------------
    metric_exporter = OTLPMetricExporter(
        endpoint=settings.otlp_endpoint,
        insecure=settings.otlp_insecure,
    )
    metric_reader = PeriodicExportingMetricReader(
        metric_exporter,
        export_interval_millis=15_000,
    )
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
    metrics.set_meter_provider(meter_provider)

    # -- Custom metrics ----------------------------------------------------
    meter: Meter = meter_provider.get_meter("mcp-honeypot")

    mcp_tool_calls_total = meter.create_counter(
        name="mcp_tool_calls_total",
        description="Total MCP tool invocations observed by the honeypot",
        unit="1",
    )
    mcp_anomalies_total = meter.create_counter(
        name="mcp_anomalies_total",
        description="Total anomaly flags raised across all sessions",
        unit="1",
    )
    mcp_response_latency_ms = meter.create_histogram(
        name="mcp_response_latency_ms",
        description="Latency of fake tool responses in milliseconds",
        unit="ms",
    )

    _telemetry_initialised = True


# ---------------------------------------------------------------------------
# Convenience accessors
# ---------------------------------------------------------------------------

def get_tracer(name: str) -> Tracer:
    """Return a tracer from the global provider."""
    return trace.get_tracer(name)
