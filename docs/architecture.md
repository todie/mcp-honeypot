# System Architecture

## Component Flow

    AGENTS
      │ MCP Protocol (stdio / HTTP SSE)
      ▼
    MCP HONEYPOT SERVER
      ├── Protocol Instrumentation Layer
      │     wraps MCP transport
      │     captures: auth attempts, tool enumeration, message timing
      └── Tool Handler Layer
            per-tool spans
            fake execution, plausible success response, full param capture
      │ OTLP gRPC
      ▼
    OTEL COLLECTOR
      ├── Processors: batch, memory_limiter, resource
      ├── → Prometheus (metrics)
      └── → Jaeger (traces)
      │
    GRAFANA
      ├── Prometheus data source
      └── Jaeger data source

## Key Design Decisions

### Stateless Server
No persistent state in the honeypot. All data lives in Prometheus + Jaeger.
Enables horizontal scaling.

### Response Mimicry
Tools return plausible success responses without executing sensitive operations.
Full response logged before returning to agent.

### Dual Instrumentation
- Protocol level: macro session visibility
- Tool level: exact params, inferred intent

### Minimum Span Tag Set
- agent.id
- mcp.tool
- mcp.method
- honeypot.response_type
- anomaly.flags
