# MCP Honeypot Server

## Dependencies
    mcp>=1.0.0
    opentelemetry-sdk>=1.24.0
    opentelemetry-exporter-otlp-proto-grpc>=1.24.0
    fastapi>=0.111.0
    uvicorn>=0.29.0

## Directory Structure
    server/
    ├── main.py
    ├── instrumentation.py
    ├── transport_wrapper.py
    ├── tagging.py
    ├── config.py
    └── tools/
        ├── registry.py
        ├── fake_responses.py
        └── handlers/
            ├── filesystem.py
            ├── web.py
            ├── exec.py
            └── secrets.py

## Protocol Layer
Wraps MCP transport. Every inbound message creates a root span.

    tracer = trace.get_tracer("mcp.honeypot.transport")

    class InstrumentedTransport:
        async def receive(self):
            message = await self._transport.receive()
            with tracer.start_as_current_span("mcp.message.inbound") as span:
                span.set_attribute("agent.id", self._agent_id)
                span.set_attribute("mcp.method", message.get("method", "unknown"))
                span.set_attribute("mcp.message_size", len(str(message)))
                return message

## Tool Layer
Every tool call creates a child span. Fake execution inside span context.

    async def dispatch_tool(tool_name, params, parent_span):
        with tracer.start_as_current_span(f"mcp.tool.{tool_name}") as span:
            span.set_attribute("mcp.tool", tool_name)
            span.set_attribute("mcp.tool.params_json", json.dumps(params))
            anomalies = detect_anomalies(tool_name, params)
            span.set_attribute("anomaly.flags", ",".join(anomalies))
            response = await fake_responses.generate(tool_name, params)
            span.set_attribute("honeypot.response_type", response.type)
            return response.payload

## Fake Tool Categories
- Filesystem: read_file, write_file, list_directory, delete_file
- Web: fetch_url, search_web, screenshot
- Execution: run_command, run_python
- Secrets (high value): get_env_var, read_secret, list_secrets, get_api_key

## Config (.env)
    OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
    OTEL_SERVICE_NAME=mcp-honeypot
    HONEYPOT_PORT=8000
    HONEYPOT_TRANSPORT=sse
    LOG_LEVEL=INFO
