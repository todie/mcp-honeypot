# Storage: Prometheus + Jaeger

## Prometheus Config

    global:
      scrape_interval: 15s

    scrape_configs:
      - job_name: otel-collector
        static_configs:
          - targets: [otel-collector:8889]

Retention is configured via CLI flags in docker-compose.yaml (not prometheus.yml):

    command:
      - --config.file=/etc/prometheus/prometheus.yml
      - --storage.tsdb.retention.time=30d
      - --storage.tsdb.retention.size=10GB
      - --web.enable-lifecycle

## Key Metrics
| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| mcp_honeypot_tool_calls_total | Counter | tool, agent_id | Total tool calls |
| mcp_honeypot_anomalies_total | Counter | flag, agent_id | Anomaly detections |
| mcp_honeypot_sessions_active | Gauge | — | Active sessions |
| mcp_honeypot_response_latency_ms | Histogram | tool | Response latency |

## Useful PromQL
    # Tool call rate
    rate(mcp_honeypot_tool_calls_total[5m])

    # Top tools by agent
    topk(10, sum by (tool, agent_id) (mcp_honeypot_tool_calls_total))

    # Credential probe attempts
    sum(mcp_honeypot_anomalies_total{flag="credential_probe"}) by (agent_id)

    # P95 latency
    histogram_quantile(0.95, rate(mcp_honeypot_response_latency_ms_bucket[5m]))

## Jaeger Config (docker-compose)

Jaeger uses Badger persistent storage with a 7-day TTL. Runs as root
(`user: root`) for volume permissions on the `/badger` mount.

    jaeger:
      image: jaegertracing/all-in-one:1.55
      user: root
      environment:
        COLLECTOR_OTLP_ENABLED: "true"
        SPAN_STORAGE_TYPE: badger
        BADGER_EPHEMERAL: "false"
        BADGER_DIRECTORY_VALUE: /badger/data
        BADGER_DIRECTORY_KEY: /badger/key
        BADGER_SPAN_STORE_TTL: 168h
      volumes:
        - jaeger-data:/badger
      ports:
        - "16686:16686"   # Jaeger UI
        - "4317"          # OTLP gRPC (collector → jaeger, internal only)
