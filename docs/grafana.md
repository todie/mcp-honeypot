# Grafana Dashboards

## Data Source Provisioning

    apiVersion: 1
    datasources:
      - name: Prometheus
        type: prometheus
        url: http://prometheus:9090
        isDefault: true
        jsonData:
          timeInterval: "15s"
      - name: Jaeger
        type: jaeger
        url: http://jaeger:16686

## Dashboard: Attack Summary
Refresh: 10s
Panels:
- Total requests (counter, 24h)
- Active sessions (gauge)
- Request rate (time series, 1h)
- Anomaly rate (time series, 1h)
- Top tools called (bar chart, 1h)
- Top agents by request count (table, 24h)
- Credential probe attempts (stat — red alert)

## Dashboard: Agent Drilldown
Variable: $agent_id (dropdown from Prometheus label values)
Panels:
- Session timeline for selected agent
- Tools called (pie chart)
- Anomaly flags triggered (table)
- Jaeger trace links (clickable table)

## Dashboard: Anomaly Monitor
Panels:
- Anomaly heatmap (flag type × time)
- Top anomaly types (bar chart)
- Path traversal attempts (time series)
- Credential probes (time series with alert threshold)
- Rapid enumeration events (time series)

## Dashboard: Tool Intelligence
Panels:
- Tool call frequency heatmap (tool × hour of day)
- Average chain depth per session
- Tool co-occurrence matrix

## Alerting Rules
    - name: CredentialProbeAlert
      condition: sum(rate(mcp_honeypot_anomalies_total{flag="credential_probe"}[5m])) > 0
      severity: critical

    - name: RapidEnumerationAlert
      condition: sum(rate(mcp_honeypot_anomalies_total{flag="rapid_enumeration"}[1m])) > 2
      severity: warning

    - name: HighVolumeAgentAlert
      condition: sum by (agent_id) (rate(mcp_honeypot_requests_total[5m])) > 10
      severity: warning
