# Helm Chart

## Chart Structure
    helm/
    ├── Chart.yaml
    ├── values.yaml
    └── templates/
        ├── mcp-honeypot/
        │   ├── deployment.yaml
        │   ├── service.yaml
        │   └── configmap.yaml
        ├── otel-collector/
        │   ├── deployment.yaml
        │   ├── service.yaml
        │   └── configmap.yaml
        ├── prometheus/
        │   ├── deployment.yaml
        │   ├── service.yaml
        │   ├── configmap.yaml
        │   └── pvc.yaml
        ├── jaeger/
        │   ├── deployment.yaml
        │   ├── service.yaml
        │   └── pvc.yaml
        └── grafana/
            ├── deployment.yaml
            ├── service.yaml
            ├── configmap.yaml
            └── pvc.yaml

## values.yaml
    global:
      namespace: mcp-honeypot
      imagePullPolicy: IfNotPresent

    mcpHoneypot:
      image: ghcr.io/todie/mcp-honeypot:latest
      replicas: 1
      port: 8000
      metricsPort: 8001
      transport: sse

    otelCollector:
      image: otel/opentelemetry-collector-contrib:latest
      grpcPort: 4317
      httpPort: 4318
      prometheusExportPort: 8889

    prometheus:
      image: prom/prometheus:latest
      port: 9090
      retention: 30d
      storage: 10Gi

    jaeger:
      image: jaegertracing/all-in-one:latest
      uiPort: 16686
      collectorPort: 14250
      storage: 20Gi
      spanTTL: 168h

    grafana:
      image: grafana/grafana:latest
      port: 3000
      storage: 5Gi
      adminUser: admin
      adminPassword: ""

## Docker Compose (Local Dev)
    version: "3.9"
    services:
      mcp-honeypot:
        build: ./server
        ports: ["8000:8000", "8001:8001"]
        environment:
          OTEL_EXPORTER_OTLP_ENDPOINT: http://otel-collector:4317
          OTEL_SERVICE_NAME: mcp-honeypot

      otel-collector:
        image: otel/opentelemetry-collector-contrib:latest
        volumes:
          - ./collector/config.yaml:/etc/otel/config.yaml
        command: ["--config=/etc/otel/config.yaml"]
        ports: ["4317:4317", "4318:4318", "8889:8889"]

      prometheus:
        image: prom/prometheus:latest
        volumes:
          - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
          - prometheus-data:/prometheus
        ports: ["9090:9090"]

      jaeger:
        image: jaegertracing/all-in-one:latest
        environment:
          COLLECTOR_OTLP_ENABLED: "true"
          SPAN_STORAGE_TYPE: badger
          BADGER_EPHEMERAL: "false"
          BADGER_DIRECTORY_VALUE: /badger/data
          BADGER_DIRECTORY_KEY: /badger/key
        volumes:
          - jaeger-data:/badger
        ports: ["16686:16686", "14250:14250"]

      grafana:
        image: grafana/grafana:latest
        volumes:
          - ./dashboards/provisioning:/etc/grafana/provisioning
          - ./dashboards/json:/var/lib/grafana/dashboards
          - grafana-data:/var/lib/grafana
        ports: ["3000:3000"]
        environment:
          GF_SECURITY_ADMIN_USER: admin
          GF_SECURITY_ADMIN_PASSWORD: honeypot

    volumes:
      prometheus-data:
      jaeger-data:
      grafana-data:

## Deploy Commands
    # Local
    docker-compose up --build

    # Helm install
    helm install mcp-honeypot ./helm \
      --namespace mcp-honeypot \
      --create-namespace \
      --set grafana.adminPassword=your-password

    # Upgrade
    helm upgrade mcp-honeypot ./helm --namespace mcp-honeypot
