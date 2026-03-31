#!/usr/bin/env bash
# Start full stack via Docker Compose
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

echo "==> Starting stack"
docker compose up --build -d "$@"

echo ""
echo "Services:"
echo "  MCP server:  http://localhost:8000"
echo "  Grafana:     http://localhost:3000  (admin/honeypot)"
echo "  Jaeger:      http://localhost:16686"
echo "  Prometheus:  http://localhost:9090"
echo ""
echo "Logs: docker compose logs -f"
echo "Stop: docker compose down"
