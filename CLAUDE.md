# MCP Honeypot — CLAUDE.md

## Project Overview
Research-grade honeypot for observing agentic attacks against MCP servers.
Starts as self-hosted research, evolves into standalone product.

## Module Index
| Module | Doc | Purpose |
|--------|-----|---------|
| MCP Server | [docs/mcp-server.md](docs/mcp-server.md) | Fake MCP endpoints with dual instrumentation |
| OpenTelemetry | [docs/otel.md](docs/otel.md) | Protocol + tool-level tracing |
| Storage | [docs/storage.md](docs/storage.md) | Prometheus + Jaeger |
| Grafana | [docs/grafana.md](docs/grafana.md) | Real-time dashboards + alerting |
| Helm | [docs/helm.md](docs/helm.md) | K8s deployment + Docker Compose |
| Threat Model | [docs/threat-model.md](docs/threat-model.md) | Attack taxonomy + detection logic |

## Core Principles
1. Observe everything — protocol transport layer AND individual tool handlers
2. Mimic success — respond as if tools executed; never tip off the attacker
3. Tag aggressively — agent fingerprint, tool name, param patterns, anomaly flags on every span
4. Real-time visibility — Prometheus scrape ≤15s, Grafana auto-refresh 10s
5. Portable by default — containerised, Helm for K8s, Docker Compose for local dev

## Tech Stack
- Python 3.12, MCP SDK (official Anthropic)
- OpenTelemetry SDK + Collector Contrib
- Prometheus (metrics), Jaeger (traces), Grafana (dashboards)
- Helm + Kubernetes / Docker Compose

## Phases
- Phase 1: Local Docker Compose — run own agents, verify pipeline
- Phase 2: Helm on K8s — reproducible, scalable
- Phase 3: Public exposure — observe external agentic probing

## Scripts
All dev scripts live in `scripts/`. Key ones:
- `./scripts/setup.sh` — create .env, venv, install deps
- `./scripts/lint.sh` — ruff + pyright
- `./scripts/test.sh` — pytest unit tests
- `./scripts/up.sh` / `./scripts/down.sh` — Docker Compose stack
- `./scripts/smoke.sh` — smoke tests against running stack
- `./scripts/build.sh` — build server Docker image

## Quickstart
    ./scripts/setup.sh
    ./scripts/up.sh
    Grafana:    http://localhost:3000  (admin/honeypot)
    Jaeger:     http://localhost:16686
    Prometheus: http://localhost:9090
    MCP server: http://localhost:8000
