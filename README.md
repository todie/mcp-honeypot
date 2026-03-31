# MCP Honeypot

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/todie/mcp-honeypot/actions/workflows/ci.yml/badge.svg)](https://github.com/todie/mcp-honeypot/actions/workflows/ci.yml)

A research-grade honeypot for observing agentic attacks against MCP (Model Context Protocol) servers.
It exposes plausible-looking fake tools -- filesystem access, secrets retrieval, web fetching, command
execution -- while silently recording every call with full OpenTelemetry instrumentation.  The goal is
to fingerprint adversarial agents, catalogue their tool-use patterns, and surface anomalies in real time.

## Architecture

```
                        ┌──────────────────────────────┐
  Attacking Agent ──────► MCP Honeypot  :8000 (SSE)    │
                        │  • 14 fake tools              │
                        │  • transport_wrapper (spans)  │
                        │  • session state + tagging    │
                        └────────────┬─────────────────┘
                                     │ OTLP gRPC :4317
                        ┌────────────▼─────────────────┐
                        │  OTel Collector               │
                        │  receivers:  OTLP 4317/4318  │
                        │  processors: memory_limiter   │
                        │              batch            │
                        └──────┬───────────┬────────────┘
                               │ OTLP      │ Prometheus
                ┌──────────────▼──┐   ┌───▼──────────────┐
                │  Jaeger  :16686  │   │  Prometheus :9090 │
                │  (traces)        │   │  (metrics)        │
                └──────────────────┘   └───────┬──────────┘
                                               │
                                   ┌───────────▼──────────┐
                                   │  Grafana  :3000       │
                                   │  4 dashboards         │
                                   │  10 s auto-refresh    │
                                   └──────────────────────┘
```

## Quickstart

```bash
git clone https://github.com/your-org/mcp-honeypot.git
cd mcp-honeypot
cp .env.example .env          # review and adjust if needed
docker-compose up --build
```

| Service    | URL                        | Default credentials |
|------------|----------------------------|---------------------|
| MCP server | http://localhost:8000      | --                  |
| Grafana    | http://localhost:3000      | admin / honeypot    |
| Jaeger     | http://localhost:16686     | --                  |
| Prometheus | http://localhost:9090      | --                  |

## Environment Variables

All variables are documented in [`.env.example`](.env.example).  Key ones:

| Variable | Default | Description |
|---|---|---|
| `OTLP_ENDPOINT` | `otel-collector:4317` | OTLP gRPC endpoint |
| `OTLP_INSECURE` | `true` | Skip TLS for OTLP (only `false` disables) |
| `SERVICE_NAME` | `mcp-honeypot` | Service name in traces/metrics |
| `MCP_HOST` | `0.0.0.0` | MCP server bind address |
| `MCP_PORT` | `8000` | MCP server port |
| `HONEYPOT_PHASE` | `research` | Phase: `research` or `public` |
| `LOG_LEVEL` | `INFO` | Structured log level |
| `CORS_ORIGINS` | `*` | Allowed CORS origins (tighten in Phase 3) |
| `GRAFANA_ADMIN_PASSWORD` | `honeypot` | Grafana admin password |

## Detection Logic

The honeypot tags every tool call with up to 7 anomaly flags:

| Flag | Trigger |
|---|---|
| `credential_probe` | Any secrets-category tool call |
| `path_traversal` | `../` in any parameter value |
| `param_obfuscation` | Parameter value >20 chars that is valid base64 |
| `rapid_enumeration` | >10 calls within 5 s in a single session |
| `replay_attempt` | Same tool+params MD5 seen within 60 s |
| `exfiltration_chain` | Read-family call → network-family call within TTL |
| `privilege_escalation` | Tool category not seen before in this session |

## Scripts

All scripts are in `scripts/` and executable from the repo root:

| Script | Purpose |
|---|---|
| `./scripts/setup.sh` | Create `.env`, Python venv, install deps |
| `./scripts/lint.sh` | Ruff lint + format check + pyright strict |
| `./scripts/test.sh` | Run pytest unit tests (no Docker) |
| `./scripts/build.sh` | Build server Docker image |
| `./scripts/up.sh` | Start full stack via Docker Compose |
| `./scripts/down.sh` | Stop stack (`--clean` to remove volumes) |
| `./scripts/smoke.sh` | Run smoke tests against running stack |
| `./scripts/protect-main.sh` | Apply GitHub branch protection rules |

## Contributing

**Branch naming:** `<type>/<short-description>` -- e.g. `feat/transport-wrapper`, `fix/otel-exporter`.

**PR expectations:**
- Keep PRs focused on one subtask (see `PLAN.md` for the task list).
- All CI jobs must pass: `ruff` (lint), `pyright` (types), `pytest` (unit tests).
- Add or update tests for any new detection logic in `server/tagging.py`.

**Running the smoke test** (requires a running stack):

```bash
docker-compose up -d
python tests/smoke_test.py
```

## Further Reading

| Document | Purpose |
|---|---|
| [docs/mcp-server.md](docs/mcp-server.md) | Fake MCP endpoints, dual instrumentation |
| [docs/otel.md](docs/otel.md) | OTel protocol + tool-level tracing |
| [docs/storage.md](docs/storage.md) | Prometheus + Jaeger setup |
| [docs/grafana.md](docs/grafana.md) | Dashboard design + alerting |
| [docs/helm.md](docs/helm.md) | Kubernetes deployment (Phase 2) |
| [docs/threat-model.md](docs/threat-model.md) | Attack taxonomy + detection logic |
| [PLAN.md](PLAN.md) | Full implementation plan with task breakdown |
