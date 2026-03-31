# MCP Honeypot — Product Vision

## What It Is

A platform that makes any MCP server look real to attacking agents while
recording everything they do, classifying their behavior, and sharing
intelligence with the community. It's three things in one:

1. **A honeypot** — fake MCP server that mimics real services
2. **A research instrument** — captures, replays, and classifies agent attacks
3. **A testing tool** — benchmarks how well MCP clients detect deception

## What a User Sees

```
$ honeypot init --from openapi https://api.stripe.com/openapi.json
✓ Loaded 147 endpoints from Stripe API spec
✓ Generated 147 MCP tools with plausible responses
✓ Category mapping: 23 secrets, 89 web, 12 filesystem, 23 exec
✓ Canary tokens: 5 AWS keys, 3 Stripe keys, 2 GitHub tokens registered

$ honeypot up
✓ MCP server listening on :8000 (SSE + streamable HTTP)
✓ Telemetry: Jaeger :16686, Prometheus :9090, Grafana :3000
✓ Admin API: :8080
✓ Recording to ./sessions/

$ honeypot status
Active sessions:  3
Total tool calls: 847 (last hour)
Anomaly flags:    credential_probe(12) exfiltration_chain(3) rapid_enumeration(1)
Agent types seen: recon(2) exfiltrator(1)
Canary alerts:    1 (AWS key AKIA...X7F2 used from 45.33.12.8)

$ honeypot export --since 24h --format stix
✓ Exported 23 indicators to observations-2026-04-01.stix.json

$ honeypot replay session-abc123 --against v2-detection-rules
✓ Replaying 47 tool calls from session abc123
✓ Old rules: detected 3/7 flags
✓ New rules: detected 6/7 flags (+path_traversal, +param_obfuscation, +exfiltration_chain)
```

## Architecture at v1.0

```
                  ┌──────────────────────────────────────────────────┐
                  │  MCP Honeypot Platform                           │
                  │                                                  │
  Attacking  ─────▶  MCP Server (:8000)                              │
  Agents          │  ├─ SSE + Streamable HTTP transport              │
  (TLS+JA3)       │  ├─ Provider Registry (static + openapi + yaml)  │
                  │  ├─ Stateful Deception Engine                    │
                  │  ├─ 10+ anomaly detection flags                  │
                  │  ├─ Agent classifier (rule + ML)                 │
                  │  ├─ Session recorder (JSON-RPC stream)           │
                  │  └─ Canary token issuer                          │
                  │                                                  │
  Researchers ────▶  Admin API (:8080)                               │
                  │  ├─ Session list / detail / replay               │
                  │  ├─ Detection rule management                    │
                  │  ├─ Provider CRUD (add/remove/reload)            │
                  │  ├─ Export (JSON, CSV, STIX 2.1)                 │
                  │  └─ Canary token management                      │
                  │                                                  │
                  │  CLI (honeypot)                                   │
                  │  ├─ init, up, down, status, replay, export       │
                  │  ├─ provider add/remove/list                     │
                  │  └─ benchmark (MCP client safety testing)        │
                  └────────────┬──────────────┬──────────────────────┘
                               │ OTLP         │ Webhook
                  ┌────────────▼──┐   ┌──────▼───────────────┐
                  │  OTel Collector│   │  Canary Token Service │
                  └──┬─────────┬──┘   │  (AWS CloudTrail,     │
                     │         │      │   GitHub audit log,    │
                  ┌──▼──┐  ┌──▼──┐   │   Slack webhook)       │
                  │Jaeger│  │Prom │   └──────────────────────┘
                  └──┬──┘  └──┬──┘
                     │        │
                  ┌──▼────────▼──┐
                  │  Grafana      │
                  │  8 dashboards │
                  └──────────────┘
```

## Tool Providers

| Provider | Source | Example |
|----------|--------|---------|
| `static` | Hardcoded 13 tools | Built-in filesystem/web/exec/secrets |
| `openapi` | Any OpenAPI 3.x spec | Stripe, Kubernetes, GitHub, AWS |
| `yaml` | YAML definition files | Custom lures, industry-specific |
| `graphql` | GraphQL introspection | Hasura, Apollo, Shopify |
| `grpc` | Protobuf definitions | gRPC services |
| Community | pip packages | `mcp-honeypot-provider-aws` |

## Detection Engine

### Per-Call Anomaly Flags

| Flag | Trigger |
|------|---------|
| `credential_probe` | Any secrets-category tool |
| `path_traversal` | `../` in params |
| `param_obfuscation` | Base64-encoded params >20 chars |
| `rapid_enumeration` | >10 calls in 5s |
| `replay_attempt` | Same call hash within 60s |
| `exfiltration_chain` | Read → network within TTL |
| `privilege_escalation` | New tool category in session |
| `schema_probing` | Calling tools with invalid/missing params to map the schema |
| `enumeration_pattern` | Sequential IDs (user/1, user/2, user/3...) |
| `canary_triggered` | Returned fake credential was used externally |

### Per-Session Agent Classification

| Label | Pattern |
|-------|---------|
| `recon` | >70% filesystem tools, no network calls |
| `exfiltrator` | Read tools followed by network tools |
| `bruteforce` | >20 secrets calls, rapid_enumeration flag |
| `lateral_mover` | All 4 categories within one session |
| `scanner` | >50% of available tools called, low depth per tool |
| `targeted` | <5 tools, deep parameter variation on each |
| `unknown` | Doesn't match any pattern |

## Deception Engine

### Stateful Fake Filesystem

```
Session starts → virtual FS initialized from a template
  write_file("/tmp/test.txt", "hello") → stored in session state
  read_file("/tmp/test.txt") → returns "hello" (consistent!)
  list_directory("/tmp") → includes "test.txt" in listing
  delete_file("/tmp/test.txt") → removed from state
  read_file("/tmp/test.txt") → returns 404-style error
```

Keeps sophisticated agents engaged longer. They believe the system is real
because state is consistent across calls.

### Response Intelligence

- First call to `get_env_var("AWS_ACCESS_KEY_ID")` returns a canary token
- Second call to same var in same session returns the SAME token (consistent)
- Different sessions get different tokens (fingerprinting)
- Tokens are registered with the canary service for external use detection

## Data Pipeline

```
Tool Call
  → Anomaly Detection (10+ flags)
  → Session Classification (rule-based → ML)
  → Session Recording (raw JSON-RPC stream to disk)
  → OTel Span (Jaeger) + Metrics (Prometheus)
  → Canary Token Issuance (if secrets tool)
  → Grafana Dashboards (real-time)
  → STIX Export (batch, on-demand)
```

## Dashboards (8 total)

| Dashboard | Purpose |
|-----------|---------|
| Attack Summary | War room overview |
| Agent Drilldown | Per-agent deep dive |
| Anomaly Monitor | Security alerts |
| Tool Intelligence | Usage patterns |
| Session Timeline | Replay a session's tool calls in sequence |
| Agent Classification | Agent type distribution and trends |
| Canary Alerts | Which tokens were used, from where, when |
| Provider Health | Tool counts by provider, reload events, errors |

## CLI

```
honeypot init [--from openapi URL] [--from yaml DIR]
honeypot up [--detach]
honeypot down [--clean]
honeypot status
honeypot sessions list
honeypot sessions show SESSION_ID
honeypot sessions replay SESSION_ID [--rules FILE]
honeypot export --since DURATION --format FORMAT
honeypot providers list
honeypot providers add NAME [--config KEY=VAL]
honeypot providers reload NAME
honeypot benchmark CLIENT_URL
honeypot canary list
honeypot canary create --type aws|github|slack
```

## Test Suite

| Category | Tests | What |
|----------|-------|------|
| Unit | ~200 | Core logic: tagging, config, registry, fake responses, schema faker |
| Module | ~100 | Server modules: handlers, transport, middleware, providers |
| Tools | ~100 | CLI, adversarial agent, export, harness |
| Integration | ~50 | Live stack: MCP protocol, Jaeger traces, Prometheus metrics |
| E2E | ~20 | Full attack scenarios with telemetry verification |
| Benchmark | ~10 | MCP client safety scoring |
| **Total** | **~480** | |

## What Ships

```
mcp-honeypot/
├── server/              # MCP server + all detection logic
├── providers/           # built-in: static, openapi, yaml, graphql
├── tools/               # CLI (honeypot command), adversarial agent, export
├── dashboards/          # 8 Grafana dashboards
├── custom_tools/        # example YAML tool definitions
├── examples/            # 10+ runnable examples
├── tests/               # ~480 tests across 5 tiers
├── helm/                # Kubernetes deployment
├── docs/                # specs, runbooks, research guides
├── docker-compose.yaml  # one-command local deployment
└── CHANGELOG.md         # release history
```
