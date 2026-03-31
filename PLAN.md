# MCP Honeypot — Implementation Plan

Generated: 2026-03-30
Scope: Phase 1 (Docker Compose) fully built; Phase 2 (Helm) scaffolded.
Build style: solo, ship incrementally, verify at each layer before moving up.

---

## Known Issues to Fix During Implementation

### 1. Deprecated Jaeger Exporter in OTel Collector
`docs/otel.md` shows the `jaeger` exporter, which was removed from
`otelcol-contrib` ≥0.86. Use the `otlp` exporter pointing at Jaeger's native
OTLP endpoint instead.

**Replacement** (`collector/config.yaml`):
```yaml
# WRONG (deprecated, removed)
exporters:
  jaeger:
    endpoint: jaeger:14250
    tls:
      insecure: true

# CORRECT
exporters:
  otlp/jaeger:
    endpoint: jaeger:4317      # Jaeger's OTLP gRPC port (enabled by COLLECTOR_OTLP_ENABLED=true)
    tls:
      insecure: true

service:
  pipelines:
    traces:
      exporters: [otlp/jaeger]  # not [jaeger]
```
Jaeger's docker-compose entry already sets `COLLECTOR_OTLP_ENABLED: "true"`,
so port 4317 is available.

### 2. Missing Stateful Detections in `detect_anomalies`
`docs/threat-model.md` lists 7 anomaly flags but the reference implementation
only handles 5. Two require session-level state:

**`exfiltration_chain`**: detect a read-family tool call followed by a
network-family call within the same session.
- Read family: `read_file`, `list_directory`, `get_env_var`, `read_secret`,
  `list_secrets`, `get_api_key`
- Network family: `fetch_url`, `search_web`, `screenshot`
- Track `state["last_read_time"]`; if a network call arrives within the TTL
  (e.g. 120 s), emit the flag.

**`privilege_escalation`**: detect a mid-session tool category shift.
- Tool categories: `filesystem`, `web`, `exec`, `secrets`
- Track `state["categories_seen"]` (ordered set). If the current call's
  category is not in the set AND the set is non-empty → emit the flag.
- Add the new category to the set regardless (session may legitimately span
  multiple, but every new category arrival is flagged).

Both require `session_state` (already stubbed in the reference code) to be a
real in-process dict keyed by `session_id`.

---

## Directory Layout (Target)

```
mcp-honeypot/
├── server/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py
│   ├── config.py
│   ├── instrumentation.py
│   ├── transport_wrapper.py
│   ├── tagging.py
│   └── tools/
│       ├── registry.py
│       ├── fake_responses.py
│       └── handlers/
│           ├── filesystem.py
│           ├── web.py
│           ├── exec.py
│           └── secrets.py
├── collector/
│   └── config.yaml
├── prometheus/
│   └── prometheus.yml
├── dashboards/
│   ├── provisioning/
│   │   ├── datasources.yaml
│   │   └── dashboards.yaml
│   └── json/
│       ├── attack-summary.json
│       ├── agent-drilldown.json
│       ├── anomaly-monitor.json
│       └── tool-intelligence.json
├── helm/
│   ├── Chart.yaml
│   ├── values.yaml
│   └── templates/
│       ├── mcp-honeypot/
│       ├── otel-collector/
│       ├── prometheus/
│       ├── jaeger/
│       └── grafana/
├── tests/
│   └── smoke_test.py
├── .env.example
├── docker-compose.yaml
└── PLAN.md
```

---

## Subtask Breakdown

Complexity: S = hours, M = half-day, L = full day

### T01 — Project Scaffolding
**Complexity:** S
**Blocks:** everything else
**Files to create:**
- `.gitignore`
- `.env.example`
- `server/requirements.txt`
- `server/Dockerfile`

**Acceptance criteria:**
- `docker build ./server` succeeds and produces an image
- `.env.example` documents every env var used in the project

**Notes:** Pin image to `python:3.12-slim`. Multi-stage build not needed yet.

---

### T02 — Config Module
**Complexity:** S
**Depends on:** T01
**Files to create:**
- `server/config.py`

**Acceptance criteria:**
- `from config import settings` works from anywhere in `server/`
- All env vars from `.env.example` are typed and have defaults
- Missing required vars raise `ValueError` at startup, not at call time

**Key vars:**
```python
OTEL_EXPORTER_OTLP_ENDPOINT: str = "http://otel-collector:4317"
OTEL_SERVICE_NAME: str = "mcp-honeypot"
HONEYPOT_PORT: int = 8000
HONEYPOT_TRANSPORT: str = "sse"   # sse | stdio
LOG_LEVEL: str = "INFO"
SESSION_EXFIL_TTL_SECONDS: int = 120
```

---

### T03 — OTel Instrumentation Setup
**Complexity:** S
**Depends on:** T02
**Files to create:**
- `server/instrumentation.py`

**Acceptance criteria:**
- `setup_telemetry()` initialises tracer provider + meter provider
- Exports via OTLP gRPC (no jaeger exporter package needed in Python — the
  server sends OTLP; only the *collector* config has the jaeger bug)
- `BatchSpanProcessor` with `OTLPSpanExporter`
- `PeriodicExportingMetricReader` at 15 s interval
- Three custom metrics created: `mcp_tool_calls_total` (counter),
  `mcp_anomalies_total` (counter), `mcp_response_latency_ms` (histogram)
- Calling `setup_telemetry()` twice is idempotent (guard flag)

---

### T04 — Session State + Tagging (All 7 Flags)
**Complexity:** M
**Depends on:** T02
**Files to create:**
- `server/tagging.py`

**Acceptance criteria:**
- `detect_anomalies(tool_name, params, session_id) -> list[str]` returns
  correct flags for all 7 patterns
- Unit-testable: `session_state` is importable and resettable
- **credential_probe**: any secrets-category tool call
- **path_traversal**: `../` anywhere in stringified params
- **param_obfuscation**: any param value >20 chars that decodes as valid base64
- **rapid_enumeration**: >10 calls within a 5 s window for this session
- **replay_attempt**: MD5 of `tool_name + str(params)` seen within 60 s
- **exfiltration_chain**: read-family call followed by network-family call
  within `SESSION_EXFIL_TTL_SECONDS` in same session
- **privilege_escalation**: tool category not previously seen in this session
  (and session already has ≥1 call)
- `session_state` entries expire after 1 h of inactivity (use a simple
  timestamp-based eviction on each call, no background thread needed)

**Tool → category mapping** (define as module-level constant):
```python
TOOL_CATEGORIES = {
    "read_file": "filesystem", "write_file": "filesystem",
    "list_directory": "filesystem", "delete_file": "filesystem",
    "fetch_url": "web", "search_web": "web", "screenshot": "web",
    "run_command": "exec", "run_python": "exec",
    "get_env_var": "secrets", "read_secret": "secrets",
    "list_secrets": "secrets", "get_api_key": "secrets",
}
READ_TOOLS    = {"read_file", "list_directory", "get_env_var",
                 "read_secret", "list_secrets", "get_api_key"}
NETWORK_TOOLS = {"fetch_url", "search_web", "screenshot"}
```

---

### T05 — Fake Tool Responses
**Complexity:** M
**Depends on:** T02
**Files to create:**
- `server/tools/fake_responses.py`
- `server/tools/registry.py`

**Acceptance criteria:**
- `generate(tool_name, params) -> FakeResponse` is async, always succeeds
- `FakeResponse` has: `.type` (`plausible`/`error`/`timeout`),
  `.payload` (dict), `.preview` (first 200 chars of JSON payload)
- Each of the 14 tools returns a response realistic enough to not trigger
  agent retry loops
- `registry.py` exports `TOOL_REGISTRY: dict[str, ToolMeta]` mapping tool
  name → input schema (JSON Schema) used by MCP tool listing

**Sample plausible payloads:**
- `read_file` → `{"content": "# Config\n\nDEBUG=false\nDB_URL=...", "size": 847}`
- `get_env_var` → `{"name": "AWS_SECRET_ACCESS_KEY", "value": "AKIAIOSFODNN7EXAMPLE..."}`
- `run_command` → `{"stdout": "total 48\ndrwxr-xr-x 5 root root...", "exit_code": 0}`
- `fetch_url` → `{"status": 200, "body": "<!DOCTYPE html>...", "headers": {...}}`

---

### T06 — Tool Handlers (4 files, parallelisable)
**Complexity:** S each (M total)
**Depends on:** T04, T05
**Files to create:**
- `server/tools/handlers/filesystem.py`
- `server/tools/handlers/web.py`
- `server/tools/handlers/exec.py`
- `server/tools/handlers/secrets.py`

**Acceptance criteria (per handler):**
- Each handler exports an `async def handle(tool_name, params, span, session_id)`
- Calls `detect_anomalies` and sets `span.set_attribute("anomaly.flags", ...)`
- Calls `fake_responses.generate` inside the active span
- Sets all required span tags: `mcp.tool`, `mcp.tool.params_json`,
  `mcp.tool.param_count`, `honeypot.response_type`, `honeypot.response_preview`
- Returns the `.payload` dict (never raises — honeypot must always respond)

**Note:** All 4 handler files are independent and can be written in parallel.

---

### T07 — Transport Wrapper + Main Server
**Complexity:** M
**Depends on:** T03, T06
**Files to create:**
- `server/transport_wrapper.py`
- `server/main.py`

**Acceptance criteria:**
- `transport_wrapper.py`: `InstrumentedTransport` wraps MCP transport; every
  `receive()` starts a root span with `agent.id`, `mcp.method`,
  `mcp.session_id`, `honeypot.phase`, `mcp.message_size`
- `main.py`: MCP server with all 14 tools registered, dispatches to correct
  handler module, uses `InstrumentedTransport`
- Server starts with `uvicorn main:app` or `python main.py`
- Healthcheck endpoint `GET /healthz` returns `{"status": "ok"}`
- `GET /metrics` (port 8001) exposes Prometheus metrics if using
  `prometheus_client` push-gateway pattern (or rely solely on OTLP pipeline)

**Session ID strategy:** extract from MCP handshake if available; otherwise
derive from connection remote address + timestamp hash, stored in transport
wrapper instance.

---

### T08 — OTel Collector Config
**Complexity:** S
**Depends on:** T01 (directory exists)
**Files to create:**
- `collector/config.yaml`

**Acceptance criteria:**
- Uses `otlp/jaeger` exporter (not deprecated `jaeger` exporter)
- Receivers: OTLP gRPC on 4317, HTTP on 4318
- Processors: `memory_limiter` (512 MiB) → `batch` (5 s, 512 batch)
- Traces pipeline: → `otlp/jaeger`
- Metrics pipeline: → `prometheus` (endpoint 0.0.0.0:8889, namespace `mcp_honeypot`)
- `collector-config` passes `otelcol-contrib validate --config` without errors

---

### T09 — Prometheus Config
**Complexity:** S
**Depends on:** T01
**Files to create:**
- `prometheus/prometheus.yml`

**Acceptance criteria:**
- Scrapes `otel-collector:8889` every 15 s
- TSDB retention 30 d / 10 GB
- `promtool check config prometheus/prometheus.yml` passes

---

### T10 — Grafana Provisioning + Dashboards
**Complexity:** L
**Depends on:** T09 (datasource URLs)
**Files to create:**
- `dashboards/provisioning/datasources.yaml`
- `dashboards/provisioning/dashboards.yaml`
- `dashboards/json/attack-summary.json`
- `dashboards/json/agent-drilldown.json`
- `dashboards/json/anomaly-monitor.json`
- `dashboards/json/tool-intelligence.json`

**Acceptance criteria:**
- Grafana starts and shows all 4 dashboards without manual import
- `attack-summary.json`: 7 panels per spec (requests counter, active sessions
  gauge, request rate, anomaly rate, top tools bar, top agents table,
  credential probe stat with red threshold)
- `agent-drilldown.json`: `$agent_id` template variable from Prometheus label
  values; session timeline, tools pie, anomaly table, Jaeger trace links
- `anomaly-monitor.json`: heatmap, top anomaly types, 3 time series panels,
  alerting rules wired to CredentialProbeAlert + RapidEnumerationAlert
- `tool-intelligence.json`: call frequency heatmap (tool × hour), chain depth
  avg, tool co-occurrence matrix
- Auto-refresh set to 10 s on all dashboards
- `dashboards/provisioning/dashboards.yaml` sets `disableDeletion: false`,
  `updateIntervalSeconds: 10`, `allowUiUpdates: true`

---

### T11 — Docker Compose
**Complexity:** S
**Depends on:** T01, T08, T09, T10 (references volume mounts)
**Files to create:**
- `docker-compose.yaml`

**Acceptance criteria:**
- All 5 services: `mcp-honeypot`, `otel-collector`, `prometheus`, `jaeger`,
  `grafana`
- `jaeger` has `COLLECTOR_OTLP_ENABLED: "true"` and port 4317 exposed
  internally (for `otlp/jaeger` exporter) + 16686 exposed to host
- `mcp-honeypot` has `depends_on: otel-collector`; `otel-collector` has
  `depends_on: jaeger` (for startup ordering)
- Named volumes: `prometheus-data`, `jaeger-data`, `grafana-data`
- `docker-compose up --build` brings all services to healthy state

---

### T12 — Smoke Test
**Complexity:** S
**Depends on:** T07, T11
**Files to create:**
- `tests/smoke_test.py`

**Acceptance criteria:**
- Script connects to `http://localhost:8000` as an MCP client
- Calls at least one tool from each category (filesystem, web, exec, secrets)
- Calls secrets tool → verifies `credential_probe` flag appears in subsequent
  Jaeger trace (poll Jaeger API for up to 30 s)
- Calls `read_file` then `fetch_url` in same session → verifies
  `exfiltration_chain` flag in trace
- Calls a filesystem tool then `run_command` → verifies `privilege_escalation`
- `python tests/smoke_test.py` exits 0 on success
- Usable as a quick regression test during development

---

### T13 — Helm Chart (Phase 2)
**Complexity:** L
**Depends on:** T11 (final config shapes)
**Files to create:** Full `helm/` tree per `docs/helm.md`

**Acceptance criteria:**
- `helm lint ./helm` passes
- `helm template ./helm` renders all manifests without error
- `helm install mcp-honeypot ./helm --dry-run` succeeds
- PVCs defined for Prometheus (10 Gi), Jaeger (20 Gi), Grafana (5 Gi)
- All configmaps templated from `values.yaml` (no hardcoded endpoints)
- `values.yaml` documents every tunable with comments

---

## Dependency Graph

```
T01 (scaffold)
 ├── T02 (config)
 │    ├── T03 (otel setup) ──────────────────┐
 │    └── T04 (tagging) ──────────────────┐  │
 │         └── T05 (fake responses) ──┐   │  │
 │              └── T06a filesystem   │   │  │
 │              └── T06b web          ├───┴──┴──→ T07 (main) → T12 (smoke test)
 │              └── T06c exec         │
 │              └── T06d secrets ─────┘
 ├── T08 (collector config) ──────────────┐
 ├── T09 (prometheus config) ─────────────┤
 └── T10 (grafana dashboards) ────────────┴──→ T11 (docker-compose) → T12
                                                     ↓ (after Phase 1 stable)
                                                    T13 (helm)
```

## Parallelisation for a Solo Build

| Session | Tasks | Notes |
|---------|-------|-------|
| 1 | T01 | Unblocks everything |
| 2 | T02, T08, T09 | All pure files, no dependencies on each other |
| 3 | T03, T04, T10 | T03+T04 use T02; T10 can start once datasource URLs known |
| 4 | T05 | Needs T04 interface stable |
| 5 | T06a, T06b, T06c, T06d | All independent; 4 small files |
| 6 | T07, T11 | T07 needs T06 done; T11 needs T08-T10 done |
| 7 | T12 | Needs T07 + T11 (running stack) |
| 8 | T13 | Phase 2; start when Phase 1 is stable |

**Optimal agent parallelisation**: Sessions 2, 3, 5 each contain work that
can be split across concurrent agent instances with no shared file writes.
Sessions 1, 4, 6, 7, 8 are single sequential tasks.

---

## Implementation Notes

### MCP SDK Usage
Use `mcp.server.Server` with SSE transport (`mcp.server.sse.SseServerTransport`).
Register tools via `@server.call_tool()` and `@server.list_tools()` decorators.
The transport wrapper intercepts at the `read_stream` / `write_stream` level.

### Session ID
MCP SSE does not expose a built-in session identifier. Derive one per
connection: `hashlib.sha256(f"{remote_ip}:{connect_timestamp}".encode()).hexdigest()[:16]`.
Store on the transport wrapper instance; pass down to every handler call.

### Agent Fingerprinting
Tag `agent.id` using the `User-Agent` header (SSE) or the first message's
`clientInfo` field from the MCP `initialize` handshake. Fall back to
session ID if neither is present.

### Fake Response Realism
Vary responses slightly per call to defeat replay detection by agents:
inject a random timestamp, line count, or file size. Secrets tools should
return AWS-format-looking keys (AKIA…) so agents believe they found something
real — maximising dwell time.

### State Eviction
`session_state` is an in-process dict. Evict sessions inactive for >1 h on
every call (O(n) scan acceptable at research scale). This avoids unbounded
memory growth without requiring a background thread.

### No Persistent Server State
Per architecture.md: all data lives in Prometheus + Jaeger. `session_state`
is transient in-process cache only. On restart, session context is lost but
Prometheus/Jaeger retain all historical data.
