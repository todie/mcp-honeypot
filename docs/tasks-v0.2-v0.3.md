# Task Breakdown: v0.2.0 + v0.3.0

## v0.2.0 — Dynamic Tools (OpenAPI Mode)

### Foundation

**T34 — Extract static tools into ToolLoader interface**
Complexity: M | Blocks: T35-T40
- Create `server/tools/loaders/__init__.py` with `ToolLoader` protocol
- Create `server/tools/loaders/static.py` — extract current 13 tools from `registry.py`
- Refactor `registry.py` to call `load_tools(mode)` dispatcher
- `HONEYPOT_MODE` config var in `config.py` (default: `static`)
- All existing tests pass unchanged (zero regression)

**T35 — OpenAPI spec parser**
Complexity: M | Depends: T34
- Create `server/tools/loaders/openapi.py`
- Fetch spec from URL or local file (`OPENAPI_SPEC_URL` / `OPENAPI_SPEC_FILE`)
- Parse OpenAPI 3.x paths → `ToolMeta` list
- Tool naming: `{method}_{path_slug}` or `operationId` if present
- `OPENAPI_TOOL_PREFIX` (default `api_`), `OPENAPI_MAX_TOOLS` (default 50)
- Handle `$ref` resolution in schemas (depth limit 10)
- Graceful failure: invalid/unreachable spec → 0 tools + warning log

**T36 — JSON Schema faker**
Complexity: M | Depends: T35
- Create `server/tools/loaders/schema_faker.py`
- Walk JSON Schema and generate plausible values:
  - string (plain, email, uri, uuid, date-time, date, enum)
  - integer/number (min/max bounds)
  - boolean, array (1-5 items), object (recurse)
  - `$ref` resolution with circular ref protection
- Variation per call (different random values each time)
- 5% error response rate (mimics real API behavior)

**T37 — Category auto-mapping**
Complexity: S | Depends: T35
- Heuristic: path keywords + HTTP method → category
- `/secret`, `/credential`, `/key`, `/token`, `/auth` + `DELETE` → secrets
- `/exec`, `/run`, `/command`, `/shell` → exec
- `/file`, `/storage`, `/blob`, `/upload` → filesystem
- Everything else → web
- `OPENAPI_CATEGORY_MAP` env var override (JSON)
- Update `tagging.py` to use dynamic `CATEGORY_MAP` from registry

### Integration

**T38 — Combined mode**
Complexity: S | Depends: T34, T35
- `HONEYPOT_MODE=combined` merges static 13 + OpenAPI tools
- Name conflict resolution: static wins (documented)
- `tools/list` returns merged set
- Dispatch routes correctly to static handlers vs OpenAPI faker

**T39 — Adversarial agent --discover mode**
Complexity: S | Depends: T38
- `--discover` flag on adversarial agent
- Calls `tools/list` at connect, builds attack phases from discovered tools
- Auto-categorizes tools by name patterns (same heuristic as T37)
- Works with both static and OpenAPI tools

### Testing & Docs

**T40 — Tests for OpenAPI loader + schema faker**
Complexity: M | Depends: T35, T36
- `tests/test_openapi_loader.py` (~20 tests)
  - Parse Petstore spec, verify tool count/names/schemas
  - Tool naming edge cases (long paths, special chars, operationId)
  - `$ref` resolution (simple, nested, circular)
  - MAX_TOOLS limit enforcement
  - Invalid spec handling (bad JSON, missing paths, unreachable URL)
- `tests/test_schema_faker.py` (~15 tests)
  - Each type generates valid values
  - Format hints produce correct patterns
  - Enum picks from allowed values
  - Nested objects recurse correctly
  - Variation: same schema → different values per call
  - Error response rate (~5%)

**T41 — Update docs and examples for v0.2.0**
Complexity: S | Depends: T38
- Update README with OpenAPI mode quickstart
- Update CLAUDE.md with new config vars
- Add `examples/openapi_mode.py` — connect to Petstore-backed honeypot
- Update CHANGELOG.md with v0.2.0 section
- Update .env.example with new vars

**T42 — v0.2.0 release**
Complexity: S | Depends: T40, T41
- Bump VERSION to 0.2.0
- Run full test suite (unit + module + tools)
- Tag + push + GitHub Release
- Verify Docker image builds and runs in OpenAPI mode

---

## v0.3.0 — Plugin System

### Core

**T43 — ToolProvider protocol**
Complexity: S | Depends: T34 (ToolLoader exists)
- Create `server/tools/providers/protocol.py`
- Evolve `ToolLoader` → `ToolProvider`:
  - Add `owns_tool(tool_name) -> bool`
  - Add `health_check() -> bool`
  - Add `reload() -> None`
  - Add `priority: int` property
- `@runtime_checkable` for isinstance checks

**T44 — ProviderRegistry**
Complexity: M | Depends: T43
- Create `server/tools/providers/__init__.py` with `ProviderRegistry`
- `__init__(provider_names: list[str])` — discover + instantiate providers
- `load_all()` — merge tools from all providers, priority-based conflict resolution
- `generate_response(tool_name, params)` — route to owning provider
- `get_all_categories()` — merge category maps
- `reload_provider(name)` — atomic reload with read-write lock
- `health_check_all()` — periodic health status

**T45 — Migrate static + openapi to provider interface**
Complexity: S | Depends: T43, T44
- Move `loaders/static.py` → `providers/static.py`, implement `ToolProvider`
- Move `loaders/openapi.py` → `providers/openapi.py`, implement `ToolProvider`
- Move `loaders/schema_faker.py` → `providers/schema_faker.py`
- `TOOL_PROVIDERS` env var replaces `HONEYPOT_MODE`
- Backward compat: `HONEYPOT_MODE=openapi` → `TOOL_PROVIDERS=static,openapi`

**T46 — YAML provider**
Complexity: L | Depends: T44
- Create `server/tools/providers/yaml_provider.py`
- Load `.yaml` files from `YAML_TOOLS_DIR`
- Parse tool definitions: name, description, category, input_schema, response template
- Template engine with 14 functions:
  - `random_hex(N)`, `random_int(min,max)`, `random_float(min,max)`
  - `random_string(N)`, `random_choice('a','b','c')`, `uuid4()`
  - `now_iso()`, `future_timestamp(hours=N)`, `past_timestamp(days=N)`
  - `aws_access_key()`, `aws_secret_key()`, `jwt_token()`, `ipv4()`
- Provider header: name, description, default_category
- Validate schemas on load, warn on invalid tools

**T47 — Hot-reload**
Complexity: M | Depends: T44, T46
- Filesystem watcher on `YAML_TOOLS_DIR` (inotify or polling fallback)
- `PROVIDER_WATCH=true`, `PROVIDER_WATCH_INTERVAL=5`
- On file change: call `registry.reload_provider("yaml")`
- Atomic swap: concurrent tool calls see old or new, never partial
- Structured log on reload event
- Existing tools from unchanged providers not affected

**T48 — External provider entry_points**
Complexity: S | Depends: T44
- `ProviderRegistry` discovers providers via `importlib.metadata.entry_points`
- Group: `mcp_honeypot.providers`
- Format: `name = package.module:ClassName`
- Example: `aws = mcp_honeypot_provider_aws:AWSProvider`
- Falls back to built-in lookup for `static`, `openapi`, `yaml`

### Integration

**T49 — Dynamic CATEGORY_MAP**
Complexity: S | Depends: T44
- `tagging.py` reads categories from `ProviderRegistry.get_all_categories()`
- Called at startup and on any provider reload
- Thread-safe update (replace dict atomically)
- All 7+ anomaly flags work with dynamic categories

**T50 — Example YAML tool definitions**
Complexity: S | Depends: T46
- `custom_tools/cloud_lures.yaml` — AWS IAM, S3, Lambda endpoints
- `custom_tools/database_tools.yaml` — backup, credential rotation
- `custom_tools/ci_cd_tools.yaml` — Jenkins, GitHub Actions

### Testing & Docs

**T51 — Tests for provider system**
Complexity: M | Depends: T44, T46, T47
- `tests/test_provider_registry.py` (~15 tests)
  - Load multiple providers, verify merged tool list
  - Priority-based conflict resolution
  - Route generate_response to correct provider
  - Reload provider atomically
  - Health check all providers
- `tests/test_yaml_provider.py` (~20 tests)
  - Parse single/multi tool YAML files
  - All 14 template functions produce valid output
  - Invalid YAML → warning, not crash
  - Empty directory → 0 tools
  - Template syntax errors → skip tool, warn
- `tests/test_hot_reload.py` (~8 tests)
  - File create → new tool appears
  - File modify → tool definition updates
  - File delete → tool removed
  - Concurrent access during reload → no crash

**T52 — Update docs and examples for v0.3.0**
Complexity: S | Depends: T50
- Update README with YAML provider quickstart
- Update CLAUDE.md with provider config
- Add `examples/yaml_provider.py` — load custom tools from YAML
- Add `examples/custom_provider.py` — build a ToolProvider from scratch
- Update CHANGELOG.md with v0.3.0 section
- Update .env.example with TOOL_PROVIDERS, YAML_TOOLS_DIR, PROVIDER_WATCH

**T53 — v0.3.0 release**
Complexity: S | Depends: T51, T52
- Bump VERSION to 0.3.0
- Run full test suite
- Verify backward compat (HONEYPOT_MODE still works)
- Tag + push + GitHub Release

---

## Dependency Graph

```
v0.2.0:
  T34 (ToolLoader interface)
   ├── T35 (OpenAPI parser)
   │    ├── T36 (Schema faker)
   │    └── T37 (Category mapping)
   ├── T38 (Combined mode) ← T35
   │    └── T39 (Agent --discover)
   └── T40 (Tests) ← T35, T36
        └── T41 (Docs)
             └── T42 (Release)

v0.3.0:
  T43 (ToolProvider protocol) ← T34
   ├── T44 (ProviderRegistry)
   │    ├── T45 (Migrate static+openapi)
   │    ├── T46 (YAML provider)
   │    │    └── T47 (Hot-reload)
   │    ├── T48 (Entry points)
   │    └── T49 (Dynamic CATEGORY_MAP)
   └── T50 (Example YAMLs) ← T46
        └── T51 (Tests) ← T44, T46, T47
             └── T52 (Docs)
                  └── T53 (Release)
```

## Parallelization

### v0.2.0 (3-5 sessions)

| Session | Tasks | Notes |
|---------|-------|-------|
| 1 | T34 | Foundation — must be first |
| 2 | T35, T37 | Parser + category mapping in parallel |
| 3 | T36, T38 | Schema faker + combined mode |
| 4 | T39, T40 | Agent discover + tests |
| 5 | T41, T42 | Docs + release |

### v0.3.0 (5-8 sessions)

| Session | Tasks | Notes |
|---------|-------|-------|
| 1 | T43 | Protocol definition |
| 2 | T44 | Registry — the core |
| 3 | T45, T48 | Migration + entry points (parallel) |
| 4 | T46 | YAML provider (largest task) |
| 5 | T47, T49 | Hot-reload + dynamic categories (parallel) |
| 6 | T50, T51 | Example YAMLs + tests |
| 7 | T52, T53 | Docs + release |
