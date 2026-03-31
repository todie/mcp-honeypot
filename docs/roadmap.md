# Roadmap

## Release Plan

| Version | Codename | Focus | Status |
|---------|----------|-------|--------|
| v0.1.0 | Phase 1 | Core honeypot + static tools + telemetry | Merged |
| v0.1.1 | Phase 1.1 | Agent fix, tests, hardening, release tooling | PR #11 |
| v0.2.0 | OpenAPI Mode | Dynamic tool generation from OpenAPI specs | Planned |
| v0.3.0 | Plugin System | Provider architecture + YAML tools + hot-reload | Planned |

## v0.2.0 — OpenAPI Mode

See [spec-openapi-mode.md](spec-openapi-mode.md) for the full specification.

**Goal:** The honeypot can mimic any API by consuming an OpenAPI 3.x spec.
A researcher points it at a Kubernetes API spec, a cloud provider API, or any
service's swagger.json — and the honeypot automatically generates MCP tools
that return plausible fake responses.

**Key deliverables:**
- `ToolLoader` protocol (internal interface, seed of the plugin system)
- OpenAPI 3.x spec parser → `ToolMeta` generation
- JSON Schema → plausible fake value generation
- Automatic category mapping (heuristic + override)
- `HONEYPOT_MODE=static|openapi|combined` configuration
- Zero behavior change for existing users (default mode = static)

## v0.3.0 — Plugin System

See [spec-plugin-system.md](spec-plugin-system.md) for the full specification.

**Goal:** The `ToolLoader` protocol evolves into a public `ToolProvider`
plugin interface. Multiple providers contribute tools from different sources.
Non-developers can add lures via YAML files.

**Key deliverables:**
- `ToolProvider` protocol with `owns_tool()`, `health_check()`, `reload()`
- `ProviderRegistry` for discovery, loading, merging, conflict resolution
- YAML provider (drop .yaml files → tools appear)
- Hot-reload via filesystem watch
- Backward compatibility shim for v0.2.0 config
- Community provider packaging pattern (`pip install mcp-honeypot-provider-X`)
