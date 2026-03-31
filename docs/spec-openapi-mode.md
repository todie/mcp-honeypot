# Specification: OpenAPI Mode (v0.2.0)

## Overview

The honeypot gains the ability to dynamically generate MCP tool definitions
from any OpenAPI 3.x specification. Instead of only the 13 hardcoded tools,
a researcher can point the honeypot at a real API's spec and it will
automatically expose those endpoints as fake MCP tools — complete with
plausible response generation and full telemetry.

## Architecture

```
                    ┌─────────────────────────┐
  OpenAPI Spec ────▶│ openapi.py (loader)      │
  (URL or file)     │  parse paths/operations  │
                    │  generate ToolMeta list   │
                    └───────────┬──────────────┘
                                │
                    ┌───────────▼──────────────┐
  Static tools ────▶│ registry.py (facade)      │
  (static.py)       │  load_tools(mode)         │
                    │  merged TOOL_REGISTRY     │
                    └───────────┬──────────────┘
                                │
                    ┌───────────▼──────────────┐
                    │ schema_faker.py            │
                    │  JSON Schema → fake values │
                    └──────────────────────────┘
```

## New Files

```
server/tools/loaders/
  __init__.py          # ToolLoader protocol + load_tools() dispatcher
  static.py            # current 13 tools extracted from registry.py
  openapi.py           # OpenAPI 3.x spec → ToolMeta list
  schema_faker.py      # JSON Schema → plausible fake values
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `HONEYPOT_MODE` | `static` | Tool loading mode: `static`, `openapi`, or `combined` |
| `OPENAPI_SPEC_URL` | — | URL to fetch OpenAPI spec from |
| `OPENAPI_SPEC_FILE` | — | Local file path (alternative to URL) |
| `OPENAPI_CATEGORY_MAP` | — | JSON mapping: path pattern → anomaly category |
| `OPENAPI_TOOL_PREFIX` | `api_` | Prefix for generated tool names |
| `OPENAPI_MAX_TOOLS` | `50` | Maximum tools to generate (prevents 800-endpoint specs) |

## ToolLoader Protocol

This is the internal interface that will evolve into the public `ToolProvider`
protocol in v0.3.0. Designed to be minimal now, extensible later.

```python
from typing import Protocol

class ToolLoader(Protocol):
    """Interface for loading tools from a source."""

    name: str

    def load(self) -> list[ToolMeta]:
        """Return tool definitions from this source."""
        ...

    async def generate_response(self, tool_name: str, params: dict) -> FakeResponse:
        """Generate a plausible fake response for the given tool call."""
        ...

    def get_categories(self) -> dict[str, str]:
        """Return tool name → anomaly category mapping."""
        ...
```

## OpenAPI Loader

### Tool Name Generation

Each OpenAPI operation becomes one MCP tool:

```
POST /api/v1/users          → post_api_v1_users
GET  /api/v1/users/{id}     → get_api_v1_users_by_id
DELETE /pets/{petId}         → delete_pets_by_petid
```

Rules:
- HTTP method prefix (lowercase)
- Path segments joined with `_`
- Path parameters `{name}` replaced with `by_name`
- Prefixed with `OPENAPI_TOOL_PREFIX` (default `api_`)
- Truncated if > 64 characters
- If `operationId` exists in spec, use it instead (already unique)

### Input Schema Generation

The tool's `inputSchema` is assembled from three OpenAPI sources:

1. **Path parameters** → required string properties
2. **Query parameters** → optional properties with types from the spec
3. **Request body** → merged from `requestBody.content.application/json.schema`

```python
def build_input_schema(operation: dict, path_params: list[str]) -> dict:
    schema = {"type": "object", "properties": {}, "required": []}

    # Path params are always required
    for param in path_params:
        schema["properties"][param] = {"type": "string"}
        schema["required"].append(param)

    # Query params
    for param in operation.get("parameters", []):
        if param["in"] == "query":
            schema["properties"][param["name"]] = param.get("schema", {"type": "string"})
            if param.get("required"):
                schema["required"].append(param["name"])

    # Request body
    body_schema = (operation
        .get("requestBody", {})
        .get("content", {})
        .get("application/json", {})
        .get("schema", {}))
    if body_schema:
        for prop, prop_schema in body_schema.get("properties", {}).items():
            schema["properties"][prop] = prop_schema
        schema["required"].extend(body_schema.get("required", []))

    return schema
```

### Category Auto-Mapping

Tools are assigned anomaly detection categories using heuristics:

| Pattern | Category | Examples |
|---------|----------|----------|
| Path contains `/secret`, `/credential`, `/key`, `/token`, `/auth` | `secrets` | `/api/v1/secrets/{name}` |
| Path contains `/exec`, `/run`, `/command`, `/shell`, `/eval` | `exec` | `/api/exec` |
| Path contains `/file`, `/storage`, `/blob`, `/upload`, `/download` | `filesystem` | `/api/files/{path}` |
| `DELETE` method on any path | `secrets` | `DELETE /users/{id}` |
| Everything else | `web` | `GET /api/v1/status` |

Override with `OPENAPI_CATEGORY_MAP`:
```json
{
  "/api/v1/secrets/*": "secrets",
  "/api/v1/admin/*": "exec",
  "DELETE *": "secrets"
}
```

## Schema Faker

Generates plausible values from JSON Schema definitions:

| Schema Type | Generation Strategy |
|-------------|-------------------|
| `string` (no format) | Random 8-20 char alphanumeric |
| `string` format=`email` | `user{N}@example.com` |
| `string` format=`uri` | `https://api.example.com/{path}` |
| `string` format=`uuid` | `uuid.uuid4()` |
| `string` format=`date-time` | Random recent ISO timestamp |
| `string` format=`date` | Random recent date |
| `string` with `enum` | Random pick from enum values |
| `integer` | Random within `[minimum, maximum]` (default 1-1000) |
| `number` | Random float within bounds |
| `boolean` | Random True/False |
| `array` | 1-5 items generated from `items` schema |
| `object` | Recurse into `properties` |
| `$ref` | Resolve reference, recurse (depth limit = 5) |

### Variation

Same tool, same params → different response each call (anti-replay, matching
the existing fake_responses.py pattern). Achieved by seeding randomness per-call.

### Error Responses

5% of calls return a plausible error response matching the spec's error schema
(or a generic `{"error": "not_found", "message": "Resource not found"}` if no
error schema defined). This mimics real API behavior and prevents agents from
detecting the honeypot by the absence of errors.

## Integration Points

### What changes
- `registry.py` gains `load_tools(mode)` dispatcher
- `fake_responses.py` gains a `generate_from_schema()` code path for OpenAPI tools
- `config.py` gains `HONEYPOT_MODE` and OpenAPI-related settings
- `tools/handlers/__init__.py` dispatch works unchanged (routes by category)

### What stays the same
- All 7 anomaly flags (operate on tool names + categories)
- Transport wrapper, SSE protocol
- OTel pipeline, dashboards, recording rules
- Rate limiting, security headers
- Adversarial agent (gains `--discover` flag to auto-use tools from `tools/list`)

## Acceptance Criteria

1. `HONEYPOT_MODE=openapi OPENAPI_SPEC_URL=https://petstore3.swagger.io/api/v3/openapi.json docker compose up`
   → server advertises Petstore tools via `tools/list`
2. Agent calling `api_get_pet_by_id(petId=1)` → plausible Pet JSON response
3. Jaeger span: `mcp.tool=api_get_pet_by_id`, category-based anomaly flags
4. `HONEYPOT_MODE=combined` → 13 static tools + N OpenAPI tools merged
5. `HONEYPOT_MODE=static` (default) → identical to v0.1.x (zero regression)
6. OpenAPI tools respect `OPENAPI_MAX_TOOLS` limit
7. Invalid/unreachable spec URL → server starts with 0 OpenAPI tools + warning log
8. Unit tests for spec parsing, schema faking, category mapping
