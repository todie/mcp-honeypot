"""Anomaly tagging engine for the MCP honeypot.

Analyses every tool call in the context of its session and returns a list
of anomaly flag strings.  Flags are consumed by the instrumentation layer
and attached to OpenTelemetry spans.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from typing import Any

# ---------------------------------------------------------------------------
# Tool category mapping
# ---------------------------------------------------------------------------
SECRETS_TOOLS = {"get_env_var", "read_secret", "list_secrets", "get_api_key"}
FILESYSTEM_TOOLS = {"read_file", "write_file", "list_directory", "delete_file"}
WEB_TOOLS = {"fetch_url", "search_web", "screenshot"}
EXEC_TOOLS = {"run_command", "run_python"}

READ_TOOLS = {"read_file", "list_directory", "get_env_var", "read_secret",
              "list_secrets", "get_api_key"}
NETWORK_TOOLS = {"fetch_url", "search_web", "screenshot"}

CATEGORY_MAP: dict[str, str] = {}
for _tool in SECRETS_TOOLS:
    CATEGORY_MAP[_tool] = "secrets"
for _tool in FILESYSTEM_TOOLS:
    CATEGORY_MAP[_tool] = "filesystem"
for _tool in WEB_TOOLS:
    CATEGORY_MAP[_tool] = "web"
for _tool in EXEC_TOOLS:
    CATEGORY_MAP[_tool] = "exec"

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------
RAPID_WINDOW_SECONDS = 5.0
RAPID_THRESHOLD = 10          # flag when count EXCEEDS this
REPLAY_TTL_SECONDS = 60.0
EXFIL_TTL_SECONDS = 300.0     # read→network chain window
SESSION_EVICT_SECONDS = 3600.0  # 1 hour

# ---------------------------------------------------------------------------
# Per-session state
# ---------------------------------------------------------------------------

def _new_session() -> dict[str, Any]:
    return {
        "calls": [],            # list of {"tool": str, "time": float}
        "hashes": {},           # call_hash → last_seen_time
        "last_read_time": None, # monotonic time of last READ_TOOLS call
        "categories_seen": set(),
        "last_active": time.monotonic(),
    }


session_state: dict[str, dict[str, Any]] = {}


def reset_state() -> None:
    """Clear all session state — used for test isolation."""
    session_state.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_plausible_base64(value: str) -> bool:
    """Return True if *value* successfully base64-decodes."""
    try:
        base64.b64decode(value, validate=True)
        return True
    except Exception:
        return False


def _call_hash(tool_name: str, params: dict[str, Any]) -> str:
    """Deterministic hash of a tool call (tool + params)."""
    try:
        raw = f"{tool_name}:{json.dumps(params, sort_keys=True, default=str)}"
    except Exception:
        raw = f"{tool_name}:{params!s}"
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Eviction
# ---------------------------------------------------------------------------

def _maybe_evict(session_id: str, now: float) -> None:
    state = session_state.get(session_id)
    if state is None:
        return
    if now - state["last_active"] > SESSION_EVICT_SECONDS:
        del session_state[session_id]


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------

def detect_anomalies(
    tool_name: str,
    params: dict[str, Any],
    session_id: str,
) -> list[str]:
    """Return a list of anomaly flag strings for a single tool call."""
    now = time.monotonic()

    # Evict stale sessions before anything else
    _maybe_evict(session_id, now)

    # Lazy-init session
    if session_id not in session_state:
        session_state[session_id] = _new_session()
    state = session_state[session_id]
    state["last_active"] = now

    flags: list[str] = []

    # --- credential_probe ---
    if tool_name in SECRETS_TOOLS:
        flags.append("credential_probe")

    # --- path_traversal ---
    if re.search(r"\.\./", str(params)):
        flags.append("path_traversal")

    # --- param_obfuscation (top-level string values only) ---
    for v in params.values():
        if isinstance(v, str) and len(v) > 20 and _is_plausible_base64(v):
            flags.append("param_obfuscation")
            break

    # --- rapid_enumeration ---
    recent = [c for c in state["calls"] if now - c["time"] < RAPID_WINDOW_SECONDS]
    if len(recent) > RAPID_THRESHOLD:
        flags.append("rapid_enumeration")

    # --- replay_attempt ---
    h = _call_hash(tool_name, params)
    prev_time = state["hashes"].get(h)
    if prev_time is not None and (now - prev_time) <= REPLAY_TTL_SECONDS:
        flags.append("replay_attempt")
        # Do NOT update the timestamp on replay — the original timestamp
        # anchors the TTL window so replays eventually age out.
    else:
        state["hashes"][h] = now

    # --- exfiltration_chain ---
    if tool_name in NETWORK_TOOLS and state["last_read_time"] is not None:
        if (now - state["last_read_time"]) <= EXFIL_TTL_SECONDS:
            flags.append("exfiltration_chain")

    if tool_name in READ_TOOLS:
        state["last_read_time"] = now

    # --- privilege_escalation ---
    category = CATEGORY_MAP.get(tool_name)
    if category is not None:
        if state["categories_seen"] and category not in state["categories_seen"]:
            flags.append("privilege_escalation")
        state["categories_seen"].add(category)

    # Book-keeping
    state["calls"].append({"tool": tool_name, "time": now})

    return flags
