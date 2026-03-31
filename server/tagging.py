"""Anomaly detection and session tagging for the MCP honeypot.

Implements all 7 anomaly flags from the threat model:
  credential_probe, path_traversal, param_obfuscation,
  rapid_enumeration, replay_attempt, exfiltration_chain,
  privilege_escalation.

Session state is an in-process dict keyed by session_id.  Entries
inactive for >1 h are evicted on every call (no background thread).
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

TOOL_CATEGORIES: dict[str, str] = {
    "read_file": "filesystem",
    "write_file": "filesystem",
    "list_directory": "filesystem",
    "delete_file": "filesystem",
    "fetch_url": "web",
    "search_web": "web",
    "screenshot": "web",
    "run_command": "exec",
    "run_python": "exec",
    "get_env_var": "secrets",
    "read_secret": "secrets",
    "list_secrets": "secrets",
    "get_api_key": "secrets",
}

READ_TOOLS: set[str] = {
    "read_file",
    "list_directory",
    "get_env_var",
    "read_secret",
    "list_secrets",
    "get_api_key",
}

NETWORK_TOOLS: set[str] = {"fetch_url", "search_web", "screenshot"}

# Exfiltration chain TTL — how long after a read-family call a subsequent
# network-family call is considered suspicious.  Reads from env so the
# value can be overridden without touching code; falls back to 120 s.
DEFAULT_EXFIL_TTL: int = 120
_EXFIL_TTL: int = int(os.environ.get("SESSION_EXFIL_TTL_SECONDS", str(DEFAULT_EXFIL_TTL)))

# Rapid-enumeration thresholds
_RAPID_WINDOW_SECS: float = 5.0
_RAPID_CALL_THRESHOLD: int = 10

# Replay-attempt window
_REPLAY_WINDOW_SECS: float = 60.0

# Session eviction after inactivity
_EVICTION_SECS: float = 3600.0  # 1 hour

# ---------------------------------------------------------------------------
# Per-session state
# ---------------------------------------------------------------------------


@dataclass
class _SessionData:
    """Mutable tracking data for a single session."""

    # Timestamps of all calls (used for rapid_enumeration)
    call_timestamps: list[float] = field(default_factory=list)

    # MD5 hex → timestamp of last occurrence (for replay_attempt)
    call_hashes: dict[str, float] = field(default_factory=dict)

    # Last time a read-family tool was invoked (for exfiltration_chain)
    last_read_time: float | None = None

    # Ordered list of unique categories seen so far (for privilege_escalation)
    categories_seen: list[str] = field(default_factory=list)

    # Timestamp of last activity (for eviction)
    last_activity: float = field(default_factory=time.monotonic)


# Global in-process state, keyed by session_id.
session_state: dict[str, _SessionData] = {}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_plausible_base64(value: str) -> bool:
    """Return True if *value* (length >20) decodes as valid base64."""
    try:
        decoded = base64.b64decode(value, validate=True)
        # b64decode accepts empty bytes; also reject if the round-trip
        # doesn't match (e.g. random strings that happen to decode).
        return base64.b64encode(decoded).decode() == value
    except Exception:
        return False


def _call_hash(tool_name: str, params: dict[str, Any]) -> str:
    """Deterministic hash of a tool call for replay detection."""
    raw = f"{tool_name}{params!s}"
    return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()


def _evict_stale_sessions(now: float) -> None:
    """Remove sessions that have been inactive for >1 h."""
    stale = [
        sid
        for sid, data in session_state.items()
        if (now - data.last_activity) > _EVICTION_SECS
    ]
    for sid in stale:
        del session_state[sid]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_anomalies(
    tool_name: str,
    params: dict[str, Any],
    session_id: str,
) -> list[str]:
    """Return a list of anomaly flag strings for this tool call.

    All 7 flags are checked on every call.  Session state is updated
    as a side-effect.
    """
    now = time.monotonic()

    # Evict stale sessions first (simple O(n) scan).
    _evict_stale_sessions(now)

    # Get or create session data.
    sd = session_state.setdefault(session_id, _SessionData(last_activity=now))

    flags: list[str] = []

    category = TOOL_CATEGORIES.get(tool_name)

    # --- 1. credential_probe ---
    if category == "secrets":
        flags.append("credential_probe")

    # --- 2. path_traversal ---
    if "../" in str(params):
        flags.append("path_traversal")

    # --- 3. param_obfuscation ---
    for value in params.values():
        if isinstance(value, str) and len(value) > 20 and _is_plausible_base64(value):
            flags.append("param_obfuscation")
            break  # one flag per call is enough

    # --- 4. rapid_enumeration ---
    sd.call_timestamps.append(now)
    # Prune timestamps older than the rapid window.
    cutoff = now - _RAPID_WINDOW_SECS
    sd.call_timestamps = [ts for ts in sd.call_timestamps if ts >= cutoff]
    if len(sd.call_timestamps) > _RAPID_CALL_THRESHOLD:
        flags.append("rapid_enumeration")

    # --- 5. replay_attempt ---
    h = _call_hash(tool_name, params)
    prev_time = sd.call_hashes.get(h)
    if prev_time is not None and (now - prev_time) <= _REPLAY_WINDOW_SECS:
        flags.append("replay_attempt")
    sd.call_hashes[h] = now

    # --- 6. exfiltration_chain ---
    if tool_name in NETWORK_TOOLS and sd.last_read_time is not None:
        if (now - sd.last_read_time) <= _EXFIL_TTL:
            flags.append("exfiltration_chain")
    if tool_name in READ_TOOLS:
        sd.last_read_time = now

    # --- 7. privilege_escalation ---
    if category is not None:
        if len(sd.categories_seen) >= 1 and category not in sd.categories_seen:
            flags.append("privilege_escalation")
        if category not in sd.categories_seen:
            sd.categories_seen.append(category)

    # Update last-activity timestamp.
    sd.last_activity = now

    return flags


def reset_state() -> None:
    """Clear all session state.  Intended for use in tests."""
    session_state.clear()
