"""Interactive agent simulator for the MCP Honeypot.

Connects to the honeypot, runs configurable attack patterns, and
displays live metrics from Jaeger + Prometheus.

Usage:
    python tools/agent_simulator.py [--scenario all|credential|exfil|escalation|rapid|traversal|replay]
    python tools/agent_simulator.py --interactive
    python tools/agent_simulator.py --base-url http://localhost:8000 --scenario credential
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from typing import Any

# Add project root to path so imports work when running as a script
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from tests.harness.mcp_client import McpTestClient
from tests.harness.scenarios import (
    SCENARIOS,
    full_attack_sequence,
)
from tests.harness.telemetry import TelemetryHarness

# ---------------------------------------------------------------------------
# ANSI color helpers (no dependencies)
# ---------------------------------------------------------------------------

class C:
    """ANSI color codes."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"

    @staticmethod
    def disable() -> None:
        for attr in ("RESET", "BOLD", "DIM", "RED", "GREEN", "YELLOW",
                      "BLUE", "MAGENTA", "CYAN", "WHITE"):
            setattr(C, attr, "")


def header(text: str) -> None:
    print(f"\n{C.BOLD}{C.CYAN}{'=' * 60}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  {text}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'=' * 60}{C.RESET}")


def info(text: str) -> None:
    print(f"  {C.BLUE}[*]{C.RESET} {text}")


def success(text: str) -> None:
    print(f"  {C.GREEN}[+]{C.RESET} {text}")


def warn(text: str) -> None:
    print(f"  {C.YELLOW}[!]{C.RESET} {text}")


def error(text: str) -> None:
    print(f"  {C.RED}[-]{C.RESET} {text}")


def dim(text: str) -> str:
    return f"{C.DIM}{text}{C.RESET}"


# ---------------------------------------------------------------------------
# Telemetry display
# ---------------------------------------------------------------------------

async def show_telemetry(harness: TelemetryHarness, label: str = "") -> None:
    """Query and display current telemetry state."""
    if label:
        print(f"\n  {C.MAGENTA}--- Telemetry: {label} ---{C.RESET}")

    # Traces
    traces = await harness.wait_for_traces(timeout=10)
    span_count = sum(len(t.get("spans", [])) for t in traces)
    info(f"Traces: {len(traces)}, Spans: {span_count}")

    # Anomaly flags from traces
    flags = await harness.get_all_anomaly_flags(timeout=5)
    if flags:
        success(f"Anomaly flags detected: {C.YELLOW}{', '.join(sorted(flags))}{C.RESET}")
    else:
        info("No anomaly flags detected yet")

    # Prometheus metrics (may not be available)
    tool_count = await harness.get_tool_call_count()
    anomaly_count = await harness.get_anomaly_count()
    if tool_count or anomaly_count:
        info(f"Prometheus: tool_calls={tool_count}, anomalies={anomaly_count}")


# ---------------------------------------------------------------------------
# Scenario runner
# ---------------------------------------------------------------------------

async def run_scenario(
    client: McpTestClient,
    harness: TelemetryHarness,
    scenario_name: str,
) -> None:
    """Run a named scenario and display results."""
    header(f"Scenario: {scenario_name}")

    start = time.monotonic()

    if scenario_name == "all":
        results = await full_attack_sequence(client)
        for name, result_list in results.items():
            success(f"  {name}: {len(result_list)} calls completed")
    else:
        func = SCENARIOS.get(scenario_name)
        if func is None:
            error(f"Unknown scenario: {scenario_name}")
            error(f"Available: {', '.join(SCENARIOS.keys())}")
            return

        results = await func(client)
        if isinstance(results, list):
            success(f"Completed {len(results)} tool calls")
        else:
            success("Completed")

    elapsed = time.monotonic() - start
    info(f"Elapsed: {elapsed:.2f}s")

    # Show telemetry after scenario
    await asyncio.sleep(2)  # Brief pause for telemetry propagation
    await show_telemetry(harness, label=f"after {scenario_name}")


# ---------------------------------------------------------------------------
# Interactive mode
# ---------------------------------------------------------------------------

INTERACTIVE_MENU = f"""
{C.BOLD}Available commands:{C.RESET}
  {C.CYAN}1{C.RESET} | credential   - Probe all 4 secrets tools
  {C.CYAN}2{C.RESET} | exfil        - read_file + fetch_url exfiltration chain
  {C.CYAN}3{C.RESET} | escalation   - Cross all 4 tool categories
  {C.CYAN}4{C.RESET} | rapid        - Rapid-fire 15 calls in quick succession
  {C.CYAN}5{C.RESET} | traversal    - Path traversal attempts
  {C.CYAN}6{C.RESET} | replay       - Duplicate call replay attack
  {C.CYAN}7{C.RESET} | all          - Run full attack sequence
  {C.CYAN}t{C.RESET} | telemetry    - Show current telemetry summary
  {C.CYAN}l{C.RESET} | list         - List available tools from server
  {C.CYAN}c{C.RESET} | call <tool>  - Call a specific tool interactively
  {C.CYAN}q{C.RESET} | quit         - Exit
"""

SCENARIO_MAP = {
    "1": "credential", "credential": "credential",
    "2": "exfil", "exfil": "exfil",
    "3": "escalation", "escalation": "escalation",
    "4": "rapid", "rapid": "rapid",
    "5": "traversal", "traversal": "traversal",
    "6": "replay", "replay": "replay",
    "7": "all", "all": "all",
}


async def interactive_mode(
    client: McpTestClient,
    harness: TelemetryHarness,
) -> None:
    """Run the interactive menu loop."""
    header("MCP Honeypot Agent Simulator -- Interactive Mode")
    info(f"Connected to {client._base_url} (session={client.session_id})")

    # List tools on start
    tools = await client.list_tools()
    info(f"Server advertises {len(tools)} tools")

    while True:
        print(INTERACTIVE_MENU)
        try:
            raw = input(f"  {C.BOLD}>{C.RESET} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not raw:
            continue

        if raw in ("q", "quit", "exit"):
            break

        if raw in ("t", "telemetry"):
            await show_telemetry(harness, label="current state")
            continue

        if raw in ("l", "list"):
            header("Available Tools")
            for tool in tools:
                name = tool.get("name", "?")
                desc = tool.get("description", "")[:60]
                print(f"    {C.GREEN}{name:20s}{C.RESET} {dim(desc)}")
            continue

        if raw.startswith("c ") or raw.startswith("call "):
            parts = raw.split(None, 1)
            if len(parts) < 2:
                warn("Usage: call <tool_name>")
                continue
            tool_name = parts[1].strip()

            # Find tool schema
            tool_def = None
            for t in tools:
                if t.get("name") == tool_name:
                    tool_def = t
                    break
            if tool_def is None:
                error(f"Unknown tool: {tool_name}")
                continue

            # Gather arguments
            schema = tool_def.get("inputSchema", {})
            properties = schema.get("properties", {})
            required = set(schema.get("required", []))
            arguments: dict[str, Any] = {}

            for param_name, param_schema in properties.items():
                req_tag = f" {C.RED}(required){C.RESET}" if param_name in required else ""
                desc = param_schema.get("description", "")
                default = param_schema.get("default")
                prompt_parts = [f"    {param_name}{req_tag}"]
                if desc:
                    prompt_parts.append(f" [{desc}]")
                if default is not None:
                    prompt_parts.append(f" (default: {default})")
                prompt_parts.append(": ")
                try:
                    val = input("".join(prompt_parts)).strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    break
                if val:
                    # Try to parse as JSON for non-string types
                    ptype = param_schema.get("type")
                    if ptype == "integer":
                        try:
                            arguments[param_name] = int(val)
                        except ValueError:
                            arguments[param_name] = val
                    elif ptype == "object":
                        try:
                            arguments[param_name] = json.loads(val)
                        except json.JSONDecodeError:
                            arguments[param_name] = val
                    else:
                        arguments[param_name] = val
                elif default is not None:
                    arguments[param_name] = default
                elif param_name in required:
                    error(f"Required parameter '{param_name}' not provided, skipping call")
                    break
            else:
                # All params gathered, make the call
                info(f"Calling {tool_name} with {json.dumps(arguments)}")
                try:
                    result = await client.call_tool(tool_name, arguments)
                    success(f"Result: {json.dumps(result, indent=2)[:500]}")
                except Exception as exc:
                    error(f"Call failed: {exc}")

                await asyncio.sleep(1)
                await show_telemetry(harness, label=f"after {tool_name}")
            continue

        # Check for scenario
        scenario = SCENARIO_MAP.get(raw)
        if scenario:
            await run_scenario(client, harness, scenario)
            continue

        warn(f"Unknown command: {raw}")


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

async def print_final_summary(harness: TelemetryHarness) -> None:
    """Print a final summary table."""
    header("Final Summary")

    traces = await harness.wait_for_traces(timeout=10)
    span_count = sum(len(t.get("spans", [])) for t in traces)
    flags = await harness.get_all_anomaly_flags(timeout=5)
    tool_count = await harness.get_tool_call_count()
    anomaly_count = await harness.get_anomaly_count()

    rows = [
        ("Traces collected", str(len(traces))),
        ("Total spans", str(span_count)),
        ("Prometheus tool calls", str(tool_count)),
        ("Prometheus anomalies", str(anomaly_count)),
        ("Anomaly flags detected", ", ".join(sorted(flags)) or "(none)"),
    ]

    max_label = max(len(r[0]) for r in rows)
    for label, value in rows:
        print(f"  {label:<{max_label + 2}} {C.BOLD}{value}{C.RESET}")

    # Collect tools seen
    tools_seen: set[str] = set()
    for trace in traces:
        for span in trace.get("spans", []):
            for tag in span.get("tags", []):
                if tag.get("key") == "mcp.tool":
                    tools_seen.add(str(tag["value"]))
    if tools_seen:
        print(f"\n  {C.DIM}Tools exercised:{C.RESET} {', '.join(sorted(tools_seen))}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def async_main(args: argparse.Namespace) -> int:
    """Async entry point."""
    if args.no_color:
        C.disable()

    harness = TelemetryHarness(
        jaeger_url=args.jaeger_url,
        prometheus_url=args.prometheus_url,
    )

    header("MCP Honeypot Agent Simulator")
    info(f"Target: {args.base_url}")
    info(f"Jaeger: {args.jaeger_url}")
    info(f"Prometheus: {args.prometheus_url}")

    # Check health
    import httpx
    try:
        resp = await httpx.AsyncClient(timeout=5).get(f"{args.base_url}/healthz")
        if resp.status_code == 200:
            success("Server health check passed")
        else:
            warn(f"Health check returned {resp.status_code}")
    except Exception as exc:
        error(f"Cannot reach server at {args.base_url}: {exc}")
        error("Is the Docker Compose stack running? (docker-compose up)")
        return 1

    client = McpTestClient(
        base_url=args.base_url,
        user_agent=args.user_agent or "AgentSimulator/1.0",
        client_info={"name": args.agent_name, "version": "1.0"},
    )

    try:
        info("Connecting via SSE...")
        await client.connect()
        success(f"Connected (session={client.session_id})")

        info("Sending MCP initialize handshake...")
        init_result = await client.initialize()
        success(f"Initialized: protocol={init_result.get('protocolVersion', '?')}")

        if args.interactive:
            await interactive_mode(client, harness)
        elif args.scenario:
            await run_scenario(client, harness, args.scenario)
        else:
            # Default: run all scenarios
            await run_scenario(client, harness, "all")

        await print_final_summary(harness)

    except TimeoutError as exc:
        error(f"Timeout: {exc}")
        return 1
    except Exception as exc:
        error(f"Error: {exc}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        await client.close()
        await harness.close()

    success("Simulation complete")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Interactive agent simulator for the MCP Honeypot.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tools/agent_simulator.py                          # Run all scenarios
  python tools/agent_simulator.py --scenario credential    # Run one scenario
  python tools/agent_simulator.py --interactive            # Interactive menu
  python tools/agent_simulator.py --agent-name EvilBot     # Custom agent name
        """,
    )
    parser.add_argument(
        "--scenario", "-s",
        choices=list(SCENARIOS.keys()),
        default=None,
        help="Run a specific attack scenario (default: all)",
    )
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Interactive mode with menu-driven tool selection",
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:8000",
        help="MCP server base URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--jaeger-url",
        default="http://localhost:16686",
        help="Jaeger URL (default: http://localhost:16686)",
    )
    parser.add_argument(
        "--prometheus-url",
        default="http://localhost:9090",
        help="Prometheus URL (default: http://localhost:9090)",
    )
    parser.add_argument(
        "--user-agent",
        default=None,
        help="Custom User-Agent header for fingerprinting tests",
    )
    parser.add_argument(
        "--agent-name",
        default="AgentSimulator",
        help="Client name sent in MCP initialize (default: AgentSimulator)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )

    args = parser.parse_args()
    sys.exit(asyncio.run(async_main(args)))


if __name__ == "__main__":
    main()
