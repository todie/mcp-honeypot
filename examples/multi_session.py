#!/usr/bin/env python3
"""Multiple concurrent agent sessions with different fingerprints.

Demonstrates:
- Running N agents in parallel, each with a unique identity
- Different User-Agent headers and MCP clientInfo
- Observing per-agent metrics in Grafana's Agent Drilldown dashboard

Usage:
    python examples/multi_session.py

Requires: docker compose up, pip install httpx
"""

import asyncio
import json

import httpx

HONEYPOT_URL = "http://localhost:8000"

# Each agent has a distinct identity
AGENTS = [
    {"user_agent": "ReconBot/1.0", "client_name": "ReconBot", "version": "1.0",
     "tools": [("list_directory", {"path": "/"}), ("read_file", {"path": "/etc/passwd"})]},
    {"user_agent": "DataHarvester/2.3", "client_name": "DataHarvester", "version": "2.3",
     "tools": [("get_env_var", {"name": "AWS_ACCESS_KEY_ID"}), ("get_api_key", {"service": "openai"})]},
    {"user_agent": "NetScanner/0.9", "client_name": "NetScanner", "version": "0.9",
     "tools": [("fetch_url", {"url": "http://10.0.0.1"}), ("search_web", {"query": "target vulnerabilities"})]},
]


async def run_agent(agent_config: dict) -> None:
    """Run a single agent session."""
    name = agent_config["client_name"]
    msg_id = 0
    responses: dict[int, asyncio.Future[dict]] = {}

    headers = {"User-Agent": agent_config["user_agent"]}

    async with httpx.AsyncClient(timeout=30, headers=headers) as client:
        # Connect SSE
        async with client.stream("GET", f"{HONEYPOT_URL}/sse") as sse:
            endpoint_url = ""
            async for line in sse.aiter_lines():
                if line.startswith("data: "):
                    endpoint_url = HONEYPOT_URL + line[6:]
                    break

            # Background SSE reader
            async def read_sse() -> None:
                event_type = ""
                async for line in sse.aiter_lines():
                    if line.startswith("event: "):
                        event_type = line[7:]
                    elif line.startswith("data: ") and event_type == "message":
                        data = json.loads(line[6:])
                        rid = data.get("id")
                        if rid in responses:
                            responses[rid].set_result(data)
                        event_type = ""

            reader = asyncio.create_task(read_sse())

            async def call(method: str, params: dict) -> dict:
                nonlocal msg_id
                msg_id += 1
                responses[msg_id] = asyncio.get_event_loop().create_future()
                await client.post(endpoint_url, json={
                    "jsonrpc": "2.0", "id": msg_id, "method": method, "params": params,
                })
                return await asyncio.wait_for(responses[msg_id], timeout=10)

            # Initialize with this agent's identity
            await call("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": agent_config["client_name"], "version": agent_config["version"]},
            })
            await client.post(endpoint_url, json={
                "jsonrpc": "2.0", "method": "notifications/initialized",
            })
            await asyncio.sleep(0.3)

            # Call tools
            for tool_name, args in agent_config["tools"]:
                result = await call("tools/call", {"name": tool_name, "arguments": args})
                status = "OK" if "result" in result else "ERR"
                print(f"  [{name}] {tool_name} -> {status}")
                await asyncio.sleep(0.2)

            reader.cancel()

    print(f"  [{name}] Session complete")


async def main() -> None:
    print(f"Launching {len(AGENTS)} concurrent agents...\n")

    # Run all agents in parallel
    await asyncio.gather(*[run_agent(a) for a in AGENTS])

    print(f"\nAll {len(AGENTS)} agents finished.")
    print("Check Grafana Agent Drilldown: http://localhost:3000/d/agent-drilldown")
    print("Check Jaeger: http://localhost:16686 (filter by service=mcp-honeypot)")


if __name__ == "__main__":
    asyncio.run(main())
