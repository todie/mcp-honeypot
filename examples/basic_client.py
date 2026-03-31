#!/usr/bin/env python3
"""Minimal MCP client — connect, initialize, call one tool.

This is the simplest possible interaction with the honeypot.
It demonstrates the MCP-over-SSE protocol from scratch.

Usage:
    python examples/basic_client.py

Requires: docker compose up, pip install httpx
"""

import asyncio
import json

import httpx

HONEYPOT_URL = "http://localhost:8000"


async def main() -> None:
    msg_id = 0

    async with httpx.AsyncClient(timeout=30) as client:
        # 1. Open SSE connection — server sends the messages endpoint URL
        print("1. Connecting to SSE...")
        async with client.stream("GET", f"{HONEYPOT_URL}/sse") as sse:
            endpoint_url = ""
            async for line in sse.aiter_lines():
                if line.startswith("data: "):
                    endpoint_url = HONEYPOT_URL + line[6:]
                    break
            print(f"   Endpoint: {endpoint_url}")

            # Helper: send a JSON-RPC request and read the response from SSE
            responses: dict[int, asyncio.Future[dict]] = {}

            async def read_sse() -> None:
                """Background task: read SSE events and dispatch responses."""
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

            async def call(method: str, params: dict | None = None) -> dict:
                nonlocal msg_id
                msg_id += 1
                responses[msg_id] = asyncio.get_event_loop().create_future()
                await client.post(
                    endpoint_url,
                    json={"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}},
                )
                return await asyncio.wait_for(responses[msg_id], timeout=10)

            async def notify(method: str, params: dict | None = None) -> None:
                """Send a notification (no id, no response expected)."""
                await client.post(
                    endpoint_url,
                    json={"jsonrpc": "2.0", "method": method, "params": params or {}},
                )

            # 2. Initialize the MCP session
            print("2. Initializing...")
            init_resp = await call(
                "initialize",
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "BasicExample", "version": "1.0"},
                },
            )
            print(f"   Server: {init_resp['result']['serverInfo']['name']}")

            # Send the required initialized notification
            await notify("notifications/initialized")
            await asyncio.sleep(0.5)

            # 3. List available tools
            print("3. Listing tools...")
            tools_resp = await call("tools/list")
            tools = tools_resp["result"]["tools"]
            print(f"   {len(tools)} tools available:")
            for t in tools:
                print(f"     - {t['name']}: {t['description'][:60]}")

            # 4. Call a tool
            print("4. Calling get_env_var...")
            result = await call(
                "tools/call",
                {
                    "name": "get_env_var",
                    "arguments": {"name": "AWS_SECRET_ACCESS_KEY"},
                },
            )
            content = json.loads(result["result"]["content"][0]["text"])
            print(f"   Response: {json.dumps(content, indent=2)[:200]}")

            # 5. Clean up
            reader.cancel()
            print("\nDone! Check Jaeger at http://localhost:16686 for the trace.")


if __name__ == "__main__":
    asyncio.run(main())
