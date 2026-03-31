"""Reference MCP client for testing the honeypot.

Implements a proper, protocol-compliant MCP client that speaks JSON-RPC 2.0
over the SSE transport.  Uses httpx for all HTTP and asyncio for concurrent
SSE stream reading.

Usage::

    async with McpTestClient(base_url="http://localhost:8000") as client:
        await client.initialize()
        tools = await client.list_tools()
        result = await client.call_tool("read_file", {"path": "/etc/passwd"})
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any
from urllib.parse import urlparse, parse_qs

import httpx

logger = logging.getLogger(__name__)


class McpTestClient:
    """Reference MCP client for testing the honeypot.

    Connects via SSE (GET /sse), reads the endpoint URL, then POSTs
    JSON-RPC messages while reading responses from the SSE stream in a
    background task.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        user_agent: str | None = None,
        client_info: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._user_agent = user_agent
        self._client_info = client_info or {"name": "mcp-test-client", "version": "1.0"}
        self._timeout = timeout

        self._msg_id = 0
        self._endpoint_url: str | None = None
        self._session_id: str | None = None

        # Pending responses: msg_id -> Future
        self._pending: dict[int, asyncio.Future[dict[str, Any]]] = {}

        # Background SSE reader task
        self._sse_task: asyncio.Task[None] | None = None
        self._sse_connected = asyncio.Event()
        self._closed = False

        # Build headers
        headers: dict[str, str] = {"Accept": "text/event-stream"}
        if user_agent is not None:
            headers["User-Agent"] = user_agent
        self._headers = headers

        self._http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=10.0),
            headers={"User-Agent": user_agent} if user_agent is not None else {},
        )
        self._sse_stream: httpx.Response | None = None

    @property
    def session_id(self) -> str | None:
        """Session ID extracted from the endpoint URL query string."""
        return self._session_id

    @property
    def endpoint_url(self) -> str | None:
        """Full POST URL for sending messages."""
        return self._endpoint_url

    @property
    def connected(self) -> bool:
        """True if the SSE connection is established and endpoint is known."""
        return self._endpoint_url is not None

    # ------------------------------------------------------------------
    # SSE background reader
    # ------------------------------------------------------------------

    async def _read_sse_stream(self) -> None:
        """Background task: read the SSE stream, dispatch responses."""
        try:
            event_type = ""
            data_lines: list[str] = []

            async for line in self._sse_stream.aiter_lines():
                if self._closed:
                    break

                if line.startswith("event:"):
                    event_type = line.split(":", 1)[1].strip()
                    data_lines = []
                elif line.startswith("data:"):
                    data_lines.append(line.split(":", 1)[1].strip())
                elif line == "":
                    # Empty line = end of SSE event
                    if event_type and data_lines:
                        data = "\n".join(data_lines)
                        await self._handle_sse_event(event_type, data)
                    event_type = ""
                    data_lines = []

        except httpx.ReadError:
            if not self._closed:
                logger.warning("SSE stream read error (connection may have closed)")
        except asyncio.CancelledError:
            pass
        except Exception:
            if not self._closed:
                logger.exception("SSE reader unexpected error")

    async def _handle_sse_event(self, event_type: str, data: str) -> None:
        """Process a single SSE event."""
        if event_type == "endpoint":
            # Extract the messages endpoint URL
            if data.startswith("/"):
                self._endpoint_url = f"{self._base_url}{data}"
            else:
                self._endpoint_url = data

            # Extract session_id from query string
            parsed = urlparse(self._endpoint_url)
            qs = parse_qs(parsed.query)
            session_ids = qs.get("session_id", [])
            if session_ids:
                self._session_id = session_ids[0]

            logger.info("SSE endpoint received: %s (session=%s)", self._endpoint_url, self._session_id)
            self._sse_connected.set()

        elif event_type == "message":
            try:
                msg = json.loads(data)
            except json.JSONDecodeError:
                logger.warning("Failed to parse SSE message data: %s", data[:200])
                return

            if not isinstance(msg, dict):
                return

            # Match response to pending request by id
            msg_id = msg.get("id")
            if msg_id is not None and msg_id in self._pending:
                future = self._pending.pop(msg_id)
                if not future.done():
                    future.set_result(msg)
            else:
                # Notification or unmatched message
                logger.debug("Received unmatched SSE message: %s", json.dumps(msg)[:200])

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Open the SSE connection and wait for the endpoint URL."""
        if self._sse_task is not None:
            raise RuntimeError("Already connected")

        # Start streaming GET /sse
        self._sse_stream = await self._http_client.send(
            self._http_client.build_request(
                "GET",
                f"{self._base_url}/sse",
                headers=self._headers,
            ),
            stream=True,
        )

        # Launch background reader
        self._sse_task = asyncio.create_task(self._read_sse_stream())

        # Wait for the endpoint event
        try:
            await asyncio.wait_for(self._sse_connected.wait(), timeout=self._timeout)
        except asyncio.TimeoutError:
            await self.close()
            raise TimeoutError(
                f"Timed out waiting for SSE endpoint event from {self._base_url}/sse"
            )

        logger.info("Connected to MCP server at %s", self._base_url)

    async def initialize(self) -> dict[str, Any]:
        """Send the MCP initialize handshake and notifications/initialized.

        Returns the initialize response result dict.
        """
        if not self.connected:
            raise RuntimeError("Not connected -- call connect() first")

        # Send initialize request
        response = await self._send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": self._client_info,
        })

        # Send notifications/initialized (no id -- it's a notification)
        await self._send_notification("notifications/initialized")

        return response.get("result", {})

    async def list_tools(self) -> list[dict[str, Any]]:
        """Call tools/list and return the list of tool definitions."""
        response = await self._send_request("tools/list", {})
        return response.get("result", {}).get("tools", [])

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Call a tool by name with the given arguments.

        Returns the full result dict from the JSON-RPC response.
        """
        params: dict[str, Any] = {"name": name}
        if arguments is not None:
            params["arguments"] = arguments
        response = await self._send_request("tools/call", params)
        return response.get("result", {})

    async def close(self) -> None:
        """Close the SSE connection and clean up."""
        self._closed = True

        # Cancel background reader
        if self._sse_task is not None and not self._sse_task.done():
            self._sse_task.cancel()
            try:
                await self._sse_task
            except asyncio.CancelledError:
                pass
            self._sse_task = None

        # Close SSE stream
        if self._sse_stream is not None:
            await self._sse_stream.aclose()
            self._sse_stream = None

        # Cancel pending futures
        for future in self._pending.values():
            if not future.done():
                future.cancel()
        self._pending.clear()

        # Close httpx client
        await self._http_client.aclose()

        logger.info("Disconnected from MCP server")

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> McpTestClient:
        await self.connect()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _next_id(self) -> int:
        self._msg_id += 1
        return self._msg_id

    async def _send_request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Send a JSON-RPC request and wait for the response."""
        if not self._endpoint_url:
            raise RuntimeError("Not connected -- no endpoint URL")

        msg_id = self._next_id()
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "method": method,
            "params": params,
        }

        # Create a future for the response
        loop = asyncio.get_running_loop()
        future: asyncio.Future[dict[str, Any]] = loop.create_future()
        self._pending[msg_id] = future

        # POST the message
        try:
            resp = await self._http_client.post(
                self._endpoint_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code not in (200, 202):
                self._pending.pop(msg_id, None)
                raise RuntimeError(
                    f"POST {self._endpoint_url} returned {resp.status_code}: {resp.text}"
                )
        except Exception:
            self._pending.pop(msg_id, None)
            raise

        # Wait for the SSE response
        try:
            result = await asyncio.wait_for(future, timeout=self._timeout)
        except asyncio.TimeoutError:
            self._pending.pop(msg_id, None)
            raise TimeoutError(
                f"Timed out waiting for response to {method} (id={msg_id})"
            )

        # Check for JSON-RPC error
        if "error" in result:
            err = result["error"]
            logger.warning("JSON-RPC error for %s: %s", method, err)

        return result

    async def _send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        """Send a JSON-RPC notification (no id, no response expected)."""
        if not self._endpoint_url:
            raise RuntimeError("Not connected -- no endpoint URL")

        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params is not None:
            payload["params"] = params

        resp = await self._http_client.post(
            self._endpoint_url,
            json=payload,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code not in (200, 202):
            logger.warning(
                "Notification %s got status %d: %s",
                method, resp.status_code, resp.text[:200],
            )
