"""TCP Bridge Server for CE Plugin communication.

The CE plugin (ce-mcp-plugin.dll) connects to this server as a TCP client.
This bridge accepts the connection and routes MCP tool calls to the plugin.

Protocol:
  Request:  "COMMAND:param1,param2,...\n"
  Response: "OK:{...json...}\n"  or  "ERR:message\n"

Architecture:
  The CE plugin connects and stays connected. Each MCP tool call writes a
  command line and waits for one response line. All I/O is serialized through
  an asyncio lock.
"""

import asyncio
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8888
DEFAULT_TIMEOUT = 10.0


class CEBridge:
    """Async TCP server the CE plugin DLL connects to.

    The bridge accepts one CE plugin connection at a time. When the
    plugin disconnects and reconnects, the bridge transparently picks
    up the new connection.
    """

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self.host = host
        self.port = port
        self._server: Optional[asyncio.Server] = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._lock = asyncio.Lock()
        self._ready = asyncio.Event()

    async def start(self) -> None:
        """Start listening for CE plugin connections."""
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        logger.info("CE Bridge listening on %s:%d", self.host, self.port)

    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter) -> None:
        """Accepts a new plugin connection, replacing any previous one."""
        addr = writer.get_extra_info("peername")

        async with self._lock:
            old = self._writer
            self._reader = reader
            self._writer = writer
            self._ready.set()
            if old:
                try:
                    old.close()
                except Exception:
                    pass

        logger.info("CE Plugin connected from %s", addr)

        # Keep the connection alive — read in background to detect disconnect
        try:
            while True:
                data = await reader.read(1024)
                if not data:
                    break
                # Unexpected data from plugin (should only respond to commands)
                logger.debug("Unexpected data from plugin: %r", data[:200])
        except Exception:
            pass
        finally:
            logger.info("CE Plugin disconnected")
            async with self._lock:
                self._reader = None
                self._writer = None
                self._ready.clear()

    @property
    def is_connected(self) -> bool:
        return self._writer is not None and not self._writer.is_closing()

    async def wait_connected(self, timeout: float = 5.0) -> bool:
        """Wait up to `timeout` seconds for the plugin to connect."""
        try:
            await asyncio.wait_for(self._ready.wait(), timeout=timeout)
            return self.is_connected
        except asyncio.TimeoutError:
            return False

    async def send_command(self, command: str, params: str = "",
                           timeout: float = DEFAULT_TIMEOUT) -> dict:
        """Send a command to the CE plugin and return the parsed response.

        Thread-safe: serializes all I/O through an asyncio lock.
        """
        async with self._lock:
            if self._writer is None or self._writer.is_closing():
                return {
                    "error": (
                        "CE Plugin not connected. "
                        "Start Cheat Engine with ce-mcp-plugin.dll loaded, "
                        "open a process, then retry."
                    )
                }

            msg = f"{command}:{params}\n"
            try:
                self._writer.write(msg.encode())
                await self._writer.drain()
            except (ConnectionError, OSError) as e:
                self._reader = None
                self._writer = None
                self._ready.clear()
                return {"error": f"Connection to CE Plugin lost: {e}"}

            try:
                line = await asyncio.wait_for(
                    self._reader.readline(), timeout=timeout
                )
                response = line.decode("utf-8", errors="replace").strip()
            except asyncio.TimeoutError:
                return {
                    "error": (
                        f"Command '{command}' timed out after {timeout}s. "
                        "The plugin may be busy or not responding."
                    )
                }
            except (ConnectionError, OSError) as e:
                self._reader = None
                self._writer = None
                self._ready.clear()
                return {"error": f"Connection lost while reading: {e}"}

            return self._parse_response(response)

    @staticmethod
    def _parse_response(response: str) -> dict:
        """Parse OK:/ERR: response from the CE plugin."""
        if not response:
            return {"error": "Empty response from plugin"}

        if response.startswith("OK:"):
            data = response[3:]
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                return {"status": "ok", "message": data}

        if response.startswith("ERR:"):
            return {"error": response[4:]}

        # Maybe multiple lines ended up in one read — try to find OK:/ERR:
        for prefix in ("OK:", "ERR:"):
            idx = response.find(prefix)
            if idx >= 0:
                return CEBridge._parse_response(response[idx:])

        return {"error": f"Unexpected response: {response[:200]}"}

    async def stop(self) -> None:
        """Stop the TCP server and disconnect the plugin."""
        async with self._lock:
            if self._writer:
                try:
                    self._writer.close()
                except Exception:
                    pass
                self._reader = None
                self._writer = None
            self._ready.clear()

        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("CE Bridge stopped")


# ---- global singleton ----

_bridge: Optional[CEBridge] = None


def get_bridge() -> Optional[CEBridge]:
    return _bridge


async def init_bridge(host: str = DEFAULT_HOST,
                      port: int = DEFAULT_PORT) -> CEBridge:
    global _bridge
    if _bridge is None:
        _bridge = CEBridge(host, port)
        await _bridge.start()
    return _bridge


async def shutdown_bridge() -> None:
    global _bridge
    if _bridge:
        await _bridge.stop()
        _bridge = None
