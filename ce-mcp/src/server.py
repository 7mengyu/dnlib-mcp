"""CE MCP Server - MCP integration for Cheat Engine analysis.

Exposes Cheat Engine analysis capabilities (memory scan, disassembly,
breakpoints, AOB scanning) as MCP tools via a TCP bridge to the
ce-mcp-plugin DLL running inside Cheat Engine.
"""

import asyncio
import logging
import json
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from .bridge import init_bridge, shutdown_bridge, get_bridge

logger = logging.getLogger(__name__)


def create_server() -> Server:
    server = Server("ce-mcp")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="ce_status",
                description="检查CE插件连接状态和当前附加的进程",
                inputSchema={"type": "object", "properties": {}, "required": []}
            ),
            Tool(
                name="ce_ping",
                description="测试与CE插件的连接，返回延迟和进程信息",
                inputSchema={"type": "object", "properties": {}, "required": []}
            ),
            Tool(
                name="ce_get_modules",
                description="获取目标进程加载的所有模块列表（名称、基址、大小）",
                inputSchema={"type": "object", "properties": {}, "required": []}
            ),
            Tool(
                name="ce_get_registers",
                description="获取当前调试寄存器快照（x64: RAX-R15/RIP/EFLAGS）",
                inputSchema={"type": "object", "properties": {}, "required": []}
            ),
            Tool(
                name="ce_read_memory",
                description="读取目标进程指定地址的内存数据，返回十六进制字节",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "要读取的十六进制地址，如 \"0x7FF6A0001000\""
                        },
                        "length": {
                            "type": "integer",
                            "description": "读取长度（字节），默认256，最大4096",
                            "default": 256
                        }
                    },
                    "required": ["address"]
                }
            ),
            Tool(
                name="ce_disassemble",
                description="反汇编指定地址处的代码，返回指令列表和原始字节",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "起始地址，如 \"0x7FF6A0001000\""
                        },
                        "count": {
                            "type": "integer",
                            "description": "反汇编指令条数，默认20，最大100",
                            "default": 20
                        }
                    },
                    "required": ["address"]
                }
            ),
            Tool(
                name="ce_aob_scan",
                description="在目标进程内存中搜索特征码（Array of Bytes），支持通配符 ??",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "特征码，如 \"48 8B 05 ?? ?? ?? ??\"，用 ?? 表示通配符"
                        },
                        "module": {
                            "type": "string",
                            "description": "限定搜索的模块名（可选），如 \"game.exe\"。不指定则搜索主模块"
                        }
                    },
                    "required": ["pattern"]
                }
            ),
            Tool(
                name="ce_set_breakpoint",
                description="设置硬件断点并持续监控指定时长。返回断点触发记录（指令地址、触发次数等）",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "断点地址，如 \"0x1A2B3C4D\""
                        },
                        "type": {
                            "type": "integer",
                            "description": "断点类型: 0=执行, 1=写入, 2=读。默认1（写入）",
                            "default": 1
                        },
                        "duration": {
                            "type": "integer",
                            "description": "监控时长（秒），默认10，最大30",
                            "default": 10
                        }
                    },
                    "required": ["address"]
                }
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        bridge = get_bridge()

        def err(msg: str) -> list[TextContent]:
            return [TextContent(type="text", text=json.dumps(
                {"error": msg}, ensure_ascii=False))]

        def ok(data) -> list[TextContent]:
            return [TextContent(type="text", text=json.dumps(
                data, ensure_ascii=False, indent=2))]

        try:
            if name == "ce_status":
                connected = bridge is not None and bridge.is_connected
                return ok({
                    "bridge_running": bridge is not None,
                    "plugin_connected": connected,
                    "host": bridge.host if bridge else "N/A",
                    "port": bridge.port if bridge else "N/A",
                })

            if bridge is None:
                return err("Bridge not initialized. The server should auto-start the bridge on launch.")

            if not bridge.is_connected:
                return err(
                    "CE Plugin not connected. "
                    "Start Cheat Engine, load ce-mcp-plugin.dll, "
                    "open a process, then try again."
                )

            if name == "ce_ping":
                result = await bridge.send_command("PING", timeout=5.0)
                return ok(result)

            elif name == "ce_get_modules":
                result = await bridge.send_command("GET_MODULES")
                return ok(result)

            elif name == "ce_get_registers":
                result = await bridge.send_command("GET_REGISTERS")
                return ok(result)

            elif name == "ce_read_memory":
                addr = str(arguments["address"])
                length = int(arguments.get("length", 256))
                result = await bridge.send_command(
                    "READ_MEMORY", f"{addr},{length}"
                )
                return ok(result)

            elif name == "ce_disassemble":
                addr = str(arguments["address"])
                count = int(arguments.get("count", 20))
                result = await bridge.send_command(
                    "DISASSEMBLE", f"{addr},{count}"
                )
                return ok(result)

            elif name == "ce_aob_scan":
                pattern = str(arguments["pattern"])
                module = str(arguments.get("module", ""))
                result = await bridge.send_command(
                    "AOB_SCAN", f"{pattern},{module}"
                )
                return ok(result)

            elif name == "ce_set_breakpoint":
                addr = str(arguments["address"])
                bp_type = int(arguments.get("type", 1))
                duration = int(arguments.get("duration", 10))
                result = await bridge.send_command(
                    "SET_BP", f"{addr},{bp_type},{duration}",
                    timeout=max(duration + 10, 40.0)
                )
                return ok(result)

            else:
                return err(f"Unknown tool: {name}")

        except Exception as e:
            logger.exception("Tool call failed: %s", name)
            return err(str(e))

    return server


async def run_server():
    """Start the TCP bridge and run the MCP server."""
    await init_bridge()
    server = create_server()
    try:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream, write_stream,
                server.create_initialization_options()
            )
    finally:
        await shutdown_bridge()


def main():
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_server())


if __name__ == "__main__":
    main()
