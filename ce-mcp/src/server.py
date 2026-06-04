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
                name="ce_get_callstack",
                description="获取当前线程的调用栈回溯，返回调用地址和模块信息",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "thread_id": {
                            "type": "integer",
                            "description": "线程ID（可选），不指定则使用调试线程",
                        },
                        "max_frames": {
                            "type": "integer",
                            "description": "最大帧数，默认16，最大32",
                            "default": 16
                        }
                    },
                    "required": []
                }
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
                description="设置硬件断点并持续监控指定时长。返回每次断点触发的完整记录（时间戳、线程ID、寄存器快照）。"
                           "插件在监控窗口内自动续执行目标进程，不会阻塞。",
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
            Tool(
                name="ce_register_trace",
                description="跨函数寄存器追踪。在函数入口和出口设置执行断点，监控指定时长，"
                           "返回配对的入口/出口寄存器快照和变化差异（diff）。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "start_address": {
                            "type": "string",
                            "description": "函数入口地址（执行断点），如 \"0x140001000\""
                        },
                        "end_address": {
                            "type": "string",
                            "description": "函数返回地址（执行断点），如 \"0x140001050\""
                        },
                        "duration": {
                            "type": "integer",
                            "description": "监控时长（秒），默认10，最大30",
                            "default": 10
                        }
                    },
                    "required": ["start_address", "end_address"]
                }
            ),
            Tool(
                name="ce_generate_hook",
                description="基于指定地址自动生成 AutoAssemble 注入脚本。"
                           "包含 ENABLE/DISABLE 段、codecave 分配、原始代码恢复。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "要 hook 的指令地址，如 \"0x140001000\""
                        },
                        "jump_to": {
                            "type": "string",
                            "description": "跳转目标地址/标签（可选），不指定则生成模板框架"
                        },
                        "codecave_size": {
                            "type": "integer",
                            "description": "codecave 大小（字节），默认1024，最小64，最大65536",
                            "default": 1024
                        }
                    },
                    "required": ["address"]
                }
            ),
            Tool(
                name="ce_memory_scan",
                description="在目标进程内存中扫描指定类型的精确值。支持 byte/word/dword/qword/float/double/string "
                           "类型。结果自动缓存，可通过 ce_memory_scan_next 进行变/不变过滤链。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "scan_type": {
                            "type": "integer",
                            "description": "值类型: 0=byte, 1=word, 2=dword, 3=qword, 4=float, 5=double, 6=string"
                        },
                        "value": {
                            "type": "string",
                            "description": "要搜索的值，如 \"100\"、\"3.14\"、\"hello\""
                        },
                        "start_address": {
                            "type": "string",
                            "description": "扫描起始地址（可选），如 \"0x140000000\""
                        },
                        "end_address": {
                            "type": "string",
                            "description": "扫描结束地址（可选），如 \"0x150000000\""
                        },
                        "max_results": {
                            "type": "integer",
                            "description": "最大结果数，默认500，最大5000",
                            "default": 500
                        }
                    },
                    "required": ["scan_type", "value"]
                }
            ),
            Tool(
                name="ce_memory_scan_next",
                description="对上次扫描结果进行变化/不变过滤。必须先用 ce_memory_scan 获得并缓存结果。"
                           "支持链式调用：多次调用逐步缩小结果集。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "filter": {
                            "type": "integer",
                            "description": "过滤类型: 1=已变化, 2=未变化"
                        },
                        "max_results": {
                            "type": "integer",
                            "description": "最大结果数，默认500，最大5000",
                            "default": 500
                        }
                    },
                    "required": ["filter"]
                }
            ),
            Tool(
                name="ce_get_symbol_info",
                description="符号名<->地址双向解析。输入地址（0x开头）返回符号名，输入符号名返回地址。"
                           "使用CE内置符号处理器，支持模块名、导出函数、PDB符号。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "input": {
                            "type": "string",
                            "description": "地址（如 \"0x140001000\"）或符号名（如 \"game.exe+1234\" 或 \"kernel32.CreateFileA\"）"
                        }
                    },
                    "required": ["input"]
                }
            ),
            Tool(
                name="ce_enum_memory_regions",
                description="枚举目标进程完整内存布局：基址、大小、保护属性（R/RW/RX/RWX）、内存类型"
                           "（IMAGE=模块/MAPPED=文件映射/PRIVATE=堆栈）。比 ce_get_modules 更全面。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "start_address": {
                            "type": "string",
                            "description": "起始地址（可选），默认从0开始"
                        },
                        "max_regions": {
                            "type": "integer",
                            "description": "最大区域数，默认500，最大2000",
                            "default": 500
                        }
                    },
                    "required": []
                }
            ),
            Tool(
                name="ce_prev_opcode",
                description="根据CE反汇编启发式算法，返回指定地址之前的指令地址",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "当前指令地址，如 \"0x140001000\""
                        }
                    },
                    "required": ["address"]
                }
            ),
            Tool(
                name="ce_next_opcode",
                description="返回指定地址的下一条指令地址（disassemble + 偏移）",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "当前指令地址，如 \"0x140001000\""
                        }
                    },
                    "required": ["address"]
                }
            ),
            Tool(
                name="ce_assemble",
                description="将单条汇编指令编码为机器码字节。DISASSEMBLE的反向操作。"
                           "返回字节数组和长度。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "instruction": {
                            "type": "string",
                            "description": "汇编指令，如 \"mov rax,[rcx+8]\" 或 \"jmp 0x140001000\""
                        },
                        "address": {
                            "type": "string",
                            "description": "汇编基址（可选），影响相对跳转的编码，如 \"0x140001000\""
                        }
                    },
                    "required": ["instruction"]
                }
            ),
            Tool(
                name="ce_generate_api_hook",
                description="调用CE内置的 GenerateAPIHookScript 生成API Hook脚本。"
                           "比 ce_generate_hook 更可靠（CE内部验证过的hook模板）。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "要hook的API地址或符号名"
                        },
                        "jump_to": {
                            "type": "string",
                            "description": "跳转目标地址（可选）"
                        }
                    },
                    "required": ["address"]
                }
            ),
            Tool(
                name="ce_resolve_pointer",
                description="解析多级指针链：base + offset1 + offset2 + ... 返回最终地址。"
                           "CE地址列表中常见的指针追踪模式。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "base": {
                            "type": "string",
                            "description": "基址，如 \"0x140000000\""
                        },
                        "offsets": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "偏移量列表，如 [0x10, 0x8, 0x20]"
                        }
                    },
                    "required": ["base"]
                }
            ),
            Tool(
                name="ce_get_process_list",
                description="列出系统所有运行进程（PID+名称）。不需要先打开进程。",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            ),
            Tool(
                name="ce_get_rtti_class",
                description="读取指定地址的C++ RTTI类名（通过vtable->RTTI链）。"
                           "支持MSVC 2017+（vtable[-1]->TypeDescriptor）和Pascal/Delphi（vtable+3*ptr->ShortString）两种格式。"
                           "需要目标二进制启用RTTI。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "对象实例地址，如 \"0x1A2B3C4D\""
                        }
                    },
                    "required": ["address"]
                }
            ),
            Tool(
                name="ce_enum_strings",
                description="扫描指定内存区域中的可打印ASCII字符串。类似Unix strings命令。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "start_address": {
                            "type": "string",
                            "description": "起始地址，如 \"0x140000000\""
                        },
                        "end_address": {
                            "type": "string",
                            "description": "结束地址，如 \"0x140100000\""
                        },
                        "min_length": {
                            "type": "integer",
                            "description": "最小字符串长度，默认4，最小3",
                            "default": 4
                        }
                    },
                    "required": ["start_address", "end_address"]
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

            elif name == "ce_get_callstack":
                tid = str(arguments.get("thread_id", ""))
                max_frames = int(arguments.get("max_frames", 16))
                result = await bridge.send_command(
                    "GET_CALLSTACK", f"{tid},{max_frames}"
                )
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

            elif name == "ce_register_trace":
                start_addr = str(arguments["start_address"])
                end_addr = str(arguments["end_address"])
                duration = int(arguments.get("duration", 10))
                result = await bridge.send_command(
                    "REGISTER_TRACE", f"{start_addr},{end_addr},{duration}",
                    timeout=max(duration + 10, 40.0)
                )
                return ok(result)

            elif name == "ce_generate_hook":
                addr = str(arguments["address"])
                jump_to = str(arguments.get("jump_to", ""))
                cave_size = int(arguments.get("codecave_size", 1024))
                result = await bridge.send_command(
                    "GENERATE_HOOK", f"{addr},{jump_to},{cave_size}"
                )
                return ok(result)

            elif name == "ce_memory_scan":
                scan_type = int(arguments["scan_type"])
                value = str(arguments["value"])
                start = str(arguments.get("start_address", ""))
                end = str(arguments.get("end_address", ""))
                max_r = int(arguments.get("max_results", 500))
                result = await bridge.send_command(
                    "MEMORY_SCAN", f"{scan_type},{value},{start},{end},{max_r}",
                    timeout=30.0
                )
                return ok(result)

            elif name == "ce_memory_scan_next":
                filter_type = int(arguments["filter"])
                max_r = int(arguments.get("max_results", 500))
                result = await bridge.send_command(
                    "MEMORY_SCAN_NEXT", f"{filter_type},{max_r}",
                    timeout=15.0
                )
                return ok(result)

            elif name == "ce_get_symbol_info":
                inp = str(arguments["input"])
                result = await bridge.send_command("GET_SYMBOL_INFO", inp)
                return ok(result)

            elif name == "ce_enum_memory_regions":
                start = str(arguments.get("start_address", ""))
                max_r = int(arguments.get("max_regions", 500))
                result = await bridge.send_command(
                    "ENUM_MEMORY_REGIONS", f"{start},{max_r}", timeout=15.0
                )
                return ok(result)

            elif name == "ce_prev_opcode":
                addr = str(arguments["address"])
                result = await bridge.send_command("PREV_OPCODE", addr)
                return ok(result)

            elif name == "ce_next_opcode":
                addr = str(arguments["address"])
                result = await bridge.send_command("NEXT_OPCODE", addr)
                return ok(result)

            elif name == "ce_assemble":
                instr = str(arguments["instruction"])
                addr = str(arguments.get("address", ""))
                result = await bridge.send_command("ASSEMBLE", f"{instr},{addr}")
                return ok(result)

            elif name == "ce_generate_api_hook":
                addr = str(arguments["address"])
                jmp = str(arguments.get("jump_to", ""))
                result = await bridge.send_command(
                    "GENERATE_API_HOOK", f"{addr},{jmp}"
                )
                return ok(result)

            elif name == "ce_resolve_pointer":
                base = str(arguments["base"])
                offsets = arguments.get("offsets", [])
                params = base
                for off in offsets:
                    params += f",{off}"
                result = await bridge.send_command("RESOLVE_POINTER", params)
                return ok(result)

            elif name == "ce_get_process_list":
                result = await bridge.send_command("GET_PROCESS_LIST", timeout=5.0)
                return ok(result)

            elif name == "ce_get_rtti_class":
                addr = str(arguments["address"])
                result = await bridge.send_command("GET_RTTI_CLASS", addr)
                return ok(result)

            elif name == "ce_enum_strings":
                start = str(arguments["start_address"])
                end = str(arguments["end_address"])
                min_len = int(arguments.get("min_length", 4))
                result = await bridge.send_command(
                    "ENUM_STRINGS", f"{start},{end},{min_len}", timeout=20.0
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
