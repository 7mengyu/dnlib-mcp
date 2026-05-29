"""Main MCP Server for reverse engineering tools."""

import asyncio
import logging
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
import json
from typing import Optional

from .backends.dnlib_backend import DnlibBackend, set_dnlib_path, DNLIB_PATH

logger = logging.getLogger(__name__)

_backend: Optional[DnlibBackend] = None


def _try_auto_init() -> bool:
    """尝试自动初始化backend"""
    global _backend
    if _backend is not None:
        return True
    if DNLIB_PATH is not None:
        try:
            _backend = DnlibBackend()
            return True
        except Exception as e:
            logger.warning(f"Auto-init failed: {e}")
            return False
    return False


def create_server() -> Server:
    """创建MCP服务器实例"""
    server = Server("reverse-tools-mcp")

    # 尝试自动初始化
    _try_auto_init()

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="dnlib_status",
                description="检查dnlib初始化状态，查看当前使用的dnlib.dll路径",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            ),
            Tool(
                name="dnlib_set_path",
                description="手动设置dnlib.dll的路径（通常不需要，系统会自动检测项目目录下的dnlib.dll）",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "dnlib.dll的完整路径"
                        }
                    },
                    "required": ["path"]
                }
            ),
            Tool(
                name="dnlib_load_assembly",
                description="加载.NET程序集文件（.dll或.exe）进行分析",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "程序集文件的完整路径"
                        }
                    },
                    "required": ["path"]
                }
            ),
            Tool(
                name="dnlib_unload_assembly",
                description="卸载已加载的程序集，释放资源",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "程序集文件的路径"
                        }
                    },
                    "required": ["path"]
                }
            ),
            Tool(
                name="dnlib_list_types",
                description="列出程序集中的所有类型（类、结构、接口、枚举等）",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "程序集文件路径"
                        }
                    },
                    "required": ["path"]
                }
            ),
            Tool(
                name="dnlib_get_type",
                description="获取指定类型的详细信息，包括方法、字段、属性等",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "程序集文件路径"
                        },
                        "type_full_name": {
                            "type": "string",
                            "description": "类型的完整名称（包含命名空间）"
                        }
                    },
                    "required": ["path", "type_full_name"]
                }
            ),
            Tool(
                name="dnlib_search_types",
                description="按名称模式搜索类型（不区分大小写，支持部分匹配）",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "程序集文件路径"
                        },
                        "pattern": {
                            "type": "string",
                            "description": "搜索模式（支持部分匹配）"
                        }
                    },
                    "required": ["path", "pattern"]
                }
            ),
            Tool(
                name="dnlib_search_methods",
                description="按名称模式搜索方法（不区分大小写，支持部分匹配）",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "程序集文件路径"
                        },
                        "pattern": {
                            "type": "string",
                            "description": "搜索模式（支持部分匹配）"
                        }
                    },
                    "required": ["path", "pattern"]
                }
            ),
            Tool(
                name="dnlib_decompile_method",
                description="反编译方法为IL代码，用于分析方法实现细节",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "程序集文件路径"
                        },
                        "type_full_name": {
                            "type": "string",
                            "description": "方法所在类型的完整名称"
                        },
                        "method_name": {
                            "type": "string",
                            "description": "方法名称"
                        }
                    },
                    "required": ["path", "type_full_name", "method_name"]
                }
            ),
            Tool(
                name="dnlib_get_entry_point",
                description="获取程序入口点（Main方法）信息",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "程序集文件路径"
                        }
                    },
                    "required": ["path"]
                }
            ),
            Tool(
                name="dnlib_list_resources",
                description="列出程序集中的嵌入资源",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "程序集文件路径"
                        }
                    },
                    "required": ["path"]
                }
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        global _backend

        try:
            if name == "dnlib_status":
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "initialized": _backend is not None,
                        "dnlib_path": DNLIB_PATH,
                        "message": "dnlib is ready" if _backend else "dnlib not initialized. Place dnlib.dll in project root or call dnlib_set_path."
                    }, ensure_ascii=False, indent=2)
                )]

            if name == "dnlib_set_path":
                path = arguments["path"]
                set_dnlib_path(path)
                _backend = DnlibBackend(path)
                return [TextContent(
                    type="text",
                    text=json.dumps({"success": True, "message": f"dnlib initialized from: {path}"}, ensure_ascii=False)
                )]

            # 尝试自动初始化
            if _backend is None:
                if not _try_auto_init():
                    return [TextContent(
                        type="text",
                        text=json.dumps({
                            "error": "dnlib not initialized",
                            "hint": "Place dnlib.dll in the project root directory, or call dnlib_set_path with the dll path"
                        }, ensure_ascii=False)
                    )]

            if name == "dnlib_load_assembly":
                info = _backend.load_assembly(arguments["path"])
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "name": info.name,
                        "full_name": info.full_name,
                        "version": info.version,
                        "modules": info.modules
                    }, ensure_ascii=False)
                )]

            elif name == "dnlib_unload_assembly":
                result = _backend.unload_assembly(arguments["path"])
                return [TextContent(
                    type="text",
                    text=json.dumps({"success": result}, ensure_ascii=False)
                )]

            elif name == "dnlib_list_types":
                types = _backend.list_types(arguments["path"])
                return [TextContent(
                    type="text",
                    text=json.dumps(types, ensure_ascii=False, indent=2)
                )]

            elif name == "dnlib_get_type":
                type_info = _backend.get_type_info(arguments["path"], arguments["type_full_name"])
                if type_info is None:
                    return [TextContent(
                        type="text",
                        text=json.dumps({"error": "Type not found"}, ensure_ascii=False)
                    )]

                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "name": type_info.name,
                        "full_name": type_info.full_name,
                        "namespace": type_info.namespace,
                        "base_type": type_info.base_type,
                        "is_public": type_info.is_public,
                        "is_sealed": type_info.is_sealed,
                        "is_abstract": type_info.is_abstract,
                        "is_interface": type_info.is_interface,
                        "is_enum": type_info.is_enum,
                        "is_value_type": type_info.is_value_type,
                        "interfaces": type_info.interfaces,
                        "token": type_info.token,
                        "methods": [
                            {
                                "name": m.name,
                                "return_type": m.return_type,
                                "parameters": m.parameters,
                                "is_static": m.is_static,
                                "is_virtual": m.is_virtual,
                                "token": m.token
                            }
                            for m in type_info.methods
                        ],
                        "fields": [
                            {
                                "name": f.name,
                                "type": f.field_type,
                                "is_static": f.is_static,
                                "is_public": f.is_public,
                                "token": f.token
                            }
                            for f in type_info.fields
                        ],
                        "properties": [
                            {
                                "name": p.name,
                                "type": p.property_type,
                                "has_getter": p.has_getter,
                                "has_setter": p.has_setter,
                                "token": p.token
                            }
                            for p in type_info.properties
                        ]
                    }, ensure_ascii=False, indent=2)
                )]

            elif name == "dnlib_search_types":
                results = _backend.search_types(arguments["path"], arguments["pattern"])
                return [TextContent(
                    type="text",
                    text=json.dumps(results, ensure_ascii=False, indent=2)
                )]

            elif name == "dnlib_search_methods":
                results = _backend.search_methods(arguments["path"], arguments["pattern"])
                return [TextContent(
                    type="text",
                    text=json.dumps(results, ensure_ascii=False, indent=2)
                )]

            elif name == "dnlib_decompile_method":
                il_code = _backend.decompile_method(
                    arguments["path"],
                    arguments["type_full_name"],
                    arguments["method_name"]
                )
                return [TextContent(
                    type="text",
                    text=il_code
                )]

            elif name == "dnlib_get_entry_point":
                ep = _backend.get_entry_point(arguments["path"])
                return [TextContent(
                    type="text",
                    text=json.dumps(ep or {"error": "No entry point found"}, ensure_ascii=False, indent=2)
                )]

            elif name == "dnlib_list_resources":
                resources = _backend.list_resources(arguments["path"])
                return [TextContent(
                    type="text",
                    text=json.dumps(resources, ensure_ascii=False, indent=2)
                )]

            else:
                return [TextContent(
                    type="text",
                    text=json.dumps({"error": f"Unknown tool: {name}"}, ensure_ascii=False)
                )]

        except Exception as e:
            return [TextContent(
                type="text",
                text=json.dumps({"error": str(e)}, ensure_ascii=False)
            )]

    return server


async def run_server():
    """运行MCP服务器"""
    server = create_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )


def main():
    """入口点"""
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_server())


if __name__ == "__main__":
    main()
