"""Main MCP Server for reverse engineering tools."""

import asyncio
import logging
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
import json
from typing import Optional

from .backends.dnlib_backend import DnlibBackend, set_dnlib_path, DNLIB_PATH
from .backends.de4dot_backend import De4dotBackend, set_de4dot_path, DE4DOT_PATH

logger = logging.getLogger(__name__)

_dnlib: Optional[DnlibBackend] = None
_de4dot: Optional[De4dotBackend] = None


def _try_auto_init_dnlib() -> bool:
    global _dnlib
    if _dnlib is not None:
        return True
    if DNLIB_PATH is not None:
        try:
            _dnlib = DnlibBackend()
            return True
        except Exception as e:
            logger.warning(f"dnlib auto-init failed: {e}")
            return False
    return False


def _try_auto_init_de4dot() -> bool:
    global _de4dot
    if _de4dot is not None:
        return True
    if DE4DOT_PATH is not None:
        try:
            _de4dot = De4dotBackend()
            return True
        except Exception as e:
            logger.warning(f"de4dot auto-init failed: {e}")
            return False
    return False


def create_server() -> Server:
    server = Server("dnlib-mcp")

    _try_auto_init_dnlib()
    _try_auto_init_de4dot()

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            # === dnlib 工具 ===
            Tool(
                name="dnlib_status",
                description="检查dnlib初始化状态",
                inputSchema={"type": "object", "properties": {}, "required": []}
            ),
            Tool(
                name="dnlib_set_path",
                description="手动设置dnlib.dll的路径",
                inputSchema={
                    "type": "object",
                    "properties": {"path": {"type": "string", "description": "dnlib.dll的完整路径"}},
                    "required": ["path"]
                }
            ),
            Tool(
                name="dnlib_load_assembly",
                description="加载.NET程序集文件（.dll或.exe）进行分析",
                inputSchema={
                    "type": "object",
                    "properties": {"path": {"type": "string", "description": "程序集文件的完整路径"}},
                    "required": ["path"]
                }
            ),
            Tool(
                name="dnlib_list_types",
                description="列出程序集中的所有类型（类、结构、接口、枚举等）",
                inputSchema={
                    "type": "object",
                    "properties": {"path": {"type": "string", "description": "程序集文件路径"}},
                    "required": ["path"]
                }
            ),
            Tool(
                name="dnlib_get_type",
                description="获取指定类型的详细信息（方法、字段、属性）",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "程序集文件路径"},
                        "type_full_name": {"type": "string", "description": "类型完整名称（含命名空间）"}
                    },
                    "required": ["path", "type_full_name"]
                }
            ),
            Tool(
                name="dnlib_search_types",
                description="按名称搜索类型，不区分大小写",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "程序集文件路径"},
                        "pattern": {"type": "string", "description": "搜索模式"}
                    },
                    "required": ["path", "pattern"]
                }
            ),
            Tool(
                name="dnlib_search_methods",
                description="按名称搜索方法，不区分大小写",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "程序集文件路径"},
                        "pattern": {"type": "string", "description": "搜索模式"}
                    },
                    "required": ["path", "pattern"]
                }
            ),
            Tool(
                name="dnlib_decompile_method",
                description="反编译方法为IL代码",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "程序集文件路径"},
                        "type_full_name": {"type": "string", "description": "方法所在类型完整名称"},
                        "method_name": {"type": "string", "description": "方法名称"}
                    },
                    "required": ["path", "type_full_name", "method_name"]
                }
            ),
            Tool(
                name="dnlib_get_entry_point",
                description="获取程序入口点",
                inputSchema={
                    "type": "object",
                    "properties": {"path": {"type": "string", "description": "程序集文件路径"}},
                    "required": ["path"]
                }
            ),
            Tool(
                name="dnlib_list_resources",
                description="列出程序集中的嵌入资源",
                inputSchema={
                    "type": "object",
                    "properties": {"path": {"type": "string", "description": "程序集文件路径"}},
                    "required": ["path"]
                }
            ),

            # === de4dot 工具 ===
            Tool(
                name="de4dot_status",
                description="检查de4dot初始化状态",
                inputSchema={"type": "object", "properties": {}, "required": []}
            ),
            Tool(
                name="de4dot_set_path",
                description="手动设置de4dot.exe的路径",
                inputSchema={
                    "type": "object",
                    "properties": {"path": {"type": "string", "description": "de4dot.exe的完整路径"}},
                    "required": ["path"]
                }
            ),
            Tool(
                name="de4dot_detect",
                description="检测.NET程序集使用了哪种混淆器（-d模式，不改动文件）",
                inputSchema={
                    "type": "object",
                    "properties": {"path": {"type": "string", "description": "程序集文件路径"}},
                    "required": ["path"]
                }
            ),
            Tool(
                name="de4dot_list_obfuscators",
                description="列出de4dot支持的所有混淆器类型及缩写",
                inputSchema={"type": "object", "properties": {}, "required": []}
            ),
            Tool(
                name="de4dot_deobfuscate",
                description="对程序集执行反混淆，输出清理后的文件。支持所有高级选项",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "程序集文件路径"},
                        "output": {"type": "string", "description": "输出文件路径（可选，默认加-cleaned后缀）"},
                        "obfuscator_type": {"type": "string", "description": "强制指定混淆器类型（可选，如 un/df/co/cf 等）"},
                        "rename": {"type": "boolean", "description": "是否重命名符号（默认true）"},
                        "keep_names": {"type": "string", "description": "保留特定符号名不重命名，组合使用: n(命名空间) t(类型) p(属性) e(事件) f(字段) m(方法) a(参数) g(泛型) d(委托字段)。如: nefm 保留命名空间/事件/字段/方法"},
                        "no_cflow": {"type": "boolean", "description": "跳过控制流反混淆（默认false）"},
                        "only_cflow": {"type": "boolean", "description": "仅执行控制流反混淆，跳过字符串解密和重命名（默认false）"},
                        "str_type": {"type": "string", "description": "字符串解密类型: none/default/static/delegate/emulate"},
                        "str_token": {"type": "string", "description": "指定解密方法的token或签名 [type::][name][(args,...)]"},
                        "keep_types": {"type": "boolean", "description": "保留混淆器添加的类型/字段/方法（默认false）"},
                        "preserve_tokens": {"type": "boolean", "description": "保留重要的元数据token（默认false）"},
                        "preserve_table": {"type": "string", "description": "精细控制保留哪些表的RID"},
                        "load_new_process": {"type": "boolean", "description": "在新进程中加载程序集做字符串解密（默认false）"}
                    },
                    "required": ["path"]
                }
            ),
            Tool(
                name="de4dot_clean_strings",
                description="仅解密字符串，不修改结构和符号名",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "程序集文件路径"},
                        "str_type": {"type": "string", "description": "字符串解密类型（none/default/static/delegate/emulate）"},
                        "str_token": {"type": "string", "description": "指定解密方法token或签名"},
                        "output": {"type": "string", "description": "输出文件路径（可选）"},
                        "load_new_process": {"type": "boolean", "description": "在新进程中加载程序集（默认false）"}
                    },
                    "required": ["path"]
                }
            ),
            Tool(
                name="de4dot_batch_deobfuscate",
                description="批量反混淆目录下的所有.NET程序集，适合处理Game/Managed目录",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "input_dir": {"type": "string", "description": "输入目录路径（含多个.dll/.exe）"},
                        "output_dir": {"type": "string", "description": "输出目录路径（可选）"},
                        "skip_unsupported": {"type": "boolean", "description": "跳过不支持的混淆文件（默认false）"},
                        "obfuscator_type": {"type": "string", "description": "强制指定混淆器类型（可选）"},
                        "rename": {"type": "boolean", "description": "是否重命名符号（默认true）"},
                        "keep_names": {"type": "string", "description": "保留特定符号名（如: ntm 保留命名空间/类型/方法）"},
                        "no_cflow": {"type": "boolean", "description": "跳过控制流反混淆（默认false）"},
                        "str_type": {"type": "string", "description": "字符串解密类型（可选）"}
                    },
                    "required": ["input_dir"]
                }
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        global _dnlib, _de4dot

        def err(msg: str) -> list[TextContent]:
            return [TextContent(type="text", text=json.dumps({"error": msg}, ensure_ascii=False))]

        def ok(data) -> list[TextContent]:
            return [TextContent(type="text", text=json.dumps(data, ensure_ascii=False, indent=2))]

        try:
            # --- dnlib 工具 ---
            if name == "dnlib_status":
                return ok({
                    "initialized": _dnlib is not None,
                    "dnlib_path": DNLIB_PATH,
                    "message": "dnlib is ready" if _dnlib else "dnlib not initialized"
                })

            if name == "dnlib_set_path":
                path = arguments["path"]
                set_dnlib_path(path)
                _dnlib = DnlibBackend(path)
                return ok({"success": True, "message": f"dnlib initialized from: {path}"})

            if name.startswith("dnlib_") and _dnlib is None:
                if not _try_auto_init_dnlib():
                    return err("dnlib not initialized. Place dnlib.dll in project root or call dnlib_set_path.")

            if name == "dnlib_load_assembly":
                info = _dnlib.load_assembly(arguments["path"])
                return ok({"name": info.name, "full_name": info.full_name, "version": info.version, "modules": info.modules})

            elif name == "dnlib_unload_assembly":
                _dnlib.unload_assembly(arguments["path"])
                return ok({"success": True})

            elif name == "dnlib_list_types":
                return [TextContent(type="text", text=json.dumps(_dnlib.list_types(arguments["path"]), ensure_ascii=False, indent=2))]

            elif name == "dnlib_get_type":
                ti = _dnlib.get_type_info(arguments["path"], arguments["type_full_name"])
                if ti is None:
                    return err("Type not found")
                return ok({
                    "name": ti.name, "full_name": ti.full_name, "namespace": ti.namespace,
                    "base_type": ti.base_type, "is_public": ti.is_public, "is_sealed": ti.is_sealed,
                    "is_abstract": ti.is_abstract, "is_interface": ti.is_interface,
                    "is_enum": ti.is_enum, "is_value_type": ti.is_value_type,
                    "interfaces": ti.interfaces, "token": ti.token,
                    "methods": [{"name": m.name, "return_type": m.return_type, "parameters": m.parameters,
                                 "is_static": m.is_static, "is_virtual": m.is_virtual, "token": m.token}
                                for m in ti.methods],
                    "fields": [{"name": f.name, "type": f.field_type, "is_static": f.is_static,
                                "is_public": f.is_public, "token": f.token} for f in ti.fields],
                    "properties": [{"name": p.name, "type": p.property_type, "has_getter": p.has_getter,
                                    "has_setter": p.has_setter, "token": p.token} for p in ti.properties]
                })

            elif name == "dnlib_search_types":
                return [TextContent(type="text", text=json.dumps(
                    _dnlib.search_types(arguments["path"], arguments["pattern"]), ensure_ascii=False, indent=2))]

            elif name == "dnlib_search_methods":
                return [TextContent(type="text", text=json.dumps(
                    _dnlib.search_methods(arguments["path"], arguments["pattern"]), ensure_ascii=False, indent=2))]

            elif name == "dnlib_decompile_method":
                il = _dnlib.decompile_method(arguments["path"], arguments["type_full_name"], arguments["method_name"])
                return [TextContent(type="text", text=il)]

            elif name == "dnlib_get_entry_point":
                ep = _dnlib.get_entry_point(arguments["path"])
                return ok(ep or {"error": "No entry point found"})

            elif name == "dnlib_list_resources":
                return [TextContent(type="text", text=json.dumps(
                    _dnlib.list_resources(arguments["path"]), ensure_ascii=False, indent=2))]

            # --- de4dot 工具 ---
            if name == "de4dot_status":
                return ok({
                    "initialized": _de4dot is not None,
                    "de4dot_path": DE4DOT_PATH,
                    "message": "de4dot is ready" if _de4dot else "de4dot not initialized"
                })

            if name == "de4dot_set_path":
                path = arguments["path"]
                set_de4dot_path(path)
                _de4dot = De4dotBackend(path)
                return ok({"success": True, "message": f"de4dot initialized from: {path}"})

            if name.startswith("de4dot_") and _de4dot is None:
                if not _try_auto_init_de4dot():
                    return err("de4dot not initialized. Place de4dot.exe in de4dot/ subdirectory or call de4dot_set_path.")

            if name == "de4dot_detect":
                return ok(_de4dot.detect(arguments["path"]))

            elif name == "de4dot_list_obfuscators":
                return [TextContent(type="text", text=json.dumps(
                    _de4dot.list_obfuscators(), ensure_ascii=False, indent=2))]

            elif name == "de4dot_deobfuscate":
                result = _de4dot.deobfuscate(
                    arguments["path"],
                    output=arguments.get("output"),
                    obfuscator_type=arguments.get("obfuscator_type"),
                    rename=arguments.get("rename", True),
                    keep_names=arguments.get("keep_names", ""),
                    no_cflow=arguments.get("no_cflow", False),
                    only_cflow=arguments.get("only_cflow", False),
                    str_type=arguments.get("str_type", ""),
                    str_token=arguments.get("str_token", ""),
                    keep_types=arguments.get("keep_types", False),
                    preserve_tokens=arguments.get("preserve_tokens", False),
                    preserve_table=arguments.get("preserve_table", ""),
                    load_new_process=arguments.get("load_new_process", False),
                )
                return ok({
                    "success": result.success,
                    "output_path": result.output_path,
                    "obfuscator": result.obfuscator,
                    "errors": result.errors,
                    "stdout": result.stdout[:2000] if result.stdout else ""
                })

            elif name == "de4dot_clean_strings":
                result = _de4dot.clean_strings(
                    arguments["path"],
                    str_type=arguments.get("str_type", "default"),
                    str_token=arguments.get("str_token", ""),
                    output=arguments.get("output"),
                    load_new_process=arguments.get("load_new_process", False),
                )
                return ok({
                    "success": result.success,
                    "output_path": result.output_path,
                    "stdout": result.stdout[:2000] if result.stdout else ""
                })

            elif name == "de4dot_batch_deobfuscate":
                result = _de4dot.batch_deobfuscate(
                    arguments["input_dir"],
                    output_dir=arguments.get("output_dir"),
                    skip_unsupported=arguments.get("skip_unsupported", False),
                    obfuscator_type=arguments.get("obfuscator_type"),
                    rename=arguments.get("rename", True),
                    keep_names=arguments.get("keep_names", ""),
                    no_cflow=arguments.get("no_cflow", False),
                    str_type=arguments.get("str_type", ""),
                )
                return ok({
                    "success": result.success,
                    "stdout": result.stdout[:2000] if result.stdout else "",
                    "stderr": result.stderr[:1000] if result.stderr else ""
                })

            else:
                return err(f"Unknown tool: {name}")

        except Exception as e:
            return err(str(e))

    return server


async def run_server():
    server = create_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main():
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_server())


if __name__ == "__main__":
    main()
