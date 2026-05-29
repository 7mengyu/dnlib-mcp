"""dnlib backend for .NET assembly analysis using pythonnet."""

import clr
import sys
import os
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field


def _get_default_dnlib_path() -> Optional[str]:
    """获取默认的dnlib.dll路径"""
    # 优先级：环境变量 > 项目目录 > 当前工作目录
    env_path = os.environ.get("DNLIB_PATH")
    if env_path and Path(env_path).exists():
        return env_path

    # 项目根目录（src/backends 的上两级）
    project_root = Path(__file__).parent.parent.parent
    project_dll = project_root / "dnlib.dll"
    if project_dll.exists():
        return str(project_dll)

    # 当前工作目录
    cwd_dll = Path.cwd() / "dnlib.dll"
    if cwd_dll.exists():
        return str(cwd_dll)

    return None


# dnlib默认路径（自动检测）
DNLIB_PATH: Optional[str] = _get_default_dnlib_path()

_dll_loaded = False


def set_dnlib_path(path: str) -> None:
    """设置dnlib.dll的路径"""
    global DNLIB_PATH
    DNLIB_PATH = path


def _ensure_dnlib_loaded() -> None:
    """确保dnlib已加载"""
    global _dll_loaded
    if _dll_loaded:
        return

    if DNLIB_PATH is None:
        raise RuntimeError(
            "dnlib.dll not found. Please either:\n"
            "1. Place dnlib.dll in the project root directory, or\n"
            "2. Set DNLIB_PATH environment variable, or\n"
            "3. Call dnlib_set_path tool with the dll path"
        )

    dll_path = Path(DNLIB_PATH)
    if not dll_path.exists():
        raise FileNotFoundError(f"dnlib.dll not found at: {DNLIB_PATH}")

    sys.path.append(str(dll_path.parent))
    clr.AddReference("dnlib")
    _dll_loaded = True


@dataclass
class MethodInfo:
    """方法信息"""
    name: str
    return_type: str
    parameters: list[tuple[str, str]]  # [(type, name), ...]
    is_static: bool
    is_virtual: bool
    is_abstract: bool
    body_size: int = 0
    token: str = ""


@dataclass
class FieldInfo:
    """字段信息"""
    name: str
    field_type: str
    is_static: bool
    is_public: bool
    token: str = ""


@dataclass
class PropertyInfo:
    """属性信息"""
    name: str
    property_type: str
    has_getter: bool
    has_setter: bool
    is_static: bool
    token: str = ""


@dataclass
class TypeInfo:
    """类型信息"""
    name: str
    full_name: str
    namespace: str
    is_public: bool
    is_sealed: bool
    is_abstract: bool
    is_interface: bool
    is_enum: bool
    is_value_type: bool
    base_type: str
    interfaces: list[str] = field(default_factory=list)
    methods: list[MethodInfo] = field(default_factory=list)
    fields: list[FieldInfo] = field(default_factory=list)
    properties: list[PropertyInfo] = field(default_factory=list)
    token: str = ""


@dataclass
class AssemblyInfo:
    """程序集信息"""
    name: str
    full_name: str
    version: str
    modules: list[str] = field(default_factory=list)


class DnlibBackend:
    """dnlib后端，用于.NET程序集静态分析"""

    def __init__(self, dnlib_path: Optional[str] = None):
        if dnlib_path:
            set_dnlib_path(dnlib_path)
        _ensure_dnlib_loaded()

        from dnlib import AssemblyResolver, ModuleDefMD, Types
        self._AssemblyResolver = AssemblyResolver
        self._ModuleDefMD = ModuleDefMD
        self._Types = Types

        self._loaded_modules: dict[str, any] = {}

    def load_assembly(self, path: str) -> AssemblyInfo:
        """加载.NET程序集"""
        from System.IO import File

        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Assembly not found: {path}")

        module = self._ModuleDefMD.Load(File.ReadAllBytes(path))
        self._loaded_modules[path] = module

        assembly = module.Assembly
        if assembly:
            version = assembly.Version.ToString() if assembly.Version else "0.0.0.0"
            return AssemblyInfo(
                name=assembly.Name or file_path.stem,
                full_name=assembly.FullName or "",
                version=version,
                modules=[module.Name or file_path.name]
            )

        return AssemblyInfo(
            name=file_path.stem,
            full_name="",
            version="0.0.0.0",
            modules=[file_path.name]
        )

    def unload_assembly(self, path: str) -> bool:
        """卸载程序集"""
        if path in self._loaded_modules:
            del self._loaded_modules[path]
            return True
        return False

    def list_types(self, path: str) -> list[str]:
        """列出程序集中的所有类型"""
        if path not in self._loaded_modules:
            self.load_assembly(path)

        module = self._loaded_modules[path]
        types = []

        for td in module.Types:
            if td.FullName:
                types.append(td.FullName)

        return types

    def get_type_info(self, path: str, type_full_name: str) -> Optional[TypeInfo]:
        """获取类型详细信息"""
        if path not in self._loaded_modules:
            self.load_assembly(path)

        module = self._loaded_modules[path]

        for td in module.Types:
            if td.FullName == type_full_name:
                return self._parse_type_def(td)

        return None

    def search_types(self, path: str, pattern: str) -> list[str]:
        """搜索类型名称"""
        if path not in self._loaded_modules:
            self.load_assembly(path)

        module = self._loaded_modules[path]
        pattern_lower = pattern.lower()
        results = []

        for td in module.Types:
            if td.FullName and pattern_lower in td.FullName.lower():
                results.append(td.FullName)

        return results

    def search_methods(self, path: str, pattern: str) -> list[dict]:
        """搜索方法"""
        if path not in self._loaded_modules:
            self.load_assembly(path)

        module = self._loaded_modules[path]
        pattern_lower = pattern.lower()
        results = []

        for td in module.Types:
            for md in td.Methods:
                if md.Name and pattern_lower in md.Name.lower():
                    results.append({
                        "type": td.FullName,
                        "method": md.Name,
                        "signature": str(md.Signature) if md.Signature else ""
                    })

        return results

    def decompile_method(self, path: str, type_full_name: str, method_name: str) -> str:
        """反编译方法为IL代码"""
        if path not in self._loaded_modules:
            self.load_assembly(path)

        module = self._loaded_modules[path]

        for td in module.Types:
            if td.FullName == type_full_name:
                for md in td.Methods:
                    if md.Name == method_name:
                        return self._get_method_il(md)

        return ""

    def get_entry_point(self, path: str) -> Optional[dict]:
        """获取程序入口点"""
        if path not in self._loaded_modules:
            self.load_assembly(path)

        module = self._loaded_modules[path]
        ep = module.EntryPoint

        if ep:
            return {
                "token": str(ep.MDToken.ToInt32()),
                "name": ep.Name,
                "declaring_type": ep.DeclaringType.FullName if ep.DeclaringType else ""
            }

        return None

    def list_resources(self, path: str) -> list[dict]:
        """列出嵌入资源"""
        if path not in self._loaded_modules:
            self.load_assembly(path)

        module = self._loaded_modules[path]
        resources = []

        for r in module.Resources:
            resources.append({
                "name": r.Name,
                "type": type(r).__name__,
                "size": getattr(r, "MemoryResourceLength", 0) or 0
            })

        return resources

    def _parse_type_def(self, td) -> TypeInfo:
        """解析类型定义"""
        base_type = ""
        if td.BaseType:
            base_type = td.BaseType.FullName or ""

        interfaces = []
        for iface in td.Interfaces:
            if iface.Interface:
                name = iface.Interface.FullName
                if name:
                    interfaces.append(name)

        methods = []
        for md in td.Methods:
            methods.append(self._parse_method_def(md))

        fields = []
        for fd in td.Fields:
            fields.append(self._parse_field_def(fd))

        properties = []
        for pd in td.Properties:
            properties.append(self._parse_property_def(pd))

        return TypeInfo(
            name=td.Name,
            full_name=td.FullName,
            namespace=td.Namespace,
            is_public=td.IsPublic,
            is_sealed=td.IsSealed,
            is_abstract=td.IsAbstract,
            is_interface=td.IsInterface,
            is_enum=td.IsEnum,
            is_value_type=td.IsValueType,
            base_type=base_type,
            interfaces=interfaces,
            methods=methods,
            fields=fields,
            properties=properties,
            token=str(td.MDToken.ToInt32())
        )

    def _parse_method_def(self, md) -> MethodInfo:
        """解析方法定义"""
        params = []
        if md.Parameters:
            for p in md.Parameters:
                if p.Type and p.Name:
                    params.append((str(p.Type), p.Name))

        return_type = "void"
        if md.Signature and md.Signature.RetType:
            return_type = str(md.Signature.RetType)

        return MethodInfo(
            name=md.Name,
            return_type=return_type,
            parameters=params,
            is_static=md.IsStatic,
            is_virtual=md.IsVirtual,
            is_abstract=md.IsAbstract,
            body_size=md.Body.Size if md.Body else 0,
            token=str(md.MDToken.ToInt32())
        )

    def _parse_field_def(self, fd) -> FieldInfo:
        """解析字段定义"""
        field_type = ""
        if fd.FieldType:
            field_type = str(fd.FieldType)

        return FieldInfo(
            name=fd.Name,
            field_type=field_type,
            is_static=fd.IsStatic,
            is_public=fd.IsPublic,
            token=str(fd.MDToken.ToInt32())
        )

    def _parse_property_def(self, pd) -> PropertyInfo:
        """解析属性定义"""
        prop_type = ""
        if pd.Type:
            prop_type = str(pd.Type)

        return PropertyInfo(
            name=pd.Name,
            property_type=prop_type,
            has_getter=pd.GetMethods.Count > 0,
            has_setter=pd.SetMethods.Count > 0,
            is_static=pd.GetMethods.Count > 0 and pd.GetMethods[0].IsStatic if pd.GetMethods.Count > 0 else False,
            token=str(pd.MDToken.ToInt32())
        )

    def _get_method_il(self, md) -> str:
        """获取方法IL代码"""
        if not md.Body:
            return "; No method body (external or abstract)"

        lines = []
        lines.append(f"; Method: {md.FullName}")
        lines.append(f"; Token: 0x{md.MDToken.ToInt32():08X}")
        lines.append("")

        for instr in md.Body.Instructions:
            lines.append(f"IL_{instr.Offset:X4}: {instr}")

        return "\n".join(lines)