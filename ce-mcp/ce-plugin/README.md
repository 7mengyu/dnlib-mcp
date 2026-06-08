# ce-mcp-plugin

Cheat Engine MCP 插件（CE 7.5 适配版），为 AI 助手提供 CE 内存分析能力。

## 设计原则

只实现**分析类命令**。读写、冻结、UI 操作在 CE 界面直接操作更高效，AI 的价值在于分析和决策。

## 通信架构

```
CE (插件 DLL) --TCP Client--> Python MCP Server (bridge.py) --stdio--> Claude Code
      127.0.0.1:8888                            ce-mcp MCP Server
```

CE 插件作为 TCP **客户端**，启动时连接 Python MCP Server。MCP Server 再通过 stdio 与 Claude Code 通信。

## 项目结构

```
ce-plugin/
├── plugin.h              # 公共头文件 (类型定义、ppinter 宏、函数声明)
├── plugin-core.c         # 核心框架 (网络/解析/生命周期/命令分发)
├── plugin-debug.c        # 调试追踪 (SET_BP/GET_REGISTERS/GET_CALLSTACK/REGISTER_TRACE)
├── plugin-analyze.c      # 分析命令 (DISASSEMBLE/AOB_SCAN/PREV_OPCODE/NEXT_OPCODE/ASSEMBLE/
│                         #            GET_SYMBOL_INFO/ENUM_MEMORY_REGIONS/GET_RTTI_CLASS/
│                         #            ENUM_STRINGS/PING/READ_MEMORY/GET_MODULES/GET_PROCESS_LIST/
│                         #            RESOLVE_POINTER)
├── plugin-scan.c         # 内存扫描 (MEMORY_SCAN/MEMORY_SCAN_NEXT)
├── plugin-gen.c          # 脚本生成 (GENERATE_HOOK/GENERATE_API_HOOK)
├── ce-mcp-plugin.def     # DLL 导出符号
├── sdk/cepluginsdk.h     # CE 7.5 SDK 头文件
├── sdk/lua.h             # Lua C API 头文件
├── sdk/lualib.h          # Lua 标准库
├── sdk/lauxlib.h         # Lua 辅助库
├── sdk/luaconf.h         # Lua 配置
├── sdk/lua.hpp           # Lua C++ 包装
├── sdk/zydis/            # Zydis 4.1.1 反汇编引擎（内嵌静态编译，替代 CE 7.5 失效的 Disassembler）
│   ├── include/
│   │   ├── Zydis/        # Zydis 公共头
│   │   │   ├── Generated/
│   │   │   └── Internal/
│   │   └── Zycore/       # Zycore 基础库头
│   │       ├── API/
│   │       └── Internal/
│   └── src/              # Zydis + Zycore 源文件（约30个.c）
│       ├── Generated/    # .inc 生成数据表
│       └── API/

../src/
├── server.py             # MCP Server (23 个工具)
├── bridge.py             # TCP 桥接
└── __init__.py
```

## 编译

### 环境要求

- **Visual Studio 2022 Build Tools**（提供 `cl.exe`、`link.exe`）
- **Windows SDK**（提供 `ws2_32.lib`、`dbghelp.lib`）
- **CE SDK 头文件**：已放在 `sdk/` 目录，无需额外配置
- **Zydis 反汇编引擎**：已放在 `sdk/zydis/` 目录，无需额外配置（替代 CE 7.5 失效的 Disassembler）

### 方式 1：Developer Command Prompt（推荐）

1. 打开 **开始菜单** → 搜索 **"x64 Native Tools Command Prompt for VS 2022"**
2. 切换到项目目录并执行：

```cmd
cd /d C:\Users\scydr\Desktop\123\nixiang-mcp\ce-mcp\ce-plugin

:: 清理上次编译产物（obj/lib/exp 会触发增量链接，可能导致冲突）
del /q *.obj *.lib *.exp 2>nul

:: 发布版 — 包含 Zydis 静态反汇编引擎
cl /utf-8 /TC /LD /O2 /I"sdk\zydis\include" /I"sdk\zydis\src" plugin-core.c plugin-debug.c plugin-analyze.c plugin-scan.c plugin-gen.c sdk\zydis\src\*.c sdk\zydis\src\API\*.c /DZYDIS_STATIC_BUILD /DZYCORE_STATIC_BUILD /Fe:ce-mcp-plugin-x64.dll /link ws2_32.lib dbghelp.lib /DEF:ce-mcp-plugin.def

:: 调试版 (PDB 符号 + 禁用优化，出问题时用 VS 附加 CE 断点排查)
cl /utf-8 /TC /LD /Od /Zi /I"sdk\zydis\include" /I"sdk\zydis\src" plugin-core.c plugin-debug.c plugin-analyze.c plugin-scan.c plugin-gen.c sdk\zydis\src\*.c sdk\zydis\src\API\*.c /DZYDIS_STATIC_BUILD /DZYCORE_STATIC_BUILD /Fe:ce-mcp-plugin-x64-debug.dll /link ws2_32.lib dbghelp.lib /DEF:ce-mcp-plugin.def
```

3. 打开 **"x86 Native Tools Command Prompt for VS 2022"**（注：x86 和 x64 必须在各自对应的终端编译）并执行：

```cmd
cd /d C:\Users\scydr\Desktop\123\nixiang-mcp\ce-mcp\ce-plugin

:: 清理上次编译产物
del /q *.obj *.lib *.exp 2>nul

:: x86 编译
cl /utf-8 /TC /LD /O2 /I"sdk\zydis\include" /I"sdk\zydis\src" ^
    plugin-core.c plugin-debug.c plugin-analyze.c plugin-scan.c plugin-gen.c ^
    sdk\zydis\src\*.c sdk\zydis\src\API\*.c ^
    /DZYDIS_STATIC_BUILD /DZYCORE_STATIC_BUILD ^
    /Fe:ce-mcp-plugin-x86.dll ^
    /link ws2_32.lib dbghelp.lib /DEF:ce-mcp-plugin.def
```

> `/TC` 强制将所有 `.c` 文件视为 C 源码。
> `/I"sdk\zydis\include"` 包含 Zydis/Zycore 头文件。
> `/DZYDIS_STATIC_BUILD /DZYCORE_STATIC_BUILD` 启用静态链接模式（无 .lib 依赖）。
> `/O2` 是发布版开关。日常用发布版跑，出问题时用上面的调试版（`/Od /Zi`）来 VS 断点排查。

### 方式 2：手动设置 vcvars

```cmd
:: x64 编译
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
:: 如果没有 Community 版，改用：
:: call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

cd /d C:\Users\scydr\Desktop\123\nixiang-mcp\ce-mcp\ce-plugin
del /q *.obj *.lib *.exp 2>nul
cl /utf-8 /TC /LD /O2 /I"sdk\zydis\include" /I"sdk\zydis\src" plugin-core.c plugin-debug.c plugin-analyze.c plugin-scan.c plugin-gen.c sdk\zydis\src\*.c sdk\zydis\src\API\*.c /DZYDIS_STATIC_BUILD /DZYCORE_STATIC_BUILD /Fe:ce-mcp-plugin-x64.dll /link ws2_32.lib dbghelp.lib /DEF:ce-mcp-plugin.def

:: x86 编译（需要 x86 终端或 vcvars32.bat）
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
cd /d C:\Users\scydr\Desktop\123\nixiang-mcp\ce-mcp\ce-plugin
del /q *.obj *.lib *.exp 2>nul
cl /TC /LD /O2 /I"sdk\zydis\include" /I"sdk\zydis\src" plugin-core.c plugin-debug.c plugin-analyze.c plugin-scan.c plugin-gen.c sdk\zydis\src\*.c sdk\zydis\src\API\*.c /DZYDIS_STATIC_BUILD /DZYCORE_STATIC_BUILD /Fe:ce-mcp-plugin-x86.dll /link ws2_32.lib dbghelp.lib /DEF:ce-mcp-plugin.def
```

### 方式 3：VS IDE 创建项目

1. **File** → **New** → **Project** → **Dynamic Link Library (DLL)**
2. 添加所有 `.c` 文件和 `plugin.h`、`.def` 文件，以及 `sdk/zydis/src/` 和 `sdk/zydis/src/API/` 下的所有 `.c` 文件
3. **Linker** → **Input** → **Additional Dependencies**: `ws2_32.lib; dbghelp.lib`
4. **C/C++** → **General** → **Additional Include Directories**: 添加 `sdk/` 和 `sdk/zydis/include/` 目录
5. **C/C++** → **Preprocessor** → **Preprocessor Definitions**: 添加 `ZYDIS_STATIC_BUILD` 和 `ZYCORE_STATIC_BUILD`
6. **C/C++** → **Advanced** → **Compile As**: `Compile as C Code (/TC)`
7. Build

### 编译参数

| 参数 | 含义 |
|------|------|
| `/utf-8` | 源文件和执行字符集设为 UTF-8（消除中文注释警告） |
| `/TC` | 强制 C 编译模式 |
| `/LD` | 生成 DLL |
| `/O2` | 优化速度 |
| `/I"sdk\zydis\include"` | Zydis/Zycore 头文件路径 |
| `/I"sdk\zydis\src"` | Zydis/Zycore 生成数据表 (.inc) 路径 |
| `/DZYDIS_STATIC_BUILD` | Zydis 静态库模式（无 .lib 依赖） |
| `/DZYCORE_STATIC_BUILD` | Zycore 静态库模式 |
| `/Fe:` | 指定输出文件名 |
| `/link` | 传递给链接器的参数 |
| `/DEF:` | 模块定义文件 |

### 验证编译结果

```cmd
dumpbin /EXPORTS ce-mcp-plugin-x64.dll
```

应看到以下导出：
- `CEPlugin_GetVersion`
- `CEPlugin_InitializePlugin`
- `CEPlugin_DisablePlugin`

## 协议

- `\n` 分隔请求和响应
- 请求: `COMMAND:param1,param2,...\n`
- 响应: `OK:{"key":"value"}\n` 或 `ERR:message\n`

## CE 7.5 兼容性说明

本插件针对 **CE 7.5 SDK v6** 编写，API 调用与 SDK 头文件签名一致。

### 直接函数指针（直接调用）

| API | SDK typedef (行号) | Pascal 实现 (行号) |
|-----|-------------------|-------------------|
| `Disassembler` | L170 `CEP_DISASSEMBLER` → BOOL | `pluginexports.pas:793` |
| `Assembler` | L169 `CEP_ASSEMBLER` → BOOL + *returnedsize | `pluginexports.pas:769` → PByteArray + pinteger |
| `disassembleEx` | L188 `CEP_DISASSEMBLEEX` → BOOL (传入 pptrUint) | `pluginexports.pas:811` → 反汇编后更新 *address |
| `debug_setBreakpoint` | L216 → BOOL | `plugin.pas:1997` |
| `debug_removeBreakpoint` | L217 → BOOL | `plugin.pas:1998` |
| `debug_continueFromBreakpoint` | L218 → BOOL | `plugin.pas:1999` |
| `sym_nameToAddress` | L181 → BOOL | `pluginexports.pas:39` → param2: PPtrUInt |
| `sym_addressToName` | L180 → BOOL | `pluginexports.pas:38` |
| `sym_generateAPIHookScript` | L179 → BOOL (5参数) | `pluginexports.pas:417` → s.Text copy |
| `previousOpcode` | L185 → UINT_PTR | `pluginexports.pas:833` → ptrUint |
| `nextOpcode` | L186 → UINT_PTR | `pluginexports.pas:838` → ptrUint |
| `Disassembler` | L170 `CEP_DISASSEMBLER` → BOOL | `pluginexports.pas:793` |
| `disassembleEx` | L188 `CEP_DISASSEMBLEEX` (UINT_PTR* address) | `pluginexports.pas:811` → 反汇编后更新 *address |

> **v0.5.0 修复**: `previousOpcode`/`nextOpcode` SDK 返回类型从 `DWORD`（32位）修正为 `UINT_PTR`（64位），修复 x64 下地址截断高位问题。
> **v0.5.0 修复**: `Disassembler`/`disassembleEx` 在 CE 7.5 插件上下文中永远返回 FALSE（CE 内部缺陷），改用 Zydis 4.1.1 独立反汇编引擎。
| `GetAddressFromPointer` | L178 → UINT_PTR | `pluginexports.pas:33` → dword (遍历 offsets) |
| `ProcessList` | L176 → BOOL | `pluginexports.pas:567` → %08X-name\r\n 格式 |
| `RegisterFunction` | L165 → int (pluginid) | `pluginexports.pas:19` → ptOnDebugEvent=2 |

### ppointer（二级指针，需解引用）

插件使用 `plugin.h` 中定义的宏统一解引用：

| 宏 | SDK 字段 | 实际类型 | Pascal 赋值 (plugin.pas) |
|----|---------|---------|------------------------|
| `RPM(hProc,...)` | `PVOID ReadProcessMemory` (L299) | `BOOL (__stdcall **)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*)` | L1880 `@@ReadProcessMemoryActual` |
| `GTC(hThread,ctx)` | `PVOID GetThreadContext` (L301) | `BOOL (__stdcall **)(HANDLE, LPCONTEXT)` | L1882 `@@GetThreadContext` |
| `OT(acc,inh,tid)` | `PVOID OpenThread` (L316) | `HANDLE (__stdcall **)(DWORD, BOOL, DWORD)` | L1897 `@@OpenThread` |
| `CS(flags,pid)` | `PVOID CreateToolhelp32Snapshot` (L354) | `HANDLE (__stdcall **)(DWORD, DWORD)` | L1936 `@@CreateToolhelp32Snapshot` |
| `M32F(snap,me)` | `PVOID Module32First` (L359) | `BOOL (__stdcall **)(HANDLE, LPMODULEENTRY32)` | L1941 `@@Module32First` |
| `M32N(snap,me)` | `PVOID Module32Next` (L360) | `BOOL (__stdcall **)(HANDLE, LPMODULEENTRY32)` | L1942 `@@Module32Next` |
| `T32F(snap,te)` | `PVOID Thread32First` (L357) | `BOOL (__stdcall **)(HANDLE, LPTHREADENTRY32)` | L1939 `@@Thread32First` |
| `T32N(snap,te)` | `PVOID Thread32Next` (L358) | `BOOL (__stdcall **)(HANDLE, LPTHREADENTRY32)` | L1940 `@@Thread32Next` |
| `VQE(hProc,addr,mbi,sz)` | `PVOID VirtualQueryEx` (L313) | `LONG (__stdcall **)(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T)` | L1894 `@@VirtualQueryExActual` |

## 支持的命令 (22条)

### 基础分析
| 命令 | 说明 | 文件 |
|------|------|------|
| PING | 连接测试和进程信息 | plugin-analyze.c |
| GET_PROCESS_LIST | 系统进程枚举 | plugin-analyze.c |
| GET_MODULES | 进程模块列表 | plugin-analyze.c |
| READ_MEMORY | 读内存 | plugin-analyze.c |

### 寄存器与调用栈
| 命令 | 说明 | 文件 |
|------|------|------|
| GET_REGISTERS | 寄存器快照 | plugin-debug.c |
| GET_CALLSTACK | 调用栈回溯（addr+模块名） | plugin-debug.c |

### 符号与内存布局
| 命令 | 说明 | 文件 |
|------|------|------|
| GET_SYMBOL_INFO | 符号名 <-> 地址双向解析 | plugin-analyze.c |
| ENUM_MEMORY_REGIONS | 完整内存区域枚举 (Base/Size/Protect/Type) | plugin-analyze.c |
| ENUM_STRINGS | 内存字符串扫描 (类似 Unix strings) | plugin-analyze.c |
| GET_RTTI_CLASS | C++ RTTI 类名解析 (vtable->RTTI) | plugin-analyze.c |
| RESOLVE_POINTER | 多级指针链解析 | plugin-analyze.c |

### 代码分析
| 命令 | 说明 | 文件 |
|------|------|------|
| DISASSEMBLE | 反汇编 | plugin-analyze.c |
| ASSEMBLE | 汇编指令 -> 机器码字节 | plugin-analyze.c |
| PREV_OPCODE | 向前查找相邻指令地址 | plugin-analyze.c |
| NEXT_OPCODE | 向后查找相邻指令地址 | plugin-analyze.c |

### 断点与追踪
| 命令 | 说明 | 文件 |
|------|------|------|
| SET_BP | 硬件断点（自动续执行，按 RIP 分组，含调用栈） | plugin-debug.c |
| REGISTER_TRACE | 跨函数寄存器追踪（入口/出口配对 + diff） | plugin-debug.c |

### 扫描与注入
| 命令 | 说明 | 文件 |
|------|------|------|
| AOB_SCAN | 特征码搜索 (支持 ?? 通配符) | plugin-analyze.c |
| MEMORY_SCAN | 精确值内存扫描 (byte/word/dword/qword/float/double/string) | plugin-scan.c |
| MEMORY_SCAN_NEXT | 变/不变过滤链 (链式调用逐步缩小) | plugin-scan.c |
| GENERATE_HOOK | AOB 注入脚本手动生成 | plugin-gen.c |
| GENERATE_API_HOOK | CE 内置 API Hook 脚本生成 (更可靠) | plugin-gen.c |

## MCP 工具 (23个)

Python MCP Server（`ce-mcp/src/server.py`）暴露了以下 MCP 工具：

### 状态与进程
| 工具 | 说明 | 对应命令 |
|------|------|---------|
| `ce_status` | 检查 CE 插件连接状态和当前附加进程 | (本地) |
| `ce_ping` | 测试 CE 插件连接，返回进程信息 | PING |
| `ce_get_process_list` | 列出系统所有运行进程 (PID+名称) | GET_PROCESS_LIST |
| `ce_get_modules` | 目标进程模块列表 (名称/基址/大小) | GET_MODULES |

### 寄存器与调用栈
| 工具 | 说明 | 对应命令 |
|------|------|---------|
| `ce_get_registers` | 当前调试寄存器快照 | GET_REGISTERS |
| `ce_get_callstack` | 当前线程调用栈 (地址+模块名) | GET_CALLSTACK |
| `ce_read_memory` | 读取指定地址内存数据 (hex) | READ_MEMORY |

### 符号与内存布局
| 工具 | 说明 | 对应命令 |
|------|------|---------|
| `ce_get_symbol_info` | 符号名<->地址双向解析 (模块/导出/PDB) | GET_SYMBOL_INFO |
| `ce_enum_memory_regions` | 枚举进程完整内存布局 (基址/大小/保护/类型) | ENUM_MEMORY_REGIONS |
| `ce_enum_strings` | 扫描内存中可打印字符串 (类似 Unix strings) | ENUM_STRINGS |
| `ce_get_rtti_class` | C++ RTTI 类名解析 (vtable->RTTI链) | GET_RTTI_CLASS |
| `ce_resolve_pointer` | 多级指针链: base+offsets->最终地址 | RESOLVE_POINTER |

### 代码分析
| 工具 | 说明 | 对应命令 |
|------|------|---------|
| `ce_disassemble` | 反汇编指定地址处的代码 | DISASSEMBLE |
| `ce_assemble` | 汇编单条指令 -> 机器码字节 | ASSEMBLE |
| `ce_prev_opcode` | 向前查找相邻指令地址 | PREV_OPCODE |
| `ce_next_opcode` | 向后查找相邻指令地址 | NEXT_OPCODE |

### 断点与追踪
| 工具 | 说明 | 对应命令 |
|------|------|---------|
| `ce_set_breakpoint` | 硬件断点监控 (命中记录含寄存器+调用栈+RIP分组) | SET_BP |
| `ce_register_trace` | 跨函数寄存器追踪 (入口/出口配对+diff) | REGISTER_TRACE |

### 扫描与注入
| 工具 | 说明 | 对应命令 |
|------|------|---------|
| `ce_aob_scan` | AOB 特征码搜索 (支持 ?? 通配符) | AOB_SCAN |
| `ce_memory_scan` | 精确值扫描 (byte/word/dword/qword/float/double/string) | MEMORY_SCAN |
| `ce_memory_scan_next` | 变/不变过滤链 (链式调用逐步缩小范围) | MEMORY_SCAN_NEXT |
| `ce_generate_hook` | 手动生成 AutoAssemble 注入脚本 | GENERATE_HOOK |
| `ce_generate_api_hook` | CE 内置 API Hook 脚本生成 (更可靠) | GENERATE_API_HOOK |
