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

## 编译

### 环境要求

- **Windows SDK**（提供 `cl.exe`、`link.exe`、`ws2_32.lib`、`dbghelp.lib`、`kernel32.lib` 等）
- **CE SDK 头文件**：已放在 `sdk/` 目录，无需额外配置

依赖的 Windows 库：

| 库文件 | 提供者 | 说明 |
|--------|--------|------|
| `ws2_32.lib` | Windows SDK | Winsock2（TCP 通信） |
| `dbghelp.lib` | Windows SDK | StackWalk64 / SymInitialize / UnDecorateSymbolNameA |
| `kernel32.lib` | Windows SDK | 隐式链接（CreateThread / Sleep 等） |

### Visual Studio 编译

#### 方式 1：Developer Command Prompt（推荐）

1. 打开 **开始菜单** → 搜索 **"Developer Command Prompt for VS"**

2. 选择对应的版本：
   - **x64 Native Tools Command Prompt for VS** → 编译 64 位 DLL
   - **x86 Native Tools Command Prompt for VS** → 编译 32 位 DLL

3. 切换到插件目录并编译：

```cmd
cd /d C:\Users\scydr\Desktop\123\nixiang-mcp\ce-mcp\ce-plugin

:: x64 编译
cl /LD /O2 ce-mcp-plugin.c /Fe:ce-mcp-plugin-x64.dll /link ws2_32.lib dbghelp.lib /DEF:ce-mcp-plugin.def

:: x86 编译
cl /LD /O2 ce-mcp-plugin.c /Fe:ce-mcp-plugin-x86.dll /link ws2_32.lib dbghelp.lib /DEF:ce-mcp-plugin.def
```

#### 方式 2：普通 cmd（需先运行 vcvars）

```cmd
:: 设置 VS 环境变量（根据安装路径调整）
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

:: 然后编译
cd /d C:\Users\scydr\Desktop\123\nixiang-mcp\ce-mcp\ce-plugin
cl /LD /O2 ce-mcp-plugin.c /Fe:ce-mcp-plugin-x64.dll /link ws2_32.lib dbghelp.lib /DEF:ce-mcp-plugin.def
```

#### 方式 3：VS IDE 创建项目

1. **File** → **New** → **Project from Existing Code**
2. 项目类型选 **Dynamic Link Library (DLL)**
3. 添加 `ce-mcp-plugin.c` 和 `ce-mcp-plugin.def`
4. **Project Properties** → **Linker** → **Input** → **Additional Dependencies** 添加：
   ```
   ws2_32.lib dbghelp.lib
   ```
5. **C/C++** → **General** → **Additional Include Directories** 添加 `sdk/` 目录
6. 选择 **x64** 或 **x86** 配置，Build

### 编译参数说明

| 参数 | 含义 |
|------|------|
| `/LD` | 生成 DLL |
| `/O2` | 优化速度 |
| `/Fe:` | 指定输出文件名 |
| `/link` | 传递给链接器的参数 |
| `/DEF:` | 模块定义文件（控制导出符号） |

编译完成后将生成的 `.dll` 复制到 CE 的插件目录（通常在 CE 安装目录下创建 `plugin` 文件夹），或通过 CE 菜单手动加载。

### 验证编译结果

```cmd
:: 检查 DLL 是否成功导出了 CE 要求的三个函数
dumpbin /EXPORTS ce-mcp-plugin-x64.dll
```

应看到以下导出：
- `CEPlugin_GetVersion`
- `CEPlugin_InitializePlugin`
- `CEPlugin_DisablePlugin`

## 支持的命令 (22条)

### 基础分析
| 命令 | 说明 | 请求示例 |
|------|------|---------|
| PING | 连接测试和进程信息 | `PING:\n` |
| GET_PROCESS_LIST | 系统进程枚举 | `GET_PROCESS_LIST:\n` |
| GET_MODULES | 进程模块列表 | `GET_MODULES:\n` |
| GET_REGISTERS | 寄存器快照 | `GET_REGISTERS:\n` |
| GET_CALLSTACK | 调用栈回溯（addr+模块名） | `GET_CALLSTACK:,16\n` |
| READ_MEMORY | 读内存 | `READ_MEMORY:0x7FF6A0001000,256\n` |
| DISASSEMBLE | 反汇编 | `DISASSEMBLE:0x7FF6A0001000,30\n` |

### 符号与内存布局
| 命令 | 说明 | 请求示例 |
|------|------|---------|
| GET_SYMBOL_INFO | 符号名 <-> 地址双向解析 | `GET_SYMBOL_INFO:kernel32.CreateFileA\n` |
| ENUM_MEMORY_REGIONS | 完整内存区域枚举 (Base/Size/Protect/Type) | `ENUM_MEMORY_REGIONS:,500\n` |
| ENUM_STRINGS | 内存字符串扫描 (类似 Unix strings) | `ENUM_STRINGS:0x140000000,0x140100000,4\n` |
| GET_RTTI_CLASS | C++ RTTI 类名解析 (vtable->RTTI) | `GET_RTTI_CLASS:0x1A2B3C4D\n` |
| RESOLVE_POINTER | 多级指针链解析 | `RESOLVE_POINTER:0x140000000,0x10,0x8,0x20\n` |

### 代码分析
| 命令 | 说明 | 请求示例 |
|------|------|---------|
| PREV_OPCODE | 向前查找相邻指令地址 | `PREV_OPCODE:0x140001000\n` |
| NEXT_OPCODE | 向后查找相邻指令地址 | `NEXT_OPCODE:0x140001000\n` |
| ASSEMBLE | 汇编指令 -> 机器码字节 | `ASSEMBLE:mov rax,[rcx+8],0x140001000\n` |

### 断点与追踪
| 命令 | 说明 | 请求示例 |
|------|------|---------|
| SET_BP | 硬件断点（自动续执行，按 RIP 分组，含调用栈） | `SET_BP:0x1A2B3C4D,1,15\n` |
| REGISTER_TRACE | 跨函数寄存器追踪（入口/出口配对 + diff） | `REGISTER_TRACE:0x140001000,0x140001050,10\n` |

### 扫描与注入
| 命令 | 说明 | 请求示例 |
|------|------|---------|
| AOB_SCAN | 特征码搜索 (支持 ?? 通配符) | `AOB_SCAN:48 8B 05 ?? ?? ?? ??,game.exe\n` |
| GENERATE_HOOK | AOB 注入脚本手动生成 | `GENERATE_HOOK:0x140001000,,1024\n` |
| GENERATE_API_HOOK | CE 内置 API Hook 脚本生成 (更可靠) | `GENERATE_API_HOOK:kernel32.CreateFileA,myHack\n` |
| MEMORY_SCAN | 精确值内存扫描 (byte/word/dword/qword/float/double/string) | `MEMORY_SCAN:2,100,0x140000000,0x150000000,500\n` |
| MEMORY_SCAN_NEXT | 变/不变过滤链 (链式调用逐步缩小) | `MEMORY_SCAN_NEXT:1,500\n` |

## 协议

- `\n` 分隔请求和响应
- 请求: `COMMAND:param1,param2,...\n`
- 响应: `OK:{"key":"value"}\n` 或 `ERR:message\n`

## CE 7.5 兼容性说明

本插件针对 **CE 7.5 SDK v6** 编写，API 调用与 SDK 头文件签名一致：

- `Exported.Disassembler` — 直接函数指针（非 ppointer）
- `Exported.ReadProcessMemory` — ppointer（二级指针），需 `(*Exported.ReadProcessMemory)(...)`
- `Exported.GetThreadContext` — ppointer，需 `(*Exported.GetThreadContext)(...)`
- `Exported.debug_setBreakpoint` / `debug_removeBreakpoint` — 直接函数指针
- `Exported.Assembler` — 直接函数指针
- `Exported.sym_nameToAddress` / `sym_addressToName` — 直接函数指针
- `Exported.sym_generateAPIHookScript` — 直接函数指针
- `Exported.previousOpcode` / `nextOpcode` — 直接函数指针
- `Exported.GetAddressFromPointer` — 直接函数指针
- `Exported.ProcessList` — 直接函数指针
- `Exported.VirtualQueryEx` — ppointer
- 模块枚举通过 `CreateToolhelp32Snapshot` + `Module32First`/`Module32Next` 实现

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
| `ce_md5_memory` | 内存区域 MD5 哈希 (完整性校验) | MD5_MEMORY |

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
