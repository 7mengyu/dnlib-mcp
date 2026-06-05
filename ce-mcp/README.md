# ce-mcp

Cheat Engine 内存分析 MCP Server，为 AI 编程助手（Claude Code）提供游戏逆向和内存分析能力。

## 功能概述

ce-mcp 由两部分组成：

1. **CE 插件 DLL**（C 语言）—— 嵌入 Cheat Engine 进程，调用 CE 7.5 SDK 提供的调试器、反汇编器、内存扫描等底层能力
2. **Python MCP Server**（Python）—— 通过 TCP Bridge 与 CE 插件通信，向 Claude Code 暴露 23 个 MCP 工具

### 通信架构

```
CE (插件 DLL) --TCP Client--> Python MCP Server (bridge.py) --stdio--> Claude Code
      127.0.0.1:8888                            ce-mcp MCP Server
```

CE 插件作为 TCP **客户端**，启动时自动连接 Python MCP Server。MCP Server 再通过 stdio 与 Claude Code 通信。

### 设计原则

只实现**分析类命令**。读写、冻结、UI 操作在 CE 界面直接操作更高效，AI 的价值在于分析和决策。

## MCP 工具列表（23 个）

### 状态与进程

| 工具 | 说明 | 对应命令 |
|------|------|---------|
| `ce_status` | 检查 CE 插件连接状态和当前附加进程 | （本地） |
| `ce_ping` | 测试 CE 插件连接，返回进程信息 | PING |
| `ce_get_process_list` | 列出系统所有运行进程（PID + 名称） | GET_PROCESS_LIST |
| `ce_get_modules` | 目标进程模块列表（名称 / 基址 / 大小） | GET_MODULES |

### 寄存器与调用栈

| 工具 | 说明 | 对应命令 |
|------|------|---------|
| `ce_get_registers` | 当前调试寄存器快照 | GET_REGISTERS |
| `ce_get_callstack` | 当前线程调用栈（地址 + 模块名） | GET_CALLSTACK |
| `ce_read_memory` | 读取指定地址内存数据（hex） | READ_MEMORY |

### 符号与内存布局

| 工具 | 说明 | 对应命令 |
|------|------|---------|
| `ce_get_symbol_info` | 符号名 <-> 地址双向解析（模块/导出/PDB） | GET_SYMBOL_INFO |
| `ce_enum_memory_regions` | 枚举进程完整内存布局（基址/大小/保护/类型） | ENUM_MEMORY_REGIONS |
| `ce_enum_strings` | 扫描内存中可打印字符串（类似 Unix strings） | ENUM_STRINGS |
| `ce_get_rtti_class` | C++ RTTI 类名解析（vtable -> RTTI 链） | GET_RTTI_CLASS |
| `ce_resolve_pointer` | 多级指针链：base + offsets → 最终地址 | RESOLVE_POINTER |

### 代码分析

| 工具 | 说明 | 对应命令 |
|------|------|---------|
| `ce_disassemble` | 反汇编指定地址处的代码 | DISASSEMBLE |
| `ce_assemble` | 汇编单条指令 → 机器码字节 | ASSEMBLE |
| `ce_prev_opcode` | 向前查找相邻指令地址 | PREV_OPCODE |
| `ce_next_opcode` | 向后查找相邻指令地址 | NEXT_OPCODE |

### 断点与追踪

| 工具 | 说明 | 对应命令 |
|------|------|---------|
| `ce_set_breakpoint` | 硬件断点监控（命中记录含寄存器 + 调用栈 + RIP 分组） | SET_BP |
| `ce_register_trace` | 跨函数寄存器追踪（入口/出口配对 + diff） | REGISTER_TRACE |

### 扫描与注入

| 工具 | 说明 | 对应命令 |
|------|------|---------|
| `ce_aob_scan` | AOB 特征码搜索（支持 `??` 通配符） | AOB_SCAN |
| `ce_memory_scan` | 精确值扫描（byte/word/dword/qword/float/double/string） | MEMORY_SCAN |
| `ce_memory_scan_next` | 变/不变过滤链（链式调用逐步缩小范围） | MEMORY_SCAN_NEXT |
| `ce_generate_hook` | 手动生成 AutoAssemble 注入脚本 | GENERATE_HOOK |
| `ce_generate_api_hook` | CE 内置 API Hook 脚本生成（更可靠） | GENERATE_API_HOOK |

## 快速开始

### 环境要求

- Python 3.10+
- Windows 系统
- Cheat Engine 7.5+
- 预编译的插件 DLL（`ce-mcp/ce-plugin/` 下已提供 x64/x86 版本）

### 步骤 1：CE 加载插件dll

- x64 DLL 用于附加 64 位进程，x86 DLL 用于附加 32 位进程
- CE `autorun/dlls` 目录不支持自动加载 DLL（仅 `autorun/` 根目录支持 Lua 脚本自动执行）
- **正确的加载方式**：CE 菜单 → Edit → Settings → Plugins → Add，手动选择 DLL 文件

### 步骤 2：启动 Python MCP Bridge

打开终端，进入 `ce-mcp` 子目录：

```cmd
cd C:\Users\scydr\Desktop\123\nixiang-mcp\ce-mcp
claude
```

> `.mcp.json` 会自动启动 Bridge 并注册 `ce-mcp` 服务器。

### 步骤 3：打开 Cheat Engine 附加进程

1. **以管理员身份**启动 Cheat Engine 7.5
2. 手动加载插件：Edit → Settings → Plugins → Add → 选择 `ce-mcp-plugin-x64.dll`
3. 通过 File → Open Process 附加目标进程
4. CE 标题栏会显示 `CE MCP Plugin v0.x - Connected to bridge`，表示插件已连接 Bridge

### 步骤 4：在 Claude Code 中使用

启动 Claude Code 后，输入 `/mcp` 确认 `ce-mcp` 状态为 ✔ connected。

### 验证测试

附加系统 notepad.exe 进程后，用以下命令验证链路：

```
# 1. 测试连接和进程信息
检查 CE 连接状态

# 2. 获取进程模块列表
列出当前进程的模块

# 3. 反汇编入口附近代码
反编译 notepad.exe 入口附近代码，20 条指令

# 4. 读取内存（任选一个模块基址）
读取 0x<模块基址> 处内存，256 字节
```

四项都能返回正常结果，说明 CE → Bridge → MCP → Claude Code 链路完整。

## 协议

- `\n` 分隔请求和响应
- 请求：`COMMAND:param1,param2,...\n`
- 响应：`OK:{"key":"value"}\n` 或 `ERR:message\n`

## 项目结构

```
ce-mcp/
├── README.md                  # 主文档（当前文件）
├── ce-plugin/
│   ├── README.md              # 插件详细文档（含编译说明）
│   ├── plugin.h               # 公共头文件（类型定义、ppinter 宏、函数声明）
│   ├── plugin-core.c          # 核心框架（网络/解析/生命周期/命令分发）
│   ├── plugin-debug.c         # 调试追踪（SET_BP / GET_REGISTERS / GET_CALLSTACK / REGISTER_TRACE）
│   ├── plugin-analyze.c       # 分析命令（14 条：DISASSEMBLE / AOB_SCAN / PREV_OPCODE / ...）
│   ├── plugin-scan.c          # 内存扫描（MEMORY_SCAN / MEMORY_SCAN_NEXT）
│   ├── plugin-gen.c           # 脚本生成（GENERATE_HOOK / GENERATE_API_HOOK）
│   ├── ce-mcp-plugin.def      # DLL 导出符号
│   ├── ce-mcp-plugin-x64.dll  # 预编译 x64 DLL
│   ├── ce-mcp-plugin-x86.dll  # 预编译 x86 DLL
│   └── sdk/                   # CE 7.5 SDK + Lua 头文件
└── src/
    ├── server.py             # MCP Server（23 个工具）
    ├── bridge.py             # TCP 桥接
    └── __init__.py
```

## 编译插件

详见 [ce-plugin/README.md](ce-plugin/README.md)。

```cmd
:: 进入插件目录
cd /d C:\Users\scydr\Desktop\123\nixiang-mcp\ce-mcp\ce-plugin

:: 清理旧编译产物
del /q *.obj *.lib *.exp 2>nul

:: x64 发布版
cl /utf-8 /TC /LD /O2 plugin-core.c plugin-debug.c plugin-analyze.c plugin-scan.c plugin-gen.c /Fe:ce-mcp-plugin-x64.dll /link ws2_32.lib dbghelp.lib /DEF:ce-mcp-plugin.def

:: x64 调试版（出问题时用 VS 断点排查）
cl /utf-8 /TC /LD /Od /Zi plugin-core.c plugin-debug.c plugin-analyze.c plugin-scan.c plugin-gen.c /Fe:ce-mcp-plugin-x64-debug.dll /link ws2_32.lib dbghelp.lib /DEF:ce-mcp-plugin.def
```

x86 编译需要在 **x86 Native Tools Command Prompt for VS 2022** 中执行。

## 相关文档

| 文档 | 说明 |
|------|------|
| [ce-plugin/README.md](ce-plugin/README.md) | CE 插件详细文档（编译、API 兼容性、命令列表） |
| [../docs/ce-design.md](../docs/ce-design.md) | CE MCP 后端架构和场景设计 |
| [../docs/ce-prompt.md](../docs/ce-prompt.md) | CE 逆向分析提示词参考 |
| [../README.md](../README.md) | 项目总览（nixiang-mcp） |
