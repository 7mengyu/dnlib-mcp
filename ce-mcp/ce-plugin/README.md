# ce-mcp-plugin

Cheat Engine MCP 插件（CE 7.5 适配版），为 AI 助手提供 CE 分析能力。

## 设计原则

只实现**分析类命令**。读写/冻结/UI操作在 CE 界面直接操作更高效，AI 的价值在于分析和决策。

## 通信架构

```
CE (插件 DLL) --TCP Client--> Python MCP Server (bridge.py) --stdio--> Claude Code
          127.0.0.1:8888                            ce-mcp MCP Server
```

CE 插件作为 TCP **客户端**，启动时连接 Python MCP Server。MCP Server 通过 stdio 与 Claude Code 通信。

## 编译

需要 Visual Studio 或 MSVC Build Tools。SDK 头文件已放在 `sdk/` 目录，无需额外配置。

```bash
# 在 ce-mcp/ce-plugin/ 目录下执行：

# x64 编译:
cl /LD /O2 ce-mcp-plugin.c /Fe:ce-mcp-plugin-x64.dll /link ws2_32.lib /DEF:ce-mcp-plugin.def

# x86 编译:
cl /LD /O2 ce-mcp-plugin.c /Fe:ce-mcp-plugin-x86.dll /link ws2_32.lib /DEF:ce-mcp-plugin.def
```

编译完成后将 `.dll` 放入 CE 的插件目录或手动加载。

## 支持的命令

| 命令 | 说明 | 请求示例 |
|------|------|---------|
| PING | 连接测试 + 进程信息 | `PING:\n` |
| DISASSEMBLE | 反汇编 | `DISASSEMBLE:0x7FF6A0001000,30\n` |
| GET_MODULES | 进程模块列表 | `GET_MODULES:\n` |
| GET_REGISTERS | 寄存器快照 | `GET_REGISTERS:\n` |
| READ_MEMORY | 读内存(调试用) | `READ_MEMORY:0x7FF6A0001000,256\n` |
| SET_BP | 硬件断点(持续监控) | `SET_BP:0x1A2B3C4D,1,15\n` |
| AOB_SCAN | 特征码搜索 | `AOB_SCAN:48 8B 05 ?? ?? ?? ??,game.exe\n` |

## 协议

- `\n` 分隔请求和响应
- 请求: `COMMAND:param1,param2,...\n`
- 响应: `OK:{"key":"value"}\n` 或 `ERR:message\n`

## CE 7.5 兼容性说明

本插件针对 **CE 7.5 SDK v6** 编写，API 调用与上游 cepluginsdk.h 签名一致：

- `Exported.Disassembler` — 直接函数指针（非 ppointer）
- `Exported.ReadProcessMemory` — ppointer（二级指针），需 `(*Exported.ReadProcessMemory)(...)`
- `Exported.GetThreadContext` — ppointer，需 `(*Exported.GetThreadContext)(...)`
- `Exported.debug_setBreakpoint` / `debug_removeBreakpoint` — 直接函数指针
- 模块枚举通过 `CreateToolhelp32Snapshot` + `Module32First`/`Module32Next` 实现

## 未实现（TODO）

- [ ] 断点触发记录自动分组（按指令地址 + 调用栈）
- [ ] 调用栈获取
- [ ] 跨函数寄存器追踪
- [ ] AOB + 注入脚本自动生成
- [ ] 内存扫描（精确值/变/不变过滤链）
