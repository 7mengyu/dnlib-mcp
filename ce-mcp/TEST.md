# CE-MCP 工具测试报告

**测试日期**: 2026-06-08  
**测试目标**: heidisql.exe (PID 11160, x64)  
**环境**: Windows 11 Pro, Cheat Engine 7.5, ce-mcp-plugin

---

## 测试结果汇总

| # | 工具 | 结果 | 说明 |
|---|------|------|------|
| 1 | `ce_ping` | ✅ | 连接正常 |
| 2 | `ce_status` | ✅ | Bridge 运行在 127.0.0.1:8888 |
| 3 | `ce_get_process_list` | ✅ | 返回完整系统进程列表 |
| 4 | `ce_get_modules` | ✅ | 返回目标进程完整模块列表 |
| 5 | `ce_get_registers` | ✅ | 返回 x64 寄存器快照 |
| 6 | `ce_read_memory` | ✅ | 正确读取指定地址内存 |
| 7 | `ce_enum_memory_regions` | ✅ | 正确返回内存区域布局 |
| 8 | `ce_get_callstack` | ✅ | 返回完整调用栈回溯 |
| 9 | `ce_get_symbol_info` | ✅ | 符号名↔地址双向解析正常 |
| 10 | `ce_disassemble` | ✅ | Zydis 反汇编输出正确 |
| 11 | `ce_aob_scan` | ✅ | 特征码模式搜索结果正确 |
| 12 | `ce_next_opcode` | ✅ | 正确跳转到下一条指令 |
| 13 | `ce_prev_opcode` | ✅ | 正确回溯上一条指令 |
| 14 | `ce_memory_scan` | ✅ | 内存值扫描正常 |
| 15 | `ce_enum_strings` | ✅ | 正确提取 ASCII 字符串 |
| 16 | `ce_resolve_pointer` | ✅ | 指针链解析正常返回 |
| 17 | `ce_generate_hook` | ✅ | 生成完整 AutoAssemble 脚本 |
| 18 | `ce_memory_scan_next` | ✅ | 二次扫描过滤正常 |
| 19 | `ce_get_rtti_class` | ✅ | 正常返回（found=false，因基址非 C++ 对象） |

### 未完成测试

| # | 工具 | 状态 | 根因 |
|---|------|------|------|
| — | `ce_assemble` | 🔴 崩溃 | 调用后 CE 插件断连（`WinError 64`），需排查实现 |
| — | `ce_set_breakpoint` | ⏭️ 跳过 | 依赖 CE 调试器附加 (Hardware Breakpoint → CPU DR0-DR7)，用户未触发 |
| — | `ce_register_trace` | ⏭️ 跳过 | 同上，依赖 `debug_setBreakpoint` API |

---

## 工具分类

### 纯内存读取类（无需调试器，全部正常）

- `ce_ping`
- `ce_status`
- `ce_get_process_list`
- `ce_get_modules`
- `ce_get_registers`
- `ce_read_memory`
- `ce_enum_memory_regions`
- `ce_get_callstack`
- `ce_get_symbol_info`
- `ce_disassemble`
- `ce_aob_scan`
- `ce_next_opcode`
- `ce_prev_opcode`
- `ce_memory_scan` / `ce_memory_scan_next`
- `ce_enum_strings`
- `ce_resolve_pointer`
- `ce_generate_hook`
- `ce_get_rtti_class`

以上工具只需要 `ReadProcessMemory` 和 CE 进程句柄，**与 CE 调试器状态无关**。

### 依赖 CE 调试器（需 `startdebuggerifneeded` 成功）

- `ce_set_breakpoint` — 硬件断点 (CPU DR0-DR3)
- `ce_register_trace` — 函数入口/出口执行断点 + 寄存器 diff

这两个工具底层调用 `Exported.debug_setBreakpoint()` → CE SDK → `ce_debug_setBreakpoint2()` → **`startdebuggerifneeded(false)`**，会同步创建调试线程并等待 `DebugActiveProcess` 成功。CE 调试器能否附加取决于目标进程的安全属性。

### 已知问题

- `ce_assemble` — 调用后 CE 插件崩溃断连，返回 `[WinError 64] 指定的网络名不再可用`，需排查 C 端实现。

---

## 已确认的根因

| 问题 | 根因位置 | 本质 |
|------|----------|------|
| `ce_set_breakpoint` / `ce_register_trace` 无法使用 | `pluginexports.pas:1544` 的 `startdebuggerifneeded(false)` 无条件同步等待调试附加 | CE SDK 设计：设置断点前必须附调试器，无绕过路径 |
| 前次 RTTI 超时 | `ce_set_breakpoint` 触发 `DebugActiveProcess` → 附加失败 → `EDebuggerAttachException` 弹窗阻塞 CE 主线程 | 非 RTTI 工具自身问题，是 CE 整体被异常对话框卡住 |
| `ce_assemble` 崩溃 | 待排查 | 调用 `Assembler` 导出函数后 CE 插件进程断连 |
