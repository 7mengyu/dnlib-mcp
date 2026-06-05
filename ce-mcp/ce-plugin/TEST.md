# ce-mcp-plugin x64 测试用例

## 前置条件

1. 启动 Cheat Engine 64 位版
2. 加载新编译的 `ce-mcp-plugin-x64.dll`
3. 打开任意 64 位进程（如 Notepad.exe）
4. 确认 MCP Server 已启动且连接正常

---

## 1. 状态与连接 (2 个)

### 测试 1-1：ce_status

**验证目标**：连接状态正确返回。

```json
{}
```

**预期**：返回 `bridge_running`、`plugin_connected`、`host`、`port`。

---

### 测试 1-2：ce_ping

**验证目标**：插件通信正常。

```json
{}
```

**预期**：返回当前进程 PID 和名称（如 Notepad.exe）。

---

## 2. 进程与模块 (2 个)

### 测试 2-1：ce_get_process_list

**验证目标**：系统进程枚举正常。

```json
{}
```

**预期**：返回系统所有运行进程列表（PID + 名称），应包含 Notepad.exe。

---

### 测试 2-2：ce_get_modules

**验证目标**：模块列表完整，参数无误。

```json
{}
```

**预期**：返回 100+ 个模块，包含名称、基址、大小。

---

## 3. 内存读写 (1 个)

### 测试 3-1：ce_read_memory

**验证目标**：确认 `GetParam` 环形缓冲区修复生效，地址不串位。

```json
{"address": "Notepad基地址", "length": 16}
```

**预期**：返回 DOS 头 `4D 5A 90 00...`，`address` 字段 = 输入地址。

**之前 Bug**：返回 `"read failed at 0x10"` 或 `"read failed at 0x100"`。

---

## 4. 寄存器与调用栈 (2 个)

### 测试 4-1：ce_get_registers

**验证目标**：寄存器快照正常。

```json
{}
```

**预期**：返回 x64 寄存器值（RAX-R15、RIP、EFLAGS）。需要进程处于调试状态或至少有一个可用线程。

**注意**：如果 CE 未调试进程，可能返回错误。

---

### 测试 4-2：ce_get_callstack

**验证目标**：调用栈回溯正常。

```json
{"max_frames": 8}
```

**预期**：返回调用栈帧列表，含地址和模块名。

**注意**：需要进程处于调试状态（断点触发后）。

---

## 5. 代码分析 (4 个)

### 测试 5-1：ce_disassemble

**验证目标**：确认反汇编地址和条数正确传入（不再是 `0x20`）。

```json
{"address": "Notepad基地址+0x1000", "count": 5}
```

**预期**：返回 5 条指令，`address` 字段 = 输入地址。

**之前 Bug**：返回 `{"address":"0x20","instructions":[...]}`。

**已知问题**：`Exported.Disassembler` 返回 false，指令列表为空。需调试排查 CE 7.5 反汇编器接口。

---

### 测试 5-2：ce_assemble

**验证目标**：汇编指令 -> 机器码字节。

```json
{"instruction": "mov rax,rcx", "address": "0x140000000"}
```

**预期**：返回编码后的字节数组（`48 8B C1`）。

---

### 测试 5-3：ce_prev_opcode

**验证目标**：向前查找相邻指令地址。

```json
{"address": "Notepad基地址+0x1010"}
```

**预期**：返回前一条指令的地址（小于输入地址）。

---

### 测试 5-4：ce_next_opcode

**验证目标**：向后查找相邻指令地址。

```json
{"address": "Notepad基地址+0x1000"}
```

**预期**：返回下一条指令的地址（大于输入地址）。

---

## 6. 符号与内存布局 (4 个)

### 测试 6-1：ce_get_symbol_info

**验证目标**：地址 -> 符号名。

```json
{"input": "Notepad基地址+0x1000"}
```

**预期**：返回 `Notepad.exe+1000`。

---

### 测试 6-2：ce_enum_memory_regions

**验证目标**：内存区域枚举。

```json
{"max_regions": 50}
```

**预期**：返回 50 个内存区域，含基址、大小、保护属性、类型。

---

### 测试 6-3：ce_resolve_pointer

**验证目标**：多级指针链解析。

```json
{"base": "Notepad基地址+0x1000", "offsets": [0, 0]}
```

**预期**：返回逐级解析的地址链。注意：随机偏移通常不可读，预期返回错误或 NULL 地址。

---

### 测试 6-4：ce_enum_strings

**验证目标**：内存字符串扫描。

```json
{"start_address": "Notepad基地址", "end_address": "Notepad基地址+0x100000", "min_length": 5}
```

**预期**：返回扫描到的 ASCII 字符串列表。

---

## 7. 扫描与搜索 (3 个)

### 测试 7-1：ce_aob_scan

**验证目标**：AOB 特征码搜索，参数正确传递。

```json
{"pattern": "48 8B 05", "module": "ntdll.dll"}
```

**预期**：返回 ntdll.dll 中若干匹配地址（50+）。

---

### 测试 7-2：ce_memory_scan

**验证目标**：5 个参数全部正确传入（scan_type、value、start、end、max_results）。

```json
{"scan_type": 2, "value": "255", "max_results": 10}
```

**预期**：返回 dword=255 的匹配地址，结果数 <= 10。

**之前 Bug**：max_results 串位到 scan_type，返回 `unknown scan type: 10`。

---

### 测试 7-3：ce_memory_scan_next

**验证目标**：变化/不变过滤链。必须先执行 `ce_memory_scan` 缓存结果。

```json
{"filter": 2}
```

**预期**：返回未变化的地址列表。如果目标进程值未变化，结果应与上次扫描相同。

---

## 8. 断点与追踪 (2 个)

### 测试 8-1：ce_set_breakpoint

**验证目标**：硬件断点设置和命中记录。

```json
{"address": "Notepad入口地址", "type": 0, "duration": 5}
```

**预期**：返回断点命中记录（时间戳、线程ID、寄存器快照、调用栈）。

**注意**：需要 Notepad 实际执行到该地址才会命中。

---

### 测试 8-2：ce_register_trace

**验证目标**：函数入口/出口寄存器追踪。

```json
{"start_address": "Notepad入口地址", "end_address": "Notepad入口地址+0x20", "duration": 5}
```

**预期**：返回配对入口/出口寄存器快照和变化 diff。

**注意**：同 ce_set_breakpoint，需要目标进程执行到函数。

---

## 9. RTTI 与类信息 (1 个)

### 测试 9-1：ce_get_rtti_class

**验证目标**：C++ RTTI 类名解析。

```json
{"address": "0x0"}
```

**预期**：返回错误（无效地址），验证参数传递正确。

---

## 10. 脚本生成 (2 个)

### 测试 10-1：ce_generate_hook

**验证目标**：AutoAssemble 注入脚本生成。

```json
{"address": "Notepad基地址+0x1000", "codecave_size": 256}
```

**预期**：返回包含 ENABLE/DISABLE 段、codecave 分配、原始代码恢复的脚本。

---

### 测试 10-2：ce_generate_api_hook

**验证目标**：CE 内置 API Hook 脚本生成。

```json
{"address": "kernel32.CreateFileA"}
```

**预期**：返回 CE 生成的 API Hook 模板脚本。

---

## 汇总清单

| # | 分类 | 工具 | 验证点 | 状态 |
|---|------|------|--------|------|
| 1-1 | 状态 | ce_status | 连接状态正确 | ☐ |
| 1-2 | 状态 | ce_ping | 通信正常，进程信息正确 | ☐ |
| 2-1 | 进程 | ce_get_process_list | 系统进程列表完整 | ☐ |
| 2-2 | 进程 | ce_get_modules | 150+ 模块，参数无串位 | ✅ |
| 3-1 | 内存 | ce_read_memory | 地址不串位 (之前=0x10) | ✅ |
| 4-1 | 寄存器 | ce_get_registers | 寄存器快照正常 | ☐ |
| 4-2 | 寄存器 | ce_get_callstack | 调用栈回溯正常 | ☐ |
| 5-1 | 代码 | ce_disassemble | 地址不串位 (之前=0x20) | ⚠️ (Disassembler返回false) |
| 5-2 | 代码 | ce_assemble | 汇编编码正确 | ☐ |
| 5-3 | 代码 | ce_prev_opcode | 返回前一条指令地址 | ☐ |
| 5-4 | 代码 | ce_next_opcode | 返回下一条指令地址 | ☐ |
| 6-1 | 符号 | ce_get_symbol_info | 地址->符号名正确 | ☐ |
| 6-2 | 符号 | ce_enum_memory_regions | 内存区域枚举完整 | ☐ |
| 6-3 | 符号 | ce_resolve_pointer | 指针链解析正常 | ☐ |
| 6-4 | 符号 | ce_enum_strings | 字符串扫描正常 | ☐ |
| 7-1 | 扫描 | ce_aob_scan | pattern 参数正确 | ✅ |
| 7-2 | 扫描 | ce_memory_scan | 5 参数正确 (之前串位) | ✅ |
| 7-3 | 扫描 | ce_memory_scan_next | filter+max_results 正确 | ☐ |
| 8-1 | 调试 | ce_set_breakpoint | 断点设置和命中记录 | ☐ |
| 8-2 | 调试 | ce_register_trace | 寄存器追踪+diff | ☐ |
| 9-1 | RTTI | ce_get_rtti_class | RTTI类名解析 | ☐ |
| 10-1 | 生成 | ce_generate_hook | AA注入脚本生成 | ☐ |
| 10-2 | 生成 | ce_generate_api_hook | API Hook脚本生成 | ☐ |

**统计**：共 **23 个工具**，已测试通过 **4 个**，待测试 **18 个**，已知缺陷 **1 个**（ce_disassemble 反汇编返回空）。
