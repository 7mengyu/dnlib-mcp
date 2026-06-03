# Cheat Engine MCP Backend - 设计文档

## 架构

```
┌─────────┐  TCP (localhost:9999)   ┌──────────────────┐
│  MCP    │ ◄─────────────────────→ │ CE Lua 脚本       │
│ (Python)│    JSON 命令/响应        │ (常驻后台，监听)   │
└─────────┘                         └──────────────────┘
```

CE 端运行一个 Lua 脚本，启动 TCP Server 监听本地端口。MCP Python 端通过 socket 实时发送命令并接收结构化响应。

## 核心场景

### 场景 1：找谁读写 + 生成 AOB 注入脚本

**用户输入：**
> 对 0x1A2B3C4D 找谁写入了，生成 AOB 脚本

**CE 执行：** 持续监控模式，设硬件断点后静默记录每条写入指令

```lua
local records = {}

function onBreakpoint()
    local ctx = getContext()
    local inst_addr = EIP
    local module, offset = getModuleAndOffset(inst_addr)

    records[inst_addr] = {
        address = string.format("%s+0x%X", module, offset),
        instruction = disassemble(inst_addr),
        registers = { eax = ctx.eax, ecx = ctx.ecx, edx = ctx.edx },
        stack = getCallStack(3),
        count = (records[inst_addr] and records[inst_addr].count or 0) + 1
    }

    return 1 -- 继续执行
end
```

**返回结果按指令分组：**

```json
[
  {
    "address": "game.exe+0x3A2B10",
    "instruction": "mov [rcx+08], eax",
    "trigger_count": 8,
    "latest_context": {
      "eax": 9999,
      "rcx": "0x1A2B3C45",
      "caller": "game.exe+0x5A0040"
    }
  },
  {
    "address": "game.exe+0x4C8F08",
    "instruction": "add [rdx+08], edx",
    "trigger_count": 2,
    "latest_context": {
      "edx": 500,
      "rdx": "0x1A2B3C3D",
      "caller": "game.exe+0x6B0000"
    }
  }
]
```

**AI 分析调用栈区分路径：**

```
AI: 找到了 3 条写入路径：
    1. game.exe+0x3A2B10 — 8次，调用栈: BuyItem() — 花钱
    2. game.exe+0x4C8F08 — 2次，调用栈: GrantReward() — 任务奖励
    3. game.exe+0x5F1234 — 1次，调用栈: Reset() — 角色重置
    要对哪个路径生成注入脚本？
```

**MCP 工具：**
- `ce_breakpoint(address, type)` — 设硬件断点（write/read/access）
- `ce_find_what_writes(address, duration_seconds)` — 持续监控 + 分组返回
- `ce_generate_aob(address, size)` — 在指定位置附近生成特征码
- `ce_generate_injection_script(address, instruction, patch_value)` — 生成 CT 注入脚本

---

### 场景 2：同一指令对应多个地址

**问题：**
> game.exe+0x3A2B10 - mov [rcx+08], eax
> 访问了 342 个不同地址（金币、经验、血量...）

**原因：** C++ 中同一个 SetValue 函数被所有数值属性复用。

**解决方案：记录 this 指针 + 偏移 + 调用者进行分组**

```lua
records.insert({
    target_address = rcx_value + offset,   -- 被写入的地址
    this_pointer = rcx_value,              -- 对象基址
    field_offset = offset,                 -- 字段偏移量
    caller = getReturnAddress(1),          -- 调用者地址
})
```

**AI 分析输出：**

```
同一条 mov [rcx+08], eax 写了 342 个地址

按调用者分组：
  game.exe+0x5A0000 (Player::Update) — 12 个地址
    偏移 +0x08 → 0x1A2B3C4D（金币）
    偏移 +0x10 → 0x1A2B4001（经验）
    偏移 +0x18 → 0x1A2B5008（血量）

  game.exe+0x6B0000 (Enemy::Update) — 30 个地址
    偏移 +0x08 → Enemy 金币

0x1A2B3C4D 是金币 → 调用者是 game.exe+0x5A0000
```

**MCP 工具：** `ce_find_what_writes(address, duration_seconds)` — 返回数据含 `this_pointer`、`field_offset`、`caller`

---

### 场景 3：分析汇编找基址

**用户输入：**
> 帮 0x1A2B3C4D 找基址，不用指针扫描

**原理：** 从写入断点出发，向上追踪源寄存器，跨函数追溯调用栈，直到找到静态地址。

**步骤 1：设断点捕获写入指令**

```
触发: game.exe+0x3A2B10 - mov [rcx+08], eax
寄存器: rcx=0x1A2B3C45, eax=9999
→ 金币地址 = rcx + 0x08
```

**步骤 2：在当前函数内追源寄存器**

```
往上翻 game.exe+0x3A2B10 所在函数:
  game.exe+0x3A2B08 - mov rcx, [rdx+20]   ← rcx 来自 [rdx+20]
  game.exe+0x3A2B04 - ...                 ← rdx 在当前函数没被修改！
```

**步骤 3：跨函数上溯**

```lua
function traceRegister(reg, from_addr, max_depth)
    for depth = 0, max_depth do
        local caller = getCallerAddress(depth)
        local instructions = disassembleRange(caller - 0x100, 0x100)

        for i = #instructions, 1, -1 do
            if instructionWritesRegister(instructions[i], reg) then
                return {
                    found_at = instructions[i].address,
                    instruction = instructions[i].text,
                    source_register = extractSourceRegister(instructions[i]),
                    depth = depth,
                    caller_module = getModuleAtAddress(caller)
                }
            end
        end
    end
end
```

**输出基址链：**

```json
{
  "chain": [
    {
      "depth": 1,
      "function": "Player::Update",
      "found_at": "game.exe+0x5A0060",
      "instruction": "mov rdx, [game.exe+0x7F0000]",
      "source": "static_address"
    }
  ],
  "base_expression": "[[game.exe+0x7F0000] + 0x20] + 0x08"
}
```

**MCP 工具：**
- `ce_disassemble_range(address, length)` — 反汇编一块区域
- `ce_trace_register(reg, from_address, max_depth)` — 跨函数追踪寄存器来源
- `ce_find_static_base(address, max_depth)` — 自动追指针链，返回基址表达式

---

### 场景 4：加密数值 — CE 搜不到精确值

**问题：**
> 游戏显示金币 100，用 CE 精确搜索 100 搜不到任何结果。
> 数值在内存中被加密存储。

**常见加密方式：**

| 方式 | 存储值示例（显示 100） |
|------|----------------------|
| XOR | `0x12345678 ^ 100` |
| 乘法 | `100 × 8 = 800` |
| 位移+异或组合 | 多步混淆 |

**关键认知：加密后无法用精确值或增减量来过滤。**

`100 - 10 = 90` 明码成立，但加密后存储值从 `0xA3B2` 变到 `0x7F1D`，不知道变了多少。只能依赖 **变/不变** 二元逻辑。

**处理策略：变/不变过滤链**

```
金币初始 100:
  ce_scan_unknown(type=4)         → 1,000,000 个 4 字节值

花钱（确保金币一定变了）:
  ce_scan_changed()               → 12,000 个值变了

逛街（金币不变）:
  ce_scan_unchanged()             → 300 个值没变

再花钱:
  ce_scan_changed()               → 8 个值又变了
                                    ↓
                              金币加密值就这 8 个中
```

**确认地址后反推算法：**

拿到候选地址后，手动改值观察游戏显示：

```
当前存储值: 0x320 → 游戏显示: 100
改成 0x640   → 游戏显示: 200   → 显示值 = 存储值 × (100/0x320)
改成 0       → 游戏显示: 0     → 确认不是 XOR（XOR 不会归零）
```

**找加密函数：**

对存金币的地址设写入断点，追踪加密逻辑：

```
断点触发: game.exe+0x3A2B10 - mov [rcx+08], eax
                                    ↑ eax 是加密后的值
往上翻汇编:
  game.exe+0x3A2B08 - xor eax, 0x12345678    ← XOR 加密
  game.exe+0x3A2B04 - mov eax, [真实金币值]
```

拿到算法后，注入脚本直接写加密后的值：

```lua
local display_value = 9999
local encrypted = display_value * 8  -- 或 xor(display_value, key)
writeInteger(address, encrypted)
```

**MCP 工具补充：**

| 工具 | 说明 |
|------|------|
| `ce_scan_unknown(type)` | 未知初始值扫描 |
| `ce_scan_changed()` | 变化的地址 |
| `ce_scan_unchanged()` | 未变化的地址 |
| `ce_decrypt_value(address)` | 修改内存值，观察显示变化，反推算法 |
| `ce_find_encryption(address)` | 设断点向上追踪加密逻辑 |

**MCP 工具更新：**

| 工具 | 说明 |
|------|------|
| `ce_decrypt_value(address)` | 修改内存值，观察游戏显示变化，反推加密算法 |
| `ce_find_encryption(address)` | 设写入断点，向上追踪加密逻辑（XOR/乘法/位移） |

---

## MCP 工具总览

| 工具 | 说明 |
|------|------|
| `ce_attach(process)` | 附加目标进程 |
| `ce_write(address, value, type)` | 写入内存 |
| `ce_read(address, type)` | 读取内存 |
| `ce_freeze(address, value)` | 锁定内存值 |
| `ce_scan_value(value, type)` | 精确值扫描 |
| `ce_scan_unknown(type)` | 未知初始值扫描（加密数值用） |
| `ce_scan_changed()` | 变化的值 |
| `ce_scan_unchanged()` | 未变化的值 |
| `ce_get_results(count)` | 获取扫描结果列表 |
| `ce_aob_scan(pattern, module)` | 特征码搜索 |
| `ce_breakpoint(address, type)` | 设置硬件断点 |
| `ce_find_what_writes(address, duration_seconds)` | 持续监控写入指令，按 this指针/偏移/调用者 分组返回 |
| `ce_disassemble_range(address, length)` | 反汇编指定范围 |
| `ce_trace_register(reg, from_address, max_depth)` | 跨函数追踪寄存器来源，返回基址链 |
| `ce_find_static_base(address, max_depth)` | 自动追踪指针链，返回基址表达式 |
| `ce_generate_aob(address, size)` | 生成特征码 |
| `ce_generate_injection_script(address, instruction, patch_value)` | 生成 CT 注入脚本 |
| `ce_decrypt_value(address)` | 修改内存值，观察游戏显示变化，反推加密算法 |
| `ce_find_encryption(address)` | 设写入断点，向上追踪加密逻辑 |
| `ce_get_modules()` | 获取进程模块列表 |
| `ce_get_registers()` | 获取当前寄存器快照 |

## 待定事项
- [ ] 断点持续监控的性能影响评估
