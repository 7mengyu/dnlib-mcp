# CE 7.5 SDK API 使用分析

CE 7.5 SDK 共导出 154 个 API（90 个直接调用 + 64 个 ppointer），当前 ce-mcp-plugin 仅使用 27 个（~18%）。本文档全面分析所有已使用和未使用的 API，并给出优先实现建议。

> **数据来源**: `sdk/cepluginsdk.h` (C SDK)、`plugin.pas` (Pascal 赋值)、`pluginexports.pas` (Pascal 实现)、`NewKernelHandler.pas` (ppinter 类型定义)。

---

## 当前已使用的 API（27 个）

### 直接调用（18 个）

| API | SDK Line | 用途 | 使用位置 |
|-----|----------|------|---------|
| `RegisterFunction` | 279 | 注册插件回调（Type 2 调试事件） | plugin-core.c |
| `UnregisterFunction` | 280 | 注销回调 | plugin-core.c |
| `OpenedProcessID` | 281 | 当前调试进程 PID | plugin-core.c, plugin-analyze.c, plugin-scan.c |
| `OpenedProcessHandle` | 282 | 当前进程句柄 | plugin-core.c, 所有 cmd_*.c |
| `Assembler` | 286 | 汇编指令 → 机器码 | plugin-analyze.c |
| `Disassembler` | 287 | 反汇编地址 → 指令文本 | plugin-analyze.c, plugin-gen.c |
| `disassembleEx` | 379 | 反汇编并获取指令长度 | plugin-analyze.c, plugin-gen.c |
| `ProcessList` | 293 | 系统进程列表（PID + 名称） | plugin-analyze.c |
| `GetAddressFromPointer` | 295 | 多级指针链 [[[base+off1]+off2]...] | plugin-analyze.c |
| `sym_nameToAddress` | 370 | 符号名 → 地址 | plugin-analyze.c |
| `sym_addressToName` | 371 | 地址 → 符号名 | plugin-analyze.c |
| `sym_generateAPIHookScript` | 372 | 生成 API Hook AA 脚本 | plugin-gen.c |
| `previousOpcode` | 377 | 向前查找指令地址 | plugin-analyze.c |
| `nextOpcode` | 378 | 向后查找指令地址 | plugin-analyze.c |
| `debug_setBreakpoint` | 410 | 设置硬件断点 | plugin-debug.c |
| `debug_removeBreakpoint` | 411 | 移除硬件断点 | plugin-debug.c, plugin-core.c |
| `debug_continueFromBreakpoint` | 412 | 断点命中后继续执行 | plugin-core.c |
| `sizeofExportedFunctions` | 277 | SDK 版本校验 | plugin-core.c |

### ppointer（9 个，通过 plugin.h 宏解引用）

| 宏 | 对应 API | SDK Line | Win32 类型 |
|----|---------|----------|-----------|
| `RPM()` | `ReadProcessMemory` | 299 | `BOOL (**)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*)` |
| `GTC()` | `GetThreadContext` | 301 | `BOOL (**)(HANDLE, LPCONTEXT)` |
| `OT()` | `OpenThread` | 316 | `HANDLE (**)(DWORD, BOOL, DWORD)` |
| `CS()` | `CreateToolhelp32Snapshot` | 354 | `HANDLE (**)(DWORD, DWORD)` |
| `M32F()` | `Module32First` | 359 | `BOOL (**)(HANDLE, LPMODULEENTRY32)` |
| `M32N()` | `Module32Next` | 360 | `BOOL (**)(HANDLE, LPMODULEENTRY32)` |
| `T32F()` | `Thread32First` | 357 | `BOOL (**)(HANDLE, LPTHREADENTRY32)` |
| `T32N()` | `Thread32Next` | 358 | `BOOL (**)(HANDLE, LPTHREADENTRY32)` |
| `VQE()` | `VirtualQueryEx` | 313 | `LONG (**)(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T)` |

---

## 高价值未使用 API（14 个）

### P0 — 立即实现（消除最大功能缺口）

| API | 类型 | Pascal 签名 | SDK Line | 价值 |
|-----|------|------------|----------|------|
| **`WriteProcessMemory`** | ppointer | `BOOL (__stdcall **)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*)` | 300 | **最大缺口**。插件只能读不能写，无法 patch 代码或修改游戏状态。Pascal 赋值: `plugin.pas:1881 @@WriteProcessMemoryActual` |
| **`AutoAssemble`** | 直接调用 | `BOOL (__stdcall *)(char *script)` | 285 | 执行完整 AA 脚本：分配 code cave、注入 hook、ENABLE/DISABLE、模板替换。Pascal 实现: `pluginexports.pas:738` |

### P1 — 代码注入必备

| API | 类型 | Pascal 签名 | SDK Line | 价值 |
|-----|------|------------|----------|------|
| **`VirtualProtectEx`** | ppointer | `BOOL (**)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD)` | 312 | 修改目标进程内存页保护属性，写 NX 页前的必要步骤。Pascal 赋值: `plugin.pas:1904 @@VirtualProtectEx` |
| **`VirtualAllocEx`** | ppointer | `LPVOID (**)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD)` | 314 | 在目标进程分配内存（shellcode / trampoline / code cave）。Pascal 赋值: `plugin.pas:1907 @@VirtualAllocEx` |
| **`pause`** | 直接调用 | `VOID (__stdcall *)(void)` | 407 | 暂停目标进程。Pascal 实现: `pluginexports.pas:1585` |
| **`unpause`** | 直接调用 | `VOID (__stdcall *)(void)` | 408 | 恢复目标进程。Pascal 实现: `pluginexports.pas:1592` |

### P2 — 能力倍增器

| API | 类型 | Pascal 签名 | SDK Line | 价值 |
|-----|------|------------|----------|------|
| **`GetLuaState`** | 直接调用 | `lua_State *(__stdcall *)()` | 455 | **最强 API**。获取 CE 的 Lua 状态机，通过 Lua C API 调用 CE 全部 Lua 绑定（内存扫描、结构体解析、符号枚举、PE 分析等），一个 API 解锁所有能力。注意：SDK typedef 声明为 `__fastcall` 但 Pascal 端用 `stdcall`，需仔细处理调用约定。Pascal 实现: `pluginexports.pas:2632` |
| **`InjectDLL`** | 直接调用 | `BOOL (__stdcall *)(char *dllname, char *functiontocall)` | 289 | 向目标注入 DLL，自动刷新符号处理器。Pascal 实现: `pluginexports.pas:972` |
| **`ChangeRegistersAtAddress`** | 直接调用 | `BOOL (*)(UINT_PTR, PREGISTERMODIFICATIONINFO)` | 288 | 条件断点 + 寄存器修改，运行时反反调试、动态 patch。使用 `REGISTERMODIFICATIONINFO` 结构体。Pascal 实现: `pluginexports.pas:1602` |

### P3 — 运行时控制

| API | 类型 | Pascal 签名 | SDK Line | 价值 |
|-----|------|------------|----------|------|
| **`speedhack_setSpeed`** | 直接调用 | `BOOL (__stdcall *)(float speed)` | 450 | 变速齿轮倍率（1.0=正常，2.0=双倍速，0.5=慢速）。Pascal 实现: `pluginexports.pas:2289` |
| **`SetThreadContext`** | ppointer | `BOOL (**)(HANDLE, LPCONTEXT)` | 302 | 直接写线程寄存器（比 ChangeRegistersAtAddress 更灵活，无需断点）。Pascal 赋值: `plugin.pas:1883 @@SetThreadContext` |
| **`SuspendThread`** | ppointer | `DWORD (**)(HANDLE)` | 303 | 挂起指定线程。Pascal 赋值: `plugin.pas:1885 @@SuspendThread` |
| **`ResumeThread`** | ppointer | `DWORD (**)(HANDLE)` | 304 | 恢复指定线程。Pascal 赋值: `plugin.pas:1886 @@ResumeThread` |
| **`CreateRemoteThread`** | ppointer | `HANDLE (**)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD)` | 315 | 在目标进程创建远程线程执行代码。Pascal 赋值: `plugin.pas:1908 @@CreateRemoteThread` |

---

## 中价值未使用 API（全部）

### 内存冻结

| API | 类型 | SDK Line | Pascal 实现 | 说明 |
|-----|------|----------|------------|------|
| `FreezeMem` | 直接调用 | 290 | `pluginexports.pas:777` | 按地址 + 大小冻结内存，返回 freezeID（-1 失败）。后台定时写回原值 |
| `UnfreezeMem` | 直接调用 | 291 | `pluginexports.pas:789` | 传入 freezeID 解冻，返回 BOOL |
| `FixMem` | 直接调用 | 292 | `pluginexports.pas:798` | 重新注入地址列表中所有冻结项（配合 CE 表使用） |

### 内存保护（CE 自身）

| API | 类型 | SDK Line | Pascal 赋值 | 说明 |
|-----|------|----------|------------|------|
| `VirtualProtect` | ppointer | 311 | `plugin.pas:1903 @@VirtualProtect` | 修改 CE 自身进程内存页保护属性 |

### 进程调试控制

| API | 类型 | SDK Line | Pascal 实现 | 说明 |
|-----|------|----------|------------|------|
| `openProcessEx` | 直接调用 | 405 | `pluginexports.pas:1646` | 通过 PID 打开进程并设置 `OpenedProcessHandle` |
| `debugProcessEx` | 直接调用 | 406 | `pluginexports.pas:1657` | 开始调试（指定调试接口类型），设置 `OpenedProcessID` |
| `getProcessIDFromProcessName` | 直接调用 | 404 | `pluginexports.pas:1637` | 进程名 → PID（如 `"game.exe"` → 12345） |

### 地址列表操作（memrec_* 系列，16 个，SDK lines 385-402）

全部为直接调用，Pascal 实现在 `pluginexports.pas:1227-1469` 附近：

| API | SDK Line | 说明 |
|-----|----------|------|
| `createTableEntry` | 385 | 创建新的地址列表条目，返回 PVOID 句柄 |
| `getTableEntry` | 386 | 按描述查找地址列表条目 |
| `memrec_setDescription` | 387 | 设置条目描述文字 |
| `memrec_getDescription` | 388 | 获取条目描述（返回 PCHAR） |
| `memrec_getAddress` | 389 | 读取地址 + 偏移量数组 |
| `memrec_setAddress` | 390 | 设置地址/偏移量/可解析地址字符串 |
| `memrec_getType` | 391 | 获取变量类型枚举（Tvariabletype: byte/word/dword/qword/float/double/string/binary/byteArray/AOB/code/autoAssemble/pointer） |
| `memrec_setType` | 392 | 设置变量类型 |
| `memrec_getValue` | 393 | 获取格式化值字符串（如 `"12345"` 或 `"3.14"`） |
| `memrec_setValue` | 394 | 写入值到目标进程（同时修改 CE 表显示） |
| `memrec_getScript` | 395 | 获取条目附带的 AA 脚本 |
| `memrec_setScript` | 396 | 设置条目附带的 AA 脚本 |
| `memrec_isfrozen` | 397 | 查询是否冻结中 |
| `memrec_freeze` | 398 | 冻结当前值（direction: >0 递增, <0 递减, 0 保持当前值） |
| `memrec_unfreeze` | 399 | 解冻 |
| `memrec_setColor` | 400 | 设置条目显示颜色（DWORD ARGB） |
| `memrec_appendtoentry` | 401 | 将 memrec2 嵌套为 memrec1 的子条目 |
| `memrec_delete` | 402 | 删除条目 |

### 模块加载

| API | 类型 | SDK Line | Pascal 实现 | 说明 |
|-----|------|----------|------------|------|
| `loadModule` | 直接调用 | 380 | `pluginexports.pas:850` | 加载 DLL 到 CE 进程并获取导出表字符串列表 |

### AA 脚本扩展

| API | 类型 | SDK Line | Pascal 实现 | 说明 |
|-----|------|----------|------------|------|
| `aa_AddExtraCommand` | 直接调用 | 381 | `pluginexports.pas:907` | 向 AA 引擎注册自定义指令（`command` 字符串） |
| `aa_RemoveExtraCommand` | 直接调用 | 382 | `pluginexports.pas:923` | 注销自定义 AA 指令 |

### 进程/堆枚举（ppointer，备选方案）

| API | 类型 | SDK Line | Pascal 赋值 | 说明 |
|-----|------|----------|------------|------|
| `Process32First` | ppointer | 355 | `plugin.pas:1937 @@Process32First` | 枚举进程快照第一个（已有 ProcessList 直接调用，但此 API 可获取更多属性） |
| `Process32Next` | ppointer | 356 | `plugin.pas:1938 @@Process32Next` | 枚举进程快照下一个 |
| `Heap32ListFirst` | ppointer | 361 | `plugin.pas:1944 @@Heap32ListFirst` | 枚举进程堆列表第一个（分析堆分配的游戏对象） |
| `Heap32ListNext` | ppointer | 362 | `plugin.pas:1945 @@Heap32ListNext` | 枚举进程堆列表下一个 |

### 调试事件（ppointer，CE 已内部管理）

| API | 类型 | SDK Line | Pascal 赋值 | 说明 |
|-----|------|----------|------------|------|
| `WaitForDebugEvent` | ppointer | 306 | `plugin.pas:1888 @@WaitForDebugEvent` | 等待调试事件（CE 内部使用） |
| `ContinueDebugEvent` | ppointer | 307 | `plugin.pas:1889 @@ContinueDebugEvent` | 继续调试事件（CE 内部使用） |
| `DebugActiveProcess` | ppointer | 308 | `plugin.pas:1890 @@DebugActiveProcess` | 附加调试器（CE 内部使用） |
| `StopDebugging` | ppointer | 309 | `plugin.pas:1891 @@StopDebugging` | 停止调试（CE 内部使用） |

### DBK32 内核级 API（需加载 DBK32 驱动，directional）

| API | 类型 | SDK Line | 说明 |
|-----|------|----------|------|
| `loadDBK32` | 直接调用 | 375 | 加载 DBK32 内核驱动（前置于所有 Kernel* API） |
| `loaddbvmifneeded` | 直接调用 | 376 | 按需加载 DBVM 虚拟机 |
| `KernelReadProcessMemory` | ppointer | 340 | 内核级读内存（绕过用户态 API hook 和部分保护） |
| `KernelWriteProcessMemory` | ppointer | 341 | 内核级写内存 |
| `MakeWritable` | ppointer | 346 | 内核级强制解除内存页保护属性 |

### 用户交互

| API | 类型 | SDK Line | 说明 |
|-----|------|----------|------|
| `ShowMessage` | 直接调用 | 278 | 通过 CE 弹出消息框（`char *message`） |
| `messageDialog` | 直接调用 | 449 | CE 标准消息对话框（message + messagetype + buttoncombination） |
| `GetMainWindowHandle` | 直接调用 | 284 | 获取 CE 主窗口 HWND（配合外部 UI 工具） |

### 设置 / 其他

| API | 类型 | SDK Line | 说明 |
|-----|------|----------|------|
| `ReloadSettings` | 直接调用 | 294 | 从磁盘重新加载 CE 设置 |
| `OpenProcess` | ppointer | 305 | 打开进程（已废弃，用 `openProcessEx`）。Pascal 赋值: `plugin.pas:1887 @@OpenProcess` |

---

## 低价值未使用 API（全部）

### GUI 控件（27 个，SDK lines 417-448）

全部为直接调用，用于在 CE 内部构建插件 UI。MCP 是 headless 分析工具，不需要 GUI。

| 类别 | API | SDK Line |
|------|-----|----------|
| 表单 | `createForm` | 417 |
| 表单操作 | `form_centerScreen`, `form_hide`, `form_show`, `form_onClose` | 418-421 |
| 面板 | `createPanel` | 423 |
| 分组框 | `createGroupBox` | 424 |
| 按钮 | `createButton` | 425 |
| 图片 | `createImage`, `image_loadImageFromFile`, `image_transparent`, `image_stretch` | 426-429 |
| 标签 | `createLabel` | 431 |
| 编辑框 | `createEdit` | 432 |
| 多行文本 | `createMemo` | 433 |
| 定时器 | `createTimer`, `timer_setInterval`, `timer_onTimer` | 434-436 |
| 控件通用 | `control_setCaption`, `control_getCaption` | 437-438 |
| 控件位置 | `control_setPosition`, `control_getX`, `control_getY` | 439-441 |
| 控件尺寸 | `control_setSize`, `control_getWidth`, `control_getHeight` | 442-444 |
| 控件布局 | `control_setAlign`, `control_onClick` | 445-446 |
| 销毁 | `object_destroy` | 448 |

### CE 窗口管理（3 个）

| API | 类型 | SDK Line | 说明 |
|-----|------|----------|------|
| `closeCE` | 直接调用 | 414 | 关闭 Cheat Engine（不应从 MCP 关闭） |
| `hideAllCEWindows` | 直接调用 | 415 | 隐藏全部 CE 窗口 |
| `unhideMainCEwindow` | 直接调用 | 416 | 显示 CE 主窗口 |

### DBK32 内核内部（25 个，ppointer，SDK lines 317-353）

全部为 `PVOID` 类型的 ppointer，需加载 DBK32 驱动才能使用。极其小众，仅内核级逆向场景有用。以下分组列出：

**进程/线程内核偏移:**
- `GetPEProcess` (317) — 获取 PEPROCESS
- `GetPEThread` (318) — 获取 PETHREAD
- `GetThreadsProcessOffset` (319) — 线程→进程偏移量
- `GetThreadListEntryOffset` (320) — 线程链表偏移量
- `GetProcessnameOffset` (321) — 进程名偏移量
- `GetDebugportOffset` (322) — 调试端口偏移量

**内核内存/保护:**
- `GetPhysicalAddress` (323) — 虚拟地址→物理地址
- `ProtectMe` (324) — CE 自身内核保护
- `GetLoadedState` (347) — 驱动加载状态

**CRx 寄存器:**
- `GetCR4` (325), `GetCR3` (326), `SetCR3` (327)

**系统表:**
- `GetSDT` (328), `GetSDTShadow` (329) — 系统描述符表

**调试/监控:**
- `setAlternateDebugMethod` (330), `getAlternateDebugMethod` (331)
- `DebugProcess` (332) — DBK32 调试
- `ChangeRegOnBP` (333) — 已废弃（用 `ChangeRegistersAtAddress`）
- `RetrieveDebugData` (334)
- `StartProcessWatch` (335), `WaitForProcessListData` (336)
- `GetProcessNameFromID` (337), `GetProcessNameFromPEProcess` (338)

**DBK32 操作:**
- `KernelOpenProcess` (339), `KernelVirtualAllocEx` (342)
- `IsValidHandle` (343)
- `GetIDTCurrentThread` (344), `GetIDTs` (345)
- `DBKSuspendThread` (348), `DBKResumeThread` (349)
- `DBKSuspendProcess` (350), `DBKResumeProcess` (351)
- `KernelAlloc` (352), `GetKProcAddress` (353)

### v5 未文档化扩展（3 个）

| API | 类型 | SDK Line | 说明 |
|-----|------|----------|------|
| `ExecuteKernelCode` | VOID* | 453 | 未文档化，执行内核代码 |
| `UserdefinedInterruptHook` | VOID* | 454 | 未文档化，自定义中断钩子 |
| `MainThreadCall` | VOID* | 456 | 未文档化，主线程调用 |

### 内部对象引用（2 个, 直接调用）

| API | 类型 | SDK Line | 说明 |
|-----|------|----------|------|
| `mainform` | PVOID | 366 | Delphi TMainForm 对象指针，C 无法直接使用 |
| `memorybrowser` | PVOID | 367 | Delphi TMemoryBrowser 对象指针，C 无法直接使用 |

### 已废弃（3 个）

| API | 类型 | SDK Line | 废弃原因 |
|-----|------|----------|---------|
| `OpenProcess` | ppointer | 305 | 用 `openProcessEx` 替代 |
| `ChangeRegOnBP` | ppointer | 333 | 用 `ChangeRegistersAtAddress` 替代 |
| `StopRegisterChange` | ppointer | 310 | CE 7.5 中 Pascal 赋值为 nil（`plugin.pas:1892`） |

---

## 统计汇总

| 类别 | 数量 |
|------|------|
| SDK 总导出 API | 154 |
| 已使用 | 27 |
| 高价值未使用 | 14 |
| 中价值未使用 | 46 |
| 低价值未使用 | 67 |

---

## 推荐实现顺序

```
第 1 批：WriteProcessMemory + AutoAssemble        ← 消除最大功能缺口
第 2 批：VirtualProtectEx + VirtualAllocEx         ← 代码注入必需品
第 3 批：pause / unpause                            ← 进程控制
第 4 批：GetLuaState                                ← 能力倍增器
第 5 批：InjectDLL + ChangeRegistersAtAddress      ← 高级注入
第 6 批：SuspendThread / ResumeThread + SetThreadContext + CreateRemoteThread
第 7 批：speedhack_setSpeed + memrec_* 系列
```
