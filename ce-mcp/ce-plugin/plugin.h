/**
 * plugin.h — ce-mcp-plugin 公共头文件
 *
 * 全局状态、类型定义、宏、函数声明。
 * CE 7.5 SDK v6.
 */

#ifndef CE_MCP_PLUGIN_H
#define CE_MCP_PLUGIN_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sdk/cepluginsdk.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dbghelp.lib")

/* ========== ppointer wrappers ========== */
/* CE 7.5 SDK declares many API pointers as PVOID.
 * plugin.pas assigns with @@ (pointer-to-pointer),
 * so we cast through typed function pointers before dereferencing. */

/* RPM: CEP_READPROCESSMEMORY = BOOL (__stdcall **)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*) */
#define RPM(hProc, addr, buf, size, pRead) \
    (*(BOOL (__stdcall **)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*))Exported.ReadProcessMemory)(hProc, addr, buf, size, pRead)

/* GTC: BOOL (__stdcall *)(HANDLE, LPCONTEXT) */
#define GTC(hThread, ctx) \
    (*(BOOL (__stdcall **)(HANDLE, LPCONTEXT))Exported.GetThreadContext)(hThread, ctx)

/* OT: HANDLE (__stdcall *)(DWORD, BOOL, DWORD) */
#define OT(access, inherit, tid) \
    (*(HANDLE (__stdcall **)(DWORD, BOOL, DWORD))Exported.OpenThread)(access, inherit, tid)

/* CS: HANDLE (__stdcall *)(DWORD, DWORD) */
#define CS(flags, pid) \
    (*(HANDLE (__stdcall **)(DWORD, DWORD))Exported.CreateToolhelp32Snapshot)(flags, pid)

/* M32F: BOOL (__stdcall *)(HANDLE, LPMODULEENTRY32) */
#define M32F(snap, me) \
    (*(BOOL (__stdcall **)(HANDLE, LPMODULEENTRY32))Exported.Module32First)(snap, me)

/* M32N: BOOL (__stdcall *)(HANDLE, LPMODULEENTRY32) */
#define M32N(snap, me) \
    (*(BOOL (__stdcall **)(HANDLE, LPMODULEENTRY32))Exported.Module32Next)(snap, me)

/* T32F: BOOL (__stdcall *)(HANDLE, LPTHREADENTRY32) */
#define T32F(snap, te) \
    (*(BOOL (__stdcall **)(HANDLE, LPTHREADENTRY32))Exported.Thread32First)(snap, te)

/* T32N: BOOL (__stdcall *)(HANDLE, LPTHREADENTRY32) */
#define T32N(snap, te) \
    (*(BOOL (__stdcall **)(HANDLE, LPTHREADENTRY32))Exported.Thread32Next)(snap, te)

/* VQE: NTSTATUS (__stdcall *)(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T) */
#define VQE(hProc, addr, mbi, sz) \
    (*(LONG (__stdcall **)(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T))Exported.VirtualQueryEx)(hProc, addr, mbi, sz)


/* ========== CE debug continue options ========== */
#define COEO_RUN        0
#define COEO_STEPINTO   1
#define COEO_STEPOVER   2
#define COEO_RUNTILL    3
#define COEO_BREAK      4

/* ========== Global state ========== */
extern int selfid;
extern ExportedFunctions Exported;
extern HANDLE pluginThreadHandle;
extern volatile BOOL pluginRunning;

extern SOCKET mcpSocket;
extern CRITICAL_SECTION socketLock;
extern char mcpHost[16];
extern int mcpPort;

/* ========== Command struct ========== */
typedef struct {
    char command[64];
    char params[2048];
} Command;

/* ========== Breakpoint monitoring ========== */
#define MAX_BP_MONITORS 8
#define MAX_BP_HITS     200

#define MAX_CALLSTACK_DEPTH 32
#define MAX_CALLSTACK_FRAMES_PER_HIT 8

typedef struct {
    UINT_PTR address;
    char moduleName[64];
} CallstackFrame;

typedef struct {
    DWORD timestamp;
    DWORD threadId;
    CONTEXT context;
    int callstackDepth;
    CallstackFrame callstack[MAX_CALLSTACK_FRAMES_PER_HIT];
} BPHitRecord;

typedef struct {
    UINT_PTR address;
    int triggerType;
    int bpSize;
    DWORD startTick;
    DWORD durationSec;
    BOOL active;
    int hitCount;
    BPHitRecord hits[MAX_BP_HITS];
} BreakpointMonitor;

extern BreakpointMonitor bpMonitors[MAX_BP_MONITORS];
extern CRITICAL_SECTION bpMonitorLock;
extern int bpCallbackId;

/* ========== Memory scan cache ========== */
#define MAX_CACHED_ADDRS 5000
extern UINT_PTR cachedScanAddrs[MAX_CACHED_ADDRS];
extern int    cachedScanCount;
extern BYTE   cachedScanValues[MAX_CACHED_ADDRS * 8];
extern int    cachedScanValueSize;

/* ========== Network helpers ========== */
BOOL WinsockInit(void);
void WinsockCleanup(void);
BOOL ConnectToMcp(void);
void DisconnectMcp(void);
void SendResponse(const char *type, const char *data);

#define OK(fmt, ...) do { \
    int _need = _scprintf(fmt, ##__VA_ARGS__); \
    char *_b = (char *)malloc((size_t)(_need + 1)); \
    if (_b) { \
        sprintf_s(_b, (size_t)(_need + 1), fmt, ##__VA_ARGS__); \
        SendResponse("OK", _b); \
        free(_b); \
    } \
} while(0)

#define ERR(fmt, ...) do { \
    int _need = _scprintf(fmt, ##__VA_ARGS__); \
    char *_b = (char *)malloc((size_t)(_need + 1)); \
    if (_b) { \
        sprintf_s(_b, (size_t)(_need + 1), fmt, ##__VA_ARGS__); \
        SendResponse("ERR", _b); \
        free(_b); \
    } \
} while(0)

/* ========== Common helpers ========== */
BOOL ParseCommand(char *buffer, Command *cmd);
UINT_PTR ParseAddr(const char *s);
char *GetParam(char *params, int idx);
HANDLE GetDebugThread(void);
int WalkCallstack(HANDLE hThread, const CONTEXT *ctx, CallstackFrame *frames, int maxFrames);

/* ========== Debug event callback ========== */
int __stdcall OnDebugEvent(LPDEBUG_EVENT DebugEvent);

/* ========== Breakpoint monitor helpers ========== */
BreakpointMonitor *AllocBpMonitor(void);
void FreeBpMonitor(BreakpointMonitor *bm);

/* ========== Command implementations ========== */
void cmd_PING(Command *cmd);
void cmd_READ_MEMORY(Command *cmd);
void cmd_DISASSEMBLE(Command *cmd);
void cmd_GET_MODULES(Command *cmd);
void cmd_GET_REGISTERS(Command *cmd);
void cmd_SET_BP(Command *cmd);
void cmd_AOB_SCAN(Command *cmd);
void cmd_GET_CALLSTACK(Command *cmd);
void cmd_REGISTER_TRACE(Command *cmd);
void cmd_GENERATE_HOOK(Command *cmd);
void cmd_MEMORY_SCAN(Command *cmd);
void cmd_MEMORY_SCAN_NEXT(Command *cmd);
void cmd_GET_SYMBOL_INFO(Command *cmd);
void cmd_ENUM_MEMORY_REGIONS(Command *cmd);
void cmd_PREV_OPCODE(Command *cmd);
void cmd_NEXT_OPCODE(Command *cmd);
void cmd_ASSEMBLE(Command *cmd);
void cmd_GENERATE_API_HOOK(Command *cmd);
void cmd_RESOLVE_POINTER(Command *cmd);
void cmd_GET_PROCESS_LIST(Command *cmd);
void cmd_GET_RTTI_CLASS(Command *cmd);
void cmd_ENUM_STRINGS(Command *cmd);

/* ========== Command dispatcher ========== */
void ExecuteCommand(Command *cmd);

/* ========== TCP listener thread ========== */
DWORD WINAPI PluginThread(LPVOID param);

#endif /* CE_MCP_PLUGIN_H */
