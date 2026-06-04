/**
 * ce-mcp-plugin.c - Cheat Engine MCP Plugin (For CE 7.5 SDK v6)
 *
 * A TCP-based analysis plugin that exposes CE's debugger and memory
 * analysis capabilities to AI assistants via JSON commands.
 *
 * TCP Protocol:
 *   Request:  "COMMAND:param1,param2,...\n"
 *   Response: "OK:{"key":"value"}\n"  or  "ERR:message\n"
 *
 * Default listen: 127.0.0.1:8888  (CE plugin acts as TCP CLIENT)
 */

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

/* ========== CE debug continue options ========== */
#define COEO_RUN        0
#define COEO_STEPINTO   1
#define COEO_STEPOVER   2
#define COEO_RUNTILL    3
#define COEO_BREAK      4

/* ========== Global state ========== */
static int selfid;
static ExportedFunctions Exported;
static HANDLE pluginThreadHandle = NULL;
static volatile BOOL pluginRunning = FALSE;

static SOCKET mcpSocket = INVALID_SOCKET;
static CRITICAL_SECTION socketLock;
static char mcpHost[16] = "127.0.0.1";
static int mcpPort = 8888;

/* ========== Command struct ========== */
typedef struct {
    char command[64];
    char params[512];
} Command;

/* ========== Breakpoint monitoring ========== */

#define MAX_BP_MONITORS 8
#define MAX_BP_HITS     200

#define MAX_CALLSTACK_DEPTH 32
#define MAX_CALLSTACK_FRAMES_PER_HIT 8

typedef struct {
    UINT_PTR address;       /* return address / instruction pointer */
    char moduleName[64];    /* resolved module name (or empty) */
} CallstackFrame;

typedef struct {
    DWORD timestamp;        /* ms since monitoring start */
    DWORD threadId;
    CONTEXT context;        /* register state at hit */
    int callstackDepth;
    CallstackFrame callstack[MAX_CALLSTACK_FRAMES_PER_HIT];
} BPHitRecord;

typedef struct {
    UINT_PTR address;
    int triggerType;        /* 0=execute, 1=write, 2=read/write */
    int bpSize;             /* hardware BP size (1/2/4/8) */
    DWORD startTick;        /* GetTickCount when monitoring started */
    DWORD durationSec;
    BOOL active;
    int hitCount;
    BPHitRecord hits[MAX_BP_HITS];
} BreakpointMonitor;

static BreakpointMonitor bpMonitors[MAX_BP_MONITORS];
static CRITICAL_SECTION bpMonitorLock;
static int bpCallbackId = -1;

/* ========== Network helpers ========== */

static BOOL WinsockInit(void) {
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
}

static void WinsockCleanup(void) {
    WSACleanup();
}

static BOOL ConnectToMcp(void) {
    struct addrinfo hints, *result = NULL, *ptr = NULL;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char portStr[6];
    sprintf_s(portStr, sizeof(portStr), "%d", mcpPort);

    if (getaddrinfo(mcpHost, portStr, &hints, &result) != 0)
        return FALSE;

    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        mcpSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (mcpSocket == INVALID_SOCKET) continue;

        /* Non-blocking connect with timeout */
        u_long mode = 1;
        ioctlsocket(mcpSocket, FIONBIO, &mode);

        int ret = connect(mcpSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (ret == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                closesocket(mcpSocket);
                mcpSocket = INVALID_SOCKET;
                continue;
            }

            fd_set writefds, errfds;
            FD_ZERO(&writefds); FD_SET(mcpSocket, &writefds);
            FD_ZERO(&errfds);   FD_SET(mcpSocket, &errfds);
            struct timeval tv = {3, 0};

            if (select(0, NULL, &writefds, &errfds, &tv) <= 0 ||
                FD_ISSET(mcpSocket, &errfds)) {
                closesocket(mcpSocket);
                mcpSocket = INVALID_SOCKET;
                continue;
            }
        }

        /* Back to blocking mode */
        mode = 0;
        ioctlsocket(mcpSocket, FIONBIO, &mode);
        break;
    }

    freeaddrinfo(result);
    return mcpSocket != INVALID_SOCKET;
}

static void DisconnectMcp(void) {
    EnterCriticalSection(&socketLock);
    if (mcpSocket != INVALID_SOCKET) {
        closesocket(mcpSocket);
        mcpSocket = INVALID_SOCKET;
    }
    LeaveCriticalSection(&socketLock);
}

static void SendResponse(const char *type, const char *data) {
    EnterCriticalSection(&socketLock);
    if (mcpSocket != INVALID_SOCKET) {
        /* data can be large (SET_BP: up to 128KB). Send in chunks. */
        char header[8];
        int headerLen = sprintf_s(header, sizeof(header), "%s:", type);
        int totalLen = (int)strlen(data) + headerLen + 1; /* +1 for \n */
        int sent = 0;

        /* Send header */
        while (sent < headerLen) {
            int n = send(mcpSocket, header + sent, headerLen - sent, 0);
            if (n <= 0) goto send_done;
            sent += n;
        }

        /* Send payload */
        sent = 0;
        int dataLen = (int)strlen(data);
        while (sent < dataLen) {
            int n = send(mcpSocket, data + sent, dataLen - sent, 0);
            if (n <= 0) goto send_done;
            sent += n;
        }

        /* Send terminator */
        char nl = '\n';
        send(mcpSocket, &nl, 1, 0);
    }
send_done:
    LeaveCriticalSection(&socketLock);
}

/* OK_LARGE for responses that may exceed 4096 bytes */
static void SendResponseLarge(const char *type, const char *data) {
    SendResponse(type, data);
}

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

/* ========== Command parser ========== */

static BOOL ParseCommand(char *buffer, Command *cmd) {
    if (!buffer || !cmd) return FALSE;

    char *colon = strchr(buffer, ':');
    if (!colon) return FALSE;

    *colon = '\0';
    strncpy_s(cmd->command, sizeof(cmd->command), buffer, _TRUNCATE);

    char *params = colon + 1;
    size_t len = strlen(params);
    while (len > 0 && (params[len - 1] == '\n' || params[len - 1] == '\r'))
        params[--len] = '\0';

    strncpy_s(cmd->params, sizeof(cmd->params), params, _TRUNCATE);
    return TRUE;
}

/* ========== Parameter helpers ========== */

static UINT_PTR ParseAddr(const char *s) {
    return s ? (UINT_PTR)strtoull(s, NULL, 16) : 0;
}

static char *GetParam(char *params, int idx) {
    static char buf[256];
    char *p = params;
    for (int i = 0; i < idx; i++) {
        p = strchr(p, ',');
        if (!p) return NULL;
        p++;
    }
    char *end = strchr(p, ',');
    size_t len = end ? (size_t)(end - p) : strlen(p);
    if (len > sizeof(buf) - 1) len = sizeof(buf) - 1;
    memcpy(buf, p, len);
    buf[len] = '\0';
    return buf;
}

/* ========== Get thread handle for context reads ========== */

static HANDLE GetDebugThread(void) {
    /* Get the main thread of the debugged process via toolhelp snapshot */
    if (!Exported.CreateToolhelp32Snapshot) return NULL;
    if (!Exported.Thread32First) return NULL;

    /* CE 7.5 plugin.pas:1936 — @@CreateToolhelp32Snapshot (pointer to function pointer).
     * SDK .h:354 — PVOID. Cast to function pointer type before dereferencing. */
    typedef HANDLE (WINAPI *CreateToolhelp32Snapshot_t)(DWORD, DWORD);
    HANDLE snap = (HANDLE)(*(CreateToolhelp32Snapshot_t *)Exported.CreateToolhelp32Snapshot)(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return NULL;

    DWORD pid = 0;
    if (Exported.OpenedProcessID)
        pid = *Exported.OpenedProcessID;

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    HANDLE result = NULL;
    /* CE 7.5 plugin.pas:1939 — @@Thread32First (pointer to function pointer).
     * SDK .h:357 — PVOID. */
    typedef BOOL (WINAPI *Thread32First_t)(HANDLE, LPTHREADENTRY32);
    if ((*(Thread32First_t *)Exported.Thread32First)(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                if (Exported.OpenThread) {
                    /* CE 7.5 plugin.pas:1897 — @@OpenThread.
                     * SDK .h:316 — PVOID. */
                    typedef HANDLE (WINAPI *OpenThread_t)(DWORD, BOOL, DWORD);
                    result = (*(OpenThread_t *)Exported.OpenThread)(
                        THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION |
                        THREAD_SUSPEND_RESUME,
                        FALSE, te.th32ThreadID);
                }
                break;
            }
        } while ((*(Thread32Next_t *)Exported.Thread32Next)(snap, &te));
    }

    CloseHandle(snap);
    return result;
}

/* ========== Stack walk helper ========== */

/**
 * Walks the callstack of the given thread, returning up to `maxFrames`
 * frames into `frames`. Returns the actual number of frames captured.
 *
 * Uses StackWalk64 (dbghelp.dll) which works on both x86 and x64.
 * The symbol handler is initialized once per process.
 */
static BOOL symInitialized = FALSE;

static int WalkCallstack(HANDLE hThread, const CONTEXT *ctx,
                         CallstackFrame *frames, int maxFrames) {
    HANDLE hProcess = Exported.OpenedProcessHandle
                      ? *Exported.OpenedProcessHandle
                      : GetCurrentProcess();

    if (!symInitialized) {
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
        SymInitialize(hProcess, NULL, TRUE);
        symInitialized = TRUE;
    }

    /* Set up stack frame for StackWalk64 */
    STACKFRAME64 sf;
    ZeroMemory(&sf, sizeof(sf));

#ifdef _WIN64
    sf.AddrPC.Offset    = ctx->Rip;
    sf.AddrFrame.Offset = ctx->Rbp;
    sf.AddrStack.Offset = ctx->Rsp;
    DWORD machineType   = IMAGE_FILE_MACHINE_AMD64;
#else
    sf.AddrPC.Offset    = ctx->Eip;
    sf.AddrFrame.Offset = ctx->Ebp;
    sf.AddrStack.Offset = ctx->Esp;
    DWORD machineType   = IMAGE_FILE_MACHINE_I386;
#endif
    sf.AddrPC.Mode    = AddrModeFlat;
    sf.AddrFrame.Mode = AddrModeFlat;
    sf.AddrStack.Mode = AddrModeFlat;

    int count = 0;
    CONTEXT walkCtx = *ctx;

    while (count < maxFrames) {
        if (!StackWalk64(machineType, hProcess, hThread,
                         &sf, &walkCtx,
                         NULL,                     /* ReadMemoryRoutine */
                         SymFunctionTableAccess64,  /* FunctionTableAccessRoutine */
                         SymGetModuleBase64,        /* GetModuleBaseRoutine */
                         NULL))                     /* TranslateAddress */
            break;

        if (sf.AddrPC.Offset == 0)
            break;

        frames[count].address = (UINT_PTR)sf.AddrPC.Offset;

        /* Resolve module name */
        IMAGEHLP_MODULE64 modInfo;
        ZeroMemory(&modInfo, sizeof(modInfo));
        modInfo.SizeOfStruct = sizeof(modInfo);
        if (SymGetModuleInfo64(hProcess, sf.AddrPC.Offset, &modInfo)) {
            strncpy_s(frames[count].moduleName,
                      sizeof(frames[count].moduleName),
                      modInfo.ModuleName, _TRUNCATE);
        } else {
            frames[count].moduleName[0] = '\0';
        }

        count++;
    }

    return count;
}

/* ========== Debug event callback (Type 2 Plugin) ========== */

/**
 * OnDebugEvent - receives debug events from CE's debugger.
 *
 * Returns non-zero to tell CE the plugin handled the event.
 */
static int __stdcall OnDebugEvent(LPDEBUG_EVENT DebugEvent) {
    if (!DebugEvent)
        return 0;

    if (DebugEvent->dwDebugEventCode != EXCEPTION_DEBUG_EVENT)
        return 0;

    EXCEPTION_RECORD *er = &DebugEvent->u.Exception.ExceptionRecord;
    DWORD code = er->ExceptionCode;

    /* HW BPs fire as SINGLE_STEP (0x80000004), SW BPs as BREAKPOINT (0x80000003) */
    if (code != EXCEPTION_SINGLE_STEP && code != EXCEPTION_BREAKPOINT)
        return 0;

    EnterCriticalSection(&bpMonitorLock);

    /* Count active monitors to decide matching strategy */
    int activeCount = 0, activeIdx = -1;
    for (int i = 0; i < MAX_BP_MONITORS; i++) {
        if (bpMonitors[i].active) { activeCount++; activeIdx = i; }
    }

    for (int i = 0; i < MAX_BP_MONITORS; i++) {
        BreakpointMonitor *bm = &bpMonitors[i];
        if (!bm->active) continue;

        BOOL isHit = FALSE;

        if (bm->triggerType == 0) {
            /* Execute BP: exact match on ExceptionAddress */
            isHit = (bm->address == (UINT_PTR)er->ExceptionAddress);
        } else if (activeCount == 1) {
            /* Only one active BP: safe to attribute */
            isHit = TRUE;
        } else {
            /* Multiple active BPs: only attribute if this is an execute type
             * (the address is unambiguous). For watchpoints (type 1/2) with
             * multiple monitors, we can't disambiguate without reading DR6. */
            isHit = FALSE;
        }

        if (!isHit) continue;

        /* Record the hit */
        if (bm->hitCount < MAX_BP_HITS) {
            int idx = bm->hitCount++;
            bm->hits[idx].timestamp = GetTickCount() - bm->startTick;
            bm->hits[idx].threadId = DebugEvent->dwThreadId;

            ZeroMemory(&bm->hits[idx].context, sizeof(CONTEXT));
            bm->hits[idx].context.ContextFlags = CONTEXT_FULL;

            HANDLE hThread = NULL;
            if (Exported.OpenThread) {
                /* CE 7.5 plugin.pas:1897 — @@OpenThread.
     * SDK .h:316 — PVOID. */
    typedef HANDLE (WINAPI *OpenThread_t)(DWORD, BOOL, DWORD);
    hThread = (*(OpenThread_t *)Exported.OpenThread)(
                    THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                    FALSE, DebugEvent->dwThreadId);
            }
            if (hThread) {
                if (Exported.GetThreadContext)
                    (*Exported.GetThreadContext)(hThread, &bm->hits[idx].context);

                bm->hits[idx].callstackDepth = WalkCallstack(
                    hThread, &bm->hits[idx].context,
                    bm->hits[idx].callstack, MAX_CALLSTACK_FRAMES_PER_HIT);

                CloseHandle(hThread);
            }
        }

        if (Exported.debug_continueFromBreakpoint)
            Exported.debug_continueFromBreakpoint(COEO_RUN);

        break;
    }

    LeaveCriticalSection(&bpMonitorLock);
    return 1;
}

/* ========== Breakpoint monitor helpers ========== */

static BreakpointMonitor *AllocBpMonitor(void) {
    EnterCriticalSection(&bpMonitorLock);
    for (int i = 0; i < MAX_BP_MONITORS; i++) {
        if (!bpMonitors[i].active) {
            ZeroMemory(&bpMonitors[i], sizeof(BreakpointMonitor));
            bpMonitors[i].active = TRUE;
            LeaveCriticalSection(&bpMonitorLock);
            return &bpMonitors[i];
        }
    }
    LeaveCriticalSection(&bpMonitorLock);
    return NULL;
}

static void FreeBpMonitor(BreakpointMonitor *bm) {
    if (!bm) return;
    EnterCriticalSection(&bpMonitorLock);
    ZeroMemory(bm, sizeof(BreakpointMonitor));
    LeaveCriticalSection(&bpMonitorLock);
}

/* ========== Command implementations ========== */

/**
 * PING - Connection test + process info
 */
static void cmd_PING(Command *cmd) {
    (void)cmd;
    if (!Exported.OpenedProcessID || !*Exported.OpenedProcessID) {
        OK("{\"pong\":true,\"attached\":false,\"message\":\"no process attached\"}");
        return;
    }
    DWORD pid = *Exported.OpenedProcessID;
    OK("{\"pong\":true,\"attached\":true,\"pid\":%lu}", pid);
}

/**
 * READ_MEMORY:address,length
 * Reads raw bytes from the target process.
 */
static void cmd_READ_MEMORY(Command *cmd) {
    char *addrStr = GetParam(cmd->params, 0);
    char *lenStr  = GetParam(cmd->params, 1);
    if (!addrStr) { ERR("missing address"); return; }

    UINT_PTR addr = ParseAddr(addrStr);
    int len = lenStr ? atoi(lenStr) : 256;
    if (len > 4096) len = 4096;
    if (len < 1) len = 1;

    BYTE buf[4096];
    SIZE_T bytesRead = 0;

    /* ReadProcessMemory is a ppointer (BOOL __stdcall **) */
    if (!Exported.ReadProcessMemory ||
        !(*Exported.ReadProcessMemory)(
            *Exported.OpenedProcessHandle,
            (LPCVOID)addr, buf, len, &bytesRead)) {
        ERR("read failed at 0x%llX", (unsigned long long)addr);
        return;
    }

    char hex[8192];
    int pos = 0;
    for (SIZE_T i = 0; i < bytesRead && pos < (int)sizeof(hex) - 4; i++)
        pos += sprintf_s(hex + pos, sizeof(hex) - pos, "%02X ", buf[i]);

    OK("{\"address\":\"0x%llX\",\"size\":%llu,\"bytes\":\"%s\"}",
       (unsigned long long)addr, (unsigned long long)bytesRead, hex);
}

/**
 * DISASSEMBLE:address,count
 * Disassembles `count` instructions starting at `address`.
 */
static void cmd_DISASSEMBLE(Command *cmd) {
    char *addrStr = GetParam(cmd->params, 0);
    char *cntStr  = GetParam(cmd->params, 1);
    if (!addrStr) { ERR("missing address"); return; }

    UINT_PTR addr = ParseAddr(addrStr);
    int count = cntStr ? atoi(cntStr) : 20;
    if (count > 100) count = 100;
    if (count < 1) count = 1;

    /* Disassembler is a direct function pointer (not ppointer) */
    if (!Exported.Disassembler) { ERR("disassembler not available"); return; }

    char result[32768];
    int pos = 0;
    pos += sprintf_s(result + pos, sizeof(result) - pos,
                     "{\"address\":\"0x%llX\",\"instructions\":[",
                     (unsigned long long)addr);

    UINT_PTR current = addr;
    for (int i = 0; i < count; i++) {
        char inst[256] = {0};
        /* Disassembler returns BOOL, not length
         * CE 7.5 pluginexports.pas:793 */
        if (!Exported.Disassembler(current, inst, sizeof(inst) - 1))
            break;

        /* ce_disassemble(pptrUint,...) advances *address to next instruction
         * CE 7.5 pluginexports.pas:811 — PtrUint^, disassembles then writes result */
        UINT_PTR next = current;
        if (Exported.disassembleEx)
            Exported.disassembleEx((UINT_PTR)&next, NULL, 0);
        int instLen = (int)(next - current);
        if (instLen <= 0) break;

        /* Read raw bytes for this instruction via RPM */
        BYTE raw[16] = {0};
        SIZE_T bytesRead = 0;
        if (Exported.ReadProcessMemory) {
            (*Exported.ReadProcessMemory)(
                *Exported.OpenedProcessHandle,
                (LPCVOID)current, raw, instLen, &bytesRead);
        }

        pos += sprintf_s(result + pos, sizeof(result) - pos, "%s{", i > 0 ? "," : "");
        pos += sprintf_s(result + pos, sizeof(result) - pos,
                         "\"offset\":\"0x%llX\",\"bytes\":\"",
                         (unsigned long long)current);
        for (SIZE_T j = 0; j < bytesRead && pos < (int)sizeof(result) - 20; j++)
            pos += sprintf_s(result + pos, sizeof(result) - pos, "%02X", raw[j]);
        pos += sprintf_s(result + pos, sizeof(result) - pos, "\",\"asm\":\"");
        /* JSON-escape the asm string */
        for (char *c = inst; *c && pos < (int)sizeof(result) - 4; c++) {
            switch (*c) {
                case '"':  pos += sprintf_s(result + pos, sizeof(result) - pos, "\\\""); break;
                case '\\': pos += sprintf_s(result + pos, sizeof(result) - pos, "\\\\"); break;
                case '\n': pos += sprintf_s(result + pos, sizeof(result) - pos, "\\n"); break;
                case '\r': pos += sprintf_s(result + pos, sizeof(result) - pos, "\\r"); break;
                case '\t': pos += sprintf_s(result + pos, sizeof(result) - pos, "\\t"); break;
                default:
                    if (*c >= 0x20 && *c < 0x7F) {
                        result[pos++] = *c;
                    } else {
                        pos += sprintf_s(result + pos, sizeof(result) - pos,
                                         "\\u%04X", (unsigned char)*c);
                    }
            }
        }
        pos += sprintf_s(result + pos, sizeof(result) - pos, "\"}");

        current += instLen;
        if (pos >= (int)sizeof(result) - 200) break;
    }

    pos += sprintf_s(result + pos, sizeof(result) - pos, "]}");
    OK("%s", result);
}

/**
 * GET_MODULES
 * Returns list of loaded modules using toolhelp API.
 */
static void cmd_GET_MODULES(Command *cmd) {
    (void)cmd;

    /* Use the SDK-provided CreateToolhelp32Snapshot + Module32First/Next */
    if (!Exported.CreateToolhelp32Snapshot) {
        ERR("CreateToolhelp32Snapshot not available");
        return;
    }
    if (!Exported.Module32First || !Exported.Module32Next) {
        ERR("Module32First/Next not available");
        return;
    }

    DWORD pid = 0;
    if (Exported.OpenedProcessID)
        pid = *Exported.OpenedProcessID;

    HANDLE snap = (HANDLE)(*(CreateToolhelp32Snapshot_t *)Exported.CreateToolhelp32Snapshot)(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        ERR("failed to create snapshot for pid %lu", pid);
        return;
    }

    MODULEENTRY32 me;
    me.dwSize = sizeof(MODULEENTRY32);

    char result[32768];
    int pos = 0;
    pos += sprintf_s(result + pos, sizeof(result) - pos, "{\"modules\":[");
    int first = 1;

    /* CE 7.5 plugin.pas:1941 — @@Module32First.
     * SDK .h:359 — PVOID. */
    typedef BOOL (WINAPI *Module32First_t)(HANDLE, LPMODULEENTRY32);
    if ((*(Module32First_t *)Exported.Module32First)(snap, &me)) {
        do {
            pos += sprintf_s(result + pos, sizeof(result) - pos,
                             "%s{\"name\":\"%s\",\"base\":\"0x%llX\",\"size\":%lu}",
                             first ? "" : ",",
                             me.szModule,
                             (unsigned long long)me.modBaseAddr,
                             me.modBaseSize);
            first = 0;
        } while ((*(Module32Next_t *)Exported.Module32Next)(snap, &me) && pos < (int)sizeof(result) - 300);
    }

    CloseHandle(snap);
    pos += sprintf_s(result + pos, sizeof(result) - pos, "]}");
    OK("%s", result);
}

/**
 * GET_REGISTERS
 * Returns current register values from the debugged thread.
 */
static void cmd_GET_REGISTERS(Command *cmd) {
    (void)cmd;

    /* GetThreadContext is a ppointer */
    if (!Exported.GetThreadContext) {
        ERR("GetThreadContext not available");
        return;
    }

    HANDLE hThread = GetDebugThread();
    if (!hThread) {
        ERR("cannot open debug thread - is a process being debugged?");
        return;
    }

    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;

    BOOL ok = (*Exported.GetThreadContext)(hThread, &ctx);
    CloseHandle(hThread);

    if (!ok) { ERR("GetThreadContext failed"); return; }

#ifdef _WIN64
    OK("{\"rax\":\"0x%llX\",\"rbx\":\"0x%llX\",\"rcx\":\"0x%llX\",\"rdx\":\"0x%llX\","
       "\"rsi\":\"0x%llX\",\"rdi\":\"0x%llX\",\"rbp\":\"0x%llX\",\"rsp\":\"0x%llX\","
       "\"r8\":\"0x%llX\",\"r9\":\"0x%llX\",\"r10\":\"0x%llX\",\"r11\":\"0x%llX\","
       "\"r12\":\"0x%llX\",\"r13\":\"0x%llX\",\"r14\":\"0x%llX\",\"r15\":\"0x%llX\","
       "\"rip\":\"0x%llX\",\"eflags\":\"0x%lX\"}",
       (unsigned long long)ctx.Rax, (unsigned long long)ctx.Rbx,
       (unsigned long long)ctx.Rcx, (unsigned long long)ctx.Rdx,
       (unsigned long long)ctx.Rsi, (unsigned long long)ctx.Rdi,
       (unsigned long long)ctx.Rbp, (unsigned long long)ctx.Rsp,
       (unsigned long long)ctx.R8,  (unsigned long long)ctx.R9,
       (unsigned long long)ctx.R10, (unsigned long long)ctx.R11,
       (unsigned long long)ctx.R12, (unsigned long long)ctx.R13,
       (unsigned long long)ctx.R14, (unsigned long long)ctx.R15,
       (unsigned long long)ctx.Rip, (unsigned long)ctx.EFlags);
#else
    OK("{\"eax\":\"0x%llX\",\"ebx\":\"0x%llX\",\"ecx\":\"0x%llX\",\"edx\":\"0x%llX\","
       "\"esi\":\"0x%llX\",\"edi\":\"0x%llX\",\"ebp\":\"0x%llX\",\"esp\":\"0x%llX\","
       "\"eip\":\"0x%llX\",\"eflags\":\"0x%lX\"}",
       (unsigned long long)ctx.Eax, (unsigned long long)ctx.Ebx,
       (unsigned long long)ctx.Ecx, (unsigned long long)ctx.Edx,
       (unsigned long long)ctx.Esi, (unsigned long long)ctx.Edi,
       (unsigned long long)ctx.Ebp, (unsigned long long)ctx.Esp,
       (unsigned long long)ctx.Eip, (unsigned long)ctx.EFlags);
#endif
}

/**
 * SET_BP:address,type,duration
 * type: 0=execute, 1=write, 2=read/write
 *
 * Sets a hardware breakpoint and monitors it for `duration` seconds.
 * The plugin registers a debug event callback (Type 2) to capture every
 * breakpoint hit during the monitoring window. The target process
 * auto-continues after each hit so monitoring is not blocked.
 *
 * Returns every hit with timestamp, thread ID, and full register context.
 */
static void cmd_SET_BP(Command *cmd) {
    char *addrStr = GetParam(cmd->params, 0);
    char *typeStr = GetParam(cmd->params, 1);
    char *durStr  = GetParam(cmd->params, 2);

    if (!addrStr) { ERR("missing address"); return; }

    UINT_PTR addr = ParseAddr(addrStr);
    int type = typeStr ? atoi(typeStr) : 1;  /* default: write */
    int duration = durStr ? atoi(durStr) : 10;
    if (duration > 30) duration = 30;
    if (duration < 1) duration = 1;

    /* Validate prerequisite APIs */
    if (!Exported.debug_setBreakpoint) {
        ERR("debug_setBreakpoint not available");
        return;
    }
    if (!Exported.debug_removeBreakpoint) {
        ERR("debug_removeBreakpoint not available");
        return;
    }
    if (bpCallbackId < 0) {
        ERR("debug event callback not registered - is a process being debugged?");
        return;
    }

    /* Allocate a monitor slot */
    BreakpointMonitor *bm = AllocBpMonitor();
    if (!bm) {
        ERR("too many concurrent breakpoint monitors (max %d)", MAX_BP_MONITORS);
        return;
    }

    bm->address = addr;
    bm->triggerType = type;
    bm->bpSize = 4;              /* 4-byte hardware BP */
    bm->startTick = GetTickCount();
    bm->durationSec = (DWORD)duration;

    /* Set the hardware breakpoint via CE's API */
    BOOL bpOk = Exported.debug_setBreakpoint(addr, bm->bpSize, type);
    if (!bpOk) {
        FreeBpMonitor(bm);
        ERR("failed to set breakpoint at 0x%llX (type=%d)",
            (unsigned long long)addr, type);
        return;
    }

    /* Wait for monitoring duration.
     * During this time, the OnDebugEvent callback records every hit
     * and auto-continues the target process. */
    Sleep((DWORD)(duration * 1000));

    /* Remove the breakpoint */
    Exported.debug_removeBreakpoint(addr);

    /* Build the response with all recorded hits, callstacks, and grouping */
    char result[131072];
    int pos = 0;

    /* First pass: group hits by instruction address (RIP)
     * Build a simple grouping in the JSON directly.
     * We store group info: first hit index, count, and list of hit indices. */

    /* Build JSON: header */
    pos += sprintf_s(result + pos, sizeof(result) - pos,
        "{\"address\":\"0x%llX\",\"type\":%d,\"duration_sec\":%d,"
        "\"hit_count\":%d,",
        (unsigned long long)addr, type, duration, bm->hitCount);

    /* Groups: for each unique RIP, list which hit indices belong to it */
    /* Simple dedup: track seen RIPs */
    UINT_PTR seenRips[200];
    int seenCount = 0;
    int groupMembers[200];   /* hit indices belonging to current group */
    int groupMemberCount = 0;

    pos += sprintf_s(result + pos, sizeof(result) - pos, "\"groups\":[");

    int firstGroup = 1;
    for (int pass = 0; pass < MAX_BP_HITS && pos < (int)sizeof(result) - 2048; pass++) {
        /* Find the next ungrouped RIP and collect all hits sharing it */
        UINT_PTR groupRip = 0;
        groupMemberCount = 0;

        for (int i = 0; i < bm->hitCount; i++) {
#ifdef _WIN64
            UINT_PTR rip = bm->hits[i].context.Rip;
#else
            UINT_PTR rip = bm->hits[i].context.Eip;
#endif
            BOOL alreadySeen = FALSE;
            for (int s = 0; s < seenCount; s++) {
                if (seenRips[s] == rip) {
                    alreadySeen = TRUE;
                    break;
                }
            }
            if (alreadySeen) continue;

            if (groupMemberCount == 0) {
                groupRip = rip;
                groupMembers[groupMemberCount++] = i;
            } else if (rip == groupRip) {
                groupMembers[groupMemberCount++] = i;
            }
        }

        if (groupMemberCount == 0) break;

        /* Mark this RIP as seen */
        if (seenCount < 200) {
            seenRips[seenCount++] = groupRip;
        }

        if (!firstGroup) pos += sprintf_s(result + pos, sizeof(result) - pos, ",");
        firstGroup = 0;

        pos += sprintf_s(result + pos, sizeof(result) - pos,
            "{\"rip\":\"0x%llX\",\"count\":%d,\"indices\":[",
            (unsigned long long)groupRip, groupMemberCount);

        for (int m = 0; m < groupMemberCount; m++) {
            pos += sprintf_s(result + pos, sizeof(result) - pos,
                "%s%d", m > 0 ? "," : "", groupMembers[m]);
        }
        pos += sprintf_s(result + pos, sizeof(result) - pos, "]}");
    }

    pos += sprintf_s(result + pos, sizeof(result) - pos, "],\"hits\":[");

    /* Now emit each hit with full details (registers + callstack) */
    for (int i = 0; i < bm->hitCount && pos < (int)sizeof(result) - 8192; i++) {
        BPHitRecord *hit = &bm->hits[i];
        pos += sprintf_s(result + pos, sizeof(result) - pos,
            "%s{\"index\":%d,\"timestamp_ms\":%lu,\"thread_id\":%lu,",
            i > 0 ? "," : "", i, hit->timestamp, hit->threadId);

        /* Callstack */
        pos += sprintf_s(result + pos, sizeof(result) - pos,
            "\"callstack\":[");
        for (int f = 0; f < hit->callstackDepth && pos < (int)sizeof(result) - 1024; f++) {
            pos += sprintf_s(result + pos, sizeof(result) - pos,
                "%s{\"frame\":%d,\"address\":\"0x%llX\"",
                f > 0 ? "," : "", f,
                (unsigned long long)hit->callstack[f].address);
            if (hit->callstack[f].moduleName[0]) {
                pos += sprintf_s(result + pos, sizeof(result) - pos,
                    ",\"module\":\"%s\"", hit->callstack[f].moduleName);
            }
            pos += sprintf_s(result + pos, sizeof(result) - pos, "}");
        }
        pos += sprintf_s(result + pos, sizeof(result) - pos, "],");

        /* Registers */
        pos += sprintf_s(result + pos, sizeof(result) - pos, "\"registers\":{");

#ifdef _WIN64
        pos += sprintf_s(result + pos, sizeof(result) - pos,
            "\"rax\":\"0x%llX\",\"rbx\":\"0x%llX\",\"rcx\":\"0x%llX\","
            "\"rdx\":\"0x%llX\",\"rsi\":\"0x%llX\",\"rdi\":\"0x%llX\","
            "\"rbp\":\"0x%llX\",\"rsp\":\"0x%llX\",\"r8\":\"0x%llX\","
            "\"r9\":\"0x%llX\",\"r10\":\"0x%llX\",\"r11\":\"0x%llX\","
            "\"r12\":\"0x%llX\",\"r13\":\"0x%llX\",\"r14\":\"0x%llX\","
            "\"r15\":\"0x%llX\",\"rip\":\"0x%llX\",\"eflags\":\"0x%lX\"",
            (unsigned long long)hit->context.Rax,
            (unsigned long long)hit->context.Rbx,
            (unsigned long long)hit->context.Rcx,
            (unsigned long long)hit->context.Rdx,
            (unsigned long long)hit->context.Rsi,
            (unsigned long long)hit->context.Rdi,
            (unsigned long long)hit->context.Rbp,
            (unsigned long long)hit->context.Rsp,
            (unsigned long long)hit->context.R8,
            (unsigned long long)hit->context.R9,
            (unsigned long long)hit->context.R10,
            (unsigned long long)hit->context.R11,
            (unsigned long long)hit->context.R12,
            (unsigned long long)hit->context.R13,
            (unsigned long long)hit->context.R14,
            (unsigned long long)hit->context.R15,
            (unsigned long long)hit->context.Rip,
            (unsigned long)hit->context.EFlags);
#else
        pos += sprintf_s(result + pos, sizeof(result) - pos,
            "\"eax\":\"0x%llX\",\"ebx\":\"0x%llX\",\"ecx\":\"0x%llX\","
            "\"edx\":\"0x%llX\",\"esi\":\"0x%llX\",\"edi\":\"0x%llX\","
            "\"ebp\":\"0x%llX\",\"esp\":\"0x%llX\",\"eip\":\"0x%llX\","
            "\"eflags\":\"0x%lX\"",
            (unsigned long long)hit->context.Eax,
            (unsigned long long)hit->context.Ebx,
            (unsigned long long)hit->context.Ecx,
            (unsigned long long)hit->context.Edx,
            (unsigned long long)hit->context.Esi,
            (unsigned long long)hit->context.Edi,
            (unsigned long long)hit->context.Ebp,
            (unsigned long long)hit->context.Esp,
            (unsigned long long)hit->context.Eip,
            (unsigned long)hit->context.EFlags);
#endif
        pos += sprintf_s(result + pos, sizeof(result) - pos, "}}");
    }

    pos += sprintf_s(result + pos, sizeof(result) - pos, "]}");

    /* Free the monitor slot */
    FreeBpMonitor(bm);

    OK("%s", result);
}

/**
 * AOB_SCAN:pattern,module_name(optional)
 * Scans memory for an array-of-bytes pattern using ? or ?? for wildcards.
 */
static void cmd_AOB_SCAN(Command *cmd) {
    char *pattern = GetParam(cmd->params, 0);
    char *moduleName = GetParam(cmd->params, 1);

    if (!pattern) { ERR("missing pattern"); return; }

    /* Parse pattern "AA BB ?? DD" into byte + mask arrays */
    BYTE pat[128];
    BYTE mask[128];
    int patLen = 0;

    char *ctx = NULL;
    char patternCopy[512];
    strncpy_s(patternCopy, sizeof(patternCopy), pattern, _TRUNCATE);

    char *tok = strtok_s(patternCopy, " ", &ctx);
    while (tok && patLen < 128) {
        if (strcmp(tok, "??") == 0 || strcmp(tok, "?") == 0) {
            mask[patLen] = 0;
            pat[patLen] = 0;
        } else {
            mask[patLen] = 1;
            pat[patLen] = (BYTE)strtoul(tok, NULL, 16);
        }
        patLen++;
        tok = strtok_s(NULL, " ", &ctx);
    }

    if (patLen == 0) { ERR("empty pattern"); return; }

    /* Find module base and size */
    UINT_PTR base = 0;
    SIZE_T size = 0;

    if (!Exported.CreateToolhelp32Snapshot ||
        !Exported.Module32First || !Exported.Module32Next) {
        ERR("module enumeration not available");
        return;
    }

    DWORD pid = 0;
    if (Exported.OpenedProcessID)
        pid = *Exported.OpenedProcessID;

    HANDLE snap = (HANDLE)(*(CreateToolhelp32Snapshot_t *)Exported.CreateToolhelp32Snapshot)(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        ERR("failed to create snapshot");
        return;
    }

    MODULEENTRY32 me;
    me.dwSize = sizeof(MODULEENTRY32);

    if (moduleName && moduleName[0]) {
        /* Search for the specified module */
        /* CE 7.5 plugin.pas:1941 — @@Module32First.
     * SDK .h:359 — PVOID. */
    typedef BOOL (WINAPI *Module32First_t)(HANDLE, LPMODULEENTRY32);
    if ((*(Module32First_t *)Exported.Module32First)(snap, &me)) {
            do {
                if (_stricmp(me.szModule, moduleName) == 0) {
                    base = (UINT_PTR)me.modBaseAddr;
                    size = me.modBaseSize;
                    break;
                }
            } while ((*(Module32Next_t *)Exported.Module32Next)(snap, &me));
        }
    } else {
        /* Use first module (main executable) */
        /* CE 7.5 plugin.pas:1941 — @@Module32First.
     * SDK .h:359 — PVOID. */
    typedef BOOL (WINAPI *Module32First_t)(HANDLE, LPMODULEENTRY32);
    if ((*(Module32First_t *)Exported.Module32First)(snap, &me)) {
            base = (UINT_PTR)me.modBaseAddr;
            size = me.modBaseSize;
        }
    }
    CloseHandle(snap);

    if (base == 0 || size == 0) {
        ERR("module not found: %s", moduleName ? moduleName : "(main)");
        return;
    }

    /* Linear scan with chunked reads */
    BYTE buf[4096];
    UINT_PTR matchAddrs[50];
    int found = 0;

    for (UINT_PTR cur = base; cur < base + size - patLen;) {
        SIZE_T chunkSize = min(sizeof(buf), base + size - cur);
        SIZE_T bytesRead = 0;

        if (!Exported.ReadProcessMemory ||
            !(*Exported.ReadProcessMemory)(
                *Exported.OpenedProcessHandle,
                (LPCVOID)cur, buf, chunkSize, &bytesRead)) {
            cur += chunkSize;
            continue;
        }

        for (SIZE_T i = 0; i + patLen <= bytesRead; i++) {
            BOOL match = TRUE;
            for (int j = 0; j < patLen; j++) {
                if (mask[j] && buf[i + j] != pat[j]) {
                    match = FALSE;
                    break;
                }
            }
            if (match && found < 50) {
                matchAddrs[found++] = cur + i;
            }
            if (found >= 50) break;
        }

        cur += bytesRead - patLen + 1;
        if (cur >= base + size) break;
    }

    char results[4096];
    int pos = 0;
    pos += sprintf_s(results + pos, sizeof(results) - pos,
                     "{\"pattern\":\"%s\",\"matches\":[", pattern);
    for (int i = 0; i < found; i++) {
        pos += sprintf_s(results + pos, sizeof(results) - pos,
                         "%s\"0x%llX\"", i > 0 ? "," : "",
                         (unsigned long long)matchAddrs[i]);
    }
    pos += sprintf_s(results + pos, sizeof(results) - pos, "],\"count\":%d}", found);
    OK("%s", results);
}

/**
 * GET_CALLSTACK:thread_id,max_frames
 * Walks the callstack of the current thread (or specified thread).
 * Returns return addresses and resolved module names.
 */
static void cmd_GET_CALLSTACK(Command *cmd) {
    char *tidStr = GetParam(cmd->params, 0);
    char *maxStr = GetParam(cmd->params, 1);
    int maxFrames = maxStr ? atoi(maxStr) : 16;
    if (maxFrames > MAX_CALLSTACK_DEPTH) maxFrames = MAX_CALLSTACK_DEPTH;
    if (maxFrames < 1) maxFrames = 1;

    /* Get thread handle */
    HANDLE hThread = NULL;
    if (tidStr && tidStr[0]) {
        DWORD tid = (DWORD)strtoul(tidStr, NULL, 10);
        if (Exported.OpenThread) {
            /* CE 7.5 plugin.pas:1897 — @@OpenThread.
     * SDK .h:316 — PVOID. */
    typedef HANDLE (WINAPI *OpenThread_t)(DWORD, BOOL, DWORD);
    hThread = (*(OpenThread_t *)Exported.OpenThread)(
                THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION |
                THREAD_SUSPEND_RESUME, FALSE, tid);
        }
    } else {
        hThread = GetDebugThread();
    }

    if (!hThread) {
        ERR("cannot open target thread");
        return;
    }

    /* Capture context */
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;

    BOOL ctxOk = FALSE;
    if (Exported.GetThreadContext)
        ctxOk = (*Exported.GetThreadContext)(hThread, &ctx);

    if (!ctxOk) {
        CloseHandle(hThread);
        ERR("GetThreadContext failed");
        return;
    }

    /* Walk the stack */
    CallstackFrame frames[MAX_CALLSTACK_DEPTH];
    int depth = WalkCallstack(hThread, &ctx, frames, maxFrames);
    CloseHandle(hThread);

    char result[16384];
    int pos = 0;
    pos += sprintf_s(result + pos, sizeof(result) - pos,
        "{\"depth\":%d,\"frames\":[", depth);
    for (int i = 0; i < depth; i++) {
        pos += sprintf_s(result + pos, sizeof(result) - pos,
            "%s{\"frame\":%d,\"address\":\"0x%llX\"",
            i > 0 ? "," : "", i,
            (unsigned long long)frames[i].address);
        if (frames[i].moduleName[0]) {
            pos += sprintf_s(result + pos, sizeof(result) - pos,
                ",\"module\":\"%s\"", frames[i].moduleName);
        }
        pos += sprintf_s(result + pos, sizeof(result) - pos, "}");
    }
    pos += sprintf_s(result + pos, sizeof(result) - pos, "]}");
    OK("%s", result);
}

/* ========== Register trace (cross-function register tracking) ========== */

/**
 * REGISTER_TRACE:start_addr,end_addr,duration
 *
 * Sets execute breakpoints at start_addr and end_addr, then monitors for
 * `duration` seconds. Each time the start BP fires, registers are captured
 * at function entry. The corresponding end BP capture (at function exit/
 * return) is paired, and a register diff is computed.
 *
 * Returns paired snapshots: entry_registers, exit_registers, diff.
 */

#define MAX_TRACE_PAIRS 100

static void cmd_REGISTER_TRACE(Command *cmd) {
    char *startStr = GetParam(cmd->params, 0);
    char *endStr   = GetParam(cmd->params, 1);
    char *durStr   = GetParam(cmd->params, 2);

    if (!startStr || !endStr) {
        ERR("missing start_addr or end_addr");
        return;
    }

    UINT_PTR startAddr = ParseAddr(startStr);
    UINT_PTR endAddr   = ParseAddr(endStr);
    int duration = durStr ? atoi(durStr) : 10;
    if (duration > 30) duration = 30;
    if (duration < 1) duration = 1;

    if (!Exported.debug_setBreakpoint ||
        !Exported.debug_removeBreakpoint) {
        ERR("breakpoint API not available");
        return;
    }

    /* Set execute breakpoints at both addresses (size=1 for execute BP) */
    BOOL startOk = Exported.debug_setBreakpoint(startAddr, 1, 0);
    BOOL endOk   = Exported.debug_setBreakpoint(endAddr, 1, 0);

    if (!startOk || !endOk) {
        if (startOk) Exported.debug_removeBreakpoint(startAddr);
        if (endOk)   Exported.debug_removeBreakpoint(endAddr);
        ERR("failed to set trace breakpoints");
        return;
    }

    /* Wait for monitoring duration.
     * The OnDebugEvent callback captures every hit with registers + callstack.
     * After the wait, we scan the BP monitor records looking for paired
     * start/end hits. */
    Sleep((DWORD)(duration * 1000));

    Exported.debug_removeBreakpoint(startAddr);
    Exported.debug_removeBreakpoint(endAddr);

    /* Collect all hits from the two breakpoint monitors.
     * Heap-allocate: BPHitRecord can be ~1300 bytes each, 400 of them
     * would overflow a 1MB thread stack at deep call depths. */
    BPHitRecord *startHits = NULL, *endHits = NULL;
    int startCount = 0, endCount = 0;

    startHits = (BPHitRecord *)calloc(150, sizeof(BPHitRecord));
    endHits   = (BPHitRecord *)calloc(150, sizeof(BPHitRecord));
    if (!startHits || !endHits) {
        free(startHits);
        free(endHits);
        Exported.debug_removeBreakpoint(startAddr);
        Exported.debug_removeBreakpoint(endAddr);
        ERR("out of memory");
        return;
    }

    EnterCriticalSection(&bpMonitorLock);
    for (int i = 0; i < MAX_BP_MONITORS; i++) {
        BreakpointMonitor *bm = &bpMonitors[i];
        if (!bm->active) continue;
        if (bm->address == startAddr && bm->triggerType == 0) {
            for (int j = 0; j < bm->hitCount && startCount < 150; j++)
                startHits[startCount++] = bm->hits[j];
        }
        if (bm->address == endAddr && bm->triggerType == 0) {
            for (int j = 0; j < bm->hitCount && endCount < 150; j++)
                endHits[endCount++] = bm->hits[j];
        }
    }
    /* Clean up these monitors */
    for (int i = 0; i < MAX_BP_MONITORS; i++) {
        if (!bpMonitors[i].active) continue;
        if (bpMonitors[i].address == startAddr || bpMonitors[i].address == endAddr) {
            ZeroMemory(&bpMonitors[i], sizeof(BreakpointMonitor));
        }
    }
    LeaveCriticalSection(&bpMonitorLock);

    /* Pair start hits with subsequent end hits by timestamp order.
     * Each start hit pairs with the next end hit that occurs after it.
     * Multi-thread safe: thread affinity is loose but timestamp order
     * gives correct entry/exit pairing for single-thread callers. */
    char result[131072];
    int pos = 0;
    pos += sprintf_s(result + pos, sizeof(result) - pos,
        "{\"start_address\":\"0x%llX\",\"end_address\":\"0x%llX\","
        "\"duration_sec\":%d,\"entry_count\":%d,\"exit_count\":%d,"
        "\"pairs\":[",
        (unsigned long long)startAddr, (unsigned long long)endAddr,
        duration, startCount, endCount);

    int endIdx = 0;
    int pairCount = 0;
    for (int s = 0; s < startCount && pairCount < MAX_TRACE_PAIRS; s++) {
        /* Find next end hit after this start hit */
        while (endIdx < endCount &&
               endHits[endIdx].timestamp < startHits[s].timestamp) {
            endIdx++;
        }
        if (endIdx >= endCount) break;

        BPHitRecord *entry = &startHits[s];
        BPHitRecord *exit  = &endHits[endIdx];
        endIdx++;

        if (pairCount > 0)
            pos += sprintf_s(result + pos, sizeof(result) - pos, ",");
        pairCount++;

        pos += sprintf_s(result + pos, sizeof(result) - pos,
            "{\"entry_timestamp_ms\":%lu,\"exit_timestamp_ms\":%lu,"
            "\"thread_id\":%lu,",
            entry->timestamp, exit->timestamp, entry->threadId);

        /* Entry registers */
        pos += sprintf_s(result + pos, sizeof(result) - pos, "\"entry\":{");
#ifdef _WIN64
        pos += sprintf_s(result + pos, sizeof(result) - pos,
            "\"rax\":\"0x%llX\",\"rbx\":\"0x%llX\",\"rcx\":\"0x%llX\","
            "\"rdx\":\"0x%llX\",\"rsi\":\"0x%llX\",\"rdi\":\"0x%llX\","
            "\"rbp\":\"0x%llX\",\"rsp\":\"0x%llX\",\"r8\":\"0x%llX\","
            "\"r9\":\"0x%llX\",\"r10\":\"0x%llX\",\"r11\":\"0x%llX\","
            "\"r12\":\"0x%llX\",\"r13\":\"0x%llX\",\"r14\":\"0x%llX\","
            "\"r15\":\"0x%llX\",\"rip\":\"0x%llX\",\"eflags\":\"0x%lX\"",
            (unsigned long long)entry->context.Rax,
            (unsigned long long)entry->context.Rbx,
            (unsigned long long)entry->context.Rcx,
            (unsigned long long)entry->context.Rdx,
            (unsigned long long)entry->context.Rsi,
            (unsigned long long)entry->context.Rdi,
            (unsigned long long)entry->context.Rbp,
            (unsigned long long)entry->context.Rsp,
            (unsigned long long)entry->context.R8,
            (unsigned long long)entry->context.R9,
            (unsigned long long)entry->context.R10,
            (unsigned long long)entry->context.R11,
            (unsigned long long)entry->context.R12,
            (unsigned long long)entry->context.R13,
            (unsigned long long)entry->context.R14,
            (unsigned long long)entry->context.R15,
            (unsigned long long)entry->context.Rip,
            (unsigned long)entry->context.EFlags);
#else
        pos += sprintf_s(result + pos, sizeof(result) - pos,
            "\"eax\":\"0x%llX\",\"ebx\":\"0x%llX\",\"ecx\":\"0x%llX\","
            "\"edx\":\"0x%llX\",\"esi\":\"0x%llX\",\"edi\":\"0x%llX\","
            "\"ebp\":\"0x%llX\",\"esp\":\"0x%llX\",\"eip\":\"0x%llX\","
            "\"eflags\":\"0x%lX\"",
            (unsigned long long)entry->context.Eax,
            (unsigned long long)entry->context.Ebx,
            (unsigned long long)entry->context.Ecx,
            (unsigned long long)entry->context.Edx,
            (unsigned long long)entry->context.Esi,
            (unsigned long long)entry->context.Edi,
            (unsigned long long)entry->context.Ebp,
            (unsigned long long)entry->context.Esp,
            (unsigned long long)entry->context.Eip,
            (unsigned long)entry->context.EFlags);
#endif
        pos += sprintf_s(result + pos, sizeof(result) - pos, "},");

        /* Exit registers */
        pos += sprintf_s(result + pos, sizeof(result) - pos, "\"exit\":{");
#ifdef _WIN64
        pos += sprintf_s(result + pos, sizeof(result) - pos,
            "\"rax\":\"0x%llX\",\"rbx\":\"0x%llX\",\"rcx\":\"0x%llX\","
            "\"rdx\":\"0x%llX\",\"rsi\":\"0x%llX\",\"rdi\":\"0x%llX\","
            "\"rbp\":\"0x%llX\",\"rsp\":\"0x%llX\",\"r8\":\"0x%llX\","
            "\"r9\":\"0x%llX\",\"r10\":\"0x%llX\",\"r11\":\"0x%llX\","
            "\"r12\":\"0x%llX\",\"r13\":\"0x%llX\",\"r14\":\"0x%llX\","
            "\"r15\":\"0x%llX\",\"rip\":\"0x%llX\",\"eflags\":\"0x%lX\"",
            (unsigned long long)exit->context.Rax,
            (unsigned long long)exit->context.Rbx,
            (unsigned long long)exit->context.Rcx,
            (unsigned long long)exit->context.Rdx,
            (unsigned long long)exit->context.Rsi,
            (unsigned long long)exit->context.Rdi,
            (unsigned long long)exit->context.Rbp,
            (unsigned long long)exit->context.Rsp,
            (unsigned long long)exit->context.R8,
            (unsigned long long)exit->context.R9,
            (unsigned long long)exit->context.R10,
            (unsigned long long)exit->context.R11,
            (unsigned long long)exit->context.R12,
            (unsigned long long)exit->context.R13,
            (unsigned long long)exit->context.R14,
            (unsigned long long)exit->context.R15,
            (unsigned long long)exit->context.Rip,
            (unsigned long)exit->context.EFlags);
#else
        pos += sprintf_s(result + pos, sizeof(result) - pos,
            "\"eax\":\"0x%llX\",\"ebx\":\"0x%llX\",\"ecx\":\"0x%llX\","
            "\"edx\":\"0x%llX\",\"esi\":\"0x%llX\",\"edi\":\"0x%llX\","
            "\"ebp\":\"0x%llX\",\"esp\":\"0x%llX\",\"eip\":\"0x%llX\","
            "\"eflags\":\"0x%lX\"",
            (unsigned long long)exit->context.Eax,
            (unsigned long long)exit->context.Ebx,
            (unsigned long long)exit->context.Ecx,
            (unsigned long long)exit->context.Edx,
            (unsigned long long)exit->context.Esi,
            (unsigned long long)exit->context.Edi,
            (unsigned long long)exit->context.Ebp,
            (unsigned long long)exit->context.Esp,
            (unsigned long long)exit->context.Eip,
            (unsigned long)exit->context.EFlags);
#endif
        pos += sprintf_s(result + pos, sizeof(result) - pos, "},");

        /* Diff: compute register changes */
        pos += sprintf_s(result + pos, sizeof(result) - pos, "\"diff\":{");
#ifdef _WIN64
        /* Only emit registers that changed (keep output compact) */
        const char *regNames64[] = {"rax","rbx","rcx","rdx","rsi","rdi",
                                     "rbp","rsp","r8","r9","r10","r11",
                                     "r12","r13","r14","r15","rip","eflags"};
        UINT_PTR entryVals[] = {
            entry->context.Rax, entry->context.Rbx, entry->context.Rcx,
            entry->context.Rdx, entry->context.Rsi, entry->context.Rdi,
            entry->context.Rbp, entry->context.Rsp, entry->context.R8,
            entry->context.R9,  entry->context.R10, entry->context.R11,
            entry->context.R12, entry->context.R13, entry->context.R14,
            entry->context.R15, entry->context.Rip, (UINT_PTR)entry->context.EFlags
        };
        UINT_PTR exitVals[] = {
            exit->context.Rax, exit->context.Rbx, exit->context.Rcx,
            exit->context.Rdx, exit->context.Rsi, exit->context.Rdi,
            exit->context.Rbp, exit->context.Rsp, exit->context.R8,
            exit->context.R9,  exit->context.R10, exit->context.R11,
            exit->context.R12, exit->context.R13, exit->context.R14,
            exit->context.R15, exit->context.Rip, (UINT_PTR)exit->context.EFlags
        };
        int nRegs = 18;
#else
        const char *regNames32[] = {"eax","ebx","ecx","edx","esi","edi",
                                     "ebp","esp","eip","eflags"};
        UINT_PTR entryVals[] = {
            entry->context.Eax, entry->context.Ebx, entry->context.Ecx,
            entry->context.Edx, entry->context.Esi, entry->context.Edi,
            entry->context.Ebp, entry->context.Esp, entry->context.Eip,
            (UINT_PTR)entry->context.EFlags
        };
        UINT_PTR exitVals[] = {
            exit->context.Eax, exit->context.Ebx, exit->context.Ecx,
            exit->context.Edx, exit->context.Esi, exit->context.Edi,
            exit->context.Ebp, exit->context.Esp, exit->context.Eip,
            (UINT_PTR)exit->context.EFlags
        };
        const char **regNames = regNames32;
        int nRegs = 10;
#endif

        int firstDiff = 1;
        for (int r = 0; r < nRegs && pos < (int)sizeof(result) - 500; r++) {
#ifdef _WIN64
            const char **regNames = regNames64;
#endif
            if (entryVals[r] != exitVals[r]) {
                INT_PTR delta = (INT_PTR)(exitVals[r] - entryVals[r]);
                pos += sprintf_s(result + pos, sizeof(result) - pos,
                    "%s\"%s\":{\"from\":\"0x%llX\",\"to\":\"0x%llX\""
                    ",\"delta\":\"%+lld\"}",
                    firstDiff ? "" : ",",
                    regNames[r],
                    (unsigned long long)entryVals[r],
                    (unsigned long long)exitVals[r],
                    (long long)delta);
                firstDiff = 0;
            }
        }
        if (firstDiff) {
            pos += sprintf_s(result + pos, sizeof(result) - pos,
                "\"_note\":\"no registers changed\"");
        }

        pos += sprintf_s(result + pos, sizeof(result) - pos, "}}");
    }

    pos += sprintf_s(result + pos, sizeof(result) - pos,
        "],\"paired_count\":%d}", pairCount);
    free(startHits);
    free(endHits);
    OK("%s", result);
}

/* ========== AOB hook script generator ========== */

/**
 * GENERATE_HOOK:address,jump_to(optional),codecave_size(optional)
 *
 * Generates an AutoAssemble script that hooks the instruction at `address`.
 * If `jump_to` is provided, the hook redirects to that address/label.
 * The script includes ENABLE and DISABLE sections with original code restored.
 */
static void cmd_GENERATE_HOOK(Command *cmd) {
    char *addrStr     = GetParam(cmd->params, 0);
    char *jumpToStr   = GetParam(cmd->params, 1);
    char *caveSizeStr = GetParam(cmd->params, 2);

    if (!addrStr) { ERR("missing address"); return; }

    UINT_PTR addr = ParseAddr(addrStr);
    int caveSize = caveSizeStr ? atoi(caveSizeStr) : 1024;
    if (caveSize < 64) caveSize = 64;
    if (caveSize > 65536) caveSize = 65536;

    if (!Exported.Disassembler) {
        ERR("disassembler not available");
        return;
    }

#ifdef _WIN64
    int minHookLen = 14; /* absolute jmp [rip+disp] */
#else
    int minHookLen = 5;  /* E9 relative jmp */
#endif

    /* Accumulate instructions to cover minHookLen bytes */
    int hookSize = 0;
    UINT_PTR cur = addr;
    while (cur < addr + 64 && hookSize < minHookLen) {
        char inst[256] = {0};
        /* Disassembler returns BOOL, not length (CE 7.5 pluginexports.pas:793) */
        if (!Exported.Disassembler(cur, inst, sizeof(inst) - 1))
            break;
        /* ce_disassemble(pptrUint,...) advances *address (CE 7.5 pluginexports.pas:811) */
        UINT_PTR nextCur = cur;
        if (Exported.disassembleEx)
            Exported.disassembleEx((UINT_PTR)&nextCur, NULL, 0);
        int len = (int)(nextCur - cur);
        if (len <= 0) break;
        hookSize += len;
        cur = addr + hookSize;
    }

    if (hookSize < minHookLen) {
        ERR("cannot accumulate enough bytes for hook (need %d, got %d)",
            minHookLen, hookSize);
        return;
    }

    char labelPrefix[32];
    sprintf_s(labelPrefix, sizeof(labelPrefix), "mcp_hook_%llX",
              (unsigned long long)addr);

    /* Build script */
    char script[8192];
    int pos = 0;
    pos += sprintf_s(script + pos, sizeof(script) - pos, "[ENABLE]\n");
    pos += sprintf_s(script + pos, sizeof(script) - pos,
        "// CE-MCP auto-generated hook at 0x%llX\n", (unsigned long long)addr);
    pos += sprintf_s(script + pos, sizeof(script) - pos,
        "alloc(%s_codecave,%d)\n", labelPrefix, caveSize);
    pos += sprintf_s(script + pos, sizeof(script) - pos,
        "label(%s_original)\n", labelPrefix);
    pos += sprintf_s(script + pos, sizeof(script) - pos,
        "label(%s_return)\n\n", labelPrefix);

    if (jumpToStr && jumpToStr[0]) {
        pos += sprintf_s(script + pos, sizeof(script) - pos,
            "%s:\n", labelPrefix);
        pos += sprintf_s(script + pos, sizeof(script) - pos,
            "  push rax\n");
        pos += sprintf_s(script + pos, sizeof(script) - pos,
            "  mov rax,%s\n", jumpToStr);
        pos += sprintf_s(script + pos, sizeof(script) - pos,
            "  call rax\n");
        pos += sprintf_s(script + pos, sizeof(script) - pos,
            "  pop rax\n");
    } else {
        pos += sprintf_s(script + pos, sizeof(script) - pos,
            "%s:\n", labelPrefix);
        pos += sprintf_s(script + pos, sizeof(script) - pos,
            "  // <-- insert your custom code here\n");
    }

    pos += sprintf_s(script + pos, sizeof(script) - pos, "\n");
    pos += sprintf_s(script + pos, sizeof(script) - pos,
        "%s_original:\n", labelPrefix);

    /* Emit original instruction bytes */
    cur = addr;
    while (cur < addr + (UINT_PTR)hookSize && pos < (int)sizeof(script) - 200) {
        char inst[256] = {0};
        if (!Exported.Disassembler(cur, inst, sizeof(inst) - 1))
            break;

        /* CE 7.5 pluginexports.pas:811 — ce_disassemble(pptrUint, ...) advances address */
        UINT_PTR nextCur = cur;
        if (Exported.disassembleEx)
            Exported.disassembleEx((UINT_PTR)&nextCur, NULL, 0);
        int len = (int)(nextCur - cur);
        if (len <= 0) break;

        BYTE raw[16] = {0};
        SIZE_T bytesRead = 0;
        if (Exported.ReadProcessMemory) {
            (*Exported.ReadProcessMemory)(
                *Exported.OpenedProcessHandle,
                (LPCVOID)cur, raw, len, &bytesRead);
        }
        pos += sprintf_s(script + pos, sizeof(script) - pos, "  ");
        for (SIZE_T b = 0; b < bytesRead; b++)
            pos += sprintf_s(script + pos, sizeof(script) - pos,
                             "%s%02X", b > 0 ? " " : "", raw[b]);
        pos += sprintf_s(script + pos, sizeof(script) - pos, " // %s\n", inst);
        cur += len;
    }
    pos += sprintf_s(script + pos, sizeof(script) - pos,
        "  jmp %s_return\n\n", labelPrefix);

    /* Write the hook jump at the target address */
    pos += sprintf_s(script + pos, sizeof(script) - pos,
        "%s+%X:\n", labelPrefix, 0);
#ifdef _WIN64
    pos += sprintf_s(script + pos, sizeof(script) - pos,
        "  db EB 0E  // jmp %s (14 bytes, absolute)\n", labelPrefix);
    pos += sprintf_s(script + pos, sizeof(script) - pos,
        "  dq %s\n", labelPrefix);
#else
    pos += sprintf_s(script + pos, sizeof(script) - pos,
        "  jmp %s  // 5-byte near jump\n", labelPrefix);
#endif
    /* Pad remaining overwritten bytes with nop */
    {
        int jmpSize;
#ifdef _WIN64
        jmpSize = 14; /* db EB 0E + dq addr */
#else
        jmpSize = 5;  /* E9 rel32 */
#endif
        int pad = hookSize - jmpSize;
        for (int n = 0; n < pad && n < 50; n++)
            pos += sprintf_s(script + pos, sizeof(script) - pos, "  nop\n");
    }

    pos += sprintf_s(script + pos, sizeof(script) - pos,
        "%s_return:\n\n", labelPrefix);
    pos += sprintf_s(script + pos, sizeof(script) - pos, "[DISABLE]\n");

    /* Restore original instruction bytes at the hook site.
     * The jmp we wrote consumed `hookSize` bytes. In DISABLE we restore
     * the original raw bytes byte-for-byte. */
    pos += sprintf_s(script + pos, sizeof(script) - pos,
        "%s+%X:\n", labelPrefix, 0);

    /* Restore original bytes */
    cur = addr;
    while (cur < addr + (UINT_PTR)hookSize && pos < (int)sizeof(script) - 200) {
        char inst[256] = {0};
        if (!Exported.Disassembler(cur, inst, sizeof(inst) - 1))
            break;

        /* CE 7.5 pluginexports.pas:811 — ce_disassemble(pptrUint, ...) advances address */
        UINT_PTR nextCur = cur;
        if (Exported.disassembleEx)
            Exported.disassembleEx((UINT_PTR)&nextCur, NULL, 0);
        int len = (int)(nextCur - cur);
        if (len <= 0) break;

        BYTE raw[16] = {0};
        SIZE_T bytesRead = 0;
        if (Exported.ReadProcessMemory) {
            (*Exported.ReadProcessMemory)(
                *Exported.OpenedProcessHandle,
                (LPCVOID)cur, raw, len, &bytesRead);
        }
        pos += sprintf_s(script + pos, sizeof(script) - pos, "  ");
        for (SIZE_T b = 0; b < bytesRead; b++)
            pos += sprintf_s(script + pos, sizeof(script) - pos,
                             "%s%02X", b > 0 ? " " : "", raw[b]);
        pos += sprintf_s(script + pos, sizeof(script) - pos, " // %s\n", inst);
        cur += len;
    }
    pos += sprintf_s(script + pos, sizeof(script) - pos,
        "dealloc(%s_codecave)\n", labelPrefix);

    /* JSON-escape the script */
    char jsonScript[16384];
    int jpos = 0;
    for (int i = 0; script[i] && jpos < (int)sizeof(jsonScript) - 4; i++) {
        switch (script[i]) {
            case '"':  jpos += sprintf_s(jsonScript + jpos, sizeof(jsonScript) - jpos, "\\\""); break;
            case '\\': jpos += sprintf_s(jsonScript + jpos, sizeof(jsonScript) - jpos, "\\\\"); break;
            case '\n': jpos += sprintf_s(jsonScript + jpos, sizeof(jsonScript) - jpos, "\\n"); break;
            case '\r': jpos += sprintf_s(jsonScript + jpos, sizeof(jsonScript) - jpos, "\\r"); break;
            case '\t': jpos += sprintf_s(jsonScript + jpos, sizeof(jsonScript) - jpos, "\\t"); break;
            default:
                if (script[i] >= 0x20 && script[i] < 0x7F)
                    jsonScript[jpos++] = script[i];
        }
    }
    jsonScript[jpos] = '\0';

    OK("{\"address\":\"0x%llX\",\"hook_size\":%d,\"min_hook_len\":%d,"
       "\"label_prefix\":\"%s\",\"assembly_script\":\"%s\"}",
       (unsigned long long)addr, hookSize, minHookLen,
       labelPrefix, jsonScript);
}

/* ========== Memory scan (value scanning with filter chain) ========== */

/* Scan type constants */
#define SCAN_TYPE_BYTE   0
#define SCAN_TYPE_WORD   1
#define SCAN_TYPE_DWORD  2
#define SCAN_TYPE_QWORD  3
#define SCAN_TYPE_FLOAT  4
#define SCAN_TYPE_DOUBLE 5
#define SCAN_TYPE_STRING 6

/* Filter types */
#define SCAN_FILTER_EXACT     0
#define SCAN_FILTER_CHANGED   1
#define SCAN_FILTER_UNCHANGED 2

/* Cached previous scan results for filter chaining */
#define MAX_CACHED_ADDRS 5000
static UINT_PTR cachedScanAddrs[MAX_CACHED_ADDRS];
static int    cachedScanCount = 0;
static BYTE   cachedScanValues[MAX_CACHED_ADDRS * 8]; /* max 8 bytes per addr */
static int    cachedScanValueSize = 0;

static UINT_PTR ReadValueU(const BYTE *buf, int size) {
    UINT_PTR v = 0;
    memcpy(&v, buf, size);
    return v;
}

static float ReadFloat(const BYTE *buf) {
    float f;
    memcpy(&f, buf, sizeof(f));
    return f;
}

static double ReadDouble(const BYTE *buf) {
    double d;
    memcpy(&d, buf, sizeof(d));
    return d;
}

/**
 * MEMORY_SCAN:type,value,start_addr,end_addr,max_results
 *
 * Scans the target process memory for a specific value.
 * Returns matching addresses. Results are cached for follow-up
 * changed/unchanged filtering via MEMORY_SCAN_NEXT.
 */
static void cmd_MEMORY_SCAN(Command *cmd) {
    char *typeStr  = GetParam(cmd->params, 0);
    char *valueStr = GetParam(cmd->params, 1);
    char *startStr = GetParam(cmd->params, 2);
    char *endStr   = GetParam(cmd->params, 3);
    char *maxStr   = GetParam(cmd->params, 4);

    if (!typeStr || !valueStr) {
        ERR("missing type or value parameter");
        return;
    }

    int scanType = atoi(typeStr);
    int maxResults = maxStr ? atoi(maxStr) : 500;
    if (maxResults > MAX_CACHED_ADDRS) maxResults = MAX_CACHED_ADDRS;
    if (maxResults < 1) maxResults = 1;

    /* Determine value size and parse the value */
    int valueSize = 0;
    BYTE targetValue[256]; /* large enough for strings */
    UINT_PTR targetU = 0;
    float targetF = 0.0f;
    double targetD = 0.0;

    switch (scanType) {
        case SCAN_TYPE_BYTE:
            valueSize = 1;
            targetU = (UINT_PTR)strtoul(valueStr, NULL, 0);
            memcpy(targetValue, &targetU, valueSize);
            break;
        case SCAN_TYPE_WORD:
            valueSize = 2;
            targetU = (UINT_PTR)strtoul(valueStr, NULL, 0);
            memcpy(targetValue, &targetU, valueSize);
            break;
        case SCAN_TYPE_DWORD:
            valueSize = 4;
            targetU = (UINT_PTR)strtoul(valueStr, NULL, 0);
            memcpy(targetValue, &targetU, valueSize);
            break;
        case SCAN_TYPE_QWORD:
            valueSize = 8;
            targetU = (UINT_PTR)strtoull(valueStr, NULL, 0);
            memcpy(targetValue, &targetU, valueSize);
            break;
        case SCAN_TYPE_FLOAT:
            valueSize = 4;
            targetF = (float)atof(valueStr);
            memcpy(targetValue, &targetF, valueSize);
            break;
        case SCAN_TYPE_DOUBLE:
            valueSize = 8;
            targetD = atof(valueStr);
            memcpy(targetValue, &targetD, valueSize);
            break;
        case SCAN_TYPE_STRING:
            valueSize = (int)strlen(valueStr);
            if (valueSize > 255) valueSize = 255;
            memcpy(targetValue, valueStr, valueSize);
            targetValue[valueSize] = '\0';
            break;
        default:
            ERR("unknown scan type: %d", scanType);
            return;
    }

    if (valueSize <= 0) {
        ERR("invalid value size");
        return;
    }

    /* Determine scan range */
    UINT_PTR startAddr = 0, endAddr = 0;
    DWORD pid = 0;
    if (Exported.OpenedProcessID)
        pid = *Exported.OpenedProcessID;

    if (startStr && startStr[0]) {
        startAddr = ParseAddr(startStr);
    } else {
        /* Default: scan from first module base */
        if (Exported.Module32First && Exported.CreateToolhelp32Snapshot) {
            HANDLE snap = (HANDLE)(*(CreateToolhelp32Snapshot_t *)Exported.CreateToolhelp32Snapshot)(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if (snap != INVALID_HANDLE_VALUE) {
                MODULEENTRY32 me;
                me.dwSize = sizeof(MODULEENTRY32);
                /* CE 7.5 plugin.pas:1941 — @@Module32First.
     * SDK .h:359 — PVOID. */
    typedef BOOL (WINAPI *Module32First_t)(HANDLE, LPMODULEENTRY32);
    if ((*(Module32First_t *)Exported.Module32First)(snap, &me)) {
                    startAddr = (UINT_PTR)me.modBaseAddr;
                    endAddr = startAddr + me.modBaseSize;
                }
                CloseHandle(snap);
            }
        }
    }

    if (endStr && endStr[0]) {
        endAddr = ParseAddr(endStr);
    }

    if (startAddr == 0 || endAddr <= startAddr) {
        ERR("invalid scan range: 0x%llX - 0x%llX",
            (unsigned long long)startAddr, (unsigned long long)endAddr);
        return;
    }

    /* Limit scan range to avoid timeouts */
    UINT_PTR rangeSize = endAddr - startAddr;
    if (rangeSize > 512 * 1024 * 1024) { /* 512 MB max */
        ERR("scan range too large (%llu bytes, max 512MB)", (unsigned long long)rangeSize);
        return;
    }

    /* Aligned chunked scan */
    BYTE chunk[65536];
    UINT_PTR found[MAX_CACHED_ADDRS];
    int foundCount = 0;

    for (UINT_PTR cur = startAddr; cur < endAddr && foundCount < maxResults;) {
        SIZE_T chunkSize = min(sizeof(chunk), endAddr - cur);
        SIZE_T bytesRead = 0;

        if (!Exported.ReadProcessMemory ||
            !(*Exported.ReadProcessMemory)(
                *Exported.OpenedProcessHandle,
                (LPCVOID)cur, chunk, chunkSize, &bytesRead)) {
            /* Skip unreadable pages (advance by 4KB page) */
            cur += 4096;
            continue;
        }

        SIZE_T limit = bytesRead;
        if (valueSize > 0) {
            if ((SIZE_T)valueSize > limit) { cur += bytesRead; continue; }
            limit = bytesRead - (valueSize - 1);
        }

        for (SIZE_T i = 0; i < limit && foundCount < maxResults; i++) {
            BOOL match = FALSE;

            switch (scanType) {
                case SCAN_TYPE_BYTE:
                case SCAN_TYPE_WORD:
                case SCAN_TYPE_DWORD:
                case SCAN_TYPE_QWORD:
                    match = (memcmp(chunk + i, targetValue, valueSize) == 0);
                    break;
                case SCAN_TYPE_FLOAT:
                case SCAN_TYPE_DOUBLE:
                    match = (memcmp(chunk + i, targetValue, valueSize) == 0);
                    break;
                case SCAN_TYPE_STRING:
                    match = (memcmp(chunk + i, targetValue, valueSize) == 0);
                    break;
            }

            if (match) {
                found[foundCount] = cur + i;
                /* Cache value for later changed/unchanged filtering */
                if (foundCount < MAX_CACHED_ADDRS) {
                    cachedScanAddrs[foundCount] = cur + i;
                    if (valueSize <= 8)
                        memcpy(&cachedScanValues[foundCount * 8], chunk + i, valueSize);
                    else
                        memcpy(&cachedScanValues[foundCount * 8], chunk + i, 8);
                }
                foundCount++;
            }
        }

        if (valueSize == 0) break;
        cur += bytesRead - valueSize + 1;
    }

    /* Store cache state */
    cachedScanCount = foundCount;
    cachedScanValueSize = min(valueSize, 8);

    char result[65536];
    int pos = 0;
    pos += sprintf_s(result + pos, sizeof(result) - pos,
        "{\"scan_type\":%d,\"value_size\":%d,\"range_start\":\"0x%llX\","
        "\"range_end\":\"0x%llX\",\"found\":%d,\"max_results\":%d,"
        "\"addresses\":[",
        scanType, valueSize,
        (unsigned long long)startAddr, (unsigned long long)endAddr,
        foundCount, maxResults);
    for (int i = 0; i < foundCount && pos < (int)sizeof(result) - 128; i++) {
        pos += sprintf_s(result + pos, sizeof(result) - pos,
            "%s\"0x%llX\"", i > 0 ? "," : "",
            (unsigned long long)found[i]);
    }
    pos += sprintf_s(result + pos, sizeof(result) - pos, "]}");
    OK("%s", result);
}

/**
 * MEMORY_SCAN_NEXT:filter_type,max_results
 *
 * Filters the cached previous scan results:
 *   filter_type=1: only addresses whose value changed
 *   filter_type=2: only addresses whose value stayed the same
 *
 * Returns the filtered address list and updates the cache for further chaining.
 */
static void cmd_MEMORY_SCAN_NEXT(Command *cmd) {
    char *filterStr = GetParam(cmd->params, 0);
    char *maxStr    = GetParam(cmd->params, 1);

    if (!filterStr) { ERR("missing filter type"); return; }

    int filterType = atoi(filterStr);
    int maxResults = maxStr ? atoi(maxStr) : 500;
    if (maxResults > MAX_CACHED_ADDRS) maxResults = MAX_CACHED_ADDRS;
    if (maxResults < 1) maxResults = 1;

    if (cachedScanCount == 0) {
        ERR("no cached scan results - run MEMORY_SCAN first");
        return;
    }

    int valueSize = cachedScanValueSize;
    BYTE curValue[8];
    UINT_PTR filtered[MAX_CACHED_ADDRS];
    int filteredCount = 0;

    for (int i = 0; i < cachedScanCount && filteredCount < maxResults; i++) {
        SIZE_T bytesRead = 0;
        BOOL readOk = FALSE;

        if (Exported.ReadProcessMemory) {
            readOk = (*Exported.ReadProcessMemory)(
                *Exported.OpenedProcessHandle,
                (LPCVOID)cachedScanAddrs[i],
                curValue, valueSize, &bytesRead);
        }

        if (!readOk || bytesRead < (SIZE_T)valueSize) continue;

        BOOL changed = (memcmp(curValue, &cachedScanValues[i * 8], valueSize) != 0);

        if ((filterType == SCAN_FILTER_CHANGED && changed) ||
            (filterType == SCAN_FILTER_UNCHANGED && !changed)) {
            filtered[filteredCount] = cachedScanAddrs[i];
            if (valueSize <= 8)
                memcpy(&cachedScanValues[filteredCount * 8], curValue, valueSize);
            filteredCount++;
        }
    }

    /* Update cache with filtered results */
    cachedScanCount = filteredCount;

    char result[65536];
    int pos = 0;
    pos += sprintf_s(result + pos, sizeof(result) - pos,
        "{\"filter\":\"%s\",\"remaining\":%d,\"addresses\":[",
        filterType == SCAN_FILTER_CHANGED ? "changed" : "unchanged",
        filteredCount);
    for (int i = 0; i < filteredCount && pos < (int)sizeof(result) - 128; i++) {
        pos += sprintf_s(result + pos, sizeof(result) - pos,
            "%s\"0x%llX\"", i > 0 ? "," : "",
            (unsigned long long)filtered[i]);
    }
    pos += sprintf_s(result + pos, sizeof(result) - pos, "]}");
    OK("%s", result);
}

/* ========== New CE 7.5 SDK capability commands ========== */

/**
 * GET_SYMBOL_INFO:address_or_name
 *
 * If param looks like an address (starts with "0x"), resolve to name.
 * Otherwise treat as symbol name and resolve to address.
 * Uses CE's built-in symbol handler (supports modules, exports, PDB symbols).
 */
static void cmd_GET_SYMBOL_INFO(Command *cmd) {
    char *input = GetParam(cmd->params, 0);
    if (!input || !input[0]) {
        ERR("missing address or symbol name");
        return;
    }

    if (input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
        /* Address -> Name */
        UINT_PTR addr = ParseAddr(input);
        char name[256] = {0};

        if (!Exported.sym_addressToName) {
            ERR("sym_addressToName not available");
            return;
        }

        BOOL ok = Exported.sym_addressToName(addr, name, (int)sizeof(name) - 1);
        OK("{\"input\":\"%s\",\"address\":\"0x%llX\",\"name\":\"%s\",\"found\":%s}",
           input, (unsigned long long)addr, name, ok ? "true" : "false");
    } else {
        /* Name -> Address */
        UINT_PTR addr = 0;

        if (!Exported.sym_nameToAddress) {
            ERR("sym_nameToAddress not available");
            return;
        }

        BOOL ok = Exported.sym_nameToAddress(input, &addr);
        OK("{\"input\":\"%s\",\"address\":\"0x%llX\",\"name\":\"%s\",\"found\":%s}",
           input, (unsigned long long)addr, ok ? input : "", ok ? "true" : "false");
    }
}

/**
 * ENUM_MEMORY_REGIONS:start_addr(optional),max_regions(optional)
 *
 * Enumerates all committed memory regions in the target process using
 * VirtualQueryEx. Returns base address, size, state, protection, and type
 * for each region.
 */
static void cmd_ENUM_MEMORY_REGIONS(Command *cmd) {
    char *startStr   = GetParam(cmd->params, 0);
    char *maxStr     = GetParam(cmd->params, 1);
    UINT_PTR start   = startStr && startStr[0] ? ParseAddr(startStr) : 0;
    int maxRegions   = maxStr ? atoi(maxStr) : 500;
    if (maxRegions > 2000) maxRegions = 2000;
    if (maxRegions < 1) maxRegions = 1;

    /* VirtualQueryEx is a ppointer */
    if (!Exported.VirtualQueryEx) {
        ERR("VirtualQueryEx not available");
        return;
    }

    typedef NTSTATUS (WINAPI *VirtualQueryEx_t)(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
    VirtualQueryEx_t pVQE = (VirtualQueryEx_t)*Exported.VirtualQueryEx;
    if (!pVQE) { ERR("VirtualQueryEx function pointer is NULL"); return; }

    char result[65536];
    int pos = 0;
    pos += sprintf_s(result + pos, sizeof(result) - pos, "{\"regions\":[");

    UINT_PTR cur = start;
    int count = 0;
    int first = 1;

    while (count < maxRegions) {
        MEMORY_BASIC_INFORMATION mbi;
        ZeroMemory(&mbi, sizeof(mbi));
        SIZE_T ret = pVQE(*Exported.OpenedProcessHandle, (LPCVOID)cur, &mbi, sizeof(mbi));
        if (ret == 0) break;

        /* Only report committed regions (skip free/reserved by default) */
        if (mbi.State == MEM_COMMIT) {
            if (!first) pos += sprintf_s(result + pos, sizeof(result) - pos, ",");
            first = 0;

            /* Protection string */
            const char *protStr = "?";
            switch (mbi.Protect & 0xFF) {
                case PAGE_NOACCESS:          protStr = "NOACCESS"; break;
                case PAGE_READONLY:          protStr = "R"; break;
                case PAGE_READWRITE:         protStr = "RW"; break;
                case PAGE_WRITECOPY:         protStr = "WC"; break;
                case PAGE_EXECUTE:           protStr = "X"; break;
                case PAGE_EXECUTE_READ:      protStr = "RX"; break;
                case PAGE_EXECUTE_READWRITE: protStr = "RWX"; break;
                case PAGE_EXECUTE_WRITECOPY: protStr = "WCX"; break;
                default: protStr = "?"; break;
            }

            /* Type string */
            const char *typeStr = "?";
            switch (mbi.Type) {
                case MEM_IMAGE:   typeStr = "IMAGE"; break;
                case MEM_MAPPED:  typeStr = "MAPPED"; break;
                case MEM_PRIVATE: typeStr = "PRIVATE"; break;
            }

            pos += sprintf_s(result + pos, sizeof(result) - pos,
                "{\"base\":\"0x%llX\",\"size\":%llu,\"protect\":\"%s\",\"type\":\"%s\"}",
                (unsigned long long)mbi.BaseAddress,
                (unsigned long long)mbi.RegionSize,
                protStr, typeStr);
            count++;
        }

        cur = (UINT_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (cur == 0) break; /* wrap-around guard (won't happen on 64-bit) */
    }

    pos += sprintf_s(result + pos, sizeof(result) - pos,
        "],\"count\":%d}", count);
    OK("%s", result);
}

/**
 * PREV_OPCODE:address
 * Returns the address of the previous opcode (based on CE's heuristic).
 */
static void cmd_PREV_OPCODE(Command *cmd) {
    char *addrStr = GetParam(cmd->params, 0);
    if (!addrStr) { ERR("missing address"); return; }
    UINT_PTR addr = ParseAddr(addrStr);

    if (!Exported.previousOpcode) {
        ERR("previousOpcode not available");
        return;
    }

    /* CE 7.5 pluginexports.pas:833 — ce_previousOpcode returns ptrUint (not DWORD).
     * SDK .h:185 declares DWORD, but the Pascal implementation returns 64-bit. */
    UINT_PTR prev = (UINT_PTR)Exported.previousOpcode(addr);
    OK("{\"address\":\"0x%llX\",\"previous\":\"0x%llX\"}",
       (unsigned long long)addr, (unsigned long long)prev);
}

/**
 * NEXT_OPCODE:address
 * Returns the address of the next opcode.
 */
static void cmd_NEXT_OPCODE(Command *cmd) {
    char *addrStr = GetParam(cmd->params, 0);
    if (!addrStr) { ERR("missing address"); return; }
    UINT_PTR addr = ParseAddr(addrStr);

    if (!Exported.nextOpcode) {
        ERR("nextOpcode not available");
        return;
    }

    /* CE 7.5 pluginexports.pas:838 ce_nextOpcode returns ptrUint (64-bit).
     * SDK .h:186 says DWORD but Pascal impl returns 64-bit to RAX. */
    UINT_PTR next = (UINT_PTR)Exported.nextOpcode(addr);
    OK("{\"address\":\"0x%llX\",\"next\":\"0x%llX\"}",
       (unsigned long long)addr, (unsigned long long)next);
}

/**
 * ASSEMBLE:instruction,address(optional)
 *
 * Assembles a single instruction into machine code bytes.
 * Returns the raw bytes and length on success.
 */
static void cmd_ASSEMBLE(Command *cmd) {
    char *instruction = GetParam(cmd->params, 0);
    char *addrStr     = GetParam(cmd->params, 1);

    if (!instruction || !instruction[0]) {
        ERR("missing assembly instruction");
        return;
    }

    UINT_PTR addr = addrStr && addrStr[0] ? ParseAddr(addrStr) : 0x0;

    if (!Exported.Assembler) {
        ERR("Assembler not available");
        return;
    }

    BYTE output[32];
    int actualSize = 0;
    BOOL ok = Exported.Assembler(addr, instruction, output,
                                  (int)sizeof(output), &actualSize);

    if (!ok || actualSize <= 0) {
        ERR("assemble failed: %s", instruction);
        return;
    }

    char hex[128];
    int hpos = 0;
    for (int i = 0; i < actualSize && hpos < (int)sizeof(hex) - 4; i++)
        hpos += sprintf_s(hex + hpos, sizeof(hex) - hpos, "%02X ", output[i]);

    OK("{\"instruction\":\"%s\",\"address\":\"0x%llX\",\"bytes\":\"%s\",\"size\":%d}",
       instruction, (unsigned long long)addr, hex, actualSize);
}

/**
 * GENERATE_API_HOOK:address,jump_to(optional)
 *
 * Calls CE's built-in generateAPIHookScript. Returns the complete
 * AutoAssemble hook script. More reliable than manual GENERATE_HOOK
 * for API-level hooks.
 */
static void cmd_GENERATE_API_HOOK(Command *cmd) {
    char *addrStr   = GetParam(cmd->params, 0);
    char *jumpToStr = GetParam(cmd->params, 1);

    if (!addrStr) { ERR("missing address"); return; }

    if (!Exported.sym_generateAPIHookScript) {
        ERR("sym_generateAPIHookScript not available");
        return;
    }

    char script[4096];
    ZeroMemory(script, sizeof(script));
    BOOL ok = Exported.sym_generateAPIHookScript(
        addrStr,                                    /* address (can be string/symbol) */
        jumpToStr && jumpToStr[0] ? jumpToStr : "", /* jump target */
        "",                                         /* new call address (unused) */
        script,
        (int)sizeof(script) - 1);

    if (!ok) {
        ERR("generateAPIHookScript failed for %s", addrStr);
        return;
    }

    /* JSON-escape the script */
    char jsonScript[8192];
    int jpos = 0;
    for (int i = 0; script[i] && jpos < (int)sizeof(jsonScript) - 4; i++) {
        switch (script[i]) {
            case '"':  jpos += sprintf_s(jsonScript + jpos, sizeof(jsonScript) - jpos, "\\\""); break;
            case '\\': jpos += sprintf_s(jsonScript + jpos, sizeof(jsonScript) - jpos, "\\\\"); break;
            case '\n': jpos += sprintf_s(jsonScript + jpos, sizeof(jsonScript) - jpos, "\\n"); break;
            case '\r': jpos += sprintf_s(jsonScript + jpos, sizeof(jsonScript) - jpos, "\\r"); break;
            case '\t': jpos += sprintf_s(jsonScript + jpos, sizeof(jsonScript) - jpos, "\\t"); break;
            default:
                if (script[i] >= 0x20 && script[i] < 0x7F)
                    jsonScript[jpos++] = script[i];
        }
    }
    jsonScript[jpos] = '\0';

    OK("{\"address\":\"%s\",\"script\":\"%s\"}", addrStr, jsonScript);
}

/**
 * RESOLVE_POINTER:base,offset1,offset2,...
 *
 * Follows a pointer chain: [[[base + offset1] + offset2] + ...]
 * Returns the final resolved address.
 */
static void cmd_RESOLVE_POINTER(Command *cmd) {
    char *baseStr = GetParam(cmd->params, 0);
    if (!baseStr) { ERR("missing base address"); return; }

    UINT_PTR base = ParseAddr(baseStr);

    /* Collect offsets from params[1..N] */
    int offsets[32];
    int offsetCount = 0;
    for (int i = 1; i < 32; i++) {
        char *offStr = GetParam(cmd->params, i);
        if (!offStr || !offStr[0]) break;
        offsets[offsetCount++] = atoi(offStr);
    }

    if (offsetCount == 0) {
        /* No offsets: just return the base address as-is */
        OK("{\"base\":\"0x%llX\",\"offsets\":[],\"resolved\":\"0x%llX\",\"valid\":true}",
           (unsigned long long)base, (unsigned long long)base);
        return;
    }

    if (!Exported.GetAddressFromPointer) {
        ERR("GetAddressFromPointer not available");
        return;
    }

    UINT_PTR resolved = Exported.GetAddressFromPointer(base, offsetCount, offsets);

    /* Verify by trying to read the final address */
    BOOL valid = FALSE;
    if (Exported.ReadProcessMemory && resolved != 0) {
        BYTE dummy;
        SIZE_T rd;
        valid = (*Exported.ReadProcessMemory)(*Exported.OpenedProcessHandle,
                                               (LPCVOID)resolved, &dummy, 1, &rd);
    }

    char offStr[512] = {0};
    for (int i = 0; i < offsetCount; i++) {
        char tmp[16];
        sprintf_s(tmp, sizeof(tmp), "%s%d", i > 0 ? "," : "", offsets[i]);
        strcat_s(offStr, sizeof(offStr), tmp);
    }

    OK("{\"base\":\"0x%llX\",\"offsets\":[%s],\"resolved\":\"0x%llX\",\"valid\":%s}",
       (unsigned long long)base, offStr,
       (unsigned long long)resolved, valid ? "true" : "false");
}

/**
 * GET_PROCESS_LIST
 *
 * Lists running processes on the system (PID + name).
 */
static void cmd_GET_PROCESS_LIST(Command *cmd) {
    (void)cmd;

    if (!Exported.ProcessList) {
        ERR("ProcessList not available");
        return;
    }

    char buf[32768];
    ZeroMemory(buf, sizeof(buf));
    BOOL ok = Exported.ProcessList(buf, (int)sizeof(buf) - 1);

    if (!ok) {
        ERR("ProcessList failed");
        return;
    }

    /* CE returns format: "00402A1C-notepad.exe\r\n00402B30-chrome.exe\r\n..."
     * We parse and emit as JSON array. */
    char result[65536];
    int pos = 0;
    pos += sprintf_s(result + pos, sizeof(result) - pos, "{\"processes\":[");

    char *lineCtx = NULL;
    char *line = strtok_s(buf, "\r\n", &lineCtx);
    int first = 1;
    while (line && pos < (int)sizeof(result) - 256) {
        /* Parse "XXXXXXXX-name" */
        char *dash = strchr(line, '-');
        if (dash) {
            *dash = '\0';
            DWORD pid = (DWORD)strtoul(line, NULL, 16);
            char *name = dash + 1;

            if (!first) pos += sprintf_s(result + pos, sizeof(result) - pos, ",");
            first = 0;

            pos += sprintf_s(result + pos, sizeof(result) - pos,
                "{\"pid\":%lu,\"name\":\"%s\"}", pid, name);
        }
        line = strtok_s(NULL, "\r\n", &lineCtx);
    }

    pos += sprintf_s(result + pos, sizeof(result) - pos, "]}");
    OK("%s", result);
}

/**
 * GET_RTTI_CLASS:address
 *
 * Returns the C++ RTTI class name for the object at the given address.
 * Implements CE's rttihelper.pas logic natively:
 *   1. Try MSVC VS2017+ method: vtable[-1] -> RTTI locator -> TypeDescriptor
 *   2. Fallback to Pascal method: vtable + ptrSize*3 -> ShortString
 * Works for both x86 and x64, with relative/absolute TypeDescriptor addressing.
 */
static void cmd_GET_RTTI_CLASS(Command *cmd) {
    char *addrStr = GetParam(cmd->params, 0);
    if (!addrStr) { ERR("missing address"); return; }
    UINT_PTR objAddr = ParseAddr(addrStr);

    UINT_PTR ptrSize = 0;
#ifdef _WIN64
    ptrSize = 8;
#else
    ptrSize = 4;
#endif

    /* Read vtable pointer */
    UINT_PTR vtable = 0;
    SIZE_T bytesRead = 0;
    if (!Exported.ReadProcessMemory ||
        !(*Exported.ReadProcessMemory)(*Exported.OpenedProcessHandle,
            (LPCVOID)objAddr, &vtable, (SIZE_T)ptrSize, &bytesRead) ||
        bytesRead < (SIZE_T)ptrSize) {
        ERR("failed to read vtable at 0x%llX", (unsigned long long)objAddr);
        return;
    }

    if (vtable == 0) {
        OK("{\"address\":\"0x%llX\",\"class_name\":\"\",\"found\":false,"
           "\"method\":\"none\",\"message\":\"vtable is NULL\"}",
           (unsigned long long)objAddr);
        return;
    }

    /* ===== Method 1: MSVC VS2017+ RTTI (vtable[-1] -> RTTICompleteObjectLocator) ===== */
    UINT_PTR rttiLocator = 0;
    UINT_PTR locatorAddr = vtable - ptrSize;
    if ((*Exported.ReadProcessMemory)(*Exported.OpenedProcessHandle,
            (LPCVOID)locatorAddr, &rttiLocator, (SIZE_T)ptrSize, &bytesRead) &&
        bytesRead >= (SIZE_T)ptrSize && rttiLocator != 0) {

        /* Verify rttiLocator is inside a module (sanity check) */
        BOOL inModule = FALSE;
        {
            DWORD pid = *Exported.OpenedProcessID;
            if (Exported.Module32First && Exported.CreateToolhelp32Snapshot) {
                HANDLE snap = (HANDLE)(*(CreateToolhelp32Snapshot_t *)Exported.CreateToolhelp32Snapshot)(
                    TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
                if (snap != INVALID_HANDLE_VALUE) {
                    MODULEENTRY32 me;
                    me.dwSize = sizeof(MODULEENTRY32);
                    /* CE 7.5 plugin.pas:1941 — @@Module32First.
     * SDK .h:359 — PVOID. */
    typedef BOOL (WINAPI *Module32First_t)(HANDLE, LPMODULEENTRY32);
    if ((*(Module32First_t *)Exported.Module32First)(snap, &me)) {
                        do {
                            UINT_PTR modBase = (UINT_PTR)me.modBaseAddr;
                            UINT_PTR modEnd = modBase + me.modBaseSize;
                            if (rttiLocator >= modBase && rttiLocator < modEnd) {
                                inModule = TRUE;
                                break;
                            }
                        } while ((*(Module32Next_t *)Exported.Module32Next)(snap, &me));
                    }
                    CloseHandle(snap);
                }
            }
        }

        if (inModule) {
            /* Read RTTICompleteObjectLocator (same layout for x86/x64):
             *   +0x00: DWORD signature (1 for relative type, other = absolute)
             *   +0x04: DWORD offset1
             *   +0x08: DWORD offset2
             *   +0x0C: DWORD typeDescriptorOffset
             * +0x10 (x64 only): padding
             */
            DWORD signature = 0, dwTypeInfo = 0;
            if ((*Exported.ReadProcessMemory)(*Exported.OpenedProcessHandle,
                    (LPCVOID)rttiLocator, &signature, sizeof(signature), &bytesRead) &&
                bytesRead >= sizeof(signature)) {

                /* dwTypeInfo is at +0x0C in both x86 and x64 packed layout */
                if ((*Exported.ReadProcessMemory)(*Exported.OpenedProcessHandle,
                        (LPCVOID)(rttiLocator + 0x0C), &dwTypeInfo,
                        sizeof(dwTypeInfo), &bytesRead) &&
                    bytesRead >= sizeof(dwTypeInfo)) {

                    UINT_PTR typeInfoAddr = 0;
                    /* rttihelper.pas:131 — if somethingtype==1 -> relative,
                     * else absolute. No bitness gate. */
                    if (signature == 1) {
                        /* Relative to module base. Find enclosing module. */
                        DWORD pid2 = *Exported.OpenedProcessID;
                        if (Exported.Module32First && Exported.CreateToolhelp32Snapshot) {
                            HANDLE snap2 = (HANDLE)(*Exported.CreateToolhelp32Snapshot)(
                                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid2);
                            if (snap2 != INVALID_HANDLE_VALUE) {
                                MODULEENTRY32 me2;
                                me2.dwSize = sizeof(MODULEENTRY32);
                                if ((*Exported.Module32First)(snap2, &me2)) {
                                    do {
                                        UINT_PTR mb = (UINT_PTR)me2.modBaseAddr;
                                        if (rttiLocator >= mb &&
                                            rttiLocator < mb + me2.modBaseSize) {
                                            typeInfoAddr = mb + dwTypeInfo;
                                            break;
                                        }
                                    } while ((*Exported.Module32Next)(snap2, &me2));
                                }
                                CloseHandle(snap2);
                            }
                        }
                    } else {
                        /* 32-bit or absolute: dwTypeInfo is the exact address */
                        typeInfoAddr = (UINT_PTR)dwTypeInfo;
                    }

                    if (typeInfoAddr != 0) {
                        /* Read TypeDescriptor:
                         *   +0x00: PVOID (ptrSize) -> vtable/pointer-to-something
                         *   +ptrSize: PVOID -> undecorated name
                         *   +2*ptrSize: char[] decorated name (starts with ".?AV") */
                        UINT_PTR decoratedOffset = typeInfoAddr + 2 * ptrSize;
                        char decorated[256] = {0};
                        if ((*Exported.ReadProcessMemory)(*Exported.OpenedProcessHandle,
                                (LPCVOID)decoratedOffset, decorated,
                                sizeof(decorated) - 1, &bytesRead) &&
                            bytesRead > 4) {
                            decorated[sizeof(decorated) - 1] = '\0';

                            /* Check for .?AV prefix (MSVC class marker) */
                            if (decorated[0] == '.' && decorated[1] == '?' &&
                                decorated[2] == 'A' && decorated[3] == 'V') {

                                /* rttihelper.pas:168-176 — UnDecorateSymbolName(..., UNDNAME_NAME_ONLY).
                             * Add "?" prefix (Pascal: s:='?'+cp) to form full decorated name,
                             * then UnDecorateSymbolNameA extracts the undecorated name. */
                                char *className = decorated + 4;
                            {
                                char decoratedForDemangle[256];
                                decoratedForDemangle[0] = '?';
                                strncpy_s(decoratedForDemangle + 1,
                                          sizeof(decoratedForDemangle) - 1,
                                          decorated + 4, _TRUNCATE);
                                decoratedForDemangle[sizeof(decoratedForDemangle) - 1] = '\0';

                                char undecorated[256] = {0};
                                DWORD nameLen = UnDecorateSymbolNameA(
                                    decoratedForDemangle,
                                    undecorated,
                                    (DWORD)sizeof(undecorated) - 1,
                                    UNDNAME_NAME_ONLY);

                                /* rttihelper.pas:179 — isvalidstring: every char in [32,126] */
                                char *finalName = (nameLen > 0 && undecorated[0])
                                    ? undecorated
                                    : (decorated + 4);  /* fallback */
                                BOOL valid = TRUE;
                                for (char *c = finalName; *c; c++) {
                                    unsigned char uc = (unsigned char)*c;
                                    if (uc < 32 || uc > 126) { valid = FALSE; break; }
                                }
                                if (!valid && finalName != (decorated + 4)) {
                                    /* rttihelper.pas:179-182 — classname:=cp fallback */
                                    finalName = decorated + 4;
                                    valid = TRUE;
                                    for (char *c = finalName; *c; c++) {
                                        unsigned char uc = (unsigned char)*c;
                                        if (uc < 32 || uc > 126) { valid = FALSE; break; }
                                    }
                                }

                                if (!valid) {
                                    /* rttihelper.pas:185-194 — hex fallback */
                                    char hexFall[64] = "unknown classid ";
                                    int hp = (int)strlen(hexFall);
                                    char *cp = decorated + 4;
                                    for (int i = 0; i < 16 && cp[i] && hp < 55; i++)
                                        hp += sprintf_s(hexFall + hp,
                                                        sizeof(hexFall) - hp,
                                                        "%02X", (unsigned char)cp[i]);
                                    OK("{\"address\":\"0x%llX\",\"vtable\":\"0x%llX\","
                                       "\"class_name\":\"%s\",\"method\":\"msvc\",\"found\":true}",
                                       (unsigned long long)objAddr,
                                       (unsigned long long)vtable, hexFall);
                                    return;
                                }

                                OK("{\"address\":\"0x%llX\",\"vtable\":\"0x%llX\","
                                   "\"class_name\":\"%s\",\"method\":\"msvc\",\"found\":true}",
                                   (unsigned long long)objAddr,
                                   (unsigned long long)vtable, finalName);
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    /* ===== Method 2: Pascal/Delphi style (vtable + ptrSize*3 -> ShortString) ===== */
    {
        UINT_PTR nameAddr = 0;
        UINT_PTR pascalNameOff = vtable + ptrSize * 3;
        if ((*Exported.ReadProcessMemory)(*Exported.OpenedProcessHandle,
                (LPCVOID)pascalNameOff, &nameAddr, (SIZE_T)ptrSize, &bytesRead) &&
            bytesRead >= (SIZE_T)ptrSize && nameAddr != 0) {

            BYTE shortStr[256] = {0};
            if ((*Exported.ReadProcessMemory)(*Exported.OpenedProcessHandle,
                    (LPCVOID)nameAddr, shortStr, sizeof(shortStr), &bytesRead) &&
                bytesRead > 0) {

                /* Pascal ShortString: first byte = length */
                BYTE len = shortStr[0];
                if (len > 0 && len < 255 && (len + 1) <= (int)bytesRead) {
                    BOOL valid = TRUE;
                    for (int i = 1; i <= len; i++) {
                        char c = (char)shortStr[i];
                        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                              (c >= '0' && c <= '9'))) {
                            valid = FALSE;
                            break;
                        }
                    }
                    /* ShortString should have \0 after length bytes */
                    if (valid && shortStr[len + 1] == 0) {
                        char pascalName[256] = {0};
                        memcpy(pascalName, shortStr + 1, len);
                        pascalName[len] = '\0';

                        OK("{\"address\":\"0x%llX\",\"vtable\":\"0x%llX\","
                           "\"class_name\":\"%s\",\"method\":\"pascal\",\"found\":true}",
                           (unsigned long long)objAddr, (unsigned long long)vtable,
                           pascalName);
                        return;
                    }
                }
            }
        }
    }

    /* Both methods failed */
    OK("{\"address\":\"0x%llX\",\"vtable\":\"0x%llX\","
       "\"class_name\":\"\",\"method\":\"none\",\"found\":false,"
       "\"message\":\"no RTTI found (not a virtual object, or unknown compiler)\"}",
       (unsigned long long)objAddr, (unsigned long long)vtable);
}

/**
 * ENUM_STRINGS:start_addr,end_addr,min_length(optional)
 *
 * Scans memory for human-readable ASCII and UTF-16LE strings.
 * Returns offset + content for each found string.
 */
static void cmd_ENUM_STRINGS(Command *cmd) {
    char *startStr  = GetParam(cmd->params, 0);
    char *endStr    = GetParam(cmd->params, 1);
    char *minStr    = GetParam(cmd->params, 2);

    if (!startStr || !endStr) {
        ERR("missing start_addr or end_addr");
        return;
    }

    UINT_PTR start = ParseAddr(startStr);
    UINT_PTR end   = ParseAddr(endStr);
    int minLen     = minStr ? atoi(minStr) : 4;
    if (minLen < 3) minLen = 3;
    if (minLen > 32) minLen = 32;

    if (end <= start) {
        ERR("invalid range");
        return;
    }

    /* Limit scan to 64MB */
    UINT_PTR range = end - start;
    if (range > 64 * 1024 * 1024) {
        ERR("range too large (max 64MB)");
        return;
    }

    char result[65536];
    int pos = 0;
    pos += sprintf_s(result + pos, sizeof(result) - pos,
        "{\"start\":\"0x%llX\",\"end\":\"0x%llX\",\"strings\":[",
        (unsigned long long)start, (unsigned long long)end);

    BYTE chunk[65536];
    int found = 0;
    int maxFound = 500;
    int first = 1;

    for (UINT_PTR cur = start; cur < end && found < maxFound;) {
        SIZE_T chunkSize = min(sizeof(chunk), end - cur);
        SIZE_T bytesRead = 0;

        if (!Exported.ReadProcessMemory ||
            !(*Exported.ReadProcessMemory)(*Exported.OpenedProcessHandle,
                (LPCVOID)cur, chunk, chunkSize, &bytesRead)) {
            cur += 4096;
            continue;
        }
        if (bytesRead == 0) { cur += 4096; continue; }

        for (SIZE_T i = 0; i + (SIZE_T)minLen <= bytesRead && found < maxFound;) {
            /* Try ASCII string */
            int len = 0;
            while (i + len < bytesRead && chunk[i + len] >= 0x20 &&
                   chunk[i + len] < 0x7F) {
                len++;
            }
            if (len >= minLen) {
                char strBuf[128];
                int copyLen = min(len, (int)sizeof(strBuf) - 1);
                memcpy(strBuf, chunk + i, (size_t)copyLen);
                strBuf[copyLen] = '\0';

                /* JSON-escape */
                char escaped[256];
                int ei = 0;
                for (int c = 0; strBuf[c] && ei < (int)sizeof(escaped) - 2; c++) {
                    if (strBuf[c] == '"') {
                        escaped[ei++] = '\\'; escaped[ei++] = '"';
                    } else if (strBuf[c] == '\\') {
                        escaped[ei++] = '\\'; escaped[ei++] = '\\';
                    } else {
                        escaped[ei++] = strBuf[c];
                    }
                }
                escaped[ei] = '\0';

                if (!first) pos += sprintf_s(result + pos, sizeof(result) - pos, ",");
                first = 0;
                pos += sprintf_s(result + pos, sizeof(result) - pos,
                    "{\"offset\":\"0x%llX\",\"type\":\"ASCII\",\"length\":%d,\"value\":\"%s\"}",
                    (unsigned long long)(cur + i), len, escaped);
                found++;
                i += len;
            } else {
                i++;
            }
        }
        cur += bytesRead;
    }

    pos += sprintf_s(result + pos, sizeof(result) - pos,
        "],\"count\":%d}", found);
    OK("%s", result);
}

static void ExecuteCommand(Command *cmd) {
    if (!cmd || !cmd->command[0]) return;

    if (strcmp(cmd->command, "PING") == 0)            cmd_PING(cmd);
    else if (strcmp(cmd->command, "READ_MEMORY") == 0) cmd_READ_MEMORY(cmd);
    else if (strcmp(cmd->command, "DISASSEMBLE") == 0) cmd_DISASSEMBLE(cmd);
    else if (strcmp(cmd->command, "GET_MODULES") == 0) cmd_GET_MODULES(cmd);
    else if (strcmp(cmd->command, "GET_REGISTERS") == 0) cmd_GET_REGISTERS(cmd);
    else if (strcmp(cmd->command, "GET_CALLSTACK") == 0) cmd_GET_CALLSTACK(cmd);
    else if (strcmp(cmd->command, "SET_BP") == 0)      cmd_SET_BP(cmd);
    else if (strcmp(cmd->command, "AOB_SCAN") == 0)    cmd_AOB_SCAN(cmd);
    else if (strcmp(cmd->command, "REGISTER_TRACE") == 0) cmd_REGISTER_TRACE(cmd);
    else if (strcmp(cmd->command, "GENERATE_HOOK") == 0) cmd_GENERATE_HOOK(cmd);
    else if (strcmp(cmd->command, "MEMORY_SCAN") == 0) cmd_MEMORY_SCAN(cmd);
    else if (strcmp(cmd->command, "MEMORY_SCAN_NEXT") == 0) cmd_MEMORY_SCAN_NEXT(cmd);
    else if (strcmp(cmd->command, "GET_SYMBOL_INFO") == 0) cmd_GET_SYMBOL_INFO(cmd);
    else if (strcmp(cmd->command, "ENUM_MEMORY_REGIONS") == 0) cmd_ENUM_MEMORY_REGIONS(cmd);
    else if (strcmp(cmd->command, "PREV_OPCODE") == 0) cmd_PREV_OPCODE(cmd);
    else if (strcmp(cmd->command, "NEXT_OPCODE") == 0) cmd_NEXT_OPCODE(cmd);
    else if (strcmp(cmd->command, "ASSEMBLE") == 0) cmd_ASSEMBLE(cmd);
    else if (strcmp(cmd->command, "GENERATE_API_HOOK") == 0) cmd_GENERATE_API_HOOK(cmd);
    else if (strcmp(cmd->command, "RESOLVE_POINTER") == 0) cmd_RESOLVE_POINTER(cmd);
    else if (strcmp(cmd->command, "GET_PROCESS_LIST") == 0) cmd_GET_PROCESS_LIST(cmd);
    else if (strcmp(cmd->command, "GET_RTTI_CLASS") == 0) cmd_GET_RTTI_CLASS(cmd);
    else if (strcmp(cmd->command, "ENUM_STRINGS") == 0) cmd_ENUM_STRINGS(cmd);
    else ERR("unknown command: %s", cmd->command);
}

/* ========== TCP listener thread ========== */

static DWORD WINAPI PluginThread(LPVOID param) {
    (void)param;

    ConnectToMcp();

    while (pluginRunning) {
        EnterCriticalSection(&socketLock);
        SOCKET sock = mcpSocket;
        LeaveCriticalSection(&socketLock);

        if (sock == INVALID_SOCKET) {
            Sleep(500);
            ConnectToMcp();
            continue;
        }

        char buf[1024];
        int len = recv(sock, buf, sizeof(buf) - 1, 0);
        if (len > 0) {
            buf[len] = '\0';

            /* Handle multiple commands separated by newlines */
            char *line = buf;
            char *next = NULL;
            char *ctx = NULL;
            line = strtok_s(buf, "\n\r", &ctx);
            while (line) {
                Command cmd;
                /* strtok_s consumed the delimiter; reconstruct with ':' */
                char lineBuf[576];
                strncpy_s(lineBuf, sizeof(lineBuf), line, _TRUNCATE);
                if (ParseCommand(lineBuf, &cmd))
                    ExecuteCommand(&cmd);
                line = strtok_s(NULL, "\n\r", &ctx);
            }
        } else {
            /* Connection closed or error */
            DisconnectMcp();
        }
    }

    return 0;
}

/* ========== CE Plugin lifecycle ========== */

BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD reason, LPVOID reserved) {
    (void)hModule; (void)reserved;
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            WinsockInit();
            InitializeCriticalSection(&socketLock);
            InitializeCriticalSection(&bpMonitorLock);
            break;
        case DLL_PROCESS_DETACH:
            DeleteCriticalSection(&bpMonitorLock);
            DeleteCriticalSection(&socketLock);
            WinsockCleanup();
            break;
    }
    return TRUE;
}

BOOL __stdcall CEPlugin_GetVersion(PPluginVersion pv, int sizeofpluginversion) {
    (void)sizeofpluginversion;
    pv->version = CESDK_VERSION;
    pv->pluginname = "CE MCP Plugin v0.3 (CE 7.5 SDK v6)";
    return TRUE;
}

BOOL __stdcall CEPlugin_InitializePlugin(PExportedFunctions ef, int pluginid) {
    selfid = pluginid;

    /* Copy the exported functions table */
    memcpy(&Exported, ef, sizeof(ExportedFunctions));

    /* Verify size matches (safety check) */
    if (Exported.sizeofExportedFunctions != sizeof(ExportedFunctions))
        return FALSE;

    /* Register Type 2 (OnDebugEvent) callback for breakpoint hit capture */
    if (Exported.RegisterFunction) {
        PLUGINTYPE2_INIT bpInit;
        ZeroMemory(&bpInit, sizeof(bpInit));
        bpInit.callbackroutine = OnDebugEvent;
        bpCallbackId = Exported.RegisterFunction(pluginid, ptOnDebugEvent, &bpInit);
    }

    /* Start the TCP bridge thread */
    pluginRunning = TRUE;
    pluginThreadHandle = CreateThread(NULL, 0, PluginThread, NULL, 0, NULL);

    return TRUE;
}

BOOL __stdcall CEPlugin_DisablePlugin(void) {
    /* Stop the TCP thread first (no more commands) */
    pluginRunning = FALSE;

    if (pluginThreadHandle) {
        WaitForSingleObject(pluginThreadHandle, 5000);
        CloseHandle(pluginThreadHandle);
        pluginThreadHandle = NULL;
    }

    DisconnectMcp();

    /* Unregister debug event callback */
    if (Exported.UnregisterFunction && bpCallbackId >= 0) {
        Exported.UnregisterFunction(selfid, bpCallbackId);
        bpCallbackId = -1;
    }

    /* Release any active breakpoint monitors */
    EnterCriticalSection(&bpMonitorLock);
    for (int i = 0; i < MAX_BP_MONITORS; i++) {
        if (bpMonitors[i].active) {
            if (Exported.debug_removeBreakpoint)
                Exported.debug_removeBreakpoint(bpMonitors[i].address);
            ZeroMemory(&bpMonitors[i], sizeof(BreakpointMonitor));
        }
    }
    LeaveCriticalSection(&bpMonitorLock);

    return TRUE;
}
