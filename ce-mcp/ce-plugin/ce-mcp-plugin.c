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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sdk/cepluginsdk.h"

#pragma comment(lib, "ws2_32.lib")

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
        char buf[4096];
        int len = sprintf_s(buf, sizeof(buf), "%s:%s\n", type, data);
        if (len > 0) send(mcpSocket, buf, len, 0);
    }
    LeaveCriticalSection(&socketLock);
}

#define OK(fmt, ...) do { \
    char _b[4096]; \
    sprintf_s(_b, sizeof(_b), fmt, ##__VA_ARGS__); \
    SendResponse("OK", _b); \
} while(0)

#define ERR(fmt, ...) do { \
    char _b[1024]; \
    sprintf_s(_b, sizeof(_b), fmt, ##__VA_ARGS__); \
    SendResponse("ERR", _b); \
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

    HANDLE snap = (HANDLE)(*Exported.CreateToolhelp32Snapshot)(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return NULL;

    DWORD pid = 0;
    if (Exported.OpenedProcessID)
        pid = *Exported.OpenedProcessID;

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    HANDLE result = NULL;
    if ((*Exported.Thread32First)(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                if (Exported.OpenThread) {
                    result = (HANDLE)(*Exported.OpenThread)(
                        THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION |
                        THREAD_SUSPEND_RESUME,
                        FALSE, te.th32ThreadID);
                }
                break;
            }
        } while ((*Exported.Thread32Next)(snap, &te));
    }

    CloseHandle(snap);
    return result;
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
        int instLen = Exported.Disassembler(current, inst, sizeof(inst) - 1);
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

    HANDLE snap = (HANDLE)(*Exported.CreateToolhelp32Snapshot)(
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

    if ((*Exported.Module32First)(snap, &me)) {
        do {
            pos += sprintf_s(result + pos, sizeof(result) - pos,
                             "%s{\"name\":\"%s\",\"base\":\"0x%llX\",\"size\":%lu}",
                             first ? "" : ",",
                             me.szModule,
                             (unsigned long long)me.modBaseAddr,
                             me.modBaseSize);
            first = 0;
        } while ((*Exported.Module32Next)(snap, &me) && pos < (int)sizeof(result) - 300);
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
 * Sets a hardware breakpoint and monitors for `duration` seconds.
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

    /* CE 7.5 SDK: debug_setBreakpoint(address, size, trigger)
     * trigger: 0=execute, 1=write, 2=read/write */
    if (!Exported.debug_setBreakpoint) {
        ERR("debug_setBreakpoint not available");
        return;
    }
    if (!Exported.debug_removeBreakpoint) {
        ERR("debug_removeBreakpoint not available");
        return;
    }

    int bpSize = 4; /* 4-byte hardware BP */

    BOOL bpOk = Exported.debug_setBreakpoint(addr, bpSize, type);
    if (!bpOk) {
        ERR("failed to set breakpoint at 0x%llX (type=%d)",
            (unsigned long long)addr, type);
        return;
    }

    /* Wait for the specified duration */
    Sleep((DWORD)(duration * 1000));

    /* Remove the breakpoint */
    Exported.debug_removeBreakpoint(addr);

    OK("{\"address\":\"0x%llX\",\"type\":%d,\"duration_sec\":%d,"
       "\"status\":\"completed\",\"message\":\"breakpoint monitored for %d seconds\"}",
       (unsigned long long)addr, type, duration, duration);
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

    HANDLE snap = (HANDLE)(*Exported.CreateToolhelp32Snapshot)(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        ERR("failed to create snapshot");
        return;
    }

    MODULEENTRY32 me;
    me.dwSize = sizeof(MODULEENTRY32);

    if (moduleName && moduleName[0]) {
        /* Search for the specified module */
        if ((*Exported.Module32First)(snap, &me)) {
            do {
                if (_stricmp(me.szModule, moduleName) == 0) {
                    base = (UINT_PTR)me.modBaseAddr;
                    size = me.modBaseSize;
                    break;
                }
            } while ((*Exported.Module32Next)(snap, &me));
        }
    } else {
        /* Use first module (main executable) */
        if ((*Exported.Module32First)(snap, &me)) {
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

/* ========== Command dispatcher ========== */

static void ExecuteCommand(Command *cmd) {
    if (!cmd || !cmd->command[0]) return;

    if (strcmp(cmd->command, "PING") == 0)            cmd_PING(cmd);
    else if (strcmp(cmd->command, "READ_MEMORY") == 0) cmd_READ_MEMORY(cmd);
    else if (strcmp(cmd->command, "DISASSEMBLE") == 0) cmd_DISASSEMBLE(cmd);
    else if (strcmp(cmd->command, "GET_MODULES") == 0) cmd_GET_MODULES(cmd);
    else if (strcmp(cmd->command, "GET_REGISTERS") == 0) cmd_GET_REGISTERS(cmd);
    else if (strcmp(cmd->command, "SET_BP") == 0)      cmd_SET_BP(cmd);
    else if (strcmp(cmd->command, "AOB_SCAN") == 0)    cmd_AOB_SCAN(cmd);
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
            break;
        case DLL_PROCESS_DETACH:
            DeleteCriticalSection(&socketLock);
            WinsockCleanup();
            break;
    }
    return TRUE;
}

BOOL __stdcall CEPlugin_GetVersion(PPluginVersion pv, int sizeofpluginversion) {
    (void)sizeofpluginversion;
    pv->version = CESDK_VERSION;
    pv->pluginname = "CE MCP Plugin v0.2 (CE 7.5 SDK v6)";
    return TRUE;
}

BOOL __stdcall CEPlugin_InitializePlugin(PExportedFunctions ef, int pluginid) {
    selfid = pluginid;

    /* Copy the exported functions table */
    memcpy(&Exported, ef, sizeof(ExportedFunctions));

    /* Verify size matches (safety check) */
    if (Exported.sizeofExportedFunctions != sizeof(ExportedFunctions))
        return FALSE;

    pluginRunning = TRUE;
    pluginThreadHandle = CreateThread(NULL, 0, PluginThread, NULL, 0, NULL);

    return TRUE;
}

BOOL __stdcall CEPlugin_DisablePlugin(void) {
    pluginRunning = FALSE;

    if (pluginThreadHandle) {
        WaitForSingleObject(pluginThreadHandle, 5000);
        CloseHandle(pluginThreadHandle);
        pluginThreadHandle = NULL;
    }

    DisconnectMcp();
    return TRUE;
}
