/**
 * plugin-core.c — 核心框架
 *
 * 网络通信、命令解析、CE 插件生命周期、命令分发、公共工具函数。
 */

#include "plugin.h"

/* ========== Global state ========== */
int selfid;
ExportedFunctions Exported;
HANDLE pluginThreadHandle = NULL;
volatile BOOL pluginRunning = FALSE;

SOCKET mcpSocket = INVALID_SOCKET;
CRITICAL_SECTION socketLock;
char mcpHost[16] = "127.0.0.1";
int mcpPort = 8888;

/* ========== Breakpoint monitoring ========== */
BreakpointMonitor bpMonitors[MAX_BP_MONITORS];
CRITICAL_SECTION bpMonitorLock;
int bpCallbackId = -1;

/* ========== Network helpers ========== */

BOOL WinsockInit(void) {
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
}

void WinsockCleanup(void) {
    WSACleanup();
}

BOOL ConnectToMcp(void) {
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

        mode = 0;
        ioctlsocket(mcpSocket, FIONBIO, &mode);
        break;
    }

    freeaddrinfo(result);
    return mcpSocket != INVALID_SOCKET;
}

void DisconnectMcp(void) {
    EnterCriticalSection(&socketLock);
    if (mcpSocket != INVALID_SOCKET) {
        closesocket(mcpSocket);
        mcpSocket = INVALID_SOCKET;
    }
    LeaveCriticalSection(&socketLock);
}

void SendResponse(const char *type, const char *data) {
    EnterCriticalSection(&socketLock);
    if (mcpSocket != INVALID_SOCKET) {
        char header[8];
        int headerLen = sprintf_s(header, sizeof(header), "%s:", type);
        const char *nl = "\n";
        int dataLen = (int)strlen(data);
        int sent = 0;

        while (sent < headerLen) {
            int n = send(mcpSocket, header + sent, headerLen - sent, 0);
            if (n <= 0) goto done;
            sent += n;
        }

        sent = 0;
        while (sent < dataLen) {
            int n = send(mcpSocket, data + sent, dataLen - sent, 0);
            if (n <= 0) goto done;
            sent += n;
        }

        send(mcpSocket, nl, 1, 0);
    }
done:
    LeaveCriticalSection(&socketLock);
}

/* ========== Command parser ========== */

BOOL ParseCommand(char *buffer, Command *cmd) {
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

UINT_PTR ParseAddr(const char *s) {
    return s ? (UINT_PTR)strtoull(s, NULL, 16) : 0;
}

char *GetParam(char *params, int idx) {
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

HANDLE GetDebugThread(void) {
    if (!Exported.CreateToolhelp32Snapshot) return NULL;
    if (!Exported.Thread32First) return NULL;

    HANDLE snap = (HANDLE)CS(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return NULL;

    DWORD pid = 0;
    if (Exported.OpenedProcessID)
        pid = *Exported.OpenedProcessID;

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    HANDLE result = NULL;
    if (T32F(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                if (Exported.OpenThread) {
                    result = OT(
                        THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
                        FALSE, te.th32ThreadID);
                }
                break;
            }
        } while (T32N(snap, &te));
    }

    CloseHandle(snap);
    return result;
}

/* ========== Stack walk helper ========== */

static BOOL symInitialized = FALSE;

int WalkCallstack(HANDLE hThread, const CONTEXT *ctx,
                  CallstackFrame *frames, int maxFrames) {
    HANDLE hProcess = Exported.OpenedProcessHandle
                      ? *Exported.OpenedProcessHandle
                      : GetCurrentProcess();

    if (!symInitialized) {
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
        SymInitialize(hProcess, NULL, TRUE);
        symInitialized = TRUE;
    }

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
                         NULL,
                         SymFunctionTableAccess64,
                         SymGetModuleBase64,
                         NULL))
            break;

        if (sf.AddrPC.Offset == 0) break;

        frames[count].address = (UINT_PTR)sf.AddrPC.Offset;

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

/* CE 7.5 plugin.pas:1963 — @ce_previousOpcode (event callback, not the navigation function) */

int __stdcall OnDebugEvent(LPDEBUG_EVENT DebugEvent) {
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

    int activeCount = 0;
    for (int i = 0; i < MAX_BP_MONITORS; i++)
        if (bpMonitors[i].active) activeCount++;

    for (int i = 0; i < MAX_BP_MONITORS; i++) {
        BreakpointMonitor *bm = &bpMonitors[i];
        if (!bm->active) continue;

        BOOL isHit = FALSE;

        if (bm->triggerType == 0)
            isHit = (bm->address == (UINT_PTR)er->ExceptionAddress);
        else if (activeCount == 1)
            isHit = TRUE;

        if (!isHit) continue;

        if (bm->hitCount < MAX_BP_HITS) {
            int idx = bm->hitCount++;
            bm->hits[idx].timestamp = GetTickCount() - bm->startTick;
            bm->hits[idx].threadId = DebugEvent->dwThreadId;

            ZeroMemory(&bm->hits[idx].context, sizeof(CONTEXT));
            bm->hits[idx].context.ContextFlags = CONTEXT_FULL;

            HANDLE hThread = OT(
                THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                FALSE, DebugEvent->dwThreadId);
            if (hThread) {
                GTC(hThread, &bm->hits[idx].context);

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

BreakpointMonitor *AllocBpMonitor(void) {
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

void FreeBpMonitor(BreakpointMonitor *bm) {
    if (!bm) return;
    EnterCriticalSection(&bpMonitorLock);
    ZeroMemory(bm, sizeof(BreakpointMonitor));
    LeaveCriticalSection(&bpMonitorLock);
}

/* ========== Command dispatcher ========== */

void ExecuteCommand(Command *cmd) {
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

DWORD WINAPI PluginThread(LPVOID param) {
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

            char *ctx = NULL;
            char *line = strtok_s(buf, "\n\r", &ctx);
            while (line) {
                Command cmd;
                char lineBuf[576];
                strncpy_s(lineBuf, sizeof(lineBuf), line, _TRUNCATE);
                if (ParseCommand(lineBuf, &cmd))
                    ExecuteCommand(&cmd);
                line = strtok_s(NULL, "\n\r", &ctx);
            }
        } else {
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
    pv->pluginname = "CE MCP Plugin v0.4 (CE 7.5 SDK v6)";
    return TRUE;
}

BOOL __stdcall CEPlugin_InitializePlugin(PExportedFunctions ef, int pluginid) {
    selfid = pluginid;

    memcpy(&Exported, ef, sizeof(ExportedFunctions));

    if (Exported.sizeofExportedFunctions != sizeof(ExportedFunctions))
        return FALSE;

    /* CE 7.5 plugin.pas:1997-1999 — register Type 2 debug event callback */
    if (Exported.RegisterFunction) {
        PLUGINTYPE2_INIT bpInit;
        ZeroMemory(&bpInit, sizeof(bpInit));
        bpInit.callbackroutine = OnDebugEvent;
        bpCallbackId = Exported.RegisterFunction(pluginid, ptOnDebugEvent, &bpInit);
    }

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

    if (Exported.UnregisterFunction && bpCallbackId >= 0) {
        Exported.UnregisterFunction(selfid, bpCallbackId);
        bpCallbackId = -1;
    }

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
