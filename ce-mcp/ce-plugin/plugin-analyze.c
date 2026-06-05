/**
 * plugin-analyze.c — 分析命令
 *
 * DISASSEMBLE / AOB_SCAN / PREV_OPCODE / NEXT_OPCODE / ASSEMBLE /
 * GET_SYMBOL_INFO / ENUM_MEMORY_REGIONS / GET_RTTI_CLASS / ENUM_STRINGS /
 * PING / READ_MEMORY / GET_MODULES / GET_PROCESS_LIST / RESOLVE_POINTER
 */

#include "plugin.h"

/* ========== 基础分析 ========== */

/**
 * PING - Connection test + process info
 */
void cmd_PING(Command *cmd) {
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
void cmd_READ_MEMORY(Command *cmd) {
    char *addrStr = GetParam(cmd->params, 0);
    char *lenStr  = GetParam(cmd->params, 1);
    if (!addrStr) { ERR("missing address"); return; }

    UINT_PTR addr = ParseAddr(addrStr);
    int len = lenStr ? atoi(lenStr) : 256;
    if (len > 4096) len = 4096;
    if (len < 1) len = 1;

    BYTE buf[4096];
    SIZE_T bytesRead = 0;

    if (!RPM(*Exported.OpenedProcessHandle, (LPCVOID)addr, buf, len, &bytesRead)) {
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

/* ========== 模块/进程枚举 ========== */

/**
 * GET_MODULES
 * Returns list of loaded modules using toolhelp API.
 */
void cmd_GET_MODULES(Command *cmd) {
    (void)cmd;

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

    HANDLE snap = (HANDLE)CS(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
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

    if (M32F(snap, &me)) {
        do {
            pos += sprintf_s(result + pos, sizeof(result) - pos,
                             "%s{\"name\":\"%s\",\"base\":\"0x%llX\",\"size\":%lu}",
                             first ? "" : ",",
                             me.szModule,
                             (unsigned long long)me.modBaseAddr,
                             me.modBaseSize);
            first = 0;
        } while (M32N(snap, &me) && pos < (int)sizeof(result) - 300);
    }

    CloseHandle(snap);
    pos += sprintf_s(result + pos, sizeof(result) - pos, "]}");
    OK("%s", result);
}

/**
 * GET_PROCESS_LIST
 * Lists running processes on the system (PID + name).
 */
void cmd_GET_PROCESS_LIST(Command *cmd) {
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
     * Parse and emit as JSON array. */
    char result[65536];
    int pos = 0;
    pos += sprintf_s(result + pos, sizeof(result) - pos, "{\"processes\":[");

    char *lineCtx = NULL;
    char *line = strtok_s(buf, "\r\n", &lineCtx);
    int first = 1;
    while (line && pos < (int)sizeof(result) - 256) {
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

/* ========== 代码分析 ========== */

/**
 * DISASSEMBLE:address,count
 * Disassembles `count` instructions starting at `address`.
 */
void cmd_DISASSEMBLE(Command *cmd) {
    char *addrStr = GetParam(cmd->params, 0);
    char *cntStr  = GetParam(cmd->params, 1);
    if (!addrStr) { ERR("missing address"); return; }

    UINT_PTR addr = ParseAddr(addrStr);
    int count = cntStr ? atoi(cntStr) : 20;
    if (count > 100) count = 100;
    if (count < 1) count = 1;

    /* Disassembler is a direct function pointer (not ppointer)
     * CE 7.5 pluginexports.pas:793 */
    if (!Exported.Disassembler) { ERR("disassembler not available"); return; }

    char result[32768];
    int pos = 0;
    pos += sprintf_s(result + pos, sizeof(result) - pos,
                     "{\"address\":\"0x%llX\",\"instructions\":[",
                     (unsigned long long)addr);

    UINT_PTR current = addr;
    for (int i = 0; i < count; i++) {
        char inst[256] = {0};
        if (!Exported.Disassembler(current, inst, sizeof(inst) - 1)) {
            /* CE 7.5 SDK 头中 Disassembler 声明为 direct fn ptr（L170），
             * 但 pplugin.pas 中为 Nil（3.2.3.1）时实为 ppointer 方案。
             * 若直接调用失败，走 disassembleEx 作为回退方案。 */
            if (Exported.disassembleEx)
                if (!Exported.disassembleEx((UINT_PTR)&current, inst, sizeof(inst) - 1))
                    break;
                else
                    continue;
            else
                break;
        }

        /* 如果 Disassembler 成功（不修改 current），用 disassembleEx
         * 推进地址以获取下一条指令的起始位置。
         * disassembleEx(address: pptrUint, ...) — pluginexports.pas:811
         * 会解引用 *address 并在反汇编后写回更新值。 */
        UINT_PTR next = current;
        if (Exported.disassembleEx)
            Exported.disassembleEx((UINT_PTR)&next, NULL, 0);
        int instLen = (int)(next - current);
        if (instLen <= 0) break;

        BYTE raw[16] = {0};
        SIZE_T bytesRead = 0;
        RPM(*Exported.OpenedProcessHandle, (LPCVOID)current, raw, instLen, &bytesRead);

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
 * PREV_OPCODE:address
 * Returns the address of the previous opcode.
 * CE 7.5 pluginexports.pas:833 — returns ptrUint.
 */
void cmd_PREV_OPCODE(Command *cmd) {
    char *addrStr = GetParam(cmd->params, 0);
    if (!addrStr) { ERR("missing address"); return; }
    UINT_PTR addr = ParseAddr(addrStr);

    if (!Exported.previousOpcode) {
        ERR("previousOpcode not available");
        return;
    }

    UINT_PTR prev = (UINT_PTR)Exported.previousOpcode(addr);
    OK("{\"address\":\"0x%llX\",\"previous\":\"0x%llX\"}",
       (unsigned long long)addr, (unsigned long long)prev);
}

/**
 * NEXT_OPCODE:address
 * Returns the address of the next opcode.
 * CE 7.5 pluginexports.pas:838 — returns ptrUint.
 */
void cmd_NEXT_OPCODE(Command *cmd) {
    char *addrStr = GetParam(cmd->params, 0);
    if (!addrStr) { ERR("missing address"); return; }
    UINT_PTR addr = ParseAddr(addrStr);

    if (!Exported.nextOpcode) {
        ERR("nextOpcode not available");
        return;
    }

    UINT_PTR next = (UINT_PTR)Exported.nextOpcode(addr);
    OK("{\"address\":\"0x%llX\",\"next\":\"0x%llX\"}",
       (unsigned long long)addr, (unsigned long long)next);
}

/**
 * ASSEMBLE:instruction,address(optional)
 * Assembles a single instruction into machine code bytes.
 */
void cmd_ASSEMBLE(Command *cmd) {
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

/* ========== 特征码扫描 ========== */

/**
 * AOB_SCAN:pattern,module_name(optional)
 * Scans memory for an array-of-bytes pattern using ? or ?? for wildcards.
 */
void cmd_AOB_SCAN(Command *cmd) {
    char *pattern = GetParam(cmd->params, 0);
    char *moduleName = GetParam(cmd->params, 1);

    if (!pattern) { ERR("missing pattern"); return; }

    /* Parse pattern "AA BB ?? DD" into byte + mask arrays */
    BYTE pat[512];
    BYTE mask[512];
    int patLen = 0;

    char *ctx = NULL;
    char patternCopy[2048];
    strncpy_s(patternCopy, sizeof(patternCopy), pattern, _TRUNCATE);

    char *tok = strtok_s(patternCopy, " ", &ctx);
    while (tok && patLen < 512) {
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

    DWORD pid = 0;
    if (Exported.OpenedProcessID)
        pid = *Exported.OpenedProcessID;

    HANDLE snap = (HANDLE)CS(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        ERR("failed to create snapshot");
        return;
    }

    MODULEENTRY32 me;
    me.dwSize = sizeof(MODULEENTRY32);

    if (moduleName && moduleName[0]) {
        if (M32F(snap, &me)) {
            do {
                if (_stricmp(me.szModule, moduleName) == 0) {
                    base = (UINT_PTR)me.modBaseAddr;
                    size = me.modBaseSize;
                    break;
                }
            } while (M32N(snap, &me));
        }
    } else {
        if (M32F(snap, &me)) {
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

        if (!RPM(*Exported.OpenedProcessHandle, (LPCVOID)cur, buf, chunkSize, &bytesRead)) {
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

/* ========== 符号与内存布局 ========== */

/**
 * GET_SYMBOL_INFO:address_or_name
 * If param looks like an address ("0x..."), resolve to name.
 * Otherwise treat as symbol name and resolve to address.
 * Uses CE's built-in symbol handler (modules, exports, PDB).
 */
void cmd_GET_SYMBOL_INFO(Command *cmd) {
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
 * Enumerates all committed memory regions using VirtualQueryEx.
 */
void cmd_ENUM_MEMORY_REGIONS(Command *cmd) {
    char *startStr   = GetParam(cmd->params, 0);
    char *maxStr     = GetParam(cmd->params, 1);
    UINT_PTR start   = startStr && startStr[0] ? ParseAddr(startStr) : 0;
    int maxRegions   = maxStr ? atoi(maxStr) : 500;
    if (maxRegions > 2000) maxRegions = 2000;
    if (maxRegions < 1) maxRegions = 1;

    char result[65536];
    int pos = 0;
    pos += sprintf_s(result + pos, sizeof(result) - pos, "{\"regions\":[");

    UINT_PTR cur = start;
    int count = 0;
    int first = 1;

    while (count < maxRegions) {
        MEMORY_BASIC_INFORMATION mbi;
        ZeroMemory(&mbi, sizeof(mbi));
        LONG ret = VQE(*Exported.OpenedProcessHandle, (LPCVOID)cur, &mbi, sizeof(mbi));
        if (ret == 0) break;

        if (mbi.State == MEM_COMMIT) {
            if (!first) pos += sprintf_s(result + pos, sizeof(result) - pos, ",");
            first = 0;

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
        if (cur == 0) break;
    }

    pos += sprintf_s(result + pos, sizeof(result) - pos,
        "],\"count\":%d}", count);
    OK("%s", result);
}

/**
 * ENUM_STRINGS:start_addr,end_addr,min_length(optional)
 * Scans memory for human-readable ASCII strings.
 */
void cmd_ENUM_STRINGS(Command *cmd) {
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

        if (!RPM(*Exported.OpenedProcessHandle, (LPCVOID)cur, chunk, chunkSize, &bytesRead)) {
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

/* ========== 指针解析 ========== */

/**
 * RESOLVE_POINTER:base,offset1,offset2,...
 * Follows a pointer chain: [[[base + offset1] + offset2] + ...]
 * Uses CE's GetAddressFromPointer.
 */
void cmd_RESOLVE_POINTER(Command *cmd) {
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
    if (resolved != 0) {
        BYTE dummy;
        SIZE_T rd;
        valid = RPM(*Exported.OpenedProcessHandle, (LPCVOID)resolved, &dummy, 1, &rd);
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

/* ========== RTTI 类型解析 ========== */

/**
 * GET_RTTI_CLASS:address
 *
 * Returns the C++ RTTI class name for the object at the given address.
 * Two-phase approach:
 *   1. MSVC VS2017+: vtable[-1] -> RTTICompleteObjectLocator -> TypeDescriptor
 *   2. Fallback: Pascal/Delphi style (vtable + ptrSize*3 -> ShortString)
 */
void cmd_GET_RTTI_CLASS(Command *cmd) {
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
    if (!RPM(*Exported.OpenedProcessHandle, (LPCVOID)objAddr,
             &vtable, (SIZE_T)ptrSize, &bytesRead) ||
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

    /* ===== Method 1: MSVC VS2017+ RTTI ===== */
    UINT_PTR rttiLocator = 0;
    UINT_PTR locatorAddr = vtable - ptrSize;
    if (RPM(*Exported.OpenedProcessHandle, (LPCVOID)locatorAddr,
            &rttiLocator, (SIZE_T)ptrSize, &bytesRead) &&
        bytesRead >= (SIZE_T)ptrSize && rttiLocator != 0) {

        /* Verify rttiLocator is inside a module */
        BOOL inModule = FALSE;
        {
            DWORD pid = *Exported.OpenedProcessID;
            HANDLE snap = (HANDLE)CS(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if (snap != INVALID_HANDLE_VALUE) {
                MODULEENTRY32 me;
                me.dwSize = sizeof(MODULEENTRY32);
                if (M32F(snap, &me)) {
                    do {
                        UINT_PTR modBase = (UINT_PTR)me.modBaseAddr;
                        UINT_PTR modEnd = modBase + me.modBaseSize;
                        if (rttiLocator >= modBase && rttiLocator < modEnd) {
                            inModule = TRUE;
                            break;
                        }
                    } while (M32N(snap, &me));
                }
                CloseHandle(snap);
            }
        }

        if (inModule) {
            DWORD signature = 0, dwTypeInfo = 0;
            if (RPM(*Exported.OpenedProcessHandle, (LPCVOID)rttiLocator,
                    &signature, sizeof(signature), &bytesRead) &&
                bytesRead >= sizeof(signature)) {

                if (RPM(*Exported.OpenedProcessHandle,
                        (LPCVOID)(rttiLocator + 0x0C), &dwTypeInfo,
                        sizeof(dwTypeInfo), &bytesRead) &&
                    bytesRead >= sizeof(dwTypeInfo)) {

                    UINT_PTR typeInfoAddr = 0;
                    if (signature == 1) {
                        /* Relative to module base */
                        DWORD pid2 = *Exported.OpenedProcessID;
                        HANDLE snap2 = (HANDLE)CS(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid2);
                        if (snap2 != INVALID_HANDLE_VALUE) {
                            MODULEENTRY32 me2;
                            me2.dwSize = sizeof(MODULEENTRY32);
                            /* M32F/M32N use ppointer macros; M32F is a ppointer but also works
                             * with the original untyped Exported.Module32First.
                             * For snap2 we need to re-open — CS returns a typed HANDLE from
                             * CreateToolhelp32Snapshot, and M32F casts Exported.Module32First. */
                            if (M32F(snap2, &me2)) {
                                do {
                                    UINT_PTR mb = (UINT_PTR)me2.modBaseAddr;
                                    if (rttiLocator >= mb &&
                                        rttiLocator < mb + me2.modBaseSize) {
                                        typeInfoAddr = mb + dwTypeInfo;
                                        break;
                                    }
                                } while (M32N(snap2, &me2));
                            }
                            CloseHandle(snap2);
                        }
                    } else {
                        typeInfoAddr = (UINT_PTR)dwTypeInfo;
                    }

                    if (typeInfoAddr != 0) {
                        /* Read TypeDescriptor:
                         *   +0x00: PVOID (vtable)
                         *   +ptrSize: PVOID (undecorated name)
                         *   +2*ptrSize: char[] decorated name (starts with ".?AV") */
                        UINT_PTR decoratedOffset = typeInfoAddr + 2 * ptrSize;
                        char decorated[256] = {0};
                        if (RPM(*Exported.OpenedProcessHandle,
                                (LPCVOID)decoratedOffset, decorated,
                                sizeof(decorated) - 1, &bytesRead) &&
                            bytesRead > 4) {
                            decorated[sizeof(decorated) - 1] = '\0';

                            /* .?AV prefix = MSVC class marker */
                            if (decorated[0] == '.' && decorated[1] == '?' &&
                                decorated[2] == 'A' && decorated[3] == 'V') {

                                /* Prepend "?" then undecorate with UNDNAME_NAME_ONLY */
                                char decoratedForDemangle[256];
                                decoratedForDemangle[0] = '?';
                                strncpy_s(decoratedForDemangle + 1,
                                          sizeof(decoratedForDemangle) - 1,
                                          decorated + 4, _TRUNCATE);
                                decoratedForDemangle[sizeof(decoratedForDemangle) - 1] = '\0';

                                char undecorated[256] = {0};
                                DWORD nameLen = 0;
                                {
                                    /* Load dynamically — d b g h e l p . d l l may not export
                                     * UnDecorateSymbolName via the .lib import table in new SDK */
                                    HMODULE hDbg = GetModuleHandleA("dbghelp.dll");
                                    if (!hDbg) hDbg = LoadLibraryA("dbghelp.dll");
                                    if (hDbg) {
                                        typedef DWORD (WINAPI *Undecorate_t)(PCSTR, PSTR, DWORD, DWORD);
                                        Undecorate_t pUnDec = (Undecorate_t)GetProcAddress(hDbg, "UnDecorateSymbolNameA");
                                        if (pUnDec)
                                            nameLen = pUnDec(decoratedForDemangle, undecorated,
                                                             (DWORD)sizeof(undecorated) - 1,
                                                             UNDNAME_NAME_ONLY);
                                    }
                                }

                                char *finalName = (nameLen > 0 && undecorated[0])
                                    ? undecorated
                                    : (decorated + 4);
                                BOOL valid = TRUE;
                                for (char *c = finalName; *c; c++) {
                                    unsigned char uc = (unsigned char)*c;
                                    if (uc < 32 || uc > 126) { valid = FALSE; break; }
                                }
                                if (!valid && finalName != (decorated + 4)) {
                                    finalName = decorated + 4;
                                    valid = TRUE;
                                    for (char *c = finalName; *c; c++) {
                                        unsigned char uc = (unsigned char)*c;
                                        if (uc < 32 || uc > 126) { valid = FALSE; break; }
                                    }
                                }

                                if (!valid) {
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

    /* ===== Method 2: Pascal/Delphi ShortString ===== */
    {
        UINT_PTR nameAddr = 0;
        UINT_PTR pascalNameOff = vtable + ptrSize * 3;
        if (RPM(*Exported.OpenedProcessHandle, (LPCVOID)pascalNameOff,
                &nameAddr, (SIZE_T)ptrSize, &bytesRead) &&
            bytesRead >= (SIZE_T)ptrSize && nameAddr != 0) {

            BYTE shortStr[256] = {0};
            if (RPM(*Exported.OpenedProcessHandle, (LPCVOID)nameAddr,
                    shortStr, sizeof(shortStr), &bytesRead) &&
                bytesRead > 0) {

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
