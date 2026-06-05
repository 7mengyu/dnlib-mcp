    UINT_PTR current = addr;
    for (int i = 0; i < count; i++) {
        char inst[256] = {0};
        int gotInstruction = 0;

        /* disassembleEx(pptrUint, output, maxsize) — pluginexports.pas:811
         * 解引用 *address 读取当前地址，反汇编后写回更新值。
         * 这是 CE 7.5 给插件设计的首选反汇编 API。
         * output 可以为 NULL（仅推进地址），也可以传入缓冲区获取指令文本。 */
        if (Exported.disassembleEx) {
            UINT_PTR next = current;
            if (Exported.disassembleEx((UINT_PTR)&next, inst, sizeof(inst) - 1) && inst[0]) {
                current = next;
                gotInstruction = 1;
            }
        }

        /* Disassembler(address, output, maxsize) — pluginexports.pas:793
         * 值传递地址，不更新地址。回退方案。 */
        if (!gotInstruction && Exported.Disassembler) {
            UINT_PTR next = current;
            if (Exported.Disassembler(current, inst, sizeof(inst) - 1) && inst[0]) {
                if (Exported.disassembleEx)
                    Exported.disassembleEx((UINT_PTR)&next, NULL, 0);
                current = next;
                gotInstruction = 1;
            }
        }

        if (!gotInstruction) break;

        /* 计算当前指令的字节长度（current 已更新到下一条指令起点） */
        UINT_PTR origAddr = addr;
        SINT_PTR advance = (SINT_PTR)(current - origAddr);
        int instLen = (int)advance;
        if (instLen <= 0) instLen = 1; /* 安全回退 */
        UINT_PTR instAddr = current - instLen;

        BYTE raw[16] = {0};
        SIZE_T bytesRead = 0;
        RPM(*Exported.OpenedProcessHandle, (LPCVOID)instAddr, instLen, &bytesRead);

        pos += sprintf_s(result + pos, sizeof(result) - pos, "%s{", i > 0 ? "," : "");
        pos += sprintf_s(result + pos, sizeof(result) - pos,
                         "\"offset\":\"0x%llX\",\"bytes\":\"",
                         (unsigned long long)instAddr);
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

        if (pos >= (int)sizeof(result) - 200) break;
    }