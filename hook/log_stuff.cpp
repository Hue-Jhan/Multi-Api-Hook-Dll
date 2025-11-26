#include "log_stuff.h"

bool g_enableLogging = false;
thread_local int g_suppressNtLogging = 0;

void cambiaColore(int colore) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, colore);
    return;
}

bool ShouldIgnoreAllocation(SIZE_T size, void* caller) {
    if (size < 15 && g_enableLogging) {
        std::fprintf(stderr, "   [ ] Small Allocation \n");
        return true; }
    HMODULE hMod = nullptr; // JIT allocs are usually 0x1000 and caller inside clrjit.dll/coreclr.dll/jscript9.dll
    if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCTSTR)caller, &hMod)) {
        char name[MAX_PATH] = { 0 };
        GetModuleFileNameA(hMod, name, MAX_PATH);
        if (strstr(name, "clrjit.dll") || strstr(name, "coreclr.dll")
            || strstr(name, "jscript9.dll")) return true;
    }
    return false;
}

bool IsRWX(DWORD protection) {
    DWORD p = protection & 0xFFu; // mask high flags, keep base protection
    return (p == PAGE_EXECUTE_READWRITE) || (p == PAGE_EXECUTE_WRITECOPY) 
        || (p == PAGE_EXECUTE) || (p == PAGE_EXECUTE_READ);
}

std::string ProtectionToString(DWORD protection) {
    DWORD p = protection & 0xFFu;
    std::string base;
    switch (p) {
        case PAGE_NOACCESS:          base = "PAGE_NOACCESS"; break;
        case PAGE_READONLY:          base = "PAGE_READONLY"; break;
        case PAGE_READWRITE:         base = "PAGE_READWRITE"; break;
        case PAGE_WRITECOPY:         base = "PAGE_WRITECOPY"; break;
        case PAGE_EXECUTE:           base = "PAGE_EXECUTE"; break;
        case PAGE_EXECUTE_READ:      base = "PAGE_EXECUTE_READ"; break;
        case PAGE_EXECUTE_READWRITE: base = "PAGE_EXECUTE_READWRITE"; break;
        case PAGE_EXECUTE_WRITECOPY: base = "PAGE_EXECUTE_WRITECOPY"; break;
        default: {
            char tmp[64];
            std::snprintf(tmp, sizeof(tmp), "PAGE_UNKNOWN(0x%02X)", (unsigned)p);
            base = tmp; }
    }

    if (protection & PAGE_GUARD)        base += "|PAGE_GUARD";
    if (protection & PAGE_NOCACHE)      base += "|PAGE_NOCACHE";
    if (protection & PAGE_WRITECOMBINE) base += "|PAGE_WRITECOMBINE";
    return base;
}

void PushRWXEvent(const char* func, LPVOID addr, SIZE_T size, DWORD prot, void* retAddr) {
    if (!(g_enableLogging)) return;
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();

    DWORD p = prot & 0xFFu;
    bool isExec = (p == PAGE_EXECUTE_READWRITE) || (p == PAGE_EXECUTE_WRITECOPY) || (p == PAGE_EXECUTE) || (p == PAGE_EXECUTE_READ);
    bool isWrite = (p == PAGE_READWRITE) || (p == PAGE_EXECUTE_READWRITE) || (p == PAGE_WRITECOPY) || (p == PAGE_EXECUTE_WRITECOPY);
    bool isRead = (p == PAGE_READONLY) || (p == PAGE_READWRITE) || (p == PAGE_EXECUTE_READ) || (p == PAGE_EXECUTE_READWRITE) || (p == PAGE_EXECUTE) || (p == PAGE_WRITECOPY) || (p == PAGE_EXECUTE_WRITECOPY);
    
    const char* label = "prt";
    if (p == PAGE_NOACCESS) label = "NOA";
    else if (isExec && isWrite) label = "RWX";
    else if (isExec && !isWrite) label = " RX";
    else if (!isExec && isWrite) label = " RW";
    else if (isRead && !isWrite && !isExec) label = "rRr";
    else label = "IDK";
    std::string protStr = ProtectionToString(prot);
    
    cambiaColore(FOREGROUND_YELLOW1);
    std::printf("   [!] %-3s DETECTED                              ", label);
    cambiaColore(FOREGROUND_GREEN);
    std::printf("pid=%-6u tid=%-6u %s addr=0x%llx size=%llu prot=0x%X \n", pid, tid, func, (unsigned long long)((uintptr_t)addr & 0xFFFFFFFF), (unsigned long long)size, prot);
}

void PushInjectionEvent(const char* func, LPVOID addr, SIZE_T size, DWORD prot, void* retAddr) {
    if (!(g_enableLogging)) return;
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
    cambiaColore(FOREGROUND_RED1);
    std::printf("   [!] %-35s       ", func);
    cambiaColore(FOREGROUND_GREEN);
    std::printf("pid=%-6u tid=%-6u addr=0x%llx size=%llu prot=0x%X \n", pid, tid, 
        (unsigned long long)((uintptr_t)addr & 0xFFFFFFFF), (unsigned long long)size, prot);
}

void PushDLLInjectionEvent(const char* api, HMODULE mod, const char* name) {
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
    cambiaColore(FOREGROUND_YELLOW1);
    // std::printf("   [!] DLL LOADING DETECTED                      ");
    std::printf("   [!] LOADING LIBRARY ATTEMPT                   ");
    cambiaColore(FOREGROUND_GREEN);

    std::printf("pid=%-6u tid=%-6u %s module=0x%llx name=%s\n", pid, tid, api,
        (unsigned long long)((uintptr_t)mod & 0xFFFFFFFF), name ? name : "(null)");
}
