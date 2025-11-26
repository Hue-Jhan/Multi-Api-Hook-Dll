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
    return protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY ||
           protection == PAGE_EXECUTE || protection == PAGE_EXECUTE_READ; }

void PushRWXEvent(const char* func, LPVOID addr, SIZE_T size, DWORD prot, void* retAddr) {
    if (!(g_enableLogging)) return;
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
    cambiaColore(FOREGROUND_YELLOW1);
    std::printf("   [!] RWX/RRX DETECTED                          ");
    cambiaColore(FOREGROUND_GREEN);
    std::printf("pid=%-6u tid=%-6u %s addr=0x%llx size=%llu prot=0x%X \n",
        pid, tid, func, (unsigned long long)((uintptr_t)addr & 0xFFFFFFFF),
        (unsigned long long)size, prot);
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
