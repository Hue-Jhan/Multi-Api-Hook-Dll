#include "hook_stuff.h"


LoadLibraryA_t fpLoadLibraryA = nullptr;
LoadLibraryW_t fpLoadLibraryW = nullptr;
LoadLibraryExA_t fpLoadLibraryExA = nullptr;
LoadLibraryExW_t fpLoadLibraryExW = nullptr;
GetProcAddress_t fpGetProcAddress = nullptr;
CreateThread_t fpCreateThread = nullptr;
CreateRemoteThread_t fpCreateRemoteThread = nullptr;
CreateRemoteThreadEx_t fpCreateRemoteThreadEx = nullptr;
VirtualAlloc_t fpVirtualAlloc = nullptr;
VirtualAllocEx_t fpVirtualAllocEx = nullptr;
VirtualProtect_t fpVirtualProtect = nullptr;
VirtualProtectEx_t fpVirtualProtectEx = nullptr;
WriteProcessMemory_t fpWriteProcessMemory = nullptr;
SuspendThread_t fpSuspendThread = nullptr;
ResumeThread_t fpResumeThread = nullptr;
OpenProcess_t fpOpenProcess = nullptr;
CloseHandle_t fpCloseHandle = nullptr;
GetThreadContext_t fpGetThreadContext = nullptr;
SetThreadContext_t fpSetThreadContext = nullptr;
QueueUserAPC_t fpQueueUserAPC = nullptr;
GetModuleHandleW_t fpGetModuleHandleW = nullptr;
WaitForSingleObject_t fpWaitForSingleObject = nullptr;
CreateToolhelp32Snapshot_t fpCreateToolhelp32Snapshot = nullptr;
Process32FirstA_t fpProcess32FirstA = nullptr;
Process32NextA_t fpProcess32NextA = nullptr;
Process32FirstW_t fpProcess32FirstW = nullptr;
Process32NextW_t fpProcess32NextW = nullptr;
GetProcessId_t fpGetProcessId = nullptr;
GetModuleFileNameA_t fpGetModuleFileNameA = nullptr;
GetModuleFileNameW_t fpGetModuleFileNameW = nullptr;

//LdrLoadDll_t fpLdrLoadDll = nullptr;
SetWindowsHookExA_t fpSetWindowsHookExA = nullptr;
SetWindowsHookExW_t fpSetWindowsHookExW = nullptr;
SetWinEventHook_t fpSetWinEventHook = nullptr;
CreateFileA_t fpCreateFileA = nullptr;
CreateFileW_t fpCreateFileW = nullptr;
WriteFile_t fpWriteFile = nullptr;
CreateFileMappingA_t fpCreateFileMappingA = nullptr;
CreateFileMappingW_t fpCreateFileMappingW = nullptr;
MapViewOfFile_t fpMapViewOfFile = nullptr;
RegSetValueExA_t fpRegSetValueExA = nullptr;
RegSetValueExW_t fpRegSetValueExW = nullptr;
RegCreateKeyExA_t fpRegCreateKeyExA = nullptr;
RegCreateKeyExW_t fpRegCreateKeyExW = nullptr;
CreateServiceA_t fpCreateServiceA = nullptr;
CreateServiceW_t fpCreateServiceW = nullptr;
StartServiceA_t fpStartServiceA = nullptr;
StartServiceW_t fpStartServiceW = nullptr;
DuplicateHandle_t fpDuplicateHandle = nullptr;
CreateNamedPipeA_t fpCreateNamedPipeA = nullptr;
CreateNamedPipeW_t fpCreateNamedPipeW = nullptr;
ConnectNamedPipe_t fpConnectNamedPipe = nullptr;
OpenMutexA_t fpOpenMutexA = nullptr;
OpenMutexW_t fpOpenMutexW = nullptr;
CreateMutexA_t fpCreateMutexA = nullptr;
CreateMutexW_t fpCreateMutexW = nullptr;


HMODULE WINAPI hkLoadLibraryA(LPCSTR name) {
    LOGFUNC("LoadLibraryA", "name=%s", name);
    return fpLoadLibraryA(name);
}
HMODULE WINAPI hkLoadLibraryW(LPCWSTR name) {
    LOGFUNC("LoadLibraryW", "name=%ls", name);
    return fpLoadLibraryW(name);
}
HMODULE WINAPI hkLoadLibraryExA(LPCSTR name, HANDLE h, DWORD flags) {
    LOGFUNC("LoadLibraryExA", "name=%s flags=0x%X handle=0x%llX", name, flags, (unsigned long long)h);
    return fpLoadLibraryExA(name, h, flags);
}
HMODULE WINAPI hkLoadLibraryExW(LPCWSTR name, HANDLE h, DWORD flags) {
    LOGFUNC("LoadLibraryExW", "name=%ls flags=0x%X handle=0x%llX", name, flags, (unsigned long long)h);
    return fpLoadLibraryExW(name, h, flags);
}
FARPROC WINAPI hkGetProcAddress(HMODULE mod, LPCSTR name) {
    LOGFUNC("GetProcAddress", "module=0x%x name=%s", (unsigned)((uintptr_t)mod & 0xFFFFFFFF),
        name ? name : "(null)");
    if (name && ((ULONG_PTR)name > 0xFFFF)) {
        if (IsLoadLibraryName(name)) PushDLLInjectionEvent("GetProcAddress", mod, name);
    }
    return fpGetProcAddress(mod, name);
}
HANDLE WINAPI hkCreateThread(LPSECURITY_ATTRIBUTES a, SIZE_T s, LPTHREAD_START_ROUTINE st, LPVOID p, DWORD f, LPDWORD id) {
    LOGFUNC("CreateThread", "start=%p param=%p size=%-6llu flags=0x%X", (void*)st, p, (unsigned long long)s, f);
    HANDLE rc = fpCreateThread(a, s, st, p, f, id);
    /* if (rc) {
        // detection part... 
    }
    */
    return rc;
}
HANDLE WINAPI hkCreateRemoteThread(HANDLE h, LPSECURITY_ATTRIBUTES a, SIZE_T s, LPTHREAD_START_ROUTINE st, LPVOID p, DWORD f, LPDWORD id) {
    LOGFUNC("CreateRemoteThread", "target=0x%llX start=0x%llx size=%-6llu", (void*)h, (void*)st, (unsigned long long)s);
    // SuppressNtLoggingGuard guard;   // to not log nt counter part each time
    HANDLE rc = fpCreateRemoteThread(h, a, s, st, p, f, id);
    /* if (rc) {
        // detection part...
    }
    */
    return rc;
}
HANDLE WINAPI hkCreateRemoteThreadEx(HANDLE h, LPSECURITY_ATTRIBUTES a, SIZE_T s, LPTHREAD_START_ROUTINE st, LPVOID p, DWORD f, LPDWORD id, LPVOID attr) {
    LOGFUNC("CreateRemoteThreadEx", "target=0x%llX start=0x%llx size=%-6llu", (void*)h, (void*)st, (unsigned long long)s);

    HANDLE rc = fpCreateRemoteThreadEx(h, a, s, st, p, f, id, attr);
    /* if (rc) {
        // detection part...
    }
    */
    return rc;
}
LPVOID WINAPI hkVirtualAlloc(LPVOID addr, SIZE_T size, DWORD type, DWORD protect) {
    if (ShouldIgnoreAllocation(size, _ReturnAddress()))
        return fpVirtualAlloc(addr, size, type, protect);
    LOGFUNC("VirtualAlloc", "addr=0x%llx size=%llu type=0x%X prot=0x%X", addr, (unsigned long long)size, type, protect);

    LPVOID rc = fpVirtualAlloc(addr, size, type, protect);

    if (rc && IsRWX(protect)) {  // rc instead of addr?
        //PushRWXEvent("VirtualAlloc", addr, size, protect, _ReturnAddress());
        // also update detection state: mark_exec(...)
    }
    return rc;
}
LPVOID WINAPI hkVirtualAllocEx(HANDLE h, LPVOID addr, SIZE_T size, DWORD type, DWORD protect) {
    if (ShouldIgnoreAllocation(size, _ReturnAddress()))
        return fpVirtualAllocEx(h, addr, size, type, protect);
    LOGFUNC("VirtualAllocEx", "proc=0x%llx addr=0x%llx size=%llu type=0x%X prot=0x%X", (void*)h, addr, (unsigned long long)size, type, protect);
    
    LPVOID rc = fpVirtualAllocEx(h, addr, size, type, protect);

    if (rc && IsRWX(protect)) { // rc instead of addr?
        //PushRWXEvent("VirtualAllocEx", addr, size, protect, _ReturnAddress());
        // also update detection state: mark_exec(...)
    }
    return rc;
}
BOOL WINAPI hkWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    LOGFUNC("WriteProcessMemory", "target=0x%llX addr=0x%llx size=%-6llu", (void*)hProcess, lpBaseAddress, (unsigned long long)nSize);
    
    /*AllocInfo a;
    if (find_alloc_for_addr((uintptr_t)lpBaseAddress, &a)) {
        if (looks_like_pe(lpBuffer, nSize)) {
            std::unique_lock<std::shared_mutex> L(g_allocs_lock);
            auto it = g_allocs.find(a.base);
            if (it != g_allocs.end()) it->second.tag += "|potential_pe";
            LOGFUNC("WriteProcessMemory", "  -> looks like PE header, marked potential module");
        }
    }*/

    BOOL rc = fpWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

    /*if (rc) {
        mark_written((uintptr_t)lpBaseAddress, nSize); // your detection hook
    }*/
    return rc;
}
BOOL WINAPI hkVirtualProtect(LPVOID addr, SIZE_T size, DWORD protect, PDWORD oldProt) {
    if (ShouldIgnoreAllocation(size, _ReturnAddress()))
        return fpVirtualProtect(addr, size, protect, oldProt);

    LOGFUNC("VirtualProtect", "addr=0x%llx size=%llu newProt=0x%X",
        (unsigned long long)((uintptr_t)addr & 0xFFFFFFFF), (unsigned long long)size, protect);

    BOOL rc = fpVirtualProtect(addr, size, protect, oldProt);

    if (rc && IsRWX(protect)) {  // rc instead of addr?
        //PushRWXEvent("VirtualProtect", addr, size, protect, _ReturnAddress());
        // also update detection state: mark_exec(...)
    }
    return rc;
}
BOOL WINAPI hkVirtualProtectEx(HANDLE h, LPVOID addr, SIZE_T size, DWORD protect, PDWORD oldProt) {
    if (ShouldIgnoreAllocation(size, _ReturnAddress()))
        return fpVirtualProtectEx(h, addr, size, protect, oldProt);

    LOGFUNC("VirtualProtectEx", "proc=0x%llX addr=0x%llx size=%llu newProt=0x%X",
        (void*)h, (unsigned long long)((uintptr_t)addr & 0xFFFFFFFF), (unsigned long long)size, protect);

    BOOL rc = fpVirtualProtectEx(h, addr, size, protect, oldProt);

    if (rc && IsRWX(protect)) {
        //PushRWXEvent("VirtualProtectEx", addr, size, protect, _ReturnAddress());
        // also update detection state: mark_exec(...)
    }
    return rc;
}
DWORD WINAPI hkSuspendThread(HANDLE hThread) {
    LOGFUNC("SuspendThread", "thread=0x%llX", (void*)hThread);
    
    return fpSuspendThread(hThread);
}
DWORD WINAPI hkResumeThread(HANDLE hThread) {
    LOGFUNC("ResumeThread", "thread=0x%llX", (void*)hThread);
    
    return fpResumeThread(hThread);
}
BOOL WINAPI hkGetThreadContext(HANDLE h, LPCONTEXT c) {
    LOGFUNC("GetThreadContext", "thread=0x%llX", h);
    return fpGetThreadContext(h, c);
}
BOOL WINAPI hkSetThreadContext(HANDLE h, const CONTEXT* c) {
    LOGFUNC("SetThreadContext", "thread=0x%llX", h);
    return fpSetThreadContext(h, c);
}
HANDLE WINAPI hkOpenProcess(DWORD access, BOOL inh, DWORD pid) {
    LOGFUNC("OpenProcess", "pid=%u access=0x%X", pid, access);
    
    return fpOpenProcess(access, inh, pid);
}
BOOL WINAPI hkCloseHandle(HANDLE h) {
    LOGFUNC("CloseHandle", "handle=0x%llX", h);
    
    return fpCloseHandle(h);
}
ULONG WINAPI hkQueueUserAPC(PAPCFUNC fn, HANDLE h, ULONG_PTR p) {
    LOGFUNC("QueueUserAPC", "thread=0x%llX func=%p param=%p", h, fn, (void*)p);
    SuppressNtLoggingGuard guard;
    return fpQueueUserAPC(fn, h, p);
}
HMODULE WINAPI hkGetModuleHandleW(LPCWSTR name) {
    LOGFUNC("GetModuleHandleW", "name=%ls", name ? name : L"(null)");
    return fpGetModuleHandleW(name);
}
DWORD WINAPI hkWaitForSingleObject(HANDLE h, DWORD timeout) {
    LOGFUNC("WaitForSingleObject", "handle=0x%x timeout=%u", (unsigned)((uintptr_t)h & 0xFFFFFFFF), timeout);
    return fpWaitForSingleObject(h, timeout);
}
HANDLE WINAPI hkCreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID) {
    
    HANDLE snap = fpCreateToolhelp32Snapshot(dwFlags, th32ProcessID);
    LOGFUNC("CreateToolhelp32Snapshot", "flags=0x%X pid=%u snap=%p", dwFlags, th32ProcessID, snap);
    return snap;
}
BOOL WINAPI hkProcess32FirstA(HANDLE hSnapshot, LPPROCESSENTRY32 lppe) {
    
    BOOL rc = fpProcess32FirstA(hSnapshot, lppe);
    LOGFUNC("Process32FirstA", "snap=%p rc=%d", hSnapshot, rc);
    if (rc && lppe && lppe->szExeFile[0]) LOGFUNC("Process32FirstA", "exe=%s pid=%u", lppe->szExeFile, lppe->th32ProcessID);
    return rc;
}
BOOL WINAPI hkProcess32NextA(HANDLE hSnapshot, LPPROCESSENTRY32 lppe) {
   
    BOOL rc = fpProcess32NextA(hSnapshot, lppe);
    LOGFUNC("Process32NextA", "snap=%p rc=%d", hSnapshot, rc);
    if (rc && lppe && lppe->szExeFile[0]) LOGFUNC("Process32NextA", "exe=%s pid=%u", lppe->szExeFile, lppe->th32ProcessID);
    return rc;
}
BOOL WINAPI hkProcess32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe) {
    BOOL rc = fpProcess32FirstW(hSnapshot, lppe);
    LOGFUNC("Process32FirstW", "snap=%p rc=%d", hSnapshot, rc);
    if (rc && lppe && lppe->szExeFile[0]) LOGFUNC("Process32FirstW", "exe=%ls pid=%u", lppe->szExeFile, lppe->th32ProcessID);
    return rc;
}
BOOL WINAPI hkProcess32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe) {
    
    BOOL rc = fpProcess32NextW(hSnapshot, lppe);
    LOGFUNC("Process32NextW", "snap=%p rc=%d", hSnapshot, rc);
    if (rc && lppe && lppe->szExeFile[0]) LOGFUNC("Process32NextW", "exe=%ls pid=%u", lppe->szExeFile, lppe->th32ProcessID);
    return rc;
}
DWORD WINAPI hkGetProcessId(HANDLE Process) {
    LOGFUNC("GetProcessId", "procHandle=0x%llx", (unsigned long long)((uintptr_t)Process & 0xFFFFFFFF));
    printf("ss");
    return fpGetProcessId(Process);
}
DWORD WINAPI hkGetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize) {
    
    DWORD rc = fpGetModuleFileNameA(hModule, lpFilename, nSize);
    const char* name = lpFilename;
    if (lpFilename && lpFilename[0]) {
        const char* lastSlash = strrchr(lpFilename, '\\');
        if (lastSlash) name = lastSlash + 1;
    }
    if (lpFilename && nSize) LOGFUNC("GetModuleFileNameA", "hModule=%p name=%s", (void*)hModule, name);
    else LOGFUNC("GetModuleFileNameA", "hModule=%p name=null", (void*)hModule);
    return rc;
}
DWORD WINAPI hkGetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize) {
   
    DWORD rc = fpGetModuleFileNameW(hModule, lpFilename, nSize);
    const wchar_t* name = lpFilename;
    if (lpFilename && lpFilename[0]) {
        const wchar_t* lastSlash = wcsrchr(lpFilename, L'\\');
        if (lastSlash) name = lastSlash + 1;
    }
    if (lpFilename && nSize && lpFilename[0]) LOGFUNC("GetModuleFileNameW", "hModule=%p name=%ls", (void*)hModule, name);
    else LOGFUNC("GetModuleFileNameW", "hModule=%p name=null", (void*)hModule);
    return rc;
}

HHOOK WINAPI hkSetWindowsHookExA(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId) {
    LOGFUNC("SetWindowsHookExA", "hook=%d mod=%p tid=%u", idHook, hMod, dwThreadId);
    return fpSetWindowsHookExA(idHook, lpfn, hMod, dwThreadId);
}
HHOOK WINAPI hkSetWindowsHookExW(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId) {
    LOGFUNC("SetWindowsHookExW", "hook=%d mod=%p tid=%u", idHook, hMod, dwThreadId);
    return fpSetWindowsHookExW(idHook, lpfn, hMod, dwThreadId);
}
HWINEVENTHOOK WINAPI hkSetWinEventHook(UINT eventMin, UINT eventMax, HMODULE hmodWinEventProc, WINEVENTPROC pfn, DWORD idProcess, DWORD idThread, DWORD dwFlags) {
    LOGFUNC("SetWinEventHook", "events=0x%X-0x%X pid=%u tid=%u flags=0x%X", eventMin, eventMax, idProcess, idThread, dwFlags);
    return fpSetWinEventHook(eventMin, eventMax, hmodWinEventProc, pfn, idProcess, idThread, dwFlags);
}
HANDLE WINAPI hkCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    LOGFUNC("CreateFileA", "name=%s access=0x%X disp=0x%X flags=0x%X", lpFileName ? lpFileName : "(null)", dwDesiredAccess, dwCreationDisposition, dwFlagsAndAttributes);
    return fpCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}
HANDLE WINAPI hkCreateFileW(LPCWSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    LOGFUNC("CreateFileW", "name=%ls access=0x%X disp=0x%X flags=0x%X", lpFileName ? lpFileName : L"(null)", dwDesiredAccess, dwCreationDisposition, dwFlagsAndAttributes);
    return fpCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile); }
BOOL WINAPI hkWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    LOGFUNC("WriteFile", "file=%p size=%u", hFile, nNumberOfBytesToWrite);
    return fpWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}
HANDLE WINAPI hkCreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName) {
    LOGFUNC("CreateFileMappingA", "file=%p name=%s protect=0x%X", hFile, lpName ? lpName : "(null)", flProtect);
    return fpCreateFileMappingA(hFile, lpAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}
HANDLE WINAPI hkCreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName) {
    LOGFUNC("CreateFileMappingW", "file=%p name=%ls protect=0x%X", hFile, lpName ? lpName : L"(null)", flProtect);
    return fpCreateFileMappingW(hFile, lpAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}
LPVOID WINAPI hkMapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap) {
    LOGFUNC("MapViewOfFile", "mapping=%p size=%llu", hFileMappingObject, (unsigned long long)dwNumberOfBytesToMap);
    return fpMapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
}
LSTATUS WINAPI hkRegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData) {
    LOGFUNC("RegSetValueExA", "key=%p name=%s size=%u", hKey, lpValueName ? lpValueName : "(null)", cbData);
    return fpRegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}
LSTATUS WINAPI hkRegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition) {
    LOGFUNC("RegCreateKeyExA", "key=%p sub=%s", hKey, lpSubKey ? lpSubKey : "(null)");
    return fpRegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
}
LSTATUS WINAPI hkRegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData) {
    LOGFUNC("RegSetValueExW", "key=%p name=%ls size=%u", hKey, lpValueName ? lpValueName : L"(null)", cbData);
    return fpRegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}
LSTATUS WINAPI hkRegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition) {
    LOGFUNC("RegCreateKeyExW", "key=%p sub=%ls", hKey, lpSubKey ? lpSubKey : L"(null)");
    return fpRegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
}
SC_HANDLE WINAPI hkCreateServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, LPCSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName, LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies, LPCSTR lpServiceStartName, LPCSTR lpPassword) {
    LOGFUNC("CreateServiceA", "scm=%p name=%s bin=%s", hSCManager, lpServiceName ? lpServiceName : "(null)", lpBinaryPathName ? lpBinaryPathName : "(null)");
    return fpCreateServiceA(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);
}
BOOL WINAPI hkStartServiceA(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCSTR* lpServiceArgVectors) {
    LOGFUNC("StartServiceA", "svc=%p argc=%u", hService, dwNumServiceArgs);
    return fpStartServiceA(hService, dwNumServiceArgs, lpServiceArgVectors);
}
SC_HANDLE WINAPI hkCreateServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword) {
    LOGFUNC("CreateServiceW", "scm=%p name=%ls bin=%ls", hSCManager, lpServiceName ? lpServiceName : L"(null)", lpBinaryPathName ? lpBinaryPathName : L"(null)");
    return fpCreateServiceW(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);
}
BOOL WINAPI hkStartServiceW(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCWSTR* lpServiceArgVectors) {
    LOGFUNC("StartServiceW", "svc=%p argc=%u", hService, dwNumServiceArgs);
    return fpStartServiceW(hService, dwNumServiceArgs, lpServiceArgVectors);
}
BOOL WINAPI hkDuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions) {
    LOGFUNC("DuplicateHandle", "srcProc=%p src=%p targetProc=%p", hSourceProcessHandle, hSourceHandle, hTargetProcessHandle);
    return fpDuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);
}
HANDLE WINAPI hkCreateNamedPipeA(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes) {
    LOGFUNC("CreateNamedPipeA", "name=%s mode=0x%X", lpName ? lpName : "(null)", dwOpenMode);
    return fpCreateNamedPipeA(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);
}
BOOL WINAPI hkConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped) {
    LOGFUNC("ConnectNamedPipe", "pipe=%p", hNamedPipe);
    return fpConnectNamedPipe(hNamedPipe, lpOverlapped);
}
HANDLE WINAPI hkOpenMutexA(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName) {
    LOGFUNC("OpenMutexA", "name=%s", lpName ? lpName : "(null)");
    return fpOpenMutexA(dwDesiredAccess, bInheritHandle, lpName);
}
HANDLE WINAPI hkCreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName) {
    LOGFUNC("CreateMutexA", "name=%s", lpName ? lpName : "(null)");
    return fpCreateMutexA(lpMutexAttributes, bInitialOwner, lpName);
}
HANDLE WINAPI hkCreateNamedPipeW(LPCWSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes) {
    LOGFUNC("CreateNamedPipeW", "name=%ls mode=0x%X", lpName ? lpName : L"(null)", dwOpenMode);
    return fpCreateNamedPipeW(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);
}
HANDLE WINAPI hkOpenMutexW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName) {
    LOGFUNC("OpenMutexW", "name=%ls", lpName ? lpName : L"(null)");
    return fpOpenMutexW(dwDesiredAccess, bInheritHandle, lpName);
}
HANDLE WINAPI hkCreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName) {
    LOGFUNC("CreateMutexW", "name=%ls", lpName ? lpName : L"(null)");
    return fpCreateMutexW(lpMutexAttributes, bInitialOwner, lpName);
}

