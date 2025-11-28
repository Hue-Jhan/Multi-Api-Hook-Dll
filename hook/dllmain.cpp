#include "pch.h"
#include "hook_stuff.h"
#include "nt_hooks.h"


bool EnsureConsole() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (h != INVALID_HANDLE_VALUE && h != nullptr && GetConsoleScreenBufferInfo(h, &csbi)) { return true; }
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {  // try to attach to parent console first 
        if (!AllocConsole()) {
            DWORD e = GetLastError();
            char buf[128];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "EnsureConsole: AllocConsole failed: %lu\n", e);
            OutputDebugStringA(buf);
            return false; } 
    }
    FILE* fOut = nullptr;  // redirect CRT streams to console
    FILE* fErr = nullptr;
    freopen_s(&fOut, "CONOUT$", "w", stdout);
    freopen_s(&fErr, "CONOUT$", "w", stderr);
    freopen_s(&fOut, "CONIN$", "r", stdin);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    return true;
}

bool ResizeConsoleShort(int width, int height) {
    if (width <= 0 || height <= 0) return false;
    if (!EnsureConsole()) return false;

    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE || h == nullptr) return false;

    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!GetConsoleScreenBufferInfo(h, &csbi)) return false;

    COORD largest = GetLargestConsoleWindowSize(h);
    if (width > largest.X) width = largest.X;
    if (height > largest.Y) height = largest.Y;

    SMALL_RECT newWindow;
    newWindow.Left = 0;
    newWindow.Top = 0;
    newWindow.Right = (SHORT)(width - 1);
    newWindow.Bottom = (SHORT)(height - 1);

    COORD newBuf;  // buffer is taller than the window so scrolling is enabled
    newBuf.X = (SHORT)width;
    SHORT desiredBufY = (SHORT)max((int)height + 100, (int)height + 1);
    if (csbi.dwSize.Y > desiredBufY) desiredBufY = csbi.dwSize.Y;
    newBuf.Y = desiredBufY;

    // if buffer must grow to fit the window, grow it first
    if (csbi.dwSize.X < newBuf.X || csbi.dwSize.Y < newBuf.Y) {
        if (!SetConsoleScreenBufferSize(h, newBuf)) return false;
        if (!SetConsoleWindowInfo(h, TRUE, &newWindow)) return false;
    } else {   // window must be shrunk first so buffer can shrink safely
        SMALL_RECT curWindow = csbi.srWindow;
        if ((curWindow.Right - curWindow.Left + 1) > newBuf.X || (curWindow.Bottom - curWindow.Top + 1) > newBuf.Y) {
            SMALL_RECT tmp = { 0, 0, 0, 0 };
            if (!SetConsoleWindowInfo(h, TRUE, &tmp)) return false;
            if (!GetConsoleScreenBufferInfo(h, &csbi)) return false; 
        }
        if (!SetConsoleScreenBufferSize(h, newBuf)) return false;
        if (!SetConsoleWindowInfo(h, TRUE, &newWindow)) return false;
    }

    return true;
}

void SetupHook(HMODULE hModule, LPCSTR funcName, void** originalPtr, void* detour) {
    if (!hModule) {
        std::fprintf(stderr, "[!] null module handle\n");
        return; }

    void* target = (void*)GetProcAddress(hModule, funcName);
    if (!target) {
        std::fprintf(stderr, "[!] cannot getproc %p!%s\n", hModule, funcName);
        return; }
    if (MH_CreateHook(target, detour, originalPtr) != MH_OK) {
        std::fprintf(stderr, "[!] MH_CreateHook failed for %p!%s\n", hModule, funcName);
        return; }
    if (MH_EnableHook(target) != MH_OK) {
        std::fprintf(stderr, "[!] MH_EnableHook failed for %p!%s\n", hModule, funcName);
        return; }
}

DWORD WINAPI Init(LPVOID) {
    if (!EnsureConsole()) {
        OutputDebugStringA("Init: EnsureConsole failed\n");
        return 0; }

    if (MH_Initialize() != MH_OK) {
        std::fprintf(stderr, "[!] MH_Initialize failed\n");
        return 0; }

    if (!ResizeConsoleShort(150, 40)) printf("resize failed\n");
    cambiaColore(FOREGROUND_GREEN);
    
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hKernel32 || !hNtdll) {
        std::fprintf(stderr, "[!] cannot getmodule kernel32.dll\n");
        std::fprintf(stderr, "[!] cannot getmodule ntdll.dll\n");
        return 0; }

    HMODULE hAdvapi = GetModuleHandleA("advapi32.dll");
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (!hAdvapi || !hUser32) {
        std::fprintf(stderr, "[!] cannot getmodule advapi32.dll\n");
        std::fprintf(stderr, "[!] cannot getmodule user32.dll\n");
        // return 0;  // no return bc some apps dont even call these
    }


    SetupHook(hKernel32, "LoadLibraryA", (void**)&fpLoadLibraryA, hkLoadLibraryA);
    SetupHook(hKernel32, "LoadLibraryW", (void**)&fpLoadLibraryW, hkLoadLibraryW);
    SetupHook(hKernel32, "LoadLibraryExA", (void**)&fpLoadLibraryExA, hkLoadLibraryExA);
    SetupHook(hKernel32, "LoadLibraryExW", (void**)&fpLoadLibraryExW, hkLoadLibraryExW);
    SetupHook(hKernel32, "GetProcAddress", (void**)&fpGetProcAddress, hkGetProcAddress);
    SetupHook(hKernel32, "CreateThread", (void**)&fpCreateThread, hkCreateThread);
    SetupHook(hKernel32, "CreateRemoteThread", (void**)&fpCreateRemoteThread, hkCreateRemoteThread);
    SetupHook(hKernel32, "CreateRemoteThreadEx", (void**)&fpCreateRemoteThreadEx, hkCreateRemoteThreadEx);
    SetupHook(hKernel32, "VirtualAlloc", (void**)&fpVirtualAlloc, hkVirtualAlloc);
    SetupHook(hKernel32, "VirtualAllocEx", (void**)&fpVirtualAllocEx, hkVirtualAllocEx);
    SetupHook(hKernel32, "WriteProcessMemory", (void**)&fpWriteProcessMemory, hkWriteProcessMemory);
    SetupHook(hKernel32, "VirtualProtect", (void**)&fpVirtualProtect, hkVirtualProtect);
    SetupHook(hKernel32, "VirtualProtectEx", (void**)&fpVirtualProtectEx, hkVirtualProtectEx);
    SetupHook(hKernel32, "SuspendThread", (void**)&fpSuspendThread, hkSuspendThread);
    SetupHook(hKernel32, "ResumeThread", (void**)&fpResumeThread, hkResumeThread);
    SetupHook(hKernel32, "GetThreadContext", (void**)&fpGetThreadContext, hkGetThreadContext);
    SetupHook(hKernel32, "SetThreadContext", (void**)&fpSetThreadContext, hkSetThreadContext);
    SetupHook(hKernel32, "OpenProcess", (void**)&fpOpenProcess, hkOpenProcess);
    SetupHook(hKernel32, "CloseHandle", (void**)&fpCloseHandle, hkCloseHandle);
    SetupHook(hKernel32, "QueueUserAPC", (void**)&fpQueueUserAPC, hkQueueUserAPC);
    SetupHook(hKernel32, "GetModuleHandleW", (void**)&fpGetModuleHandleW, hkGetModuleHandleW);
    SetupHook(hKernel32, "WaitForSingleObject", (void**)&fpWaitForSingleObject, hkWaitForSingleObject);
    SetupHook(hKernel32, "CreateToolhelp32Snapshot", (void**)&fpCreateToolhelp32Snapshot, hkCreateToolhelp32Snapshot);
    SetupHook(hKernel32, "CreateFileA", (void**)&fpCreateFileA, hkCreateFileA);
    SetupHook(hKernel32, "CreateFileW", (void**)&fpCreateFileW, hkCreateFileW);
    SetupHook(hKernel32, "WriteFile", (void**)&fpWriteFile, hkWriteFile);
    SetupHook(hKernel32, "CreateFileMappingA", (void**)&fpCreateFileMappingA, hkCreateFileMappingA);
    SetupHook(hKernel32, "CreateFileMappingW", (void**)&fpCreateFileMappingW, hkCreateFileMappingW);
    SetupHook(hKernel32, "MapViewOfFile", (void**)&fpMapViewOfFile, hkMapViewOfFile);
    SetupHook(hKernel32, "DuplicateHandle", (void**)&fpDuplicateHandle, hkDuplicateHandle);
    SetupHook(hKernel32, "CreateNamedPipeA", (void**)&fpCreateNamedPipeA, hkCreateNamedPipeA);
    SetupHook(hKernel32, "CreateNamedPipeW", (void**)&fpCreateNamedPipeW, hkCreateNamedPipeW);
    SetupHook(hKernel32, "ConnectNamedPipe", (void**)&fpConnectNamedPipe, hkConnectNamedPipe);
    SetupHook(hKernel32, "OpenMutexA", (void**)&fpOpenMutexA, hkOpenMutexA);
    SetupHook(hKernel32, "OpenMutexW", (void**)&fpOpenMutexW, hkOpenMutexW);
    SetupHook(hKernel32, "CreateMutexA", (void**)&fpCreateMutexA, hkCreateMutexA);
    SetupHook(hKernel32, "CreateMutexW", (void**)&fpCreateMutexW, hkCreateMutexW);
    //SetupHook(hKernel32, "Process32First", (void**)&fpProcess32FirstA, hkProcess32FirstA);
    //SetupHook(hKernel32, "Process32Next", (void**)&fpProcess32NextA, hkProcess32NextA);
    //SetupHook(hKernel32, "Process32FirstW", (void**)&fpProcess32FirstW, hkProcess32FirstW);
    //SetupHook(hKernel32, "Process32NextW", (void**)&fpProcess32NextW, hkProcess32NextW); SetupHook("kernel32.dll", "GetProcessId", (void**)&fpGetProcessId, hkGetProcessId);
    //SetupHook(hKernel32, "GetModuleFileNameA", (void**)&fpGetModuleFileNameA, hkGetModuleFileNameA);
    //SetupHook(hKernel32, "GetModuleFileNameW", (void**)&fpGetModuleFileNameW, hkGetModuleFileNameW);

    /*SetupHook(hUser32, "SetWindowsHookExA", (void**)&fpSetWindowsHookExA, hkSetWindowsHookExA);
    SetupHook(hUser32, "SetWindowsHookExW", (void**)&fpSetWindowsHookExW, hkSetWindowsHookExW);
    SetupHook(hUser32, "SetWinEventHook", (void**)&fpSetWinEventHook, hkSetWinEventHook);
    SetupHook(hAdvapi, "RegSetValueExA", (void**)&fpRegSetValueExA, hkRegSetValueExA);
    SetupHook(hAdvapi, "RegSetValueExW", (void**)&fpRegSetValueExW, hkRegSetValueExW);
    SetupHook(hAdvapi, "RegCreateKeyExA", (void**)&fpRegCreateKeyExA, hkRegCreateKeyExA);
    SetupHook(hAdvapi, "RegCreateKeyExW", (void**)&fpRegCreateKeyExW, hkRegCreateKeyExW);
    SetupHook(hAdvapi, "CreateServiceA", (void**)&fpCreateServiceA, hkCreateServiceA);
    SetupHook(hAdvapi, "CreateServiceW", (void**)&fpCreateServiceW, hkCreateServiceW);
    SetupHook(hAdvapi, "StartServiceA", (void**)&fpStartServiceA, hkStartServiceA);
    SetupHook(hAdvapi, "StartServiceW", (void**)&fpStartServiceW, hkStartServiceW);*/
    

    // SetupHook(hNtdll, "NtClose", (void**)&NtClose, hkNtClose);
    SetupHook(hNtdll, "NtOpenProcess", (void**)&NtOpenProcess, hkNtOpenProcess);
    SetupHook(hNtdll, "NtOpenThread", (void**)&NtOpenThread, hkNtOpenThread);
    SetupHook(hNtdll, "NtAllocateVirtualMemory", (void**)&NtAllocateVirtualMemory, hkNtAllocateVirtualMemory);
    SetupHook(hNtdll, "NtProtectVirtualMemory", (void**)&NtProtectVirtualMemory, hkNtProtectVirtualMemory);
    SetupHook(hNtdll, "NtWriteVirtualMemory", (void**)&NtWriteVirtualMemory, hkNtWriteVirtualMemory);
    SetupHook(hNtdll, "NtCreateThreadEx", (void**)&NtCreateThreadEx, hkNtCreateThreadEx);
    SetupHook(hNtdll, "NtCreateThread", (void**)&NtCreateThread, hkNtCreateThread);
    SetupHook(hNtdll, "NtWaitForSingleObject", (void**)&NtWaitForSingleObject, hkNtWaitForSingleObject);
    // SetupHook(hNtdll, "NtFreeVirtualMemory", (void**)&NtFreeVirtualMemory, hkNtFreeVirtualMemory);
    SetupHook(hNtdll, "NtSuspendThread", (void**)&NtSuspendThread, hkNtSuspendThread);
    SetupHook(hNtdll, "NtResumeThread", (void**)&NtResumeThread, hkNtResumeThread);
    SetupHook(hNtdll, "NtGetContextThread", (void**)&NtGetContextThread, hkNtGetContextThread);
    SetupHook(hNtdll, "NtSetContextThread", (void**)&NtSetContextThread, hkNtSetContextThread);
    SetupHook(hNtdll, "NtQuerySystemInformation", (void**)&NtQuerySystemInformation, hkNtQuerySystemInformation);
    SetupHook(hNtdll, "NtQueryInformationProcess", (void**)&NtQueryInformationProcess, hkNtQueryInformationProcess);
    SetupHook(hNtdll, "NtQueryInformationThread", (void**)&NtQueryInformationThread, hkNtQueryInformationThread);
    SetupHook(hNtdll, "NtSetInformationThread", (void**)&NtSetInformationThread, hkNtSetInformationThread);
    SetupHook(hNtdll, "NtSetInformationProcess", (void**)&NtSetInformationProcess, hkNtSetInformationProcess);
    SetupHook(hNtdll, "NtReadVirtualMemory", (void**)&NtReadVirtualMemory, hkNtReadVirtualMemory);
    /*SetupHook(hNtdll, "NtQueryVirtualMemory", (void**)&NtQueryVirtualMemory, hkNtQueryVirtualMemory);
    SetupHook(hNtdll, "NtQueryObject", (void**)&NtQueryObject, hkNtQueryObject);
    SetupHook(hNtdll, "NtOpenSection", (void**)&NtOpenSection, hkNtOpenSection);
    SetupHook(hNtdll, "NtMapViewOfSection", (void**)&NtMapViewOfSection, hkNtMapViewOfSection);
    SetupHook(hNtdll, "NtUnmapViewOfSection", (void**)&NtUnmapViewOfSection, hkNtUnmapViewOfSection);
    SetupHook(hNtdll, "NtQueryInformationFile", (void**)&NtQueryInformationFile, hkNtQueryInformationFile);
    SetupHook(hNtdll, "LdrLoadDll", (void**)&fpLdrLoadDll, hkLdrLoadDll); */
    SetupHook(hNtdll, "NtCreateFile", (void**)&NtCreateFile, hkNtCreateFile);
    SetupHook(hNtdll, "NtOpenFile", (void**)&NtOpenFile, hkNtOpenFile);
    SetupHook(hNtdll, "NtQueueApcThread", (void**)&NtQueueApcThread, hkNtQueueApcThread);

    std::printf("[-] WinAPI monitoring hooks installed \n\n");
    g_enableLogging = true;
    fflush(stdout);
    return 0;
}


BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID lp) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            CreateThread(nullptr, 0, Init, nullptr, 0, nullptr);
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
