#include "pch.h"
#include "hook_stuff.h"
#include "nt_hooks.h"

void SetupHook(LPCSTR mod, LPCSTR funcName, void** originalPtr, void* detour) {
    HMODULE h = GetModuleHandleA(mod);
    if (!h) {
        std::fprintf(stderr, "[!] cannot getmodule %s\n", mod);
        return; }
    void* target = (void*)GetProcAddress(h, funcName);
    if (!target) {
        std::fprintf(stderr, "[!] cannot getproc %s!%s\n", mod, funcName);
        return;
    } if (MH_CreateHook(target, detour, originalPtr) != MH_OK) {
        std::fprintf(stderr, "[!] MH_CreateHook failed for %s!%s\n", mod, funcName);
        return;
    } if (MH_EnableHook(target) != MH_OK) {
        std::fprintf(stderr, "[!] MH_EnableHook failed for %s!%s\n", mod, funcName);
        return; }
}

DWORD WINAPI Init(LPVOID) {
    if (AllocConsole()) {
        FILE* fpOut = nullptr;
        FILE* fpErr = nullptr;
        freopen_s(&fpOut, "CONOUT$", "w", stdout);
        freopen_s(&fpErr, "CONOUT$", "w", stderr);
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0); }

    if (MH_Initialize() != MH_OK) {
        std::fprintf(stderr, "[!] MH_Initialize failed\n");
        return 0; }
    cambiaColore(FOREGROUND_GREEN);
    printf("\n");
    
    /*HMODULE k = GetModuleHandleA("kernel32.dll");
    if (!k) {
        std::fprintf(stderr, "[!] cannot getmodule %s\n", "Kernel32.dll");
        return 0; }

    HMODULE n = GetModuleHandleA("ntdll.dll");
    if (!n) {
        std::fprintf(stderr, "[!] cannot getmodule %s\n", "Ntdll.dll");
        return 0; }

    HMODULE u = GetModuleHandleA("user32.dll");
    if (!u) {
        std::fprintf(stderr, "[!] cannot getmodule %s\n", "user32.dll");
        return 0; }

    HMODULE a = GetModuleHandleA("advapi32.dll");
    if (!a) {
        std::fprintf(stderr, "[!] cannot getmodule %s\n", "Advapi32.dll");
        return 0; }*/

    SetupHook("kernel32.dll", "LoadLibraryA", (void**)&fpLoadLibraryA, hkLoadLibraryA);
    SetupHook("kernel32.dll", "LoadLibraryW", (void**)&fpLoadLibraryW, hkLoadLibraryW);
    SetupHook("kernel32.dll", "LoadLibraryExA", (void**)&fpLoadLibraryExA, hkLoadLibraryExA);
    SetupHook("kernel32.dll", "LoadLibraryExW", (void**)&fpLoadLibraryExW, hkLoadLibraryExW);
    SetupHook("kernel32.dll", "GetProcAddress", (void**)&fpGetProcAddress, hkGetProcAddress);
    SetupHook("kernel32.dll", "CreateThread", (void**)&fpCreateThread, hkCreateThread);
    SetupHook("kernel32.dll", "CreateRemoteThread", (void**)&fpCreateRemoteThread, hkCreateRemoteThread);
    SetupHook("kernel32.dll", "CreateRemoteThreadEx", (void**)&fpCreateRemoteThreadEx, hkCreateRemoteThreadEx);
    SetupHook("kernel32.dll", "VirtualAlloc", (void**)&fpVirtualAlloc, hkVirtualAlloc);
    SetupHook("kernel32.dll", "VirtualAllocEx", (void**)&fpVirtualAllocEx, hkVirtualAllocEx);
    SetupHook("kernel32.dll", "WriteProcessMemory", (void**)&fpWriteProcessMemory, hkWriteProcessMemory);
    SetupHook("kernel32.dll", "VirtualProtect", (void**)&fpVirtualProtect, hkVirtualProtect);
    SetupHook("kernel32.dll", "VirtualProtectEx", (void**)&fpVirtualProtectEx, hkVirtualProtectEx);   
    SetupHook("kernel32.dll", "SuspendThread", (void**)&fpSuspendThread, hkSuspendThread);
    SetupHook("kernel32.dll", "ResumeThread", (void**)&fpResumeThread, hkResumeThread);
    SetupHook("kernel32.dll", "GetThreadContext", (void**)&fpGetThreadContext, hkGetThreadContext);
    SetupHook("kernel32.dll", "SetThreadContext", (void**)&fpSetThreadContext, hkSetThreadContext);
    SetupHook("kernel32.dll", "OpenProcess", (void**)&fpOpenProcess, hkOpenProcess);
    SetupHook("kernel32.dll", "CloseHandle", (void**)&fpCloseHandle, hkCloseHandle);
    SetupHook("kernel32.dll", "QueueUserAPC", (void**)&fpQueueUserAPC, hkQueueUserAPC);
    SetupHook("kernel32.dll", "GetModuleHandleW", (void**)&fpGetModuleHandleW, hkGetModuleHandleW);
    SetupHook("kernel32.dll", "WaitForSingleObject", (void**)&fpWaitForSingleObject, hkWaitForSingleObject);
    SetupHook("kernel32.dll", "CreateToolhelp32Snapshot", (void**)&fpCreateToolhelp32Snapshot, hkCreateToolhelp32Snapshot);
    //SetupHook("kernel32.dll", "Process32First", (void**)&fpProcess32FirstA, hkProcess32FirstA);
    //SetupHook("kernel32.dll", "Process32Next", (void**)&fpProcess32NextA, hkProcess32NextA);
    //SetupHook("kernel32.dll", "Process32FirstW", (void**)&fpProcess32FirstW, hkProcess32FirstW);
    //SetupHook("kernel32.dll", "Process32NextW", (void**)&fpProcess32NextW, hkProcess32NextW); SetupHook("kernel32.dll", "GetProcessId", (void**)&fpGetProcessId, hkGetProcessId);
    //SetupHook("kernel32.dll", "GetModuleFileNameA", (void**)&fpGetModuleFileNameA, hkGetModuleFileNameA);
    //SetupHook("kernel32.dll", "GetModuleFileNameW", (void**)&fpGetModuleFileNameW, hkGetModuleFileNameW);

    //SetupHook("user32.dll", "SetWindowsHookExA", (void**)&fpSetWindowsHookExA, hkSetWindowsHookExA);
    //SetupHook("user32.dll", "SetWindowsHookExW", (void**)&fpSetWindowsHookExW, hkSetWindowsHookExW);
    //SetupHook("user32.dll", "SetWinEventHook", (void**)&fpSetWinEventHook, hkSetWinEventHook);
    SetupHook("kernel32.dll", "CreateFileA", (void**)&fpCreateFileA, hkCreateFileA);
    SetupHook("kernel32.dll", "CreateFileW", (void**)&fpCreateFileW, hkCreateFileW);
    SetupHook("kernel32.dll", "WriteFile", (void**)&fpWriteFile, hkWriteFile);
    SetupHook("kernel32.dll", "CreateFileMappingA", (void**)&fpCreateFileMappingA, hkCreateFileMappingA);
    SetupHook("kernel32.dll", "CreateFileMappingW", (void**)&fpCreateFileMappingW, hkCreateFileMappingW);
    SetupHook("kernel32.dll", "MapViewOfFile", (void**)&fpMapViewOfFile, hkMapViewOfFile);
    /*SetupHook("advapi32.dll", "RegSetValueExA", (void**)&fpRegSetValueExA, hkRegSetValueExA);
    SetupHook("advapi32.dll", "RegSetValueExW", (void**)&fpRegSetValueExW, hkRegSetValueExW);
    SetupHook("advapi32.dll", "RegCreateKeyExA", (void**)&fpRegCreateKeyExA, hkRegCreateKeyExA);
    SetupHook("advapi32.dll", "RegCreateKeyExW", (void**)&fpRegCreateKeyExW, hkRegCreateKeyExW);
    SetupHook("advapi32.dll", "CreateServiceA", (void**)&fpCreateServiceA, hkCreateServiceA);
    SetupHook("advapi32.dll", "CreateServiceW", (void**)&fpCreateServiceW, hkCreateServiceW);
    SetupHook("advapi32.dll", "StartServiceA", (void**)&fpStartServiceA, hkStartServiceA);
    SetupHook("advapi32.dll", "StartServiceW", (void**)&fpStartServiceW, hkStartServiceW);*/
    SetupHook("kernel32.dll", "DuplicateHandle", (void**)&fpDuplicateHandle, hkDuplicateHandle);
    SetupHook("kernel32.dll", "CreateNamedPipeA", (void**)&fpCreateNamedPipeA, hkCreateNamedPipeA);
    SetupHook("kernel32.dll", "CreateNamedPipeW", (void**)&fpCreateNamedPipeW, hkCreateNamedPipeW);
    SetupHook("kernel32.dll", "ConnectNamedPipe", (void**)&fpConnectNamedPipe, hkConnectNamedPipe);
    SetupHook("kernel32.dll", "OpenMutexA", (void**)&fpOpenMutexA, hkOpenMutexA);
    SetupHook("kernel32.dll", "OpenMutexW", (void**)&fpOpenMutexW, hkOpenMutexW);
    SetupHook("kernel32.dll", "CreateMutexA", (void**)&fpCreateMutexA, hkCreateMutexA);
    SetupHook("kernel32.dll", "CreateMutexW", (void**)&fpCreateMutexW, hkCreateMutexW);


    //SetupHook("ntdll.dll", "NtClose", (void**)&NtClose, hkNtClose);
    SetupHook("ntdll.dll", "NtOpenProcess", (void**)&NtOpenProcess, hkNtOpenProcess);
    SetupHook("ntdll.dll", "NtOpenThread", (void**)&NtOpenThread, hkNtOpenThread);
    SetupHook("ntdll.dll", "NtAllocateVirtualMemory", (void**)&NtAllocateVirtualMemory, hkNtAllocateVirtualMemory);
    SetupHook("ntdll.dll", "NtProtectVirtualMemory", (void**)&NtProtectVirtualMemory, hkNtProtectVirtualMemory);
    SetupHook("ntdll.dll", "NtWriteVirtualMemory", (void**)&NtWriteVirtualMemory, hkNtWriteVirtualMemory);
    SetupHook("ntdll.dll", "NtCreateThreadEx", (void**)&NtCreateThreadEx, hkNtCreateThreadEx);
    SetupHook("ntdll.dll", "NtCreateThread", (void**)&NtCreateThread, hkNtCreateThread);
    SetupHook("ntdll.dll", "NtWaitForSingleObject", (void**)&NtWaitForSingleObject, hkNtWaitForSingleObject);
    // SetupHook("ntdll.dll", "NtFreeVirtualMemory", (void**)&NtFreeVirtualMemory, hkNtFreeVirtualMemory);
    SetupHook("ntdll.dll", "NtSuspendThread", (void**)&NtSuspendThread, hkNtSuspendThread);
    SetupHook("ntdll.dll", "NtResumeThread", (void**)&NtResumeThread, hkNtResumeThread);
    SetupHook("ntdll.dll", "NtGetContextThread", (void**)&NtGetContextThread, hkNtGetContextThread);
    SetupHook("ntdll.dll", "NtSetContextThread", (void**)&NtSetContextThread, hkNtSetContextThread);
    SetupHook("ntdll.dll", "NtQuerySystemInformation", (void**)&NtQuerySystemInformation, hkNtQuerySystemInformation);
    SetupHook("ntdll.dll", "NtQueryInformationProcess", (void**)&NtQueryInformationProcess, hkNtQueryInformationProcess);
    SetupHook("ntdll.dll", "NtQueryInformationThread", (void**)&NtQueryInformationThread, hkNtQueryInformationThread);
    /*SetupHook("ntdll.dll", "NtReadVirtualMemory", (void**)&NtReadVirtualMemory, hkNtReadVirtualMemory);
    SetupHook("ntdll.dll", "NtQueryVirtualMemory", (void**)&NtQueryVirtualMemory, hkNtQueryVirtualMemory);
    SetupHook("ntdll.dll", "NtQueryObject", (void**)&NtQueryObject, hkNtQueryObject);
    SetupHook("ntdll.dll", "NtOpenSection", (void**)&NtOpenSection, hkNtOpenSection);
    SetupHook("ntdll.dll", "NtMapViewOfSection", (void**)&NtMapViewOfSection, hkNtMapViewOfSection);
    SetupHook("ntdll.dll", "NtUnmapViewOfSection", (void**)&NtUnmapViewOfSection, hkNtUnmapViewOfSection);
    SetupHook("ntdll.dll", "NtQueryInformationFile", (void**)&NtQueryInformationFile, hkNtQueryInformationFile);
    */SetupHook("ntdll.dll", "NtSetInformationThread", (void**)&NtSetInformationThread, hkNtSetInformationThread);
    SetupHook("ntdll.dll", "NtSetInformationProcess", (void**)&NtSetInformationProcess, hkNtSetInformationProcess);
    //SetupHook("ntdll.dll", "LdrLoadDll", (void**)&fpLdrLoadDll, hkLdrLoadDll);
    SetupHook("ntdll.dll", "NtCreateFile", (void**)&NtCreateFile, hkNtCreateFile);
    SetupHook("ntdll.dll", "NtOpenFile", (void**)&NtOpenFile, hkNtOpenFile);
    SetupHook("ntdll.dll", "NtQueueApcThread", (void**)&NtQueueApcThread, hkNtQueueApcThread);


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
