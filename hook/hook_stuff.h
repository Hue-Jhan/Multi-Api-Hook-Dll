#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include "MinHook.h"
#include "log_stuff.h"
#include "detection.h"
#pragma comment(lib, "libMinHook.x64.lib")
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// void SetupHook(LPCSTR mod, LPCSTR funcName, void** originalPtr, void* detour);
static inline bool IsLoadLibraryName(const char* name) {
    if (!name) return false;
    return _stricmp(name, "LoadLibraryA") == 0 ||
        _stricmp(name, "LoadLibraryW") == 0 ||
        _stricmp(name, "LoadLibraryExA") == 0 ||
        _stricmp(name, "LoadLibraryExW") == 0;
}

typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR);
typedef HMODULE(WINAPI* LoadLibraryW_t)(LPCWSTR);
typedef HMODULE(WINAPI* LoadLibraryExA_t)(LPCSTR, HANDLE, DWORD);
typedef HMODULE(WINAPI* LoadLibraryExW_t)(LPCWSTR, HANDLE, DWORD);
typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE, LPCSTR);
typedef HANDLE(WINAPI* CreateThread_t)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HANDLE(WINAPI* CreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HANDLE(WINAPI* CreateRemoteThreadEx_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD, LPVOID);
typedef LPVOID(WINAPI* VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef LPVOID(WINAPI* VirtualAllocEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL(WINAPI* VirtualProtectEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL(WINAPI* WriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef DWORD(WINAPI* SuspendThread_t)(HANDLE);
typedef DWORD(WINAPI* ResumeThread_t)(HANDLE);
typedef HANDLE(WINAPI* OpenProcess_t)(DWORD, BOOL, DWORD);
typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);
typedef BOOL(WINAPI* GetThreadContext_t)(HANDLE, LPCONTEXT);
typedef BOOL(WINAPI* SetThreadContext_t)(HANDLE, const CONTEXT*);
typedef ULONG(WINAPI* QueueUserAPC_t)(PAPCFUNC, HANDLE, ULONG_PTR);
typedef HMODULE(WINAPI* GetModuleHandleW_t)(LPCWSTR);
typedef DWORD(WINAPI* WaitForSingleObject_t)(HANDLE, DWORD);
typedef HANDLE(WINAPI* CreateToolhelp32Snapshot_t)(DWORD, DWORD); 
typedef DWORD(WINAPI* GetProcessId_t)(HANDLE);
typedef BOOL(WINAPI* Process32FirstA_t)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI* Process32NextA_t)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI* Process32FirstW_t)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL(WINAPI* Process32NextW_t)(HANDLE, LPPROCESSENTRY32W);
typedef DWORD(WINAPI* GetModuleFileNameA_t)(HMODULE, LPSTR, DWORD);
typedef DWORD(WINAPI* GetModuleFileNameW_t)(HMODULE, LPWSTR, DWORD);

typedef HHOOK(WINAPI* SetWindowsHookExA_t)(int, HOOKPROC, HINSTANCE, DWORD);
typedef HHOOK(WINAPI* SetWindowsHookExW_t)(int, HOOKPROC, HINSTANCE, DWORD);
typedef HWINEVENTHOOK(WINAPI* SetWinEventHook_t)(UINT, UINT, HMODULE, WINEVENTPROC, DWORD, DWORD, DWORD);
typedef HANDLE(WINAPI* CreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE(WINAPI* CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI* WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef HANDLE(WINAPI* CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef HANDLE(WINAPI* CreateFileMappingW_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
typedef LPVOID(WINAPI* MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef LSTATUS(WINAPI* RegSetValueExA_t)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LSTATUS(WINAPI* RegSetValueExW_t)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LSTATUS(WINAPI* RegCreateKeyExA_t)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LSTATUS(WINAPI* RegCreateKeyExW_t)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef SC_HANDLE(WINAPI* CreateServiceA_t)(SC_HANDLE, LPCSTR, LPCSTR, DWORD, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR);
typedef SC_HANDLE(WINAPI* CreateServiceW_t)(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
typedef BOOL(WINAPI* StartServiceA_t)(SC_HANDLE, DWORD, LPCSTR*);
typedef BOOL(WINAPI* StartServiceW_t)(SC_HANDLE, DWORD, LPCWSTR*);
typedef BOOL(WINAPI* DuplicateHandle_t)(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
typedef HANDLE(WINAPI* CreateNamedPipeA_t)(LPCSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
typedef HANDLE(WINAPI* CreateNamedPipeW_t)(LPCWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
typedef BOOL(WINAPI* ConnectNamedPipe_t)(HANDLE, LPOVERLAPPED);
typedef HANDLE(WINAPI* OpenMutexA_t)(DWORD, BOOL, LPCSTR);
typedef HANDLE(WINAPI* OpenMutexW_t)(DWORD, BOOL, LPCWSTR);
typedef HANDLE(WINAPI* CreateMutexA_t)(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
typedef HANDLE(WINAPI* CreateMutexW_t)(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR);


extern LoadLibraryA_t fpLoadLibraryA;
extern LoadLibraryW_t fpLoadLibraryW;
extern LoadLibraryExA_t fpLoadLibraryExA;
extern LoadLibraryExW_t fpLoadLibraryExW;
extern GetProcAddress_t fpGetProcAddress;
extern CreateThread_t fpCreateThread;
extern CreateRemoteThread_t fpCreateRemoteThread;
extern CreateRemoteThreadEx_t fpCreateRemoteThreadEx;
extern VirtualAlloc_t fpVirtualAlloc;
extern VirtualAllocEx_t fpVirtualAllocEx;
extern VirtualProtect_t fpVirtualProtect;
extern VirtualProtectEx_t fpVirtualProtectEx;
extern WriteProcessMemory_t fpWriteProcessMemory;
extern SuspendThread_t fpSuspendThread;
extern ResumeThread_t fpResumeThread;
extern OpenProcess_t fpOpenProcess;
extern CloseHandle_t fpCloseHandle;
extern GetThreadContext_t fpGetThreadContext;
extern SetThreadContext_t fpSetThreadContext;
extern QueueUserAPC_t fpQueueUserAPC;
extern GetModuleHandleW_t fpGetModuleHandleW;
extern WaitForSingleObject_t fpWaitForSingleObject;
extern CreateToolhelp32Snapshot_t fpCreateToolhelp32Snapshot;
extern Process32FirstA_t fpProcess32FirstA;
extern Process32NextA_t fpProcess32NextA;
extern Process32FirstW_t fpProcess32FirstW;
extern Process32NextW_t fpProcess32NextW;
extern GetProcessId_t fpGetProcessId;
extern GetModuleFileNameA_t fpGetModuleFileNameA;
extern GetModuleFileNameW_t fpGetModuleFileNameW;
// extern LdrLoadDll_t fpLdrLoadDll;
extern SetWindowsHookExA_t fpSetWindowsHookExA;
extern SetWindowsHookExW_t fpSetWindowsHookExW;
extern SetWinEventHook_t fpSetWinEventHook;
extern CreateFileA_t fpCreateFileA;
extern CreateFileW_t fpCreateFileW;
extern WriteFile_t fpWriteFile;
extern CreateFileMappingA_t fpCreateFileMappingA;
extern CreateFileMappingW_t fpCreateFileMappingW;
extern MapViewOfFile_t fpMapViewOfFile;
extern RegSetValueExA_t fpRegSetValueExA;
extern RegSetValueExW_t fpRegSetValueExW;
extern RegCreateKeyExA_t fpRegCreateKeyExA;
extern RegCreateKeyExW_t fpRegCreateKeyExW;
extern CreateServiceA_t fpCreateServiceA;
extern CreateServiceW_t fpCreateServiceW;
extern StartServiceA_t fpStartServiceA;
extern StartServiceW_t fpStartServiceW;
extern DuplicateHandle_t fpDuplicateHandle;
extern CreateNamedPipeA_t fpCreateNamedPipeA;
extern CreateNamedPipeW_t fpCreateNamedPipeW;
extern ConnectNamedPipe_t fpConnectNamedPipe;
extern OpenMutexA_t fpOpenMutexA;
extern OpenMutexW_t fpOpenMutexW;
extern CreateMutexA_t fpCreateMutexA;
extern CreateMutexW_t fpCreateMutexW;


HMODULE WINAPI hkLoadLibraryA(LPCSTR name);
HMODULE WINAPI hkLoadLibraryW(LPCWSTR name);
HMODULE WINAPI hkLoadLibraryExA(LPCSTR name, HANDLE h, DWORD flags);
HMODULE WINAPI hkLoadLibraryExW(LPCWSTR name, HANDLE h, DWORD flags);
//NTSTATUS NTAPI hkLdrLoadDll(PWCHAR path, ULONG flags, PUNICODE_STRING name, PHANDLE handle);
FARPROC WINAPI hkGetProcAddress(HMODULE mod, LPCSTR name);
HANDLE WINAPI hkCreateThread(LPSECURITY_ATTRIBUTES a, SIZE_T s, LPTHREAD_START_ROUTINE st, LPVOID p, DWORD f, LPDWORD id);
HANDLE WINAPI hkCreateRemoteThread(HANDLE h, LPSECURITY_ATTRIBUTES a, SIZE_T s, LPTHREAD_START_ROUTINE st, LPVOID p, DWORD f, LPDWORD id);
HANDLE WINAPI hkCreateRemoteThreadEx(HANDLE h, LPSECURITY_ATTRIBUTES a, SIZE_T s, LPTHREAD_START_ROUTINE st, LPVOID p, DWORD f, LPDWORD id, LPVOID attr);
LPVOID WINAPI hkVirtualAlloc(LPVOID addr, SIZE_T size, DWORD type, DWORD protect);
LPVOID WINAPI hkVirtualAllocEx(HANDLE h, LPVOID addr, SIZE_T size, DWORD type, DWORD protect);
BOOL WINAPI hkWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
BOOL WINAPI hkVirtualProtect(LPVOID addr, SIZE_T size, DWORD protect, PDWORD oldProt);
BOOL WINAPI hkVirtualProtectEx(HANDLE h, LPVOID addr, SIZE_T size, DWORD protect, PDWORD oldProt);
DWORD WINAPI hkSuspendThread(HANDLE hThread);
DWORD WINAPI hkResumeThread(HANDLE hThread);
BOOL WINAPI hkGetThreadContext(HANDLE h, LPCONTEXT c);
BOOL WINAPI hkSetThreadContext(HANDLE h, const CONTEXT* c);
HANDLE WINAPI hkOpenProcess(DWORD access, BOOL inh, DWORD pid);
BOOL WINAPI hkCloseHandle(HANDLE h);
ULONG WINAPI hkQueueUserAPC(PAPCFUNC fn, HANDLE h, ULONG_PTR p);
HMODULE WINAPI hkGetModuleHandleW(LPCWSTR name);
DWORD WINAPI hkWaitForSingleObject(HANDLE h, DWORD timeout);
HANDLE WINAPI hkCreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
BOOL WINAPI hkProcess32FirstA(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
BOOL WINAPI hkProcess32NextA(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
BOOL WINAPI hkProcess32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
BOOL WINAPI hkProcess32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
DWORD WINAPI hkGetProcessId(HANDLE Process);
DWORD WINAPI hkGetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize);
DWORD WINAPI hkGetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);

HHOOK WINAPI hkSetWindowsHookExA(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId);
HHOOK WINAPI hkSetWindowsHookExW(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId);
HWINEVENTHOOK WINAPI hkSetWinEventHook(UINT eventMin, UINT eventMax, HMODULE hmodWinEventProc, WINEVENTPROC pfn, DWORD idProcess, DWORD idThread, DWORD dwFlags);
HANDLE WINAPI hkCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
HANDLE WINAPI hkCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
BOOL WINAPI hkWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
HANDLE WINAPI hkCreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
HANDLE WINAPI hkCreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName);
LPVOID WINAPI hkMapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
LSTATUS WINAPI hkRegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData);
LSTATUS WINAPI hkRegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition);
LSTATUS WINAPI hkRegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData);
LSTATUS WINAPI hkRegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition);
SC_HANDLE WINAPI hkCreateServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, LPCSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName, LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies, LPCSTR lpServiceStartName, LPCSTR lpPassword);
BOOL WINAPI hkStartServiceA(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCSTR* lpServiceArgVectors);
SC_HANDLE WINAPI hkCreateServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword);
BOOL WINAPI hkStartServiceW(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCWSTR* lpServiceArgVectors);
BOOL WINAPI hkDuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
HANDLE WINAPI hkCreateNamedPipeA(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
BOOL WINAPI hkConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped);
HANDLE WINAPI hkOpenMutexA(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName);
HANDLE WINAPI hkCreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName);
HANDLE WINAPI hkCreateNamedPipeW(LPCWSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
HANDLE WINAPI hkOpenMutexW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName);
HANDLE WINAPI hkCreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName);


