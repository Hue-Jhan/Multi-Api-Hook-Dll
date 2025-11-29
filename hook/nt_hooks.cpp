#include "nt_hooks.h"
#include "detection.h"

static std::string WideToUtf8(const wchar_t* w) {
    if (!w) return "(null)";
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    std::string out(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &out[0], len, NULL, NULL);
    return out;
}

static std::string ExtractFileNameFromNtPath(const wchar_t* wpath) {
    if (!wpath || !wpath[0])
        return "(null)";

    const wchar_t* lastSlash = wcsrchr(wpath, L'\\');
    if (!lastSlash)
        return WideToUtf8(wpath);

    return WideToUtf8(lastSlash + 1);
}

xd_NtClose NtClose = NULL;
xd_NtOpenProcess NtOpenProcess = NULL;
xd_NtOpenThread NtOpenThread = NULL;
xd_NtAllocateVirtualMemory NtAllocateVirtualMemory = NULL;
xd_NtWriteVirtualMemory NtWriteVirtualMemory = NULL;
xd_NtProtectVirtualMemory NtProtectVirtualMemory = NULL;
xd_NtCreateThreadEx NtCreateThreadEx = NULL;
xd_NtCreateThread NtCreateThread = NULL;
xd_NtWaitForSingleObject NtWaitForSingleObject = NULL;
xd_NtFreeVirtualMemory NtFreeVirtualMemory = NULL;
xd_NtSuspendThread NtSuspendThread = NULL;
xd_NtResumeThread NtResumeThread = NULL;
xd_NtGetContextThread NtGetContextThread = NULL;
xd_NtSetContextThread NtSetContextThread = NULL;
xd_NtQuerySystemInformation NtQuerySystemInformation = NULL;
NtReadVirtualMemory_t NtReadVirtualMemory = NULL;
NtQueryVirtualMemory_t NtQueryVirtualMemory = NULL;
NtQueryObject_t NtQueryObject = NULL;
NtQueryInformationThread_t NtQueryInformationThread = NULL;
NtOpenSection_t NtOpenSection = NULL;
NtMapViewOfSection_t NtMapViewOfSection = NULL;
NtUnmapViewOfSection_t NtUnmapViewOfSection = NULL;
NtQueryInformationFile_t NtQueryInformationFile = NULL;
NtSetInformationThread_t NtSetInformationThread = NULL;
NtSetInformationProcess_t NtSetInformationProcess = NULL;
NtCreateFile_t NtCreateFile = NULL;
NtOpenFile_t NtOpenFile = NULL;
LdrLoadDll_t fpLdrLoadDll = NULL;
NtQueryInformationProcess_t NtQueryInformationProcess = NULL;
NtQueueApcThread_t NtQueueApcThread = NULL;
NtCreateSnapshot_t NtCreateSnapshot = NULL;
//hkNtQueryInformationProcess_ModuleList_t NtQueryInformationProcess_ModuleList = NULL;
//hkNtQuerySystemInformation_Process_t NtQuerySystemInformation_Process = NULL;


NTSTATUS NTAPI hkNtClose(HANDLE Handle) {
    if (g_suppressNtLogging) {
        printf("nt counterpart for ntclose not logged\n");
        return NtClose(Handle);
    }
    LOGFUNC("NtClose", "handle=0x%llx", (void*)Handle);
    return NtClose(Handle);
}
NTSTATUS NTAPI hkNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    if (g_suppressNtLogging) {
        printf("nt counterpart for open process not logged\n");
        return NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
    LOGFUNC("NtOpenProcess", "pid=0x%llx access=0x%X", (void*)ClientId->UniqueProcess, DesiredAccess);
    return NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}
NTSTATUS NTAPI hkNtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    if (g_suppressNtLogging) {
        printf("nt counterpart for open thread not logged\n");
        return NtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
    LOGFUNC("NtOpenThread", "tid=0x%llx access=0x%X", (void*)ClientId->UniqueThread, DesiredAccess);
    return NtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
}
NTSTATUS NTAPI hkNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    SIZE_T size = RegionSize ? *RegionSize : 0;
    if (ShouldIgnoreAllocation(size, _ReturnAddress()))
        return NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    if (g_suppressNtLogging) {
        printf("nt counterpart for allocate virtual memory not logged\n");
        return NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect); }

    LOGFUNC("NtAllocateVirtualMemory", "proc=0x%llX size=%llu type=0x%X prot=0x%X", (void*)ProcessHandle, (unsigned long long) * RegionSize, AllocationType, Protect);
    NTSTATUS st = NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

    if (IsRWX(Protect)) PushRWXEvent("NtAllocateVirtualMemory", BaseAddress, size, Protect, _ReturnAddress());
    if (NT_SUCCESS(st)) record_alloc((uintptr_t)*BaseAddress, size, Protect, GetCurrentThreadId(), GetProcessId(ProcessHandle), "NtAllocateVirtualMemory");
    return st;
}
NTSTATUS NTAPI hkNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
    SIZE_T size = RegionSize ? *RegionSize : 0;
    PVOID addr = BaseAddress ? *BaseAddress : nullptr;
    if (ShouldIgnoreAllocation(size, _ReturnAddress())) return NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);

    if (g_suppressNtLogging) {
        printf("nt counterpart for protect virtual memory not logged\n");
        return NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect); }

    LOGFUNC("NtProtectVirtualMemory", "proc=0x%llX addr=0x%llx size=%llu newProt=0x%X", (void*)ProcessHandle, *BaseAddress, (unsigned long long) * RegionSize, NewProtect);
    if (IsRWX(NewProtect)) PushRWXEvent("NtProtectVirtualMemory", BaseAddress, size, NewProtect, _ReturnAddress());

    NTSTATUS st = NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
    if (NT_SUCCESS(st)) mark_exec((uintptr_t)addr, size, NewProtect);
    return st;
}
NTSTATUS NTAPI hkNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
    if (g_suppressNtLogging) {
        printf("nt counterpart for write virtual memory not logged\n");
        return NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);}
    LOGFUNC("NtWriteVirtualMemory", "proc=0x%llX addr=0x%llx size=%llu", (void*)ProcessHandle, BaseAddress, (unsigned long long)NumberOfBytesToWrite);
    
    const SIZE_T SAMPLE = (NumberOfBytesToWrite > 4096) ? 4096 : NumberOfBytesToWrite;
    bool isPE = looks_like_pe(Buffer, SAMPLE);
    bool isAsciiPath = looks_like_ascii_path(Buffer, SAMPLE);
    bool isWidePath = looks_like_wide_path(Buffer, SAMPLE);
    if (isPE || isAsciiPath || isWidePath) {
        AllocInfo a;
        if (find_alloc_for_addr((uintptr_t)BaseAddress, &a)) {
            std::unique_lock<std::shared_mutex> L(g_allocs_lock);
            auto it = g_allocs.find(a.base);
            if (it != g_allocs.end()) {
                if (isPE) it->second.tag += "|potential_pe";
                if (isAsciiPath || isWidePath) it->second.tag += "|potential_dll_path";
    }   }   }

    NTSTATUS st = NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
    if (NT_SUCCESS(st)) mark_written((uintptr_t)BaseAddress, NumberOfBytesToWrite);
    return st;
}
NTSTATUS NTAPI hkNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList) {
    if (g_suppressNtLogging) {
        printf("nt counterpart for Create Thread ex not logged\n");
        return NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
    }
    LOGFUNC("NtCreateThreadEx", "proc=0x%llX start=0x%llx flags=0x%X", (void*)ProcessHandle, StartRoutine, CreateFlags);
    
    bool suspect = false;
    DWORD targetPid = resolve_pid_from_handle(ProcessHandle);
    if (targetPid == 0) targetPid = GetCurrentProcessId();

    std::wstring modName;           // check if StartAddr is in a known module
    if (remote_module_by_addr(targetPid, (uintptr_t)StartRoutine, modName)) {
                                        // if kernel32, its most likely loadlibrary 
        if (_wcsicmp(modName.c_str(), L"kernel32.dll") == 0 || _wcsicmp(modName.c_str(), L"kernelbase.dll") == 0) {
            AllocInfo ai;       // check if the thread was already tracked, and has a dll path tag
            
            if (Argument && find_alloc_for_addr((uintptr_t)Argument, &ai, targetPid) && ai.tag.find("potential_dll_path") != std::string::npos) {
                PushInjectionEvent("DLL INJECTION DETECTED", (LPVOID)ai.base, ai.size, 0, (void*)_ReturnAddress());
                suspect = true;
            } else if (Argument) {   // else try to read argument from the target process to see if its a path
                char buf[512] = { 0 };
                SIZE_T bytesRead = 0;
                g_enableLogging = false;
                HANDLE h = (targetPid == GetCurrentProcessId()) ? GetCurrentProcess() :
                    OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, targetPid);
                g_enableLogging = true;
                if (h) {
                    if (ReadProcessMemory(h, Argument, buf, sizeof(buf) - 1, &bytesRead) && bytesRead > 0) {
                        if (looks_like_ascii_path(buf, bytesRead) || looks_like_wide_path(buf, bytesRead)) {
                            suspect = true;
                            PushInjectionEvent("DLL INJECTION DETECTED", Argument, bytesRead, 0, (void*)_ReturnAddress()); } }
                    if (h != GetCurrentProcess()) CloseHandle(h); }
            }
        } else if (_wcsicmp(modName.c_str(), L"ntdll.dll") == 0) {
            bool ldrLikely = false;     // if its ntdll then it might be ldrloadlib
            if (Argument) {
                char buf[512] = { 0 };
                g_enableLogging = false;
                SIZE_T br = 0;
                HANDLE h = (targetPid == GetCurrentProcessId()) ? GetCurrentProcess() : OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, targetPid);
                g_enableLogging = true;
                if (h) {
                    if (ReadProcessMemory(h, Argument, buf, sizeof(buf) - 1, &br) && br > 0) {
                        if (looks_like_ascii_path(buf, br) || looks_like_wide_path(buf, br)) {
                            suspect = true;
                            PushInjectionEvent("DLL INJECTION (LdrLoadDll)", Argument, 0, 0, (void*)_ReturnAddress());
                        } }
                    if (h != GetCurrentProcess()) CloseHandle(h); }
            }
        } else {    // then it might be inside an executable region of the target that matches a tracked allocation, manual mapping
            AllocInfo ai;
            // printf("weird\n");
            if (find_alloc_for_addr((uintptr_t)StartRoutine, &ai, targetPid)) {
                uint64_t now = GetTickCount64();
                if (ai.written && ai.madeExecutable && (now - ai.ts) <= DETECTION_WINDOW_MS) {
                    suspect = true;
                    PushInjectionEvent("INJECTION CHAIN DETECTED (start inside tracked RX alloc)", (LPVOID)ai.base, ai.size, 0, (void*)_ReturnAddress()); } }
    }   }

    if (suspect && targetPid == GetCurrentProcessId()) {
        if (blockExecution()) return STATUS_ACCESS_VIOLATION;
    } else if (suspect) {
        if (blockExecution()) return STATUS_ACCESS_VIOLATION; }

    if (check_thread_start((uintptr_t)StartRoutine, GetCurrentThreadId())) {
        if (blockExecution()) return STATUS_ACCESS_VIOLATION; }

    NTSTATUS st = NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
    return st;
}
NTSTATUS NTAPI hkNtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PCOBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended) {
    if (g_suppressNtLogging) {
        printf("nt counterpart for Create Thread not logged\n");
        return NtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
    }

    LOGFUNC("NtCreateThread", "proc=0x%llX tid=0x%llx", (void*)ProcessHandle, (void*)ClientId->UniqueThread);
    
    NTSTATUS st = NtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
    //if (NT_SUCCESS(st)) check_thread_start((uintptr_t)ThreadContext->Rip, (DWORD)(ULONG_PTR)ClientId->UniqueThread);
    return st;
}
NTSTATUS NTAPI hkNtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    if (g_suppressNtLogging) {
        printf("nt counterpart for suspend thread not logged\n");
        return NtSuspendThread(ThreadHandle, PreviousSuspendCount);
    }
    LOGFUNC("NtSuspendThread", "thread=0x%llx", (void*)ThreadHandle);
    record_thread_suspend_handle(ThreadHandle);
    return NtSuspendThread(ThreadHandle, PreviousSuspendCount);
}
NTSTATUS NTAPI hkNtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    if (g_suppressNtLogging) {
        printf("nt counterpart for resume thread not logged\n");
        return NtResumeThread(ThreadHandle, PreviousSuspendCount);
    }
    LOGFUNC("NtResumeThread", "thread=0x%llx", (void*)ThreadHandle);

    if (record_thread_resume_handle(ThreadHandle)) {
        if (blockExecution()) return STATUS_ACCESS_VIOLATION;
        // if (blockExecutionWithMsgBox()) return STATUS_ACCESS_VIOLATION; }
    }
    NTSTATUS st = NtResumeThread(ThreadHandle, PreviousSuspendCount);
    return st;
}
NTSTATUS NTAPI hkNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
    if (g_suppressNtLogging) {
        printf("nt counterpart for get thread context not logged\n");
        return NtGetContextThread(ThreadHandle, ThreadContext);
    }
    LOGFUNC("NtGetContextThread", "thread=0x%llx", (void*)ThreadHandle);
    record_thread_getcontext_handle(ThreadHandle);
    return NtGetContextThread(ThreadHandle, ThreadContext);
}
NTSTATUS NTAPI hkNtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
    if (g_suppressNtLogging) {
        printf("nt counterpart for set thread ctx not logged\n");
        return NtSetContextThread(ThreadHandle, ThreadContext);
    }
    LOGFUNC("NtSetContextThread", "thread=0x%llx", (void*)ThreadHandle);
#ifdef _WIN64
    uintptr_t newIp = ThreadContext ? (uintptr_t)ThreadContext->Rip : 0;
#else
    uintptr_t newIp = ThreadContext ? (uintptr_t)ThreadContext->Eip : 0;
#endif
    record_thread_setcontext_handle(ThreadHandle, newIp);
    return NtSetContextThread(ThreadHandle, ThreadContext);
}
NTSTATUS NTAPI hkNtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {
    if (g_suppressNtLogging) {
        printf("nt counterpart for wait4single obj not logged\n");
        return NtWaitForSingleObject(Handle, Alertable, Timeout);
    }
    LOGFUNC("NtWaitForSingleObject", "handle=0x%llx alertable=%d", (void*)Handle, Alertable);
    return NtWaitForSingleObject(Handle, Alertable, Timeout);
}
NTSTATUS NTAPI hkNtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType) {
    if (g_suppressNtLogging) {
        printf("nt counterpart for free virtual mem not logged\n");
        return NtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);
    }
    LOGFUNC("NtFreeVirtualMemory", "proc=0x%llX addr=0x%llx size=%llu type=0x%X", (void*)ProcessHandle, *BaseAddress, (unsigned long long) * RegionSize, FreeType);
    return NtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);
}
NTSTATUS NTAPI hkNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    if (g_suppressNtLogging) {
        printf("nt counterpart nt QUERY SYS INFO not logged\n");
        return NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    }
    LOGFUNC("NtQuerySystemInformation", "class=%d length=%lu", SystemInformationClass, SystemInformationLength);
    return NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}
NTSTATUS NTAPI hkNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
    if (g_suppressNtLogging) {
        printf("nt counterpart query INFO PROC not logged\n");
        return NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
    }
    LOGFUNC("NtQueryInformationProcess", "proc=0x%llx class=%d length=%lu", (void*)ProcessHandle, ProcessInformationClass, ProcessInformationLength);
    return NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}
NTSTATUS NTAPI hkNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead) {
    if (g_suppressNtLogging) {
        printf("nt counterpart read virtual mem not logged\n");
        return NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
    }
    LOGFUNC("NtReadVirtualMemory", "proc=0x%llX addr=0x%llx size=%llu", (void*)ProcessHandle, BaseAddress, (unsigned long long)NumberOfBytesToRead);
    return NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
}
NTSTATUS NTAPI hkNtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength) {
    if (g_suppressNtLogging) {
        printf("nt counterpart query virtual mem not logged\n");
        return NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
    }
    LOGFUNC("NtQueryVirtualMemory", "proc=0x%llx addr=0x%llx class=%d length=%llu", (void*)ProcessHandle, BaseAddress, MemoryInformationClass, (unsigned long long)MemoryInformationLength);
    return NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
}
NTSTATUS NTAPI hkNtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength) {
    if (g_suppressNtLogging) {
        printf("nt counterpart query obj not logged\n");
        return NtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
    }
    LOGFUNC("NtQueryObject", "handle=0x%llx class=%d length=%lu", (void*)Handle, ObjectInformationClass, ObjectInformationLength);
    return NtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
}
NTSTATUS NTAPI hkNtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength) {
    if (g_suppressNtLogging) {
        printf("nt counterpart query info thread not logged\n");
        return NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
    }
    LOGFUNC("NtQueryInformationThread", "thread=0x%llx class=%d length=%lu", (void*)ThreadHandle, ThreadInformationClass, ThreadInformationLength);
    return NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
}
NTSTATUS NTAPI hkNtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    if (g_suppressNtLogging) {
        printf("nt counterpart open section not logged\n");
        return NtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes);
    }
    LOGFUNC("NtOpenSection", "access=0x%X", DesiredAccess);
    return NtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes);
}
NTSTATUS NTAPI hkNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {
    if (g_suppressNtLogging) return NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
    LOGFUNC("NtMapViewOfSection", "section=0x%llx proc=0x%llx size=%llu prot=0x%X", (void*)SectionHandle, (void*)ProcessHandle, (unsigned long long) * ViewSize, Win32Protect);
    return NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
}
NTSTATUS NTAPI hkNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    if (g_suppressNtLogging) return NtUnmapViewOfSection(ProcessHandle, BaseAddress);
    LOGFUNC("NtUnmapViewOfSection", "proc=0x%llx addr=0x%llx", (void*)ProcessHandle, BaseAddress);
    return NtUnmapViewOfSection(ProcessHandle, BaseAddress);
}
NTSTATUS NTAPI hkNtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    if (g_suppressNtLogging) return NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    LOGFUNC("NtQueryInformationFile", "file=0x%llx class=%d length=%lu", (void*)FileHandle, FileInformationClass, Length);
    return NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}
NTSTATUS NTAPI hkNtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength) {
    if (g_suppressNtLogging) {
        printf("nt counterpart set info thread not logged\n");
        return NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
    }
    LOGFUNC("NtSetInformationThread", "thread=0x%llx class=%d length=%lu", (void*)ThreadHandle, ThreadInformationClass, ThreadInformationLength);
    return NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}
NTSTATUS NTAPI hkNtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength) {
    if (g_suppressNtLogging) return NtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
    LOGFUNC("NtSetInformationProcess", "proc=0x%llx class=%d length=%lu", (void*)ProcessHandle, ProcessInformationClass, ProcessInformationLength);
    return NtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
}
NTSTATUS NTAPI hkLdrLoadDll(PWCHAR Path, ULONG Flags, PUNICODE_STRING ModuleName, PHANDLE Handle) {
    if (g_suppressNtLogging) {
        printf("nt counterpart ldr load dll not logged\n");
        return fpLdrLoadDll(Path, Flags, ModuleName, Handle);
    }
    LOGFUNC("LdrLoadDll", "path=%ls flags=0x%X", Path ? Path : L"(null)", Flags);
    return fpLdrLoadDll(Path, Flags, ModuleName, Handle);
}
NTSTATUS NTAPI hkNtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
    if (g_suppressNtLogging) {
        printf("nt counterpart for open file not logged\n");
        return NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
    }
    const wchar_t* wname = (ObjectAttributes && ObjectAttributes->ObjectName) ? ObjectAttributes->ObjectName->Buffer : L"(null)";
    std::string name = ExtractFileNameFromNtPath(wname);
    LOGFUNC("NtOpenFile", "access=0x%X options=0x%X name=%s", DesiredAccess, OpenOptions, name.c_str());
    return NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}
NTSTATUS NTAPI hkNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
    if (g_suppressNtLogging) {
        printf("nt counterpart for create file not logged\n");
        return NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
    }
    const wchar_t* wname = (ObjectAttributes && ObjectAttributes->ObjectName) ? ObjectAttributes->ObjectName->Buffer : L"(null)";
    std::string name = ExtractFileNameFromNtPath(wname);
    LOGFUNC("NtCreateFile", "access=0x%X disposition=0x%X options=0x%X, name=%s", DesiredAccess, CreateDisposition, CreateOptions, name.c_str());
    return NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}
NTSTATUS NTAPI hkNtQueueApcThread(HANDLE ThreadHandle, PKNORMAL_ROUTINE ApcRoutine, PVOID SystemArgument1, PVOID SystemArgument2, PVOID SystemArgument3) {
    if (g_suppressNtLogging) {
        printf("nt counterpart for queue apc not logged\n");
        return NtQueueApcThread(ThreadHandle, ApcRoutine, SystemArgument1, SystemArgument2, SystemArgument3);
    }
    LOGFUNC("NtQueueApcThread", "thread=0x%llX routine=%p param=%p", (void*)ThreadHandle, ApcRoutine);
    return NtQueueApcThread(ThreadHandle, ApcRoutine, SystemArgument1, SystemArgument2, SystemArgument3);
}
NTSTATUS NTAPI hkNtCreateSnapshot(HANDLE* SnapshotHandle, ULONG Flags, ULONG ProcessId) {
    if (g_suppressNtLogging) {
        printf("nt counterpart for create 32 tool snapshot not logged");
        return NtCreateSnapshot(SnapshotHandle, Flags, ProcessId);
    }
    LOGFUNC("NtCreateSnapshot", "flags=0x%X pid=%u snap=%p", Flags, ProcessId, SnapshotHandle ? *SnapshotHandle : nullptr);
    return NtCreateSnapshot(SnapshotHandle, Flags, ProcessId);
}




UINT_PTR GetNtFunctionAddress(LPCSTR FunctionName, HMODULE ModuleHandle) {
	return (UINT_PTR)GetProcAddress(ModuleHandle, FunctionName);
}
