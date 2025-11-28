# Multi Api Hook Dll
Simple Antivirus DLL that when injected into a malware will hook WinApi and Native api functions through minook, track suspicious patterns and stop potentially malicious code. 

Successfully detects most of my malware, such as [this](), [this](), [this](), and [this](), but because it operates at usermode it cannot detect syscall injections, raw syscall tracking would require kernel-mode instrumentation which i cant do, maybe in the future.

Currently focused on Windows x64. 

# ⚓ Hooks

The DLL applies hooks with minhook to a wide range of functions at both the WinAPI and Native API (Nt/Zw) level, including but not limited to:

- Memory management: VirtualAlloc, VirtualAllocEx, VirtualProtect, VirtualProtectEx, WriteProcessMemory, memcpy
- Threading: CreateThread, CreateRemoteThread, NtResumeThread, NtSetContextThread, SuspendThread
- Module loading: LoadLibraryA/W, LdrLoadDll, GetProcAddress
- Networking: connect, WSAConnect, send, recv, WinHttpSendRequest, SSL_write/SSL_read (optional)
-Other suspicious behaviors tracked via system call equivalents to these functions

Each hook logs function parameters, memory addresses, and patterns such as RWX allocations, thread hijacking, and remote module injection. Some hooks also block execution if malicious behavior is detected.

# 💻 Code
The code is divided into several sections:

- hook_stuff.cpp / hook_stuff.h:
  
- nt_hooks.cpp / nt_hooks.h: Contains the hooks for Ntdll/WinAPI functions. The majority of detection logic resides here. Functions include memory allocation, thread manipulation, module loading, and more.

- detection.cpp / detection.h: This is the core detection engine, contains the functions that monitor memory protections, log RWX or suspicious executable regions, flags thread hijacking attempts and injection chains.

- log_stuff.cpp / log_stuff.h: utility functions, logging helpers (LOGFUNC, Push...Event), color-coded console output, timestamp helpers, and bounded memory copies for safe logging of suspicious buffers.

- dll_main.cpp: entry point and hook installer using MinHook, installs all hooks when the DLL is injected and ensures the original functions are called safely if execution is allowed.

# 👾 Malware Detection

Succesfully stops almost all my malware, here is the list of patterns currently detected:

- **Thread Hijacking**: VirtualAlloc(Ex) + VirtualWrite/Memcpy/WriteProcessMem + RWX + Hijacking: to make the shellcode execute it tracks PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_EXECUTE, PAGE_EXECUTE_READ via VirtualProtect(Ex). The hijacking part is simple, the malware enumerates threads until it finds one of the target process, then it suspends it, changes its instruction pointer to shellcode, and resumes it.

- **Memory injection**: VirtualAlloc(Ex) + VirtualWrite/Memcpy/WriteProcessMem + RWX + CreateThread(Ex): Same as before but the program directly creates a thread in the target process that points to the previously allocated shellcode, or it may create a suspended one that points to a dummy function, then change its RIP and resume it instantly. 

- **DLL Injection**: VirtualAlloc(Ex) + VirtualWrite/Memcpy/WriteProcessMem/Manual + GetModuleHandleW + GetProcAddr(loading function) or LoadLibrary(A/W/ExA/ExW)/LdrLoadLibrary/Manual Mapping + CreateThread(Ex): If the program starts a thread with a StartRoutine in a known library (kernel32 for LoadLibrary, ntdll for LdrLoadLib), or with an Argument that looks like a dll, or in a previously tracked memory, the dll will flag this pattern, analyze it and stop it if necessary.

- **DLL Hijacking**: work in progress..... 

- **Queue APC Thread**: work in progress...

- **Callback exploit**: work in progress...

The DLL also hooks the respective Ntdll functions of many Windows Api procedures, which means that even malwares that use native api are detected. 

For simplicity, not every function variation is listed above, for example memory copying can occur via VirtualWriteMemory, Memcopy, WriteProcessMemory, but i did not list all the function possible for "copying memory", the same thing applies for thread manipulation, changing memory protections, etc. For a full list check out the contents of the functions in ```nt_hooks.cpp```, where the majority of the detection part takes place.

System calls are not detected because they bypass libraries or function as well as almost any usermode hooks, you could potentially track raw syscalls in the stack but idk, maybe in the future i will create a full kernel mode Edr... Also, advanced malware may evade hooks if it manually manipulates memory and threads in unconventional ways.


