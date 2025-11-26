# Multi Api Hook Dll
Simple Antivirus DLL that when injected into a malware will hook WinApi and Native api functions through minhook, track suspicious patterns and stops potentially malicious code. 

Successfully detects most of my malware, such as [this](), [this](), [this](), but because it operates at usermode level it cannot detect syscall injections.

# ⚓ Hooks

a

# 💻 Code

b

# 👾 Malware Detection

Succesfully stops almost all my malware, here is the list of patterns currently detected:

- **Thread Hijacking**: VirtualAlloc(Ex) + VirtualWrite/Memcpy/WriteProcessMem + RWX + Hijacking: to make the shellcode execute it tracks PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_EXECUTE, PAGE_EXECUTE_READ via VirtualProtect(Ex). The hijacking part is simple, the code will enumerate to find an existing thread in the target process, then it will suspend it, change its RIP to the shellcode and resume it.

- **Memory injection**: VirtualAlloc(Ex) + VirtualWrite/Memcpy/WriteProcessMem + RWX + CreateThread(Ex): Same as before but the program directly creates a thread in the target process that points to the previously allocated shellcode, or it may create a suspended one that points to a dummy function, then change its RIP and resume it instantly. 

- **DLL Injection**: VirtualAlloc(Ex) + VirtualWrite/Memcpy/WriteProcessMem/Manual + GetModuleHandleW + GetProcAddr(loading function) or LoadLibrary(A/W/ExA/ExW)/LdrLoadLibrary/Manual Mapping + CreateThread(Ex): If the program starts a thread with a StartRoutine in a known library (kernel32 for LoadLibrary, ntdll for LdrLoadLib), or with an Argument that looks like a dll, or in a previously tracked memory, the dll will flag this pattern, analyze it and stop it if necessary.

- **DLL Hijacking**: work in progress..... 

- **Queue APC Thread**: work in progress...

- **Callback exploit**: work in progress...

The DLL also hooks the respective Ntdll functions of many Windows Api procedures, which means that even malwares that use native api are detected. 

In the examples above i did not include all the functions for a given action, for example when a program copies memory it might use VirtualWriteMemory, Memcopy, WriteProcessMemory, but i did not list all the function possible for "copying memory", the same thing applies for creating or suspending threads, changing memory protections, etc. For a full list check out the contents of the functions in ```nt_hooks.cpp```, where the majority of the detection part takes place.

System calls are not detected because they bypass libraries or function as well as almost any usermode hooks, you could potentially track raw syscalls in the stack but idk, maybe in the future i will create a full kernel mode Edr...


