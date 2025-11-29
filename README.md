# Multi Api Hook Dll
Simple Antivirus DLL that when injected into a malware will hook WinApi and Native api functions through minook, track suspicious patterns and stop potentially malicious code; currently focused on Windows x64. 

Successfully detects most of my malware, such as [this](https://github.com/Hue-Jhan/Self-Injection-Reverse-Shell-Undetected), [this](https://github.com/Hue-Jhan/Encrypted-Trojan-Undetected), [this](https://github.com/Hue-Jhan/Local-Process-injection-Trojan), [this](https://github.com/Hue-Jhan/Remote-Dll-injector-Trojan), [this](https://github.com/Hue-Jhan/Ntdll-Process-inj-Trojan), [this](https://github.com/Hue-Jhan/Thread-Hijacking-Collection), [this](https://github.com/Hue-Jhan/Ntdll-Dll-Injection-Trojan) and [this](https://github.com/Hue-Jhan/Ntdll-Thread-Hijacking-trojan), but because it operates at usermode it cannot detect syscall injections (like [this](https://github.com/Hue-Jhan/Direct-Syscall-Process-Injection-Trojan) or [this](https://github.com/Hue-Jhan/Direct-Syscall-Dll-Injection)) since raw syscall tracking would require kernel-mode instrumentation which i cant do.

1. [⚓ Hooks explained](#hooks)
2. [💻 Code](#code)
   
   2.1 [Project Structure](#Howto)
   
   2.2 [In Depth Explanation](#expl)
   
4. [👾 Malware Detection](#malw)



<a name="hooks">



# ⚓ Hooks

Hooks basically allow the DLL to intercept calls before the target function executes, when a hooked API is called, control is redirected to a custom detour function, which can inspect arguments, analyze behavior, log events, or block execution. Specifically, MinHook performs inline hooking by rewriting the first bytes of a target function with a jump instruction (trampoline). The original bytes are preserved in a function so the hook can safely pass execution back to the real API after processing. <img align="right" src="media/huk-hijak-cr0.png" width="300" />

This DLL applies hooks with minhook to a wide range of functions at both the WinAPI and their Native API (Nt/Zw) counterpart (E.g VirtualAlloc -> NtAllocateVirtualMemory), including but not limited to:


- Memory allocation: VirtualAlloc, VirtualAllocEx, VirtualProtect, VirtualProtectEx;
  
- Memory management: WriteProcessMemory, Memcpy, Manual copying;
  
- Threading: CreateThread, CreateRemoteThread, NtResumeThread, NtSetContextThread, SuspendThread;
  
- Module/Dll loading: LoadLibraryA/W, LdrLoadDll, GetProcAddress, Manual Mapping; <img align="right" src="media/huk-hijak-cr1.png" width="300" />

- File manipulation: CreateFileA/W, and more, useful in case a dll/persistence file is dropped;

  
- And many more, for the full list check out ```nt_hooks.cpp``` and ```hook_stuff.cpp```.
  
Each nt hook also logs function parameters, memory addresses, and patterns such as RWX allocations, thread hijacking, and remote module injection. Some hooks also **block** execution if malicious behavior is detected, dump the memory region of the alleged payload and prompt the user with a simple question: "Do you want to block the execution?", if the answer is no, the malware will go on, else it will stop (and most likely crash or end execution). 

</a>



<a name="code">

# 💻 Code

This project includes not only the hook dll, but also a starter file and some malware samples you can try.


<a name="Howto">

### 📕 How to use

Here's how to use the tools once you compile the starter and the hook (with [minhook VC17](https://github.com/TsudaKageyu/minhook/tree/master/build) library in a ```lib``` folder):

1) Use the ```starter.exe``` file to start a malware as a suspended process with ```./starter.exe malware.exe```, do not close the console;
2) Inject the Dll into the malware and wait until all the hooks are placed (couple of seconds);
3) Launch the process that the malware will target (if necessary);
4) Go back to the starter console and press Enter to resume the malware;
5) Get hacked (xd).

You can inject the dll in various ways, the simplest one in my opinion is to use Process hacker 2 (not the latest version known as System Informer), to do this simply open ProcHack, find the malware (harmless bc in a suspended state), right click, misc, inject dll. You can alternatively use a custom injector but this is imo the fastest way. Some Antiviruses might remove ProcHacker so add it to the exceptions if necessary. 

Most malware in their initial stage act as remote process injectors, they target softwares with AV/Edr exceptions or sometimes well known processes that are usually not suspicious and always active like explorer.exe or some windows internal services. All the malware samples in the zip file are process injectors that target notepad and inject shellcode (or a dll) that pops up a simple messagebox saying "xd". 

If you want to hook a DLL you can too, the ```dll-inj-xd.exe``` or whatever i named it is a simple remote dll injector that uses LoadLibraryA to inject a dll that acts as a self injector, targeting the process it's being loaded into to inject shellcode and pop up a msgbox. In order to hook it you must first spawn the malware as suspended, then spawn the targetes process (notepad), hook it with procHacker, then hook the injector too (in case you wanna hook them both), and resume it. The hook dll will recognize and stop the injector first (but you can choose not to stop the execution), then it will stop the malicious dll inside notepad, you can choose not to stop the injection here too.

#### Starter File 
The starter file is a very simple executable that given an executable it will start it as a suspended process, then by pressing enter the process will resume. In my opinion this starter file is fundamental to properly hook all functions before execution and to avoid race conditions. You can try to hook the malware while it's running but it might crash or simply already have done some damage.

#### Hook Dll <img align="right" src="media/huk-nt-hijak-find2.png" width="450" />
The code for the hook is divided into several sections:

- dll_main.cpp: entry point and hook installer using MinHook, installs all hooks when the DLL is injected and resizes console;

- hook_stuff.cpp / hook_stuff.h: Contains the hooks for the WinApi functions, i also included some Advapi and User32 functions, you can add the ones you like;
  
- nt_hooks.cpp / nt_hooks.h: Contains the hooks for Ntdll/WinAPI functions, the majority of the detection logic resides here.

- detection.cpp / detection.h: This is the core detection engine, contains the functions that monitor memory protections, RWX or suspicious executable regions, thread hijacking attempts and injection chains.

- log_stuff.cpp / log_stuff.h: utility functions, logging helpers (LOGFUNC, Push...Event), color coded console output, timestamp helpers, and bounded memory copies for safe logging of suspicious buffers (mostly shellcode).

#### Malware Samples <img align="right" src="media/huk-nt-hijak-find.png" width="350" />
In the release i also included some malware samples you can try, they are completely harmless shellcode injectors that use various techniques to target notepad and spawn a message box that says "xd". If you do not trust the samples you can find the code for them on my profile in the Malware Dev section, i included: Thread Hijacking (4 versions), Process injection (3 verions), Dll injection (2 versions). In the future i will add more samples that include methodes queue Apc, callback exploiting, and more.

</a>



<a name="expl">
  
### 🔍 Code in details

aaa




</a>



</a>



<a name="malw">

# 👾 Malware Detection

Succesfully stops almost all my malware, here is the list of patterns currently detected:

- **Thread Hijacking**: VirtualAlloc(Ex) + VirtualWrite/Memcpy/WriteProcessMem + RWX + Hijacking: to make the shellcode execute it tracks PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_EXECUTE, PAGE_EXECUTE_READ via VirtualProtect(Ex). The hijacking part is simple, the malware enumerates threads until it finds one of the target process, then it suspends it, changes its instruction pointer to shellcode, and resumes it.

- **Memory injection**: VirtualAlloc(Ex) + VirtualWrite/Memcpy/WriteProcessMem + RWX + CreateThread(Ex): Same as before but the program directly creates a thread in the target process that points to the previously allocated shellcode, or it may create a suspended one that points to a dummy function, then change its RIP and resume it instantly. 

- **DLL Injection**: VirtualAlloc(Ex) + VirtualWrite/Memcpy/WriteProcessMem/Manual + GetModuleHandleW + GetProcAddr(loading function) or LoadLibrary(A/W/ExA/ExW)/LdrLoadLibrary/Manual Mapping + CreateThread(Ex): If the program starts a thread with a StartRoutine in a known library (kernel32 for LoadLibrary, ntdll for LdrLoadLib), or with an Argument that looks like a dll, or in a previously tracked memory, the dll will flag this pattern, analyze it and stop it if necessary.

- **DLL Hijacking**: work in progress, i will update this after i created a good dll hijacker..... 

- **Queue APC Thread**: work in progress, same thing....

- **Callback exploit**: work in progress, same thing...

Because the DLL also hooks the respective Ntdll functions of many Windows Api procedures, even malwares that use native api are detected. For simplicity, not every function variation is listed above, for example memory copying can occur via VirtualWriteMemory, Memcopy, WriteProcessMemory, but i did not list all the function possible for "copying memory", the same thing applies for thread manipulation, changing memory protections, etc. For a full list check out the contents of the functions in ```nt_hooks.cpp```, where the majority of the detection part takes place.

System calls are not detected because they bypass libraries or function as well as almost any usermode hooks, you could potentially track raw syscalls in the stack but idk, i tried with my direct-syscall malwares but every time it ended up crashing them... maybe in the future i will create a full kernel mode Edr... 

Btw advanced malware may evade hooks if it manually manipulates memory and threads in unconventional ways    : (


</a>

