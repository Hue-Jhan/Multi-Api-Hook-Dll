#include "detection.h"
#include <mutex>
#include <cstdio>
#include <windows.h>

std::unordered_map<uintptr_t, AllocInfo> g_allocs;
std::shared_mutex g_allocs_lock;
std::unordered_map<uintptr_t, ThreadState> g_thread_states;
std::shared_mutex g_thread_states_lock;
const uint64_t DETECTION_WINDOW_MS = 5000; // 5 seconds
const size_t MIN_TRACK_SIZE = 16; // ignore tiny allocations
using namespace std::chrono_literals;

static inline uint64_t now_ms() { return GetTickCount64(); }

/*bool blockExecution() {
    if (!(g_enableLogging)) return false;

    cambiaColore(FOREGROUND_LIGHT_BLUE);
    printf(" [?] Wanna block the execution? Y/N: ");

    int c = getchar(); 
    while (c == '\n' || c == '\r') c = getchar(); 

    if (c == 'Y' || c == 'y') { 
        printf(" [!] Execution blocked.\n");
        cambiaColore(FOREGROUND_GREEN);
        return true; } 

    printf(" [i] Execution allowed.\n"); 
    cambiaColore(FOREGROUND_GREEN);
    return false; 
}*/

bool blockExecution() {
    if (!g_enableLogging) return false;
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (hIn == INVALID_HANDLE_VALUE || !GetConsoleMode(hIn, &mode)) {
        std::printf("   [i] No console attached, allowing execution.\n");
        std::fflush(stdout);  // sometimes this message wont show bc the handle is EoF, which is saved in the buffer and allows the execution later
        return false; }

    static std::mutex g_block_prompt_mutex;
    std::lock_guard<std::mutex> lg(g_block_prompt_mutex);
    cambiaColore(FOREGROUND_LIGHT_BLUE);
    std::printf("\n   [?] Wanna block the execution? Y/N: ");
    std::fflush(stdout);

    int c = getchar();
    while (c == '\n' || c == '\r') {
        c = getchar();
        if (c == EOF) {
            std::printf("\n   [i] No console input available, allowing execution.\n");
            cambiaColore(FOREGROUND_GREEN);
            std::fflush(stdout);
            return false; }
    }

    bool block = (c == 'Y' || c == 'y');
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF) { /* consume rest of line */ }
    if (block) { std::printf("   [!] Execution blocked.\n");
    } else { std::printf("   [i] Execution allowed.\n"); }

    cambiaColore(FOREGROUND_GREEN);
    std::fflush(stdout);
    // system("pause");
    return block;
}
bool blockExecutionWithMsgBox(const char* reason) {  // doesnt work as expected
    if (!g_enableLogging) return false;
    HWINSTA hwinsta = GetProcessWindowStation();
    if (!hwinsta) return false;
    USEROBJECTFLAGS uof = { 0 };
    DWORD needed = 0;
    if (!GetUserObjectInformationA(hwinsta, UOI_FLAGS, &uof, sizeof(uof), &needed)) return false;
    std::string title = "Injection detected";
    int r = MessageBoxA(NULL, reason, title.c_str(), MB_YESNO | MB_ICONWARNING | MB_SYSTEMMODAL);
    return (r == IDYES);
}

void record_alloc(uintptr_t base, size_t size, DWORD prot, DWORD tid, DWORD pid, const char* tag) {
    if (!base || size < MIN_TRACK_SIZE) return;
    if (ShouldIgnoreAllocation(size, _ReturnAddress())) return;

    AllocInfo info;
    info.base = base;
    info.size = size;
    info.initialProt = prot & 0xFFu;
    info.written = false;
    info.madeExecutable = ((info.initialProt == PAGE_EXECUTE_READWRITE) || (info.initialProt == PAGE_EXECUTE_WRITECOPY) || (info.initialProt == PAGE_EXECUTE) || (info.initialProt == PAGE_EXECUTE_READ));
    info.ts = now_ms();
    info.creatorTid = tid;
    info.ownerPid = pid;
    info.tag = tag ? tag : "";

    std::unique_lock<std::shared_mutex> lock(g_allocs_lock);
    g_allocs[base] = std::move(info);
    if (g_enableLogging) printf("        + recorded allocation\n");
}
bool find_alloc_for_addr(uintptr_t addr, AllocInfo* out, DWORD ownerPid) {
    std::shared_lock<std::shared_mutex> lock(g_allocs_lock);
    for (const auto& kv : g_allocs) {
        const AllocInfo& a = kv.second;
        /*if (a.ownerPid != ownerPid) {
            printf("N \n");
            continue;
        }*/
        if (addr >= a.base && addr < a.base + a.size) {
            //if (ownerPid == 0 || a.ownerPid == ownerPid) {
                if (out) *out = a;
                return true;
            //}
        }
    }
    return false;
}
void mark_written(uintptr_t addr, size_t writeSize) {
    std::unique_lock<std::shared_mutex> lock(g_allocs_lock);
    for (auto& kv : g_allocs) {
        auto& a = kv.second;
        if (addr >= a.base && addr < a.base + a.size) {
            a.written = true;
            a.ts = now_ms();
            break;
        }
    }
    if (g_enableLogging) printf("        + recorded copy\n");
}
void mark_exec(uintptr_t addr, size_t size, DWORD newProt) {
    DWORD p = newProt & 0xFFu;
    bool isExec = (p == PAGE_EXECUTE_READWRITE) || (p == PAGE_EXECUTE_WRITECOPY) ||
        (p == PAGE_EXECUTE) || (p == PAGE_EXECUTE_READ);
    if (!isExec) return;

    std::unique_lock<std::shared_mutex> lock(g_allocs_lock);
    for (auto& kv : g_allocs) {
        auto& a = kv.second;
        if (addr >= a.base && addr < a.base + a.size) {
            DWORD init = a.initialProt & 0xFFu;
            bool wasExec = (init == PAGE_EXECUTE_READWRITE) || (init == PAGE_EXECUTE_WRITECOPY) || (init == PAGE_EXECUTE) || (init == PAGE_EXECUTE_READ);
            if (!wasExec) {
                a.madeExecutable = true;
                a.ts = now_ms(); }
            break; }
    }
    if (g_enableLogging) printf("        + recorded RWX\n");
}
bool check_thread_start(uintptr_t startAddr, DWORD tid) {
    AllocInfo a;
    if (!find_alloc_for_addr(startAddr, &a)) return false;
    uint64_t now = now_ms();
    
    if (!(a.madeExecutable && a.written && (now - a.ts) <= DETECTION_WINDOW_MS)) {
        if (g_enableLogging) printf("        + recorded Thread creation\n");
        return false; }
    if (a.tag.find("potential_pe") != std::string::npos) {
        PushDLLInjectionEvent("MANUAL MAP DLL INJECTION", (HMODULE)a.base, a.tag.c_str());
    } else if (a.tag.find("potential_dll_path") != std::string::npos) {
        PushDLLInjectionEvent("LOADLIB REMOTE INJECTION CANDIDATE", (HMODULE)a.base, a.tag.c_str()); }

    PushInjectionEvent("INJECTION CHAIN DETECTED", (LPVOID)a.base, a.size, 0, (void*)_ReturnAddress());
    const size_t DUMP_LIMIT = 512;  // havoc has bigger sizes shellcodes, like 3k bytes

    bool dumped = false; // Prefer to dump from the startAddr (thread IP) if it's within tracked allocation
    if (startAddr >= a.base && startAddr < a.base + a.size) {
        size_t remain = (a.base + a.size) - startAddr;
        size_t want = min(remain, (size_t)DUMP_LIMIT);
        if (want > 0) {
            dumped = read_and_hexdump_region(a.ownerPid, startAddr, want, DUMP_LIMIT);
            if (dumped) std::printf("        + dumped from thread startAddr=0x%llx\n", (unsigned long long)startAddr); }
    }

    // if not dumped yet and allocation looks like PE, try its entry point (base + entry_rva)
    if (!dumped && a.tag.find("potential_pe") != std::string::npos) {
        const size_t peekSize = std::min<size_t>(a.size, 4096); // headers usually within first pages
        std::vector<unsigned char> headerBuf(peekSize);
        bool ok = false;        // try to read headers
        if (read_process_region_into_vector(a.ownerPid, a.base, headerBuf)) {
            uint32_t entryRva = (uint32_t)parse_pe_entry_rva(headerBuf.data(), headerBuf.size());
            if (entryRva != 0) {
                uintptr_t entryAddr = a.base + entryRva;
                size_t want = min((size_t)DUMP_LIMIT, a.size - (size_t)entryRva);
                dumped = read_and_hexdump_region(a.ownerPid, entryAddr, want, DUMP_LIMIT);
                if (dumped)  std::printf("        + dumped from PE entryAddr=0x%llx (rva=0x%x)\n", (unsigned long long)entryAddr, entryRva); }
    }   }

    if (!dumped) {
        dumped = read_and_hexdump_region(a.ownerPid, a.base, std::min<size_t>(a.size, DUMP_LIMIT), DUMP_LIMIT);
        if (dumped) std::printf("        + dumped from alloc base=0x%llx\n", (unsigned long long)a.base);
    } else std::printf("        + no dump performed\n");

    {std::unique_lock<std::shared_mutex> wlock(g_allocs_lock);
        auto it = g_allocs.find(a.base);
        if (it != g_allocs.end()) {
            it->second.tag += "|alerted";
            it->second.ts = now_ms(); }
    }
    return true;
}

void record_thread_suspend_handle(HANDLE threadHandle) {
    uintptr_t key = (uintptr_t)threadHandle;
    ThreadState s;
    s.action = ThAction::Suspended;
    s.ts = now_ms();
    std::unique_lock<std::shared_mutex> L(g_thread_states_lock);
    g_thread_states[key] = s;
}
void record_thread_getcontext_handle(HANDLE threadHandle) {
    uintptr_t key = (uintptr_t)threadHandle;
    std::unique_lock<std::shared_mutex> L(g_thread_states_lock);
    auto& entry = g_thread_states[key];
    entry.action = ThAction::GotContext;
    entry.ts = now_ms();
}
void record_thread_setcontext_handle(HANDLE threadHandle, uintptr_t newIp) {
    uintptr_t key = (uintptr_t)threadHandle;
    uint64_t now = now_ms();
    ThreadState prev;

    {std::unique_lock<std::shared_mutex> L(g_thread_states_lock);
        auto it = g_thread_states.find(key);
        if (it != g_thread_states.end()) prev = it->second;
        ThreadState s;
        s.action = ThAction::SetContext;
        s.ts = now;
        s.ip = newIp;
        g_thread_states[key] = s;
    }
    AllocInfo a;
    if (find_alloc_for_addr(newIp, &a)) {  // if new rip is in tracked allocs + rwx, alert
        uint64_t now2 = now_ms();  // to confirm it we check if he resumes the thread
        if (a.written && a.madeExecutable && (now2 - a.ts) <= DETECTION_WINDOW_MS)
            PushInjectionEvent("SUSPICIOUS THREAD ACTIVITY", (LPVOID)a.base, a.size, 0, (void*)_ReturnAddress());
    }
}
bool record_thread_resume_handle(HANDLE threadHandle) {
    uintptr_t key = (uintptr_t)threadHandle;
    uint64_t now = now_ms();
    ThreadState st;
    bool threat = false;
    // g_enableLogging = false;
    {std::unique_lock<std::shared_mutex> L(g_thread_states_lock);
        auto it = g_thread_states.find(key);
        if (it == g_thread_states.end()) return false;
        st = it->second;
        g_thread_states.erase(it);
    }

    /*if (st.action == ThAction::SetContext && (now - st.ts) <= DETECTION_WINDOW_MS) {
        AllocInfo a;
        if (find_alloc_for_addr(st.ip, &a)) {
            if (a.written && a.madeExecutable && (now - a.ts) <= DETECTION_WINDOW_MS) {
                threat = true;
                PushInjectionEvent("THREAD HIJACK DETECTED", (LPVOID)a.base, a.size, 0, (void*)_ReturnAddress());
                const size_t DUMP_LIMIT = 512;  // havoc has bigger sizes shellcodes, like 3k bytes
                bool ok = read_and_hexdump_region(a.ownerPid, a.base, a.size, DUMP_LIMIT);
                if (!ok) std::printf("        + no dump performed\n");
                std::unique_lock<std::shared_mutex> L(g_allocs_lock);
                g_allocs.erase(a.base); }
    }   }
    return threat; */

    if (st.action != ThAction::SetContext) { 
        //g_enableLogging = true; 
        return false; }
    if ((now - st.ts) > DETECTION_WINDOW_MS) { 
        // g_enableLogging = true; 
        return false; }
    DWORD ownerPid = 0;
    ownerPid = GetProcessIdOfThread(threadHandle);
    if (ownerPid == 0) ownerPid = GetCurrentProcessId();

    AllocInfo a;
    bool found = find_alloc_for_addr((uintptr_t)st.ip, &a, ownerPid);
    if (!found) { // g_enableLogging = true; 
        return false; }
    if (!a.written || !a.madeExecutable) { 
        // g_enableLogging = true; 
        return false; }
    if ((now - a.ts) > DETECTION_WINDOW_MS) { 
        // g_enableLogging = true; 
        return false; }
    PushInjectionEvent("THREAD HIJACK DETECTED", (LPVOID)a.base, a.size, 0, (void*)_ReturnAddress());

    const size_t DUMP_LIMIT = 512;
    // g_enableLogging = true;
    bool ok = read_and_hexdump_region(a.ownerPid, a.base, a.size, DUMP_LIMIT);
    if (!ok) std::printf("        + no dump performed\n");

    {std::unique_lock<std::shared_mutex> lock(g_allocs_lock);
        auto it = g_allocs.find(a.base);
        if (it != g_allocs.end()) g_allocs.erase(it);
    }

    return true;
}

bool looks_like_pe(const void* buf, SIZE_T len) {
    if (!buf || len < 0x40) return false;
    const unsigned char* b = (const unsigned char*)buf;
    if (b[0] != 'M' || b[1] != 'Z') return false;

    uint32_t e_lfanew = *(uint32_t*)(b + 0x3C);
    if (e_lfanew + 4 >= len) return false;

    const unsigned char* pe = b + e_lfanew;
    if (pe[0] != 'P' || pe[1] != 'E' || pe[2] != 0 || pe[3] != 0) return false;
    return true;
}
bool looks_like_ascii_path(const void* buf, SIZE_T len) {
    if (!buf || len == 0) return false;
    const char* s = (const char*)buf; // must be printable ascii + backslash or dot somewhere and end with \\0 within len
    size_t i = 0; bool hasDot = false, hasSlash = false;
    for (; i < len; ++i) {
        unsigned char c = s[i];
        if (c == 0) break;
        if (c < 0x20 || c >= 0x7f) return false;
        if (c == '.') hasDot = true;
        if (c == '\\' || c == '/') hasSlash = true;
    }
    if (i == 0 || i == len) return false; // no termination within buffer
    return (hasDot || hasSlash);  // require at least a dot (dll/ext) or a slash (path)
}
bool looks_like_wide_path(const void* buf, SIZE_T len) {
    if (!buf || len < 4) return false;
    const uint16_t* w = (const uint16_t*)buf;
    size_t max = len / 2;
    size_t i = 0; bool hasDot = false, hasSlash = false;
    for (; i < max; ++i) {
        uint16_t c = w[i];
        if (c == 0) break;
        if (c < 0x20 || c >= 0x7f) return false;
        if (c == L'.') hasDot = true;
        if (c == L'\\' || c == L'/') hasSlash = true;
    }
    if (i == 0 || i == max) return false;
    return (hasDot || hasSlash);
}
bool remote_module_by_addr(DWORD pid, uintptr_t addr, std::wstring& outModuleName) {
    g_enableLogging = false;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        g_enableLogging = true;
        return false; }
    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    bool found = false;

    if (Module32FirstW(snap, &me)) {
        do {
            uintptr_t base = (uintptr_t)me.modBaseAddr;
            uintptr_t end = base + me.modBaseSize;
            if (addr >= base && addr < end) {
                outModuleName = me.szModule;
                found = true;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    g_enableLogging = true;
    return found;
}

DWORD resolve_pid_from_handle(HANDLE hProc) {
    DWORD pid = 0;
    g_enableLogging = false;
    if (hProc) pid = GetProcessId(hProc);
    if (pid == 0) pid = GetCurrentProcessId();
    g_enableLogging = true;
    return pid;
}

bool read_and_hexdump_region(uint32_t ownerPid, uintptr_t base, size_t wantSize, size_t dumpLimit) {
    const size_t DUMP_LIMIT = dumpLimit;
    size_t toDump = (wantSize < DUMP_LIMIT) ? wantSize : DUMP_LIMIT;
    if (toDump == 0) return false;
    HANDLE hProc = nullptr;
    bool opened = false;
    g_enableLogging = false;
    if (ownerPid == GetCurrentProcessId()) hProc = GetCurrentProcess();
    else {
        hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ownerPid);
        if (!hProc) {
            g_enableLogging = true;
            std::printf("        + remote hexdump skipped (OpenProcess failed pid=%u err=%u)\n", ownerPid, GetLastError());
            return false; }
        opened = true;
    }

    SYSTEM_INFO si;  // query for system page size
    GetSystemInfo(&si);
    const uintptr_t pageSize = (uintptr_t)si.dwPageSize;
    auto align_down = [&](uintptr_t v) { return (v / pageSize) * pageSize; };
    auto align_up = [&](uintptr_t v) { return ((v + pageSize - 1) / pageSize) * pageSize; };
    
    std::vector<unsigned char> accum;  // read bytes
    accum.reserve(toDump);
    uintptr_t cur = base;
    uintptr_t end = base + toDump;

    while (cur < end) {
        MEMORY_BASIC_INFORMATION mbi;  // now we get the memory region info that contains cur.
        SIZE_T q = (ownerPid == GetCurrentProcessId()) ? VirtualQuery((LPCVOID)cur, &mbi, sizeof(mbi)) :
            VirtualQueryEx(hProc, (LPCVOID)cur, &mbi, sizeof(mbi));

        if (!q) { cur = align_up(cur + 1);  // skip to next page
            continue; }

        uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
        SIZE_T regionSize = mbi.RegionSize; // region may be larger than the exact address
        uintptr_t regionEnd = regionBase + regionSize;
        uintptr_t readStart = max(cur, regionBase);  // so lets use these
        uintptr_t readEnd = min(end, regionEnd);

        // only read if its committed and not NOACCESS/GUARD
        bool committed = (mbi.State == MEM_COMMIT);
        const DWORD READABLE_MASK = PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY;
        bool guard = (mbi.Protect & PAGE_GUARD) != 0;
        bool noaccess = (mbi.Protect & PAGE_NOACCESS) != 0;
        bool hasReadable = (mbi.Protect & READABLE_MASK) != 0;

        if (committed && !noaccess && !guard && hasReadable) {
            SIZE_T chunkSize = (SIZE_T)(readEnd - readStart);
            uintptr_t p = readStart;

            /*while (p < readEnd) {          // read only up to the current page boundary
                SIZE_T thisChunk = (SIZE_T)std::min<uintptr_t>(pageSize - (p % pageSize), readEnd - p);
                std::vector<unsigned char> buf(thisChunk);
                SIZE_T bytesRead = 0;
                BOOL ok = ReadProcessMemory(hProc, (LPCVOID)p, buf.data(), thisChunk, &bytesRead);
                if (ok && bytesRead > 0) {
                    accum.insert(accum.end(), buf.begin(), buf.begin() + bytesRead);
                    p += bytesRead; }
                else p = align_up(p + 1);  // skip page so a single unreadable one doesnt kill the whole dump
                if (accum.size() >= toDump) break;
            } */

            while (p < readEnd && accum.size() < toDump) {
                SIZE_T thisChunk = (SIZE_T)std::min<uintptr_t>(pageSize - (p % pageSize), readEnd - p);
                std::vector<unsigned char> buf(thisChunk);
                SIZE_T bytesRead = 0;
                BOOL ok = ReadProcessMemory(hProc, (LPCVOID)p, buf.data(), thisChunk, &bytesRead);
                if (ok && bytesRead > 0) {
                    SIZE_T want = (SIZE_T)std::min<size_t>(toDump - accum.size(), bytesRead);
                    accum.insert(accum.end(), buf.begin(), buf.begin() + want);
                    p += bytesRead;
                } else {
                    // skip this page if RPM failed
                    p = align_up(p + 1); }
        }   }
        cur = min(end, regionEnd);  // move to next region
    }

    if (opened) CloseHandle(hProc);
    if (accum.empty()) {
        g_enableLogging = true;
        std::printf("        + hexdump failed (no readable bytes) \n");
        return false; }

    g_enableLogging = true;
    size_t finalBytes = min(accum.size(), toDump);
    hexdump_mem(accum.data(), finalBytes, base);
    return true;
}
void hexdump_mem(const void* ptr, size_t bytes, uintptr_t baseAddrForPrint = 0) {
    static std::mutex g_hexdump_mutex;
    std::lock_guard<std::mutex> lg(g_hexdump_mutex);
    const unsigned char* p = static_cast<const unsigned char*>(ptr);
    const size_t width = 16;
    cambiaColore(FOREGROUND_YELLOW1);
    std::printf("   [i]  Memory Dump: base=0x%016llx size=%llu\n", (unsigned long long)baseAddrForPrint, (unsigned long long)bytes);

    for (size_t i = 0; i < bytes; i += width) {
        size_t rowlen = min(width, bytes - i);
        //std::printf("    %016llx  ", (unsigned long long)(baseAddrForPrint + i));
        std::printf("        ");
        for (size_t j = 0; j < width; ++j) {
            if (j < rowlen) std::printf("%02x ", p[i + j]);
            else std::printf("   "); }

        /*std::printf(" ");
        for (size_t j = 0; j < rowlen; ++j) {
            unsigned char c = p[i + j];
            std::printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.'); }
        */
        std::printf("\n");
    }
    cambiaColore(FOREGROUND_GREEN);
}
uintptr_t parse_pe_entry_rva(const unsigned char* buf, size_t bufsz) {
    if (bufsz < 0x40) return 0;
    uint32_t e_lfanew = *(uint32_t*)(buf + 0x3c);
    if (e_lfanew + 0x18 > bufsz) return 0;
    if (memcmp(buf + e_lfanew, "PE\0\0", 4) != 0) return 0;  // check "PE\0\0"
    uint16_t machine = *(uint16_t*)(buf + e_lfanew + 4);
    
    uint16_t optMagic = *(uint16_t*)(buf + e_lfanew + 24);  // to identify 32/64
    if (optMagic == 0x10b) { // PE32
        if (e_lfanew + 0x18 + 96 > bufsz) return 0;
        uint32_t entry = *(uint32_t*)(buf + e_lfanew + 24 + 16);
        return entry; }
    else if (optMagic == 0x20b) { // PE32+
        if (e_lfanew + 0x18 + 112 > bufsz) return 0;
        uint32_t entry = *(uint32_t*)(buf + e_lfanew + 24 + 16);
        return entry; }
    return 0;
}
bool read_process_region_into_vector(uint32_t ownerPid, uintptr_t base, std::vector<unsigned char>& outBuf) {
    if (outBuf.empty()) return false;
    g_enableLogging = false;
    HANDLE hProc = nullptr;
    bool opened = false;
    if (ownerPid == GetCurrentProcessId()) hProc = GetCurrentProcess();
    else {
        hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ownerPid);
        if (!hProc) {
            g_enableLogging = true;
            return false; }
        opened = true; }
    SIZE_T bytesRead = 0;
    BOOL ok = ReadProcessMemory(hProc, (LPCVOID)base, outBuf.data(), outBuf.size(), &bytesRead);
    if (opened) CloseHandle(hProc);
    g_enableLogging = true;
    return (ok && bytesRead > 0);
}



