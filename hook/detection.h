#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <windows.h>
#include <algorithm>
#include <chrono>
#include <TlHelp32.h>
#include "log_stuff.h"

extern const uint64_t DETECTION_WINDOW_MS;
extern const size_t MIN_TRACK_SIZE;

struct AllocInfo {
    uintptr_t base;
    size_t size;
    DWORD initialProt;
    bool written = false;
    bool madeExecutable = false;    // protection changed to executable after write
    uint64_t ts = 0;
    DWORD creatorTid = 0;
    DWORD ownerPid = 0;
    std::string tag;    // function name
};

enum class ThAction : uint8_t { None = 0, Suspended, GotContext, SetContext };
struct ThreadState {
    ThAction action = ThAction::None;
    uint64_t ts = 0;
    uintptr_t ip = 0;
};

extern std::unordered_map<uintptr_t, AllocInfo> g_allocs;
extern std::shared_mutex g_allocs_lock; // to prevent concurrent writers/readers from corrupting memory
extern std::unordered_map<uintptr_t, ThreadState> g_thread_states;
extern std::shared_mutex g_thread_states_lock;

bool blockExecution();
bool blockExecutionWithMsgBox(const char* reason = "Suspicious code execution detected. Block execution?");

void record_alloc(uintptr_t base, size_t size, DWORD prot, DWORD tid, DWORD pid, const char* tag);
bool find_alloc_for_addr(uintptr_t addr, AllocInfo* out, DWORD ownerPid=0);
void mark_written(uintptr_t addr, size_t writeSize);
void mark_exec(uintptr_t addr, size_t size, DWORD newProt);
bool check_thread_start(uintptr_t startAddr, DWORD tid);
void hexdump_mem(const void* ptr, size_t bytes, uintptr_t baseAddrForPrint);
bool read_and_hexdump_region(uint32_t ownerPid, uintptr_t base, size_t wantSize, size_t dumpLimit);

bool looks_like_pe(const void* buf, SIZE_T len);
bool looks_like_ascii_path(const void* buf, SIZE_T len);
bool looks_like_wide_path(const void* buf, SIZE_T len);

DWORD resolve_pid_from_handle(HANDLE hProc);
bool remote_module_by_addr(DWORD pid, uintptr_t addr, std::wstring& outModuleName);


void record_thread_suspend_handle(HANDLE threadHandle);
void record_thread_getcontext_handle(HANDLE threadHandle);
void record_thread_setcontext_handle(HANDLE threadHandle, uintptr_t newIp);
bool record_thread_resume_handle(HANDLE threadHandle);
uintptr_t parse_pe_entry_rva(const unsigned char* buf, size_t bufsz);
bool read_process_region_into_vector(uint32_t ownerPid, uintptr_t base, std::vector<unsigned char>& outBuf);


