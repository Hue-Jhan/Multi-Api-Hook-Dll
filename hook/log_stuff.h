#pragma once
#include <iostream>
#include <Windows.h>
#include <cstring>
#include <cinttypes>
#define PID_COLUMN 48
#define FOREGROUND_LIGHT_BLUE (FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define FOREGROUND_RED1 (FOREGROUND_RED | FOREGROUND_INTENSITY)
#define FOREGROUND_YELLOW1 (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define FOREGROUND_PURPLE1 (FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#ifndef PAGE_NOCACHE
    #define PAGE_NOCACHE 0x200
#endif
#ifndef PAGE_WRITECOMBINE
    #define PAGE_WRITECOMBINE 0x400
#endif
#define TRY_MH(call, name) \
    if ((call) != MH_OK) std::fprintf(stderr, "[!] MinHook error on %s\n", name);

extern bool g_enableLogging;
extern thread_local int g_suppressNtLogging;
struct SuppressNtLoggingGuard {
    SuppressNtLoggingGuard() { ++g_suppressNtLogging; }
    ~SuppressNtLoggingGuard() { --g_suppressNtLogging; }
};

#define LOGFUNC(tag, fmt, ...) \
    do { \
        if (g_enableLogging) { \
            DWORD _pid = GetCurrentProcessId(); \
            DWORD _tid = GetCurrentThreadId(); \
            const char* prefix = (strncmp(tag, "Nt", 2) == 0 || strncmp(tag, "Ldr", 3) == 0) \
                ? "       (+)  " /* visual (+) shifted right inside prefix */ \
                : "   [+]  " /* visual [+] a bit left inside same prefix field */; \
            size_t _len = strlen(prefix) + strlen(tag); \
            int _pad = (PID_COLUMN > (int)_len) ? (PID_COLUMN - (int)_len) : 1; \
            /* print prefix+tag, then _pad spaces, then pid/tid and the rest */ \
            std::printf("%s%s%*s pid=%-6u tid=%-6u " fmt "\n", prefix, tag, _pad, "", _pid, _tid, __VA_ARGS__); \
            fflush(stdout); \
        } \
    } while(0)

#define LOGFUNC_NOARGS(tag) \
    do { \
        if (g_enableLogging) { \
            DWORD _pid = GetCurrentProcessId(); \
            DWORD _tid = GetCurrentThreadId(); \
            const char* prefix = (strncmp(tag, "Nt", 2) == 0 || strncmp(tag, "Ldr", 3) == 0) \
                ? "       (+)  " \
                : "   [+]  "; \
            size_t _len = strlen(prefix) + strlen(tag); \
            int _pad = (PID_COLUMN > (int)_len) ? (PID_COLUMN - (int)_len) : 1; \
            std::printf("%s%s%*s pid=%-6u tid=%-6u\n", prefix, tag, _pad, "", _pid, _tid); \
            fflush(stdout); \
        } \
    } while(0)

void cambiaColore(int colore);
bool ShouldIgnoreAllocation(SIZE_T size, void* caller);
bool IsRWX(DWORD protection);
std::string ProtectionToString(DWORD protection);
void PushRWXEvent(const char* func, LPVOID addr, SIZE_T size, DWORD prot, void* retAddr);
void PushDLLInjectionEvent(const char* api, HMODULE mod, const char* name);
void PushInjectionEvent(const char* func, LPVOID addr, SIZE_T size, DWORD prot, void* retAddr);

static inline void* hk_memcpy(void* dst, const void* src, size_t sz) {
    std::printf("[+] memcpy              size=%llu\n", (unsigned long long)sz);
    fflush(stdout);
    return std::memcpy(dst, src, sz);
}
