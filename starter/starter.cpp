#include <windows.h>
#include <stdio.h>
#include <string>

void ControlProcess(const char* targetExeName) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(targetExeName,NULL,NULL,NULL,FALSE,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE ,NULL,NULL,&si,&pi)) {
        printf("[!] CreateProcess failed (%lu).\n", GetLastError());
        return; }

    printf("[1] Process launched SUSPENDED!");
    printf(" PID: %lu", pi.dwProcessId);
    printf(", TID: %lu\n", pi.dwThreadId);
    printf("[2] Press ENTER to resume the process\n");
    system("pause");

    DWORD resumeCount = ResumeThread(pi.hThread);
    if (resumeCount == (DWORD)-1) { printf("[!] ResumeThread failed (%lu).\n", GetLastError());
    } else { printf("[3] Process RESUMED successfully. \n\n"); }

    // WaitForSingleObject(pi.hProcess, INFINITE); 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <Target_Executable_Name.exe>\n", argv[0]);
        return 1; }
    ControlProcess(argv[1]);
    return 0;
}