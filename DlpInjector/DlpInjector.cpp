//#include <windows.h>
//#include <iostream>
//#include <tlhelp32.h>
//#include <string>
//
//// Helper: Find Process ID by Name
//DWORD GetProcessIdByName(const std::wstring& processName) {
//    DWORD pid = 0;
//    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
//    if (hSnapshot != INVALID_HANDLE_VALUE) {
//        PROCESSENTRY32W pe32;
//        pe32.dwSize = sizeof(PROCESSENTRY32W);
//        if (Process32FirstW(hSnapshot, &pe32)) {
//            do {
//                if (processName == pe32.szExeFile) {
//                    pid = pe32.th32ProcessID;
//                    break;
//                }
//            } while (Process32NextW(hSnapshot, &pe32));
//        }
//        CloseHandle(hSnapshot);
//    }
//    return pid;
//}
//
//// THE INJECTION LOGIC
//bool InjectDLL(DWORD pid, const char* dllPath) {
//    // 1. Open the Target Process
//    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
//    if (!hProcess) {
//        std::cerr << "Failed to open process. (Run as Admin?)" << std::endl;
//        return false;
//    }
//
//    // 2. Allocate memory INSIDE the target process for the DLL path
//    void* pRemotePath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
//
//    // 3. Write the DLL path string into that memory
//    WriteProcessMemory(hProcess, pRemotePath, dllPath, strlen(dllPath) + 1, NULL);
//
//    // 4. Force the target to call "LoadLibraryA" with our path
//    // This causes the target to load our DLL, triggering DllMain -> Hooks
//    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
//        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),
//        pRemotePath, 0, NULL);
//
//    if (hThread) {
//        WaitForSingleObject(hThread, INFINITE);
//        CloseHandle(hThread);
//        std::cout << "Successfully Injected into PID: " << pid << std::endl;
//    }
//    else {
//        std::cerr << "Failed to create remote thread." << std::endl;
//    }
//
//    // Cleanup
//    VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
//    CloseHandle(hProcess);
//    return true;
//}
//
//int main() {
//    // Path to your compiled DLL (Full Path Required)
//    const char* dllPath = "C:\\Users\\HP\\Documents\\Github\\DLPHook\\x64\\Debug\\DLPHook.dll";
//
//    std::cout << "DLP Injector Running..." << std::endl;
//
//    // Example: Inject into Notepad
//    // In a real app, you would loop through all processes or listen for new process creation
//    DWORD pid = GetProcessIdByName(L"Notepad.exe");
//
//    if (pid != 0) {
//        std::cout << "Found Chrome (PID " << pid << "). Injecting..." << std::endl;
//        InjectDLL(pid, dllPath);
//    }
//    else {
//        std::cout << "Chrome not found. Please open Notepad and try again." << std::endl;
//    }
//    system("pause");
//
//    return 0;
//}



#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <vector>
#include <string>
std::vector<DWORD> GetAllProcessIds(const std::wstring& processName) {
    std::vector<DWORD> pids;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (processName == pe32.szExeFile) {
                    pids.push_back(pe32.th32ProcessID);
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return pids;
}
bool InjectDLL(DWORD pid, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    void* pRemotePath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProcess, pRemotePath, dllPath, strlen(dllPath) + 1, NULL);

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),
        pRemotePath, 0, NULL);

    if (hThread) {
        WaitForSingleObject(hThread, 2000); // Wait up to 2s
        CloseHandle(hThread);
    }
    VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return (hThread != NULL);
}

void InjectIntoAll(const std::wstring& processName, const char* dllPath) {
    std::vector<DWORD> pids = GetAllProcessIds(processName);
    std::wcout << L"--- " << processName << L" ---" << std::endl;
    if (pids.empty()) {
        std::wcout << processName << L" is not running." << std::endl;
        return;
    }
    std::cout << "Found " << pids.size() << " processes." << std::endl;
    for (DWORD pid : pids) {
        std::cout << "Injecting into PID: " << pid << "... ";
        if (InjectDLL(pid, dllPath)) {
            std::cout << "Success" << std::endl;
        }
        else {
            std::cout << "Failed (Access Denied / Sandbox)" << std::endl;
        }
    }
}

int main() {
    const char* dllPath = "C:\\Projects\\Project-Browser-Bridge\\Root\\DLPHook\\x64\\Debug\\DLPHook.dll";

    std::cout << "--- DLP Mass Injector ---" << std::endl;

    InjectIntoAll(L"Slack.exe", dllPath);
    InjectIntoAll(L"chrome.exe", dllPath);
    InjectIntoAll(L"msedge.exe", dllPath);

    system("pause");
    return 0;
}