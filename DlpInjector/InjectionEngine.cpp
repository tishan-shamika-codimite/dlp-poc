#include "InjectionEngine.h"
#include "Logger.h"
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <unordered_set>

static const std::vector<std::wstring> TARGET_PROCESSES = {
    L"Slack.exe", L"chrome.exe", L"msedge.exe", L"notepad.exe",
    L"Acrobat.exe", L"AcroRd32.exe"
};

static std::unordered_set<DWORD> g_InjectedPids;
static std::string g_DllPath;

// Resolve DLPHook.dll path relative to the service executable
static bool ResolveDllPath() {
    char exePath[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, exePath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return false;

    // Strip the executable filename to get the directory
    std::string dir(exePath, len);
    size_t pos = dir.find_last_of("\\/");
    if (pos == std::string::npos) return false;
    dir = dir.substr(0, pos + 1);

    g_DllPath = dir + "DLPHook.dll";

    // Verify the DLL exists
    DWORD attr = GetFileAttributesA(g_DllPath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        LogError(L"DLPHook.dll not found at: " + std::wstring(g_DllPath.begin(), g_DllPath.end()));
        return false;
    }
    return true;
}

// Enumerate all PIDs for a given process name
static std::vector<DWORD> GetAllProcessIds(const std::wstring& processName) {
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

// Inject DLPHook.dll into a target process
static bool InjectDLL(DWORD pid, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    void* pRemotePath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemotePath) {
        CloseHandle(hProcess);
        return false;
    }

    WriteProcessMemory(hProcess, pRemotePath, dllPath, strlen(dllPath) + 1, NULL);

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),
        pRemotePath, 0, NULL);

    bool success = false;
    if (hThread) {
        WaitForSingleObject(hThread, 2000);
        CloseHandle(hThread);
        success = true;
    }

    VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return success;
}

// Remove PIDs of processes that have exited (prevents unbounded growth and handles PID reuse)
static void PruneStaleEntries() {
    std::vector<DWORD> stale;
    for (DWORD pid : g_InjectedPids) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) {
            stale.push_back(pid);
        } else {
            CloseHandle(h);
        }
    }
    for (DWORD pid : stale) {
        g_InjectedPids.erase(pid);
    }
}

// Scan for target processes and inject into any new ones
static void ScanAndInject() {
    for (const auto& processName : TARGET_PROCESSES) {
        std::vector<DWORD> pids = GetAllProcessIds(processName);
        for (DWORD pid : pids) {
            if (g_InjectedPids.count(pid) > 0) continue;

            if (InjectDLL(pid, g_DllPath.c_str())) {
                g_InjectedPids.insert(pid);
                LogInfo(L"Injected DLPHook.dll into " + processName + L" (PID " + std::to_wstring(pid) + L")");
            } else {
                LogError(L"Failed to inject into " + processName + L" (PID " + std::to_wstring(pid) + L")");
            }
        }
    }
}

void StartMonitoring(HANDLE hStopEvent) {
    if (!ResolveDllPath()) {
        LogError(L"Cannot start monitoring: DLPHook.dll not found");
        return;
    }

    LogInfo(L"DLP monitoring started. DLL path: " + std::wstring(g_DllPath.begin(), g_DllPath.end()));

    int cycleCount = 0;
    while (true) {
        DWORD waitResult = WaitForSingleObject(hStopEvent, 3000);
        if (waitResult == WAIT_OBJECT_0) break; // Stop requested

        ScanAndInject();

        cycleCount++;
        if (cycleCount % 10 == 0) {
            PruneStaleEntries();
        }
    }

    LogInfo(L"DLP monitoring stopped.");
}
