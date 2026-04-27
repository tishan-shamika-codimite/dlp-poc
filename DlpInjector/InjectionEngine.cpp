#include "InjectionEngine.h"
#include "Logger.h"
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <unordered_set>

// ── Configuration ─────────────────────────────────────────────────────────────

static const std::vector<std::wstring> kTargetProcesses = {
    L"Slack.exe", L"chrome.exe", L"msedge.exe", L"notepad.exe",
    L"Acrobat.exe", L"AcroRd32.exe",
    // Screen-share detection: inject into Zoom and Microsoft Teams so
    // ScreenShareHook.cpp can detect active capture via BitBlt / StretchBlt.
    L"Zoom.exe", L"ms-teams.exe", L"Teams.exe"
};

static constexpr DWORD kScanIntervalMs  = 3000; // Time between injection scans
static constexpr int   kPruneCycleCount = 10;   // Prune stale PIDs every N scans

// ── Module state ──────────────────────────────────────────────────────────────

static std::unordered_set<DWORD> g_injectedPids;
static std::string               g_dllPath;

// ── Helpers ───────────────────────────────────────────────────────────────────

// Resolves DLPHook.dll path relative to the service executable's directory.
[[nodiscard]] static bool ResolveDllPath() {
    char exePath[MAX_PATH];
    const DWORD len = GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return false;

    std::string dir(exePath, len);
    const size_t pos = dir.find_last_of("\\/");
    if (pos == std::string::npos) return false;

    g_dllPath = dir.substr(0, pos + 1) + "DLPHook.dll";

    if (GetFileAttributesA(g_dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        LogError(L"DLPHook.dll not found at: " +
                 std::wstring(g_dllPath.begin(), g_dllPath.end()));
        return false;
    }
    return true;
}

// Enumerates all live PIDs matching processName.
[[nodiscard]] static std::vector<DWORD> GetAllProcessIds(const std::wstring& processName) {
    std::vector<DWORD> pids;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return pids;

    PROCESSENTRY32W pe32 = {};
    pe32.dwSize = sizeof(pe32);
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (processName == pe32.szExeFile)
                pids.push_back(pe32.th32ProcessID);
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return pids;
}

// Injects DLPHook.dll into the target process via CreateRemoteThread → LoadLibraryA.
[[nodiscard]] static bool InjectDLL(DWORD pid, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    const size_t pathLen = strlen(dllPath) + 1;
    void* pRemotePath = VirtualAllocEx(hProcess, nullptr, pathLen,
                                       MEM_COMMIT, PAGE_READWRITE);
    if (!pRemotePath) {
        CloseHandle(hProcess);
        return false;
    }

    WriteProcessMemory(hProcess, pRemotePath, dllPath, pathLen, nullptr);

    auto* pfnLoadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"));

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                        pfnLoadLibrary, pRemotePath, 0, nullptr);
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

// Removes PIDs of processes that have exited, preventing unbounded set growth
// and avoiding false "already injected" matches if a PID is reused by the OS.
static void PruneStaleEntries() {
    std::vector<DWORD> stale;
    for (DWORD pid : g_injectedPids) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h)
            stale.push_back(pid);
        else
            CloseHandle(h);
    }
    for (DWORD pid : stale)
        g_injectedPids.erase(pid);
}

// Scans for target processes and injects into any that have not yet been seen.
static void ScanAndInject() {
    for (const auto& name : kTargetProcesses) {
        for (DWORD pid : GetAllProcessIds(name)) {
            if (g_injectedPids.count(pid)) continue;

            if (InjectDLL(pid, g_dllPath.c_str())) {
                g_injectedPids.insert(pid);
                LogInfo(L"Injected DLPHook.dll into " + name +
                        L" (PID " + std::to_wstring(pid) + L")");
            } else {
                LogError(L"Failed to inject into " + name +
                         L" (PID " + std::to_wstring(pid) + L")");
            }
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

void StartMonitoring(HANDLE hStopEvent) {
    if (!ResolveDllPath()) {
        LogError(L"Cannot start monitoring: DLPHook.dll not found");
        return;
    }

    LogInfo(L"DLP monitoring started. DLL: " +
            std::wstring(g_dllPath.begin(), g_dllPath.end()));

    int cycle = 0;
    while (true) {
        if (WaitForSingleObject(hStopEvent, kScanIntervalMs) == WAIT_OBJECT_0)
            break;

        ScanAndInject();

        if (++cycle % kPruneCycleCount == 0)
            PruneStaleEntries();
    }

    LogInfo(L"DLP monitoring stopped.");
}
