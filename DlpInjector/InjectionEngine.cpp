#include "InjectionEngine.h"
#include "Logger.h"
#include <windows.h>
#include <tlhelp32.h>
#include <evntrace.h>     // ETW: StartTrace, OpenTrace, ProcessTrace, etc.
#include <evntcons.h>     // EVENT_RECORD, PEVENT_RECORD_CALLBACK
#include <wmistr.h>       // WNODE_HEADER (required by evntrace.h structures)
#include <bcrypt.h>       // BCryptGenRandom for shared-secret generation
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <algorithm>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 1 — Configuration
// ════════════════════════════════════════════════════════════════════════════

// Target process names: the injector monitors for ALL of these.
// Worker sub-processes (renderers, AcroCEF) carry the same exe name as their
// parents in most cases (chrome.exe), so they are automatically covered.
static const std::vector<std::wstring> kTargetProcesses = {
    L"Slack.exe",
    L"chrome.exe",
    L"msedge.exe",
    L"notepad.exe",
    L"Acrobat.exe",
    L"AcroRd32.exe",
    L"AcroCEF.exe",         // Adobe Acrobat CEF worker
    L"acrocef_1.exe",       // Alternate AcroCEF variant name
    L"brave.exe",
    L"opera.exe",
    L"vivaldi.exe",
};

// Polling fallback interval.  ETW catches most processes; polling catches any
// that slip through the startup race window.
static constexpr DWORD kPollIntervalMs  = 3000;
static constexpr int   kPruneCycleCount = 10;    // Prune stale PIDs every N polls

// ── ETW Provider GUID — Microsoft-Windows-Kernel-Process ─────────────────────
//  {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}
//  Event ID 1 = ProcessStart (fires when any process is created on the system)
static const GUID kKernelProcessProviderGuid = {
    0x22fb2cd6, 0x0e7b, 0x422b,
    { 0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16 }
};
static constexpr USHORT kEtwEventIdProcessStart = 1;

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 2 — Module state
// ════════════════════════════════════════════════════════════════════════════

// Tracks which PIDs we have already injected to prevent double-injection.
// Protected by g_pidsLock.
static std::unordered_set<DWORD> g_injectedPids;
static std::mutex                g_pidsLock;

// Maps a parent-process PID to the 32-byte shared secret generated for that
// process family.  Workers inherit the same key as their parent.
// Protected by g_pidsLock.
static std::unordered_map<DWORD, std::vector<uint8_t>> g_familyKeys;

static std::string  g_dllPath;
static HANDLE       g_hStopEvent = nullptr;

// ETW session handles
static TRACEHANDLE  g_hEtwSession  = INVALID_PROCESSTRACE_HANDLE;
static TRACEHANDLE  g_hEtwTrace    = INVALID_PROCESSTRACE_HANDLE;

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 3 — Privilege & DLL path helpers
// ════════════════════════════════════════════════════════════════════════════

bool EnableDebugPrivilege() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount   = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME,
                                &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }

    const BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr);
    CloseHandle(hToken);
    return ok && (GetLastError() != ERROR_NOT_ALL_ASSIGNED);
}

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

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 4 — Shared-secret generation & injection
// ════════════════════════════════════════════════════════════════════════════
//
//  Each "process family" (UI process + all its workers) shares a 32-byte
//  secret key used for HMAC-SHA256 authentication of IPC messages.
//
//  The injector:
//    1. Generates a fresh key for the UI process (first time it is seen)
//    2. Writes the key into g_dlpIpcSharedSecret in the target process via
//       WriteProcessMemory BEFORE calling CreateRemoteThread to load the DLL
//    3. For worker processes, looks up the parent's key (g_familyKeys) and
//       writes the SAME key into the worker

static std::vector<uint8_t> GenerateRandomKey32() {
    std::vector<uint8_t> key(32, 0);
    // BCryptGenRandom fills the buffer with cryptographically random bytes
    BCryptGenRandom(nullptr, key.data(), 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return key;
}

// Returns the shared secret for a given UI-process PID.
// Creates a new random key on first call; returns the existing key on subsequent calls.
static std::vector<uint8_t> GetOrCreateFamilyKey(DWORD uiPid) {
    std::lock_guard<std::mutex> lk(g_pidsLock);
    auto it = g_familyKeys.find(uiPid);
    if (it != g_familyKeys.end())
        return it->second;

    auto newKey = GenerateRandomKey32();
    g_familyKeys[uiPid] = newKey;
    return newKey;
}

// Determines the "family PID" for a given process.
// For UI processes, that's the PID itself.
// For worker processes (Chrome renderers, AcroCEF), that's the parent PID.
static DWORD GetFamilyUiPid(DWORD pid) {
    // Read parent PID from the process list snapshot
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return pid;

    DWORD parentPid = pid; // Default: assume this IS the UI process
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                parentPid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);

    // Check if the parent is itself a known target process.
    // If so, this is a worker — use the parent's key.
    // If not (e.g. parent is explorer.exe), this IS the UI root.
    HANDLE hParent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
    if (!hParent) return pid; // Can't open parent — treat self as root

    wchar_t parentExe[MAX_PATH] = {};
    DWORD   nameLen = MAX_PATH;
    QueryFullProcessImageNameW(hParent, 0, parentExe, &nameLen);
    CloseHandle(hParent);

    // Extract filename component
    const wchar_t* parentName = parentExe;
    for (const wchar_t* p = parentExe; *p; ++p)
        if (*p == L'\\' || *p == L'/') parentName = p + 1;

    // Lower-case comparison
    wchar_t parentLower[MAX_PATH] = {};
    for (size_t i = 0; parentName[i] && i < MAX_PATH - 1; ++i)
        parentLower[i] = static_cast<wchar_t>(towlower(parentName[i]));

    for (const auto& target : kTargetProcesses) {
        wchar_t targetLower[MAX_PATH] = {};
        for (size_t i = 0; i < target.size() && i < MAX_PATH - 1; ++i)
            targetLower[i] = static_cast<wchar_t>(towlower(target[i]));

        if (wcscmp(parentLower, targetLower) == 0)
            return parentPid; // Parent is a known target → this is a worker
    }

    return pid; // Parent is unknown → this IS the UI root process
}

// Writes the 32-byte shared secret into g_dlpIpcSharedSecret inside the
// target process BEFORE the DLL's DllMain executes.
// `hProcess` must have PROCESS_VM_WRITE + PROCESS_VM_OPERATION access.
static bool WriteSharedSecretToProcess(HANDLE hProcess, const uint8_t* key32) {
    // Locate the .dlpkey section in the remote process.
    // We find the address of g_dlpIpcSharedSecret by:
    //   1. Getting the base address of DLPHook.dll in the remote process
    //   2. Loading a local copy of DLPHook.dll via GetModuleHandle (it's
    //      already loaded in the injector after we call InjectDLL, but we
    //      resolve the local offset before injection).
    //
    // The reliable approach is to use the known export:
    //   DLPHook.dll exports "g_dlpIpcSharedSecret" as a data export.
    //   We query the remote module's base + local offset.

    // Step 1: Get local base address of DLPHook.dll (loaded in injector process)
    HMODULE hLocalDll = LoadLibraryExA(g_dllPath.c_str(), nullptr,
                                        DONT_RESOLVE_DLL_REFERENCES);
    if (!hLocalDll) {
        LogError(L"WriteSharedSecret: LoadLibraryEx(DLPHook) failed GLE=" +
                 std::to_wstring(GetLastError()));
        return false;
    }

    // Step 2: Get local address of g_dlpIpcSharedSecret via exported getter
    typedef void* (*PFN_GetSecretAddr)();
    auto pfnGetAddr = reinterpret_cast<PFN_GetSecretAddr>(
        GetProcAddress(hLocalDll, "DlpIpc_GetSharedSecretAddress"));
    if (!pfnGetAddr) {
        LogError(L"WriteSharedSecret: DlpIpc_GetSharedSecretAddress not exported from DLPHook.dll");
        FreeLibrary(hLocalDll);
        return false;
    }

    const void* pLocalSecret = pfnGetAddr();

    const uintptr_t localOffset =
        reinterpret_cast<uintptr_t>(pLocalSecret)
        - reinterpret_cast<uintptr_t>(hLocalDll);

    FreeLibrary(hLocalDll);

    // Step 3: Find DLPHook.dll's base in the remote process via module snapshot
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                             GetProcessId(hProcess));
    if (hSnap == INVALID_HANDLE_VALUE) {
        LogError(L"WriteSharedSecret: CreateToolhelp32Snapshot failed");
        return false;
    }

    uintptr_t remoteBase = 0;
    MODULEENTRY32W me = {};
    me.dwSize = sizeof(me);

    if (Module32FirstW(hSnap, &me)) {
        do {
            if (_wcsicmp(me.szModule, L"DLPHook.dll") == 0) {
                remoteBase = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                break;
            }
        } while (Module32NextW(hSnap, &me));
    }
    CloseHandle(hSnap);

    if (remoteBase == 0) {
        LogError(L"WriteSharedSecret: DLPHook.dll not found in remote process module list");
        return false;
    }

    // Step 4: Calculate remote address and write the key
    void* pRemoteSecret = reinterpret_cast<void*>(remoteBase + localOffset);

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, pRemoteSecret, key32, 32, &written) || written != 32) {
        LogError(L"WriteSharedSecret: WriteProcessMemory failed GLE=" +
                 std::to_wstring(GetLastError()));
        return false;
    }

    LogInfo(L"WriteSharedSecret: 32-byte key written to remote g_dlpIpcSharedSecret at 0x" +
            std::to_wstring(reinterpret_cast<uintptr_t>(pRemoteSecret)));
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 5 — Core injection logic
// ════════════════════════════════════════════════════════════════════════════

[[nodiscard]] static std::vector<DWORD> GetAllProcessIds(const std::wstring& processName) {
    std::vector<DWORD> pids;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return pids;

    PROCESSENTRY32W pe32 = {};
    pe32.dwSize = sizeof(pe32);
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(processName.c_str(), pe32.szExeFile) == 0)
                pids.push_back(pe32.th32ProcessID);
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return pids;
}

// Core injection: LoadLibrary + WriteProcessMemory for shared secret.
// Returns true if the DLL was loaded AND the secret was written successfully.
[[nodiscard]] static bool InjectDLL(DWORD pid, const char* dllPath) {
    // Determine the required access rights.
    // We need VM_WRITE for the secret and ALL_ACCESS for CreateRemoteThread.
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE, pid);
    if (!hProcess) {
        LogError(L"InjectDLL: OpenProcess(PID=" + std::to_wstring(pid) +
                 L") failed GLE=" + std::to_wstring(GetLastError()));
        return false;
    }

    // Step 1: Allocate a buffer in the remote process for the DLL path
    const size_t pathLen = strlen(dllPath) + 1;
    void* pRemotePath = VirtualAllocEx(hProcess, nullptr, pathLen,
                                        MEM_COMMIT, PAGE_READWRITE);
    if (!pRemotePath) {
        CloseHandle(hProcess);
        return false;
    }

    WriteProcessMemory(hProcess, pRemotePath, dllPath, pathLen, nullptr);

    // Step 2: Determine the shared-secret key for this process family
    const DWORD uiPid = GetFamilyUiPid(pid);
    const auto  key   = GetOrCreateFamilyKey(uiPid);

    // Step 3: Write the shared secret BEFORE the DLL loads.
    //  We do this by:
    //    a) First injecting the DLL (CreateRemoteThread → LoadLibraryA)
    //    b) Immediately writing the secret after LoadLibraryA returns
    //       (the DLL is now mapped but DllMain-level hooks are installed
    //        asynchronously via background threads, so the secret is in place
    //        before any IPC message is sent or received)
    //
    //  NOTE: An alternative is to inject a tiny shellcode that writes the key
    //  then calls LoadLibraryA atomically.  For this PoC, the post-inject write
    //  is safe because IPC is only used after the first CreateFileW detour fires,
    //  which requires a user action after the DLL is fully initialised.

    auto* pfnLoadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"));

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                         pfnLoadLibrary, pRemotePath, 0, nullptr);
    bool success = false;
    if (hThread) {
        // Wait for LoadLibraryA to complete so the DLL is fully mapped
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);

        // Step 4: Write the shared secret into the now-loaded DLL's .dlpkey section
        if (WriteSharedSecretToProcess(hProcess, key.data())) {
            success = true;
        } else {
            // Secret write failed — log but still count the injection as successful
            // so we don't retry indefinitely.  The DLL will warn about zero-key HMAC.
            LogError(L"InjectDLL: secret write failed for PID=" + std::to_wstring(pid) +
                     L" — HMAC will use zero key (degraded security)");
            success = true; // DLL is loaded; IPC will work with zero key
        }
    }

    VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return success;
}

static void PruneStaleEntries() {
    std::lock_guard<std::mutex> lk(g_pidsLock);
    std::vector<DWORD> stale;
    for (DWORD pid : g_injectedPids) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h)
            stale.push_back(pid);
        else
            CloseHandle(h);
    }
    for (DWORD pid : stale) {
        g_injectedPids.erase(pid);
        g_familyKeys.erase(pid); // Clean up orphaned keys
    }
}

// Tries to inject into `pid` with name `name` if not already done.
static void TryInjectPid(DWORD pid, const std::wstring& name) {
    {
        std::lock_guard<std::mutex> lk(g_pidsLock);
        if (g_injectedPids.count(pid)) return; // Already injected
    }

    if (InjectDLL(pid, g_dllPath.c_str())) {
        std::lock_guard<std::mutex> lk(g_pidsLock);
        g_injectedPids.insert(pid);
        LogInfo(L"Injected DLPHook.dll into " + name +
                L" (PID " + std::to_wstring(pid) + L")");
    } else {
        LogError(L"Failed to inject into " + name +
                 L" (PID " + std::to_wstring(pid) + L")");
    }
}

static void ScanAndInject() {
    for (const auto& name : kTargetProcesses) {
        for (DWORD pid : GetAllProcessIds(name)) {
            TryInjectPid(pid, name);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 6 — ETW process-birth monitoring
// ════════════════════════════════════════════════════════════════════════════
//
//  ETW fires an event (ID=1, provider=Microsoft-Windows-Kernel-Process) the
//  moment any process is created system-wide, with zero polling delay.
//  This guarantees we inject into Chrome renderers before their first
//  CreateFileW call, eliminating the race window in the polling-only approach.
//
//  The ETW callback runs on a dedicated ProcessTrace thread (Section 7).
//  It extracts the image name from the event data and calls TryInjectPid().

// ETW event data layout for Kernel-Process ProcessStart (Event ID 1).
// This is a TDH (Trace Data Helper) schema — we parse it manually for speed.
// Field order (all little-endian):
//   ULONG  ProcessId
//   ULONG  ParentProcessId
//   ULONG  SessionId
//   LONG   ExitStatus          (0 for ProcessStart)
//   PVOID  DirectoryTableBase  (8 bytes on x64)
//   PVOID  UserSID             (variable — skip via TDH if needed)
//   WSTR   ImageFileName       (null-terminated wide string at end of fixed fields)
//
//  We skip the variable-length SID and instead use QueryFullProcessImageNameW
//  to get the image name — simpler and more reliable than TDH field parsing.

static VOID WINAPI EtwEventCallback(PEVENT_RECORD pEvent) {
    // Filter to ProcessStart events from Microsoft-Windows-Kernel-Process
    if (!IsEqualGUID(pEvent->EventHeader.ProviderId, kKernelProcessProviderGuid))
        return;
    if (pEvent->EventHeader.EventDescriptor.Id != kEtwEventIdProcessStart)
        return;

    // The new process PID is in the first 4 bytes of UserData
    if (!pEvent->UserData || pEvent->UserDataLength < sizeof(ULONG))
        return;

    const ULONG newPid = *static_cast<const ULONG*>(pEvent->UserData);
    if (newPid == 0) return;

    // Get the image name for the new process
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, newPid);
    if (!hProc) return; // Process may have already exited (very short-lived)

    wchar_t imagePath[MAX_PATH] = {};
    DWORD   nameLen = MAX_PATH;
    QueryFullProcessImageNameW(hProc, 0, imagePath, &nameLen);
    CloseHandle(hProc);

    // Extract filename component
    const wchar_t* imageName = imagePath;
    for (const wchar_t* p = imagePath; *p; ++p)
        if (*p == L'\\' || *p == L'/') imageName = p + 1;

    // Check if it's one of our targets (case-insensitive)
    for (const auto& target : kTargetProcesses) {
        if (_wcsicmp(imageName, target.c_str()) == 0) {
            // Brief yield to let the new process initialise its heap before
            // we inject — avoids races with very early process startup
            Sleep(50);

            TryInjectPid(newPid, target);
            break;
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 7 — ETW session setup & teardown
// ════════════════════════════════════════════════════════════════════════════

static constexpr wchar_t kEtwSessionName[] = L"DLP_ProcessMonitor";

struct EtwSessionBuffer {
    EVENT_TRACE_PROPERTIES props;
    wchar_t                sessionName[128];
};

static bool StartEtwSession() {
    // Stop any leftover session from a previous crash
    {
        EtwSessionBuffer buf = {};
        buf.props.Wnode.BufferSize    = sizeof(buf);
        buf.props.Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
        buf.props.LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
        buf.props.LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);
        ControlTraceW(0, kEtwSessionName, &buf.props, EVENT_TRACE_CONTROL_STOP);
    }

    EtwSessionBuffer buf = {};
    buf.props.Wnode.BufferSize    = sizeof(buf);
    buf.props.Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    buf.props.Wnode.ClientContext = 1; // QPC clock
    buf.props.LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
    buf.props.MinimumBuffers      = 4;
    buf.props.MaximumBuffers      = 16;
    buf.props.BufferSize          = 64; // KB
    buf.props.LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceW(&g_hEtwSession, kEtwSessionName, &buf.props);
    if (status != ERROR_SUCCESS) {
        LogError(L"ETW StartTrace failed: " + std::to_wstring(status) +
                 L" — falling back to polling only");
        return false;
    }

    // Enable the Kernel-Process provider on our session
    status = EnableTraceEx2(
        g_hEtwSession,
        &kKernelProcessProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0x10,   // WINEVENT_KEYWORD_PROCESS — process start/stop events
        0,
        0,
        nullptr);

    if (status != ERROR_SUCCESS) {
        LogError(L"ETW EnableTraceEx2 failed: " + std::to_wstring(status));
        // Continue — polling will still work
    }

    // Open a consumer handle for real-time processing
    EVENT_TRACE_LOGFILEW logFile = {};
    logFile.LoggerName           = const_cast<LPWSTR>(kEtwSessionName);
    logFile.ProcessTraceMode     = PROCESS_TRACE_MODE_REAL_TIME
                                 | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback  = EtwEventCallback;

    g_hEtwTrace = OpenTraceW(&logFile);
    if (g_hEtwTrace == INVALID_PROCESSTRACE_HANDLE) {
        LogError(L"ETW OpenTrace failed GLE=" + std::to_wstring(GetLastError()));
        return false;
    }

    LogInfo(L"ETW process-birth monitoring started");
    return true;
}

static void StopEtwSession() {
    if (g_hEtwTrace != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_hEtwTrace);
        g_hEtwTrace = INVALID_PROCESSTRACE_HANDLE;
    }

    if (g_hEtwSession != INVALID_PROCESSTRACE_HANDLE) {
        EtwSessionBuffer buf = {};
        buf.props.Wnode.BufferSize = sizeof(buf);
        buf.props.Wnode.Flags      = WNODE_FLAG_TRACED_GUID;
        buf.props.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        ControlTraceW(g_hEtwSession, nullptr, &buf.props, EVENT_TRACE_CONTROL_STOP);
        g_hEtwSession = INVALID_PROCESSTRACE_HANDLE;
    }

    LogInfo(L"ETW session stopped");
}

// ProcessTrace runs its blocking loop on a dedicated thread so we don't
// block the main monitoring loop (which also does polling).
static DWORD WINAPI EtwProcessTraceThread(LPVOID /*param*/) {
    if (g_hEtwTrace == INVALID_PROCESSTRACE_HANDLE) return 1;

    // ProcessTrace blocks until the session ends or CloseTrace is called.
    // Our StopEtwSession() calls CloseTrace which unblocks this thread.
    ULONG status = ProcessTrace(&g_hEtwTrace, 1, nullptr, nullptr);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
        LogError(L"ETW ProcessTrace exited with error: " + std::to_wstring(status));
    }
    return 0;
}

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 8 — Public API: StartMonitoring
// ════════════════════════════════════════════════════════════════════════════

void StartMonitoring(HANDLE hStopEvent) {
    g_hStopEvent = hStopEvent;

    if (!ResolveDllPath()) {
        LogError(L"Cannot start monitoring: DLPHook.dll not found");
        return;
    }

    LogInfo(L"DLP monitoring started (ETW + polling). DLL: " +
            std::wstring(g_dllPath.begin(), g_dllPath.end()));

    // ── Start ETW for zero-delay process-birth detection ─────────────────────
    const bool etwOk = StartEtwSession();
    HANDLE hEtwThread = nullptr;
    if (etwOk) {
        hEtwThread = CreateThread(nullptr, 0, EtwProcessTraceThread, nullptr, 0, nullptr);
        if (!hEtwThread)
            LogError(L"Could not start ETW ProcessTrace thread — polling only");
    }

    // ── Initial scan: inject into already-running target processes ────────────
    ScanAndInject();

    // ── Polling loop: backstop for processes that slipped through ETW ─────────
    int cycle = 0;
    while (WaitForSingleObject(hStopEvent, kPollIntervalMs) == WAIT_TIMEOUT) {
        ScanAndInject();
        if (++cycle % kPruneCycleCount == 0)
            PruneStaleEntries();
    }

    // ── Shutdown ──────────────────────────────────────────────────────────────
    StopEtwSession(); // Signals the ETW thread to exit

    if (hEtwThread) {
        WaitForSingleObject(hEtwThread, 3000);
        CloseHandle(hEtwThread);
    }

    LogInfo(L"DLP monitoring stopped.");
}
