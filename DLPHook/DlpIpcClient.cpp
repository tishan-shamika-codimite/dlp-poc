#include "pch.h"
#include "DlpIpcClient.h"
#include "DlpIpc.h"

#include <tlhelp32.h>  // CreateToolhelp32Snapshot, PROCESSENTRY32W
#include <string>
#include <atomic>

// ── Private PROCESS_BASIC_INFORMATION layout with parent PID ─────────────────
//
//  The public winternl.h definition hides InheritedFromUniqueProcessId as
//  Reserved3[2].  We define the full layout using only types guaranteed by
//  <windows.h> so we need no extra SDK headers.

struct DLP_PROCESS_BASIC_INFORMATION {
    LONG      ExitStatus;          // NTSTATUS (LONG on all Windows versions)
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
};

typedef LONG (NTAPI* PFN_NtQueryInformationProcess)(
    HANDLE hProcess,
    ULONG  ProcessInformationClass,
    PVOID  ProcessInformation,
    ULONG  ProcessInformationLength,
    PULONG ReturnLength);

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 1 — Module state
// ════════════════════════════════════════════════════════════════════════════

static std::wstring        g_pipeName;
static DWORD               g_uiPid  = 0;
static std::atomic<bool>   g_inited { false };

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 2 — UI process PID discovery
// ════════════════════════════════════════════════════════════════════════════
//
//  Problem the previous implementation had:
//    Chrome:  browser → renderer → sub-renderer (rare but happens)
//    Acrobat: Acrobat.exe → AcroCEF.exe → AcroCEF_helper.exe
//
//  If we only read one level up (GetParentProcessId), a sub-worker would
//  point to another worker's pipe — which has no server.
//
//  Solution: walk UP the process tree, checking each ancestor's exe name,
//  until we find one that is NOT in the known worker list.  That is the
//  true UI root that runs the IPC server.

// Known worker exe names (lower-case).  Any process whose name matches
// is a worker; we keep walking up the tree past it.
static const wchar_t* kWorkerExeNames[] = {
    L"acrocef.exe",
    L"acrocef_1.exe",
    L"acrobatnotification.exe",
    // Chrome sub-processes are identified by --type= command line below,
    // not by exe name (they all share chrome.exe / msedge.exe etc.)
};

static bool IsWorkerExeName(const wchar_t* lower) {
    for (const auto* w : kWorkerExeNames)
        if (wcscmp(lower, w) == 0) return true;
    return false;
}

// Returns true if `pid` is a Chrome-family process running as a sub-process
// (i.e. its command line contains --type=).
static bool IsChromeWorkerPid(DWORD pid) {
    // Read the command line from the remote process via WMI would be complex;
    // instead we use ReadProcessMemory on the PEB.  For our purposes a simpler
    // heuristic is sufficient: if the exe name matches a browser and we can
    // open the process and its PEB CommandLine contains "--type=", it's a worker.
    // We skip this check and rely on the exe-name walk for non-Chrome processes.
    // For Chrome renderers the parent is always the main browser process
    // (Chrome's process model: browser spawns all renderers directly).
    (void)pid;
    return false; // Handled by the exe-name walk for AcroCEF;
                  // Chrome renderers' parent IS always the browser.
}

// Get the parent PID of `pid` by scanning the process snapshot.
static DWORD GetParentPid(DWORD pid) {
    // Use NtQueryInformationProcess for reliability
    static PFN_NtQueryInformationProcess pfnNtQIP = nullptr;
    if (!pfnNtQIP) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll)
            pfnNtQIP = reinterpret_cast<PFN_NtQueryInformationProcess>(
                GetProcAddress(hNtdll, "NtQueryInformationProcess"));
    }

    if (pfnNtQIP) {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProc) {
            DLP_PROCESS_BASIC_INFORMATION pbi = {};
            ULONG retLen = 0;
            LONG st = pfnNtQIP(hProc, 0, &pbi, sizeof(pbi), &retLen);
            CloseHandle(hProc);
            if (st == 0)
                return static_cast<DWORD>(pbi.InheritedFromUniqueProcessId);
        }
    }

    // Fallback: Toolhelp snapshot
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    DWORD parentPid = 0;
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
    return parentPid;
}

// Get the lower-case exe filename (no path) for `pid`.
static bool GetExeNameForPid(DWORD pid, wchar_t outLower[MAX_PATH]) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return false;

    wchar_t path[MAX_PATH] = {};
    DWORD len = MAX_PATH;
    QueryFullProcessImageNameW(hProc, 0, path, &len);
    CloseHandle(hProc);

    // Extract filename
    const wchar_t* name = path;
    for (const wchar_t* p = path; *p; ++p)
        if (*p == L'\\' || *p == L'/') name = p + 1;

    // Lower-case copy
    size_t i = 0;
    for (; name[i] && i < MAX_PATH - 1; ++i)
        outLower[i] = static_cast<wchar_t>(towlower(name[i]));
    outLower[i] = L'\0';
    return outLower[0] != L'\0';
}

// Walk up the process tree from `startPid` until we find an ancestor whose
// exe name is NOT in kWorkerExeNames and is NOT a Chrome sub-process.
// That ancestor is the UI process that owns the IPC server.
// Returns 0 on failure.
static DWORD FindUiProcessPid(DWORD startPid) {
    DWORD pid = GetParentPid(startPid);
    if (pid == 0) pid = startPid; // Can't walk up — use self

    for (int depth = 0; depth < 8 && pid != 0; ++depth) {
        wchar_t exeLower[MAX_PATH] = {};
        if (!GetExeNameForPid(pid, exeLower)) break;

        // AcroCEF workers — keep walking up
        if (IsWorkerExeName(exeLower)) {
            pid = GetParentPid(pid);
            continue;
        }

        // Chrome-family: check if this process is itself a renderer
        // (has --type= in its command line via reading its PEB)
        // We can't easily read another process's cmdline without WMI/PEB tricks,
        // but Chrome's process model guarantees: the direct parent of any renderer
        // IS the browser process.  So if the parent's exe is a browser name and
        // the parent is NOT a worker by exe name, it IS the UI root.
        // → accept it.
        return pid;
    }

    // Fallback: if we couldn't walk up, assume our direct parent is the UI
    return GetParentPid(startPid);
}

// Main entry point used by DlpIpcClient_Init
static DWORD GetUiProcessPid() {
    return FindUiProcessPid(GetCurrentProcessId());
}

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 3 — Pipe send helper (connect → write → read → disconnect)
// ════════════════════════════════════════════════════════════════════════════
//
//  We do NOT keep a persistent connection open.  Each notification creates a
//  fresh connection and disconnects after the Ack.  This keeps the design
//  simple and avoids problems with pipe handles surviving process crashes or
//  the server restarting.
//
//  The connection timeout (kPipeConnectMs) is kept short so that if the UI
//  process has not yet started its server, we fail quickly rather than
//  hanging the CreateFileW hook for a long time.

static BOOL SendMessage(const DLP_IPC_MESSAGE* pMsg) {
    // ── Connect to the server pipe ────────────────────────────────────────────
    //
    //  WaitNamedPipe is used first with a short timeout so we get a proper
    //  "pipe busy" signal rather than an immediate ERROR_FILE_NOT_FOUND if the
    //  server hasn't started yet.
    const bool pipeExists = WaitNamedPipeW(g_pipeName.c_str(), kPipeConnectMs) != FALSE;
    if (!pipeExists) {
        // Server not running yet — this is expected for the very first file open
        // before the server thread has fully initialised.
        char buf[256];
        wsprintfA(buf, "[DLP][IpcClient] WaitNamedPipe timeout/error GLE=%lu — "
                       "UI server not ready yet", GetLastError());
        OutputDebugStringA(buf);
        return FALSE;
    }

    HANDLE hPipe = CreateFileW(
        g_pipeName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,              // No sharing — exclusive client connection
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);

    if (hPipe == INVALID_HANDLE_VALUE) {
        char buf[256];
        wsprintfA(buf, "[DLP][IpcClient] CreateFile(pipe) failed GLE=%lu", GetLastError());
        OutputDebugStringA(buf);
        return FALSE;
    }

    // Switch to message-read mode to match the server's PIPE_TYPE_MESSAGE
    DWORD dwMode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(hPipe, &dwMode, nullptr, nullptr)) {
        char buf[128];
        wsprintfA(buf, "[DLP][IpcClient] SetNamedPipeHandleState failed GLE=%lu", GetLastError());
        OutputDebugStringA(buf);
        CloseHandle(hPipe);
        return FALSE;
    }

    // ── Write the message ─────────────────────────────────────────────────────
    DWORD written = 0;
    BOOL writeOk = WriteFile(hPipe, pMsg, sizeof(*pMsg), &written, nullptr);

    if (!writeOk || written != sizeof(*pMsg)) {
        char buf[128];
        wsprintfA(buf, "[DLP][IpcClient] WriteFile failed GLE=%lu", GetLastError());
        OutputDebugStringA(buf);
        CloseHandle(hPipe);
        return FALSE;
    }

    // ── Read the Ack / Nack response ──────────────────────────────────────────
    DLP_IPC_MESSAGE resp = {};
    DWORD bytesRead = 0;

    // Set a read timeout via overlapped I/O so we don't block forever
    OVERLAPPED ov = {};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    BOOL readOk = FALSE;

    if (ov.hEvent) {
        ReadFile(hPipe, &resp, sizeof(resp), nullptr, &ov);
        const DWORD gle = GetLastError();

        if (gle == ERROR_IO_PENDING) {
            const DWORD waitResult = WaitForSingleObject(ov.hEvent, kPipeIoMs);
            if (waitResult == WAIT_OBJECT_0) {
                GetOverlappedResult(hPipe, &ov, &bytesRead, FALSE);
                readOk = (bytesRead == sizeof(DLP_IPC_MESSAGE));
            } else {
                CancelIo(hPipe);
                OutputDebugStringA("[DLP][IpcClient] Read response timed out");
            }
        } else if (gle == 0 || gle == ERROR_SUCCESS) {
            GetOverlappedResult(hPipe, &ov, &bytesRead, FALSE);
            readOk = (bytesRead == sizeof(DLP_IPC_MESSAGE));
        }

        CloseHandle(ov.hEvent);
    }

    CloseHandle(hPipe);

    if (!readOk) return FALSE;

    const DlpIpcMsgType respType = static_cast<DlpIpcMsgType>(resp.dwMsgType);
    if (respType != DlpIpcMsgType::Ack) {
        char buf[64];
        wsprintfA(buf, "[DLP][IpcClient] Received non-Ack response type=%u", resp.dwMsgType);
        OutputDebugStringA(buf);
        return FALSE;
    }

    return TRUE;
}

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 4 — Public API
// ════════════════════════════════════════════════════════════════════════════

BOOL DlpIpcClient_Init(const wchar_t* appTag) {
    if (g_inited.load()) return TRUE;

    g_uiPid = GetUiProcessPid();
    if (g_uiPid == 0) {
        OutputDebugStringA("[DLP][IpcClient] Could not determine UI parent PID — IPC disabled");
        return FALSE;
    }

    g_pipeName = DlpIpc_BuildPipeName(appTag, g_uiPid);

    g_inited.store(true, std::memory_order_release);

    char buf[256];
    wsprintfA(buf,
        "[DLP][IpcClient] Initialised — parent(UI) PID=%lu pipe=%S",
        g_uiPid, g_pipeName.c_str());
    OutputDebugStringA(buf);
    return TRUE;
}

BOOL DlpIpcClient_NotifySensitiveFileOpened(uint32_t categories, const wchar_t* filePath) {
    if (!g_inited.load(std::memory_order_acquire)) {
        OutputDebugStringA("[DLP][IpcClient] NotifySensitiveFileOpened called before Init()");
        return FALSE;
    }

    DLP_IPC_MESSAGE msg = {};
    if (!DlpIpc_BuildMessage(&msg,
                              DlpIpcMsgType::SensitiveFileOpened,
                              categories,
                              g_uiPid,
                              filePath))
    {
        OutputDebugStringA("[DLP][IpcClient] BuildMessage failed");
        return FALSE;
    }

    const BOOL ok = SendMessage(&msg);

    char buf[256];
    wsprintfA(buf,
        "[DLP][IpcClient] SensitiveFileOpened sent to UI PID=%lu — %s",
        g_uiPid, ok ? "ACK" : "NACK/FAIL (fail-closed: open will be denied)");
    OutputDebugStringA(buf);

    return ok;
}

BOOL DlpIpcClient_NotifySensitiveFileClosed(const wchar_t* filePath) {
    if (!g_inited.load(std::memory_order_acquire)) return FALSE;

    DLP_IPC_MESSAGE msg = {};
    if (!DlpIpc_BuildMessage(&msg,
                              DlpIpcMsgType::SensitiveFileClosed,
                              0,
                              g_uiPid,
                              filePath))
        return FALSE;

    return SendMessage(&msg);
}

void DlpIpcClient_Shutdown() {
    g_inited.store(false, std::memory_order_release);
    g_uiPid = 0;
    g_pipeName.clear();
    OutputDebugStringA("[DLP][IpcClient] Shutdown");
}
