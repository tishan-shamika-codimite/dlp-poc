#include "ScreenShareDetector.h"
#include <windows.h>
#include <tlhelp32.h>
#include <atomic>
#include <chrono>
#include <thread>
#include <string>
#include <vector>
#include <cwchar>
#include <psapi.h>

// ── Shared state ──────────────────────────────────────────────────────────────

// g_sharingPoll  — set by the window/process poll thread (Method 1)
// g_sharingPipe  — set by the named-pipe thread (Method 2, hook DLL signals)
// Either source can assert sharing=true; both must agree on false to clear.
static std::atomic<bool>    g_sharingPoll{ false };
static std::atomic<bool>    g_sharingPipe{ false };
static std::atomic<bool>    g_running{ false };
static std::thread          g_pollThread;
static std::thread          g_pipeThread;

// ── Pipe-side confirm delay ───────────────────────────────────────────────────
// The DXGI hook fires on the very first successful AcquireNextFrame.  Zoom
// and Teams can briefly call AcquireNextFrame during window compositing
// operations that are unrelated to screen sharing (e.g. when their internal
// video renderer initialises).  We require the pipe signal to be continuously
// true for at least PIPE_CONFIRM_MS milliseconds before asserting sharing.
static constexpr int64_t PIPE_CONFIRM_MS = 2000; // 2 seconds

// Monotonic timestamp (ms) when "SHARING=1" was first received in the current
// run.  0 means not yet seen / reset.
static std::atomic<int64_t> g_pipeFirstSeenMs{ 0 };

static int64_t NowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Returns the executable filename (e.g. L"slack.exe") of the process that owns
// the given window handle.  Used to confirm process ownership before acting on
// generic window class names (e.g. SingleWindowBorderClass, Chrome_WidgetWin_1)
// that could appear in non-Slack processes.
// Returns an empty wstring if the process cannot be queried (e.g. access denied).
static std::wstring GetWindowProcessName(HWND hwnd) {
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == 0) return {};

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return {};

    wchar_t path[MAX_PATH] = {};
    DWORD len = MAX_PATH;
    QueryFullProcessImageNameW(hProc, 0, path, &len);
    CloseHandle(hProc);

    // Extract just the filename component from the full path.
    const wchar_t* slash = wcsrchr(path, L'\\');
    return slash ? std::wstring(slash + 1) : std::wstring(path);
}

static bool IsProcessRunning(const wchar_t* name) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) { found = true; break; }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return found;
}

// ── Window enumeration ────────────────────────────────────────────────────────
//
// Detection strategy verified by live window enumeration on Zoom 5.x/6.x
// during both "sharing" and "not sharing" states within the same meeting.
//
// KEY INSIGHT: Many Zoom window classes exist in BOTH states (sharing and not
// sharing). The reliable differentiator is IsWindowVisible() — certain windows
// are created but hidden when idle, and only become visible during active share.
//
// ── Tier 1: Visible-only-during-share windows (highest confidence) ────────────
//
//   "sharing frame"  [CptHost.exe]
//       Zoom's screen-capture subprocess (CptHost.exe) owns this window.
//       The window EXISTS in both states but IsWindowVisible() returns TRUE
//       only when a screen share is actively in progress.  This is the most
//       reliable single signal found in live testing.
//
//   "ZPFloatControlPanelMgrClass"  [Zoom.exe]  title="Video layouts"
//       The meeting control panel manager.  Visible (vis=True) only during
//       an active share; hidden (vis=False) at all other times.
//
//   "ZPFloatToolbarClass"  [Zoom.exe]  title="Screen sharing meeting controls"
//       The floating toolbar shown to the sharer.  Only visible during an active
//       share.  Verified via live capture: absent entirely when not sharing.
//
//   "SingleWindowBorderClass"  [slack.exe]  title="Transparent Window"
//       Slack's (Electron) screen-share border/frame overlay window.
//       EXISTS in both idle and sharing states (owned by the Slack main PID)
//       but IsWindowVisible() returns TRUE ONLY during an active screen share.
//       Process ownership check against slack.exe is mandatory — the class name
//       is generic and could theoretically appear in other applications.
//       Verified by live window enumeration (find-slack-sharing.ps1):
//         Idle:    SingleWindowBorderClass  vis=False  title="Transparent Window"
//         Sharing: SingleWindowBorderClass  vis=True   title="Transparent Window"
//
// ── Explicitly excluded (verified vis=True in BOTH sharing and not-sharing) ────
//   VideoFrameWndClass  — vis=True in both states; NOT a reliable signal.
//   unsharing frame     — vis=True in both states; NOT a reliable signal.
//   ZPToolBarParentWndClass, ZPFloatVideoWndClass, ZPActiveSpeakerWndClass,
//   ZPVideoScrollBtnClass, ZOOM.CPTHOST.FRAMEOWNER — all irrelevant.
//
// ── Tier 2: Windows that only EXIST during sharing (also reliable) ─────────────
//
//   "ZPAnnotateEntryPointClass"  [Zoom.exe]  title="Annotation Entry Point"
//       Only created once the user starts sharing.  Absent entirely when not
//       sharing.  (Annotation panel itself requires user interaction to open.)
//
//   "ZoomAnnoWindowWndClass"  [Zoom.exe]  title="Annotation - Zoom"
//       The annotation overlay window.  Only present during an active share
//       session (though it requires the annotation toolbar to be open).
//
// ── Microsoft Teams class names ───────────────────────────────────────────────
//   MSTeamsSharing        — transparent overlay drawn around the shared region.
//   MSTeamsRdpWindowClass — Teams RDP sharing window.

struct EnumState {
    bool sharing = false;
};

static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    wchar_t cls[256] = {};
    GetClassNameW(hwnd, cls, 256);

    // ── Tier 1: class+visibility check (window exists in both states but is   ──
    // ──         ONLY visible when sharing is active)                           ──

    struct VisCheck { const wchar_t* cls; };
    static const VisCheck kZoomVisibleWhenSharing[] = {
        { L"sharing frame" },              // CptHost: vis=True ONLY during share (verified)
        { L"ZPFloatControlPanelMgrClass" },// Zoom: vis=True during share, vis=False otherwise (verified)
        { L"ZPFloatToolbarClass" },        // Zoom: "Screen sharing meeting controls" toolbar (verified)
        // NOTE: VideoFrameWndClass intentionally excluded — vis=True in BOTH states (false positive)
        // NOTE: unsharing frame intentionally excluded — vis=True in BOTH states (false positive)
    };
    for (const auto& vc : kZoomVisibleWhenSharing) {
        if (_wcsicmp(cls, vc.cls) == 0) {
            if (IsWindowVisible(hwnd)) {
                reinterpret_cast<EnumState*>(lParam)->sharing = true;
                return FALSE; // stop enumeration
            }
        }
    }

    // ── Tier 2: windows that only EXIST during an active share ────────────────
    static const wchar_t* kZoomShareOnlyClasses[] = {
        L"ZPAnnotateEntryPointClass", // annotation entry point — absent when not sharing
        L"ZoomAnnoWindowWndClass",    // annotation overlay — absent when not sharing
        // Legacy class names from older Zoom builds:
        L"ZPContentViewWnd",
        L"ZPFloatToolBarParentWnd",
    };
    for (const wchar_t* c : kZoomShareOnlyClasses) {
        if (_wcsicmp(cls, c) == 0) {
            reinterpret_cast<EnumState*>(lParam)->sharing = true;
            return FALSE;
        }
    }

    // ── Microsoft Teams sharing-active class names ────────────────────────────
    static const wchar_t* kTeamsClasses[] = {
        L"MSTeamsSharing",
        L"MSTeamsRdpWindowClass",
    };
    for (const wchar_t* c : kTeamsClasses) {
        if (_wcsicmp(cls, c) == 0) {
            reinterpret_cast<EnumState*>(lParam)->sharing = true;
            return FALSE;
        }
    }

    // ── Slack (Electron) — Tier-1: SingleWindowBorderClass visibility flip ────
    //
    // "Transparent Window" (class SingleWindowBorderClass) is owned by
    // slack.exe in BOTH idle and sharing states, but IsWindowVisible() returns
    // TRUE only while a screen share is actively in progress.
    //
    // Process ownership is verified via GetWindowProcessName() to prevent false
    // positives from any other application that happens to use the same generic
    // window class name.
    if (_wcsicmp(cls, L"SingleWindowBorderClass") == 0 && IsWindowVisible(hwnd)) {
        std::wstring owner = GetWindowProcessName(hwnd);
        if (_wcsicmp(owner.c_str(), L"slack.exe") == 0) {
            reinterpret_cast<EnumState*>(lParam)->sharing = true;
            return FALSE; // stop enumeration
        }
    }

    return TRUE; // continue enumeration
}

static bool DetectViaWindowClasses() {
    EnumState state;
    EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&state));
    return state.sharing;
}

static bool DetectViaProcessAndWindows() {
    // Only enumerate windows if a target process is running — avoids the
    // EnumWindows cost when Zoom/Teams are not open at all.
    static const wchar_t* kTargets[] = {
        L"Zoom.exe",     // Zoom main process
        L"CptHost.exe",  // Zoom screen-capture subprocess (owns "sharing frame")
        L"ms-teams.exe", // Microsoft Teams (classic)
        L"Teams.exe",    // Microsoft Teams (alternate name)
        L"msteams.exe",  // Microsoft Teams (another variant)
        L"slack.exe",    // Slack desktop app (Electron)
    };
    bool anyRunning = false;
    for (const wchar_t* name : kTargets) {
        if (IsProcessRunning(name)) { anyRunning = true; break; }
    }
    if (!anyRunning) return false;

    return DetectViaWindowClasses();
}

// ── Poll thread (Method 1) ────────────────────────────────────────────────────

static void PollThreadProc() {
    while (g_running.load()) {
        bool sharing = DetectViaProcessAndWindows();
        g_sharingPoll.store(sharing);
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

// ── Pipe thread (Method 2) ────────────────────────────────────────────────────
// Reads signals written by ScreenShareHook.cpp inside Zoom/Teams processes.
// Applies a PIPE_CONFIRM_MS confirmation delay before asserting sharing=true.

static void PipeThreadProc() {
    while (g_running.load()) {
        HANDLE hPipe = CreateNamedPipeW(
            L"\\\\.\\pipe\\DlpScreenShare",
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            0, 4096,
            500,
            nullptr);

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        BOOL connected = ConnectNamedPipe(hPipe, nullptr);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(hPipe);
            continue;
        }

        char buf[64] = {};
        DWORD bytesRead = 0;
        if (ReadFile(hPipe, buf, sizeof(buf) - 1, &bytesRead, nullptr) && bytesRead > 0) {
            std::string msg(buf, bytesRead);

            if (msg.find("SHARING=1") != std::string::npos) {
                // Start the confirm timer on the first SHARING=1 message.
                int64_t firstSeen = g_pipeFirstSeenMs.load(std::memory_order_relaxed);
                if (firstSeen == 0) {
                    g_pipeFirstSeenMs.store(NowMs(), std::memory_order_relaxed);
                } else {
                    // Check if we have held SHARING=1 long enough to confirm.
                    if ((NowMs() - firstSeen) >= PIPE_CONFIRM_MS) {
                        g_sharingPipe.store(true);
                    }
                }
            } else if (msg.find("SHARING=0") != std::string::npos) {
                // Reset both the confirmed state and the confirm timer.
                g_sharingPipe.store(false);
                g_pipeFirstSeenMs.store(0, std::memory_order_relaxed);
            }
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

void ScreenShareDetector_Start() {
    g_running.store(true);
    g_pollThread = std::thread(PollThreadProc);
    g_pipeThread = std::thread(PipeThreadProc);
}

void ScreenShareDetector_Stop() {
    g_running.store(false);
    if (g_pollThread.joinable()) g_pollThread.join();
    if (g_pipeThread.joinable()) g_pipeThread.join();
}

bool ScreenShareDetector_IsSharing() {
    // Either detection method asserting true is sufficient to block the screen.
    // Both must independently clear before we consider sharing stopped.
    return g_sharingPoll.load() || g_sharingPipe.load();
}
