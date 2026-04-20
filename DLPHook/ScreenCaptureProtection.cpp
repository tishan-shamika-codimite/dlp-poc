#include "pch.h"
#include "ScreenCaptureProtection.h"

#include <unordered_map>
#include <vector>
#include <mutex>
#include <utility>   // std::pair

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 1 — SetWindowDisplayAffinity wrapper & constants
// ════════════════════════════════════════════════════════════════════════════
//
//  WDA_EXCLUDEFROMCAPTURE (0x00000011) was added in Windows 10 build 19041.
//  We load the function dynamically so the DLL can be loaded on older systems
//  without a hard import failure; protection simply degrades gracefully to a
//  no-op on unsupported builds.
//
//  WDA_NONE             = 0x00000000  — remove any affinity (restore normal)
//  WDA_MONITOR          = 0x00000001  — legacy; window only visible on its
//                                        current monitor (seldom used for DLP)
//  WDA_EXCLUDEFROMCAPTURE = 0x00000011 — renders BLACK in all capture APIs
//                                        (GDI BitBlt, DXGI Desktop Dup,
//                                         WinRT GraphicsCapture, PrintScreen,
//                                         Snipping Tool, screen-sharing apps)

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE  0x00000011u
#endif
#ifndef WDA_NONE
#define WDA_NONE                0x00000000u
#endif

// Dynamically-resolved pointer to SetWindowDisplayAffinity.
// Resolved once in ScreenCaptureProtection_Install(); remains valid for the
// lifetime of the DLL because user32.dll is never unloaded.
typedef BOOL (WINAPI* PFN_SetWindowDisplayAffinity)(HWND, DWORD);
static PFN_SetWindowDisplayAffinity g_pfnSetWDA = nullptr;

// Safe wrapper: calls the real API, returns FALSE + logs if unavailable.
static BOOL SetWDA(HWND hwnd, DWORD affinity) {
    if (!g_pfnSetWDA) {
        // Graceful degradation: platform does not support WDA_EXCLUDEFROMCAPTURE
        OutputDebugStringA("[DLP][SCP] SetWindowDisplayAffinity not available on this OS version");
        return FALSE;
    }
    const BOOL ok = g_pfnSetWDA(hwnd, affinity);
    if (!ok) {
        char buf[128];
        wsprintfA(buf, "[DLP][SCP] SetWindowDisplayAffinity(hwnd=%p, aff=0x%X) failed — GLE=%lu",
                  hwnd, affinity, GetLastError());
        OutputDebugStringA(buf);
    }
    return ok;
}

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 2 — Protected-window registry
// ════════════════════════════════════════════════════════════════════════════
//
//  g_protected maps HWND → owning PID.
//  The PID is stored so we can efficiently answer "remove all windows for PID
//  N" without having to enumerate the entire Windows z-order again.
//
//  All access is guarded by g_mutex (std::mutex, non-recursive is fine because
//  none of our internal helpers call back into themselves).

static std::mutex                          g_mutex;
static std::unordered_map<HWND, DWORD>     g_protected;   // hwnd → pid

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 3 — Background monitor thread
// ════════════════════════════════════════════════════════════════════════════
//
//  The monitor thread wakes every MONITOR_INTERVAL_MS and scans g_protected
//  for windows that are no longer valid (IsWindow() == FALSE).  When a window
//  is gone we cannot call SetWindowDisplayAffinity on it (the handle is stale),
//  but we still must remove it from the registry so it does not accumulate
//  indefinitely.
//
//  The thread is signalled to terminate via g_stopEvent (a manual-reset event).

static constexpr DWORD kMonitorIntervalMs = 1500; // poll interval

static HANDLE g_stopEvent  = nullptr;
static HANDLE g_monThread  = nullptr;

static DWORD WINAPI MonitorThreadProc(LPVOID /*param*/) {
    OutputDebugStringA("[DLP][SCP] Monitor thread started");

    while (WaitForSingleObject(g_stopEvent, kMonitorIntervalMs) == WAIT_TIMEOUT) {
        //
        // Snapshot the current registry under the lock, then release the lock
        // before calling any Win32 APIs (avoids potential deadlock if another
        // thread holds a Win32 lock while trying to acquire g_mutex).
        //
        std::vector<HWND> snapshot;
        {
            std::lock_guard<std::mutex> lk(g_mutex);
            snapshot.reserve(g_protected.size());
            for (const auto& kv : g_protected)
                snapshot.push_back(kv.first);
        }

        std::vector<HWND> stale;
        for (HWND hwnd : snapshot) {
            if (!IsWindow(hwnd))
                stale.push_back(hwnd);
        }

        if (!stale.empty()) {
            std::lock_guard<std::mutex> lk(g_mutex);
            for (HWND hwnd : stale) {
                // The window is already gone — SetWDA would fail; just erase.
                g_protected.erase(hwnd);

                char buf[96];
                wsprintfA(buf, "[DLP][SCP] Window %p destroyed — removed from protected set", hwnd);
                OutputDebugStringA(buf);
            }
        }
    }

    OutputDebugStringA("[DLP][SCP] Monitor thread stopping");
    return 0;
}

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 4 — EnumWindows callback helpers
// ════════════════════════════════════════════════════════════════════════════

struct EnumCtx {
    DWORD pid;
    UINT  count;    // number of windows successfully processed
    DWORD affinity; // WDA_EXCLUDEFROMCAPTURE or WDA_NONE
};

// ApplyAffinityToHwnd — applies WDA_EXCLUDEFROMCAPTURE or WDA_NONE to a single
// HWND that is confirmed to belong to the target PID.  Called from both the
// top-level EnumWindows callback and the child-window EnumChildProc below.
//
// NOTE: We intentionally do NOT filter on IsWindowVisible() here.
//
//  WHY: Adobe Acrobat (and other hardware-accelerated viewers) host their actual
//  rendered content in an *invisible* DirectComposition / CEF compositor child
//  window.  The visible frame window is just chrome (title bar, borders).
//  DXGI Desktop Duplication and the WinRT GraphicsCapture API capture the
//  compositor surface, NOT the frame window.
//
//  If we skip invisible windows:
//    • Only the visible frame gets WDA_EXCLUDEFROMCAPTURE
//    • The invisible compositor HWND remains unprotected
//    • Windows detects a mixed protected/unprotected state for the process and
//      ABORTS the Snipping Tool overlay entirely instead of showing a black box
//
//  By protecting all windows (visible + invisible) we ensure every HWND in the
//  process is flagged, the capture pipeline sees a uniformly protected surface,
//  and the Snipping Tool correctly renders a black rectangle over the PDF while
//  its own dark selection overlay is still displayed to the user.
static void ApplyAffinityToHwnd(HWND hwnd, EnumCtx* ctx) {
    if (ctx->affinity == WDA_EXCLUDEFROMCAPTURE) {
        // Arm protection — include invisible windows (compositor surfaces, etc.)
        if (SetWDA(hwnd, WDA_EXCLUDEFROMCAPTURE)) {
            std::lock_guard<std::mutex> lk(g_mutex);
            g_protected[hwnd] = ctx->pid;
            ctx->count++;

            char buf[128];
            wsprintfA(buf, "[DLP][SCP] PROTECTED hwnd=%p pid=%lu", hwnd, ctx->pid);
            OutputDebugStringA(buf);
        }
    } else {
        // Remove protection
        if (SetWDA(hwnd, WDA_NONE)) {
            std::lock_guard<std::mutex> lk(g_mutex);
            g_protected.erase(hwnd);
            ctx->count++;

            char buf[128];
            wsprintfA(buf, "[DLP][SCP] UNPROTECTED hwnd=%p pid=%lu", hwnd, ctx->pid);
            OutputDebugStringA(buf);
        }
    }
}

// EnumChildProc — recursively visits every child window of a top-level HWND.
// Acrobat's compositor surface is a child window, so EnumWindows alone misses it.
static BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
    auto* ctx = reinterpret_cast<EnumCtx*>(lParam);

    // Child windows always share the PID of their top-level ancestor in the same
    // process.  We re-check here for safety (e.g. cross-process child windows).
    DWORD winPid = 0;
    GetWindowThreadProcessId(hwnd, &winPid);
    if (winPid != ctx->pid)
        return TRUE;

    ApplyAffinityToHwnd(hwnd, ctx);
    return TRUE; // continue enumeration
}

// Callback used by both ScreenCapture_ProtectProcess and _UnprotectProcess.
// Filters to top-level windows that belong to `ctx->pid`, applies the requested
// affinity to the top-level HWND itself, then descends into all child windows
// via EnumChildWindows.  We deliberately visit ALL windows (visible and hidden)
// for the PID because:
//   • Adobe Acrobat uses multiple top-level HWNDs (task pane, toolbar, …)
//   • Acrobat's actual render surface is an invisible child compositor window
//   • Chrome spawns separate renderer windows for some content
//   • Skipping invisible windows leaves compositor surfaces unprotected, which
//     causes the Snipping Tool overlay to abort instead of showing a black box
static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    auto* ctx = reinterpret_cast<EnumCtx*>(lParam);

    DWORD winPid = 0;
    GetWindowThreadProcessId(hwnd, &winPid);
    if (winPid != ctx->pid)
        return TRUE; // keep enumerating — this window belongs to a different process

    // Apply affinity to the top-level window itself (visible or not).
    ApplyAffinityToHwnd(hwnd, ctx);

    // Descend into all child windows — this catches the hidden compositor
    // surfaces that are the actual DXGI/WinRT capture targets.
    EnumChildWindows(hwnd, EnumChildProc, lParam);

    return TRUE; // continue enumeration
}

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 5 — Public API implementation
// ════════════════════════════════════════════════════════════════════════════

BOOL ScreenCapture_ProtectWindow(HWND hwnd) {
    if (!hwnd || !IsWindow(hwnd)) return FALSE;

    {
        std::lock_guard<std::mutex> lk(g_mutex);
        if (g_protected.count(hwnd)) return TRUE; // already protected
    }

    if (!SetWDA(hwnd, WDA_EXCLUDEFROMCAPTURE))
        return FALSE;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);

    {
        std::lock_guard<std::mutex> lk(g_mutex);
        g_protected[hwnd] = pid;
    }

    char buf[128];
    wsprintfA(buf, "[DLP][SCP] PROTECTED hwnd=%p pid=%lu (direct)", hwnd, pid);
    OutputDebugStringA(buf);
    return TRUE;
}

BOOL ScreenCapture_UnprotectWindow(HWND hwnd) {
    if (!hwnd) return TRUE;

    // If the window is already gone we skip the API call (it would fail).
    if (IsWindow(hwnd)) {
        if (!SetWDA(hwnd, WDA_NONE))
            return FALSE;
    }

    {
        std::lock_guard<std::mutex> lk(g_mutex);
        g_protected.erase(hwnd);
    }

    char buf[96];
    wsprintfA(buf, "[DLP][SCP] UNPROTECTED hwnd=%p (direct)", hwnd);
    OutputDebugStringA(buf);
    return TRUE;
}

UINT ScreenCapture_ProtectProcess(DWORD pid) {
    if (!pid) return 0;

    EnumCtx ctx = { pid, 0u, WDA_EXCLUDEFROMCAPTURE };
    EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&ctx));

    char buf[128];
    wsprintfA(buf, "[DLP][SCP] ProtectProcess pid=%lu: %u window(s) protected", pid, ctx.count);
    OutputDebugStringA(buf);
    return ctx.count;
}

UINT ScreenCapture_UnprotectProcess(DWORD pid) {
    if (!pid) return 0;

    EnumCtx ctx = { pid, 0u, WDA_NONE };
    EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&ctx));

    char buf[128];
    wsprintfA(buf, "[DLP][SCP] UnprotectProcess pid=%lu: %u window(s) unprotected", pid, ctx.count);
    OutputDebugStringA(buf);
    return ctx.count;
}

UINT ScreenCapture_GetProtectedCount() {
    std::lock_guard<std::mutex> lk(g_mutex);
    return static_cast<UINT>(g_protected.size());
}

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 6 — Module lifecycle
// ════════════════════════════════════════════════════════════════════════════

void ScreenCaptureProtection_Install() {
    // ── Resolve SetWindowDisplayAffinity dynamically ──────────────────────────
    //
    //  user32.dll is always loaded, but SetWindowDisplayAffinity was only
    //  added in Windows 8 and WDA_EXCLUDEFROMCAPTURE in Windows 10 19041.
    //  Dynamic resolution lets the DLL load without crashing on older systems.
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (hUser32) {
        g_pfnSetWDA = reinterpret_cast<PFN_SetWindowDisplayAffinity>(
            GetProcAddress(hUser32, "SetWindowDisplayAffinity"));
    }

    if (!g_pfnSetWDA) {
        OutputDebugStringA("[DLP][SCP] WARNING: SetWindowDisplayAffinity not found "
                           "— screen-capture protection disabled (requires Win10 19041+)");
        // Do NOT start the monitor thread; there is nothing to monitor.
        return;
    }

    // ── Create the stop event (manual-reset, initially unsignalled) ───────────
    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stopEvent) {
        OutputDebugStringA("[DLP][SCP] ERROR: CreateEvent failed — monitor thread not started");
        return;
    }

    // ── Start the background monitor thread ───────────────────────────────────
    g_monThread = CreateThread(nullptr, 0, MonitorThreadProc, nullptr, 0, nullptr);
    if (!g_monThread) {
        OutputDebugStringA("[DLP][SCP] ERROR: CreateThread failed — monitor thread not started");
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
        return;
    }

    OutputDebugStringA("[DLP][SCP] Screen-capture protection module installed "
                       "(WDA_EXCLUDEFROMCAPTURE active)");
}

void ScreenCaptureProtection_Remove() {
    // ── Signal the monitor thread to stop ─────────────────────────────────────
    if (g_stopEvent) {
        SetEvent(g_stopEvent);
    }
    if (g_monThread) {
        // Wait up to 3 seconds for the thread to acknowledge the stop.
        // 3 s > kMonitorIntervalMs (1.5 s) so a normally sleeping thread will
        // always wake and exit within the wait window.
        const DWORD waitResult = WaitForSingleObject(g_monThread, 3000);
        if (waitResult == WAIT_TIMEOUT) {
            OutputDebugStringA("[DLP][SCP] WARNING: Monitor thread did not exit in time — "
                               "proceeding with forced cleanup");
        }
        CloseHandle(g_monThread);
        g_monThread = nullptr;
    }
    if (g_stopEvent) {
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
    }

    // ── Remove protection from all remaining windows ──────────────────────────
    //
    //  It is critical that we restore WDA_NONE before the DLL unloads.
    //  If we leave WDA_EXCLUDEFROMCAPTURE set and the DLL is then unloaded,
    //  the window handle becomes associated with a protection flag that the
    //  process can no longer service — the window renders black permanently
    //  (until the host process restarts).
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        for (auto& kv : g_protected) {
            HWND hwnd = kv.first;
            if (IsWindow(hwnd)) {
                SetWDA(hwnd, WDA_NONE);
                char buf[96];
                wsprintfA(buf, "[DLP][SCP] Cleanup: restored WDA_NONE on hwnd=%p", hwnd);
                OutputDebugStringA(buf);
            }
        }
        g_protected.clear();
    }

    OutputDebugStringA("[DLP][SCP] Screen-capture protection module removed — all windows restored");
}
