/*
 * ScreenShareHook.cpp
 *
 * Detects active screen sharing inside an injected Zoom / Teams process by
 * hooking the DXGI Desktop Duplication API at the COM vtable level.
 *
 * Strategy
 * ────────
 * Modern Zoom and Teams use IDXGIOutputDuplication to pull GPU frames for
 * encoding.  The method IDXGIOutputDuplication::AcquireNextFrame (vtable
 * index 8) is called in a tight loop while screen sharing is active.
 * Hooking it gives a precise, per-frame signal that is ONLY active during
 * real screen capture — unlike BitBlt / StretchBlt which fire on every
 * window repaint (minimize, maximize, drag, resize).
 *
 * How the vtable patch works
 * ──────────────────────────
 * 1. We call D3D11CreateDevice to obtain an ID3D11Device in this process.
 *    Zoom/Teams already have one; our call simply creates a second device
 *    on the same adapter — this is lightweight and does not interfere.
 * 2. We enumerate adapter outputs and call DuplicateOutput1 (or
 *    DuplicateOutput as fallback) to obtain an IDXGIOutputDuplication
 *    object.  Its vtable pointer is the same for ALL instances of the
 *    interface in this process.
 * 3. We use MinHook to patch vtable slot 8 (AcquireNextFrame).
 * 4. We release our temporary duplication object — the vtable patch
 *    persists for every IDXGIOutputDuplication instance in the process,
 *    including the one Zoom/Teams are actively using.
 *
 * Sharing "stop" detection
 * ────────────────────────
 * AcquireNextFrame returns DXGI_ERROR_WAIT_TIMEOUT when there is no new
 * frame within the caller's timeout window.  A sharing app calls it in a
 * loop, so timeouts during an active share are normal.  We therefore track
 * the last time a frame was *successfully* acquired and declare sharing
 * stopped if no success has been seen for INACTIVITY_TIMEOUT_SEC seconds.
 * A dedicated watchdog thread performs this check.
 *
 * Pipe protocol (same as before — NativeMessagingHost unchanged)
 * ──────────────────────────────────────────────────────────────
 *   "SHARING=1\n"  — sharing started / confirmed
 *   "SHARING=0\n"  — sharing stopped
 */

#include "pch.h"
#include "ScreenShareHook.h"
#include "MinHook.h"

#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <dxgi1_5.h>   // IDXGIOutput5 / DuplicateOutput1 — optional, falls back
#include <atomic>
#include <chrono>
#include <thread>
#include <mutex>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

// ── Configuration ─────────────────────────────────────────────────────────────

// Seconds without a successful AcquireNextFrame before we declare sharing stopped.
static constexpr double INACTIVITY_TIMEOUT_SEC = 6.0;

// How often the watchdog checks for inactivity.
static constexpr int WATCHDOG_INTERVAL_MS = 500;

// ── Named pipe ────────────────────────────────────────────────────────────────

static void NotifyPipe(const char* msg) {
    HANDLE hPipe = CreateFileA(
        "\\\\.\\pipe\\DlpScreenShare",
        GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING,
        nullptr);
    if (hPipe == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(hPipe, msg, static_cast<DWORD>(strlen(msg)), &written, nullptr);
    FlushFileBuffers(hPipe);
    CloseHandle(hPipe);
}

// ── Shared state ──────────────────────────────────────────────────────────────

static std::atomic<bool>   g_sharing{ false };
static std::atomic<bool>   g_hookActive{ false };

// Timestamp (in steady_clock ticks) of the last successful AcquireNextFrame.
// Written by the hook, read by the watchdog.  Use a plain int64 with relaxed
// atomics — exact ordering is not required here.
static std::atomic<int64_t> g_lastFrameTick{ 0 };

static std::atomic<bool>   g_watchdogRunning{ false };
static std::thread         g_watchdogThread;

static void SetSharing(bool active) {
    bool prev = g_sharing.exchange(active);
    if (prev != active) {
        OutputDebugStringA(active
            ? "[DLP] ScreenShare: sharing STARTED (DXGI)"
            : "[DLP] ScreenShare: sharing STOPPED (DXGI inactivity)");
        NotifyPipe(active ? "SHARING=1\n" : "SHARING=0\n");
    }
}

// ── Watchdog thread ───────────────────────────────────────────────────────────
// Clears sharing flag when no frame has been acquired for INACTIVITY_TIMEOUT_SEC.

static void WatchdogProc() {
    using namespace std::chrono;
    const int64_t timeoutTicks = static_cast<int64_t>(
        INACTIVITY_TIMEOUT_SEC * steady_clock::period::den / steady_clock::period::num);

    while (g_watchdogRunning.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(milliseconds(WATCHDOG_INTERVAL_MS));

        if (!g_sharing.load(std::memory_order_relaxed))
            continue; // nothing to clear

        int64_t last  = g_lastFrameTick.load(std::memory_order_relaxed);
        int64_t now   = steady_clock::now().time_since_epoch().count();

        if (last > 0 && (now - last) >= timeoutTicks) {
            SetSharing(false);
            // Reset so a new share session is treated freshly.
            g_lastFrameTick.store(0, std::memory_order_relaxed);
        }
    }
}

// ── DXGI AcquireNextFrame hook ────────────────────────────────────────────────

using FnAcquireNextFrame = HRESULT(STDMETHODCALLTYPE*)(
    IDXGIOutputDuplication*, UINT, DXGI_OUTDUPL_FRAME_INFO*, IDXGIResource**);

static FnAcquireNextFrame g_origAcquireNextFrame = nullptr;

static HRESULT STDMETHODCALLTYPE Hook_AcquireNextFrame(
    IDXGIOutputDuplication* pThis,
    UINT                    TimeoutInMilliseconds,
    DXGI_OUTDUPL_FRAME_INFO* pFrameInfo,
    IDXGIResource**          ppDesktopResource)
{
    HRESULT hr = g_origAcquireNextFrame(pThis, TimeoutInMilliseconds, pFrameInfo, ppDesktopResource);

    if (SUCCEEDED(hr)) {
        // A successful frame acquisition — real capture is active.
        using namespace std::chrono;
        int64_t now = steady_clock::now().time_since_epoch().count();
        g_lastFrameTick.store(now, std::memory_order_relaxed);
        SetSharing(true);
    }
    // DXGI_ERROR_WAIT_TIMEOUT is normal during an active share (no new frame).
    // We do NOT clear sharing on timeout — the watchdog handles inactivity.

    return hr;
}

// ── DXGI vtable patch ─────────────────────────────────────────────────────────

/*
 * IDXGIOutputDuplication vtable layout (from dxgi1_2.h):
 *   0  QueryInterface
 *   1  AddRef
 *   2  Release
 *   3  GetPrivateData
 *   4  SetPrivateData
 *   5  SetPrivateDataInterface
 *   6  GetParent          (IDXGIObject)
 *   7  GetDesc
 *   8  AcquireNextFrame   ← we hook this
 *   9  GetFrameDirtyRects
 *  10  GetFrameMoveRects
 *  11  GetFramePointerShape
 *  12  MapDesktopSurface
 *  13  UnMapDesktopSurface
 *  14  ReleaseFrame
 */
static constexpr int kAcquireNextFrameVtblIndex = 8;

static bool PatchDxgiVtable(IDXGIOutputDuplication* pDupl) {
    // Read the vtable pointer from the COM object.
    void** vtbl = *reinterpret_cast<void***>(pDupl);
    void*  target = vtbl[kAcquireNextFrameVtblIndex];

    if (MH_CreateHook(
            target,
            reinterpret_cast<void*>(&Hook_AcquireNextFrame),
            reinterpret_cast<void**>(&g_origAcquireNextFrame)) != MH_OK) {
        OutputDebugStringA("[DLP] MH_CreateHook(AcquireNextFrame) failed");
        return false;
    }

    if (MH_EnableHook(target) != MH_OK) {
        OutputDebugStringA("[DLP] MH_EnableHook(AcquireNextFrame) failed");
        return false;
    }

    OutputDebugStringA("[DLP] IDXGIOutputDuplication::AcquireNextFrame vtable hook INSTALLED");
    return true;
}

// ── InstallDxgiHook ───────────────────────────────────────────────────────────

static void InstallDxgiHook() {
    // Step 1 — Create a D3D11 device so we can instantiate IDXGIOutputDuplication.
    //          We use D3D_DRIVER_TYPE_HARDWARE first; fall back to WARP.
    ID3D11Device* pDevice = nullptr;
    D3D_FEATURE_LEVEL featureLevel = {};

    HRESULT hr = D3D11CreateDevice(
        nullptr,                    // default adapter
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        0,                          // no special flags
        nullptr, 0,                 // default feature levels
        D3D11_SDK_VERSION,
        &pDevice, &featureLevel, nullptr);

    if (FAILED(hr)) {
        // Try WARP (software) — always available, used as a fallback.
        hr = D3D11CreateDevice(
            nullptr,
            D3D_DRIVER_TYPE_WARP,
            nullptr, 0, nullptr, 0,
            D3D11_SDK_VERSION,
            &pDevice, &featureLevel, nullptr);
    }

    if (FAILED(hr) || !pDevice) {
        OutputDebugStringA("[DLP] D3D11CreateDevice failed — DXGI hook skipped");
        return;
    }

    // Step 2 — Obtain IDXGIDevice → IDXGIAdapter → IDXGIOutput1.
    IDXGIDevice* pDxgiDevice = nullptr;
    hr = pDevice->QueryInterface(__uuidof(IDXGIDevice),
                                 reinterpret_cast<void**>(&pDxgiDevice));
    if (FAILED(hr)) { pDevice->Release(); return; }

    IDXGIAdapter* pAdapter = nullptr;
    hr = pDxgiDevice->GetParent(__uuidof(IDXGIAdapter),
                                reinterpret_cast<void**>(&pAdapter));
    pDxgiDevice->Release();
    if (FAILED(hr)) { pDevice->Release(); return; }

    IDXGIOutput* pOutput = nullptr;
    hr = pAdapter->EnumOutputs(0, &pOutput);
    pAdapter->Release();
    if (FAILED(hr)) { pDevice->Release(); return; }

    IDXGIOutput1* pOutput1 = nullptr;
    hr = pOutput->QueryInterface(__uuidof(IDXGIOutput1),
                                 reinterpret_cast<void**>(&pOutput1));
    pOutput->Release();
    if (FAILED(hr)) { pDevice->Release(); return; }

    // Step 3 — Create a temporary IDXGIOutputDuplication to get the vtable.
    //          This succeeds even if another app is already duplicating because
    //          DuplicateOutput allows multiple simultaneous duplicators.
    IDXGIOutputDuplication* pDupl = nullptr;
    hr = pOutput1->DuplicateOutput(pDevice, &pDupl);
    pOutput1->Release();

    if (FAILED(hr) || !pDupl) {
        // DuplicateOutput can fail with DXGI_ERROR_UNSUPPORTED in Remote
        // Desktop / headless sessions.  Log and bail gracefully.
        char buf[128];
        sprintf_s(buf, "[DLP] DuplicateOutput failed hr=0x%08X — DXGI hook skipped", (unsigned)hr);
        OutputDebugStringA(buf);
        pDevice->Release();
        return;
    }

    // Step 4 — Patch the vtable.  The patch is global to the process; our
    //          temporary object can be released immediately afterwards.
    bool patched = PatchDxgiVtable(pDupl);

    pDupl->Release();  // Release OUR temporary duplicator — patch remains active
    pDevice->Release();

    if (!patched) {
        OutputDebugStringA("[DLP] DXGI vtable patch failed — hook not active");
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

void ScreenShareHook_Install() {
    // Install the DXGI vtable hook — this is the only capture-path hook.
    // BitBlt / StretchBlt are intentionally NOT hooked: those GDI functions
    // are called on every window repaint (minimize, maximize, drag, resize)
    // and produce constant false positives.
    InstallDxgiHook();

    g_hookActive.store(true);

    // Start the watchdog that clears sharing after INACTIVITY_TIMEOUT_SEC
    // seconds of no successful AcquireNextFrame calls.
    g_watchdogRunning.store(true);
    g_watchdogThread = std::thread(WatchdogProc);

    OutputDebugStringA("[DLP] ScreenShareHook installed (DXGI AcquireNextFrame only)");
}

void ScreenShareHook_Remove() {
    g_hookActive.store(false);

    // Stop watchdog
    g_watchdogRunning.store(false);
    if (g_watchdogThread.joinable())
        g_watchdogThread.join();

    // Signal stop if we were sharing
    if (g_sharing.load()) {
        NotifyPipe("SHARING=0\n");
        g_sharing.store(false);
    }

    // MinHook removal is handled globally by MH_DisableHook(MH_ALL_HOOKS)
    // in dllmain.cpp — no need to remove individual hooks here.
    OutputDebugStringA("[DLP] ScreenShareHook removed");
}
