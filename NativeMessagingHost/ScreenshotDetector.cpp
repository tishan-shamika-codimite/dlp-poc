#include "ScreenshotDetector.h"
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <atomic>
#include <chrono>
#include <thread>
#include <mutex>
#include <string>
#include <cwchar>

// ── Shared state ──────────────────────────────────────────────────────────────
//
// Two independent signals:
//
//  g_processActive  — true while any known screenshot process is running.
//                     Driven by the process existence watcher (200ms poll).
//                     Stays true for the full process lifetime — overlay is held
//                     up until the user closes the tool.
//
//  g_keypressActive — true for KEYPRESS_CLEAR_MS after the last keyboard or
//                     clipboard trigger. Handles methods with no long-lived
//                     process (e.g. plain PrintScreen → goes straight to clipboard).
//
// IsActive() = g_processActive || g_keypressActive.
//
// The notify callback is called immediately on every transition of IsActive(),
// so the browser receives the message with no poll-loop delay.

static std::atomic<bool>    g_processActive { false };
static std::atomic<bool>    g_keypressActive{ false };
static std::atomic<int64_t> g_keypressTriggerMs{ 0 };
static std::atomic<bool>    g_running{ false };

// How long (ms) the keypress/clipboard signal stays active.
// Only used when no screenshot process is running.
static constexpr int64_t KEYPRESS_CLEAR_MS = 3000;

// Notify callback — called immediately on any IsActive() state change.
static ScreenshotNotifyFn g_notify;

// Mutex guards g_notify calls so only one thread fires at a time.
static std::mutex g_notifyMutex;

static int64_t NowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

// ── State change helper ───────────────────────────────────────────────────────
// Computes the current combined IsActive() value and fires the notify callback
// if it has changed. Called by every detection method on every state update.

static bool s_lastNotified = false; // last value we reported to the callback

static void NotifyIfChanged() {
    bool now = g_processActive.load(std::memory_order_acquire) ||
               g_keypressActive.load(std::memory_order_acquire);

    std::lock_guard<std::mutex> lk(g_notifyMutex);
    if (now != s_lastNotified) {
        s_lastNotified = now;
        if (g_notify) g_notify(now);
    }
}

// ── Keypress/clipboard trigger ────────────────────────────────────────────────
// Called by keyboard hook and clipboard listener.
// Immediately notifies the browser — no poll delay.

static void TriggerKeypress() {
    g_keypressTriggerMs.store(NowMs(), std::memory_order_relaxed);
    g_keypressActive.store(true, std::memory_order_release);
    NotifyIfChanged(); // fires callback immediately
}

// ── Known screenshot processes ────────────────────────────────────────────────

static const wchar_t* kScreenshotProcesses[] = {
    L"SnippingTool.exe",        // Classic Snipping Tool & Win 11 integrated tool
    L"ScreenClippingHost.exe",  // Win+Shift+S snip overlay (Win 10/11)
    L"ScreenSketch.exe",        // Snip & Sketch (older Windows builds)
    L"ShareX.exe",              // ShareX
    L"Greenshot.exe",           // Greenshot
};

// ── Detection 1: Low-level keyboard hook ──────────────────────────────────────
//
// WH_KEYBOARD_LL fires system-wide BEFORE the OS acts on the key.
// Catches PrintScreen (all variants) and Win+Shift+S.
//
// Critically, calling TriggerKeypress() here → NotifyIfChanged() → g_notify()
// sends the message to the browser IMMEDIATELY, before the OS even launches
// ScreenClippingHost.exe. No poll delay at all.

static HHOOK g_kbHook     = nullptr;
static DWORD g_kbThreadId = 0;

static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        const KBDLLHOOKSTRUCT* kb = reinterpret_cast<const KBDLLHOOKSTRUCT*>(lParam);

        // PrintScreen family: plain, Alt+PrintScreen, Ctrl+PrintScreen.
        if (kb->vkCode == VK_SNAPSHOT) {
            TriggerKeypress();
        }

        // Win+Shift+S — fires before ScreenClippingHost.exe is even launched.
        if (kb->vkCode == 'S') {
            bool winDown   = (GetAsyncKeyState(VK_LWIN)   & 0x8000) ||
                             (GetAsyncKeyState(VK_RWIN)   & 0x8000);
            bool shiftDown = (GetAsyncKeyState(VK_SHIFT)  & 0x8000) ||
                             (GetAsyncKeyState(VK_LSHIFT) & 0x8000) ||
                             (GetAsyncKeyState(VK_RSHIFT) & 0x8000);
            if (winDown && shiftDown) {
                TriggerKeypress(); // immediate notify — browser gets message NOW
            }
        }
    }
    return CallNextHookEx(g_kbHook, nCode, wParam, lParam);
}

static void KeyboardHookThreadProc() {
    g_kbThreadId = GetCurrentThreadId();
    g_kbHook     = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc, nullptr, 0);
    if (!g_kbHook) return;

    MSG msg;
    while (g_running.load()) {
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    UnhookWindowsHookEx(g_kbHook);
    g_kbHook = nullptr;
}

// ── Detection 2: Clipboard listener ──────────────────────────────────────────
//
// WM_CLIPBOARDUPDATE fires whenever any process writes an image to clipboard.
// Also calls NotifyIfChanged() immediately — no poll delay.

static HWND g_clipWnd      = nullptr;
static ATOM g_clipWndClass = 0;

static LRESULT CALLBACK ClipboardWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_CLIPBOARDUPDATE) {
        if (IsClipboardFormatAvailable(CF_BITMAP) ||
            IsClipboardFormatAvailable(CF_DIB)    ||
            IsClipboardFormatAvailable(CF_DIBV5)) {
            TriggerKeypress(); // immediate notify
        }
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void ClipboardListenerThreadProc() {
    WNDCLASSEXW wc   = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = ClipboardWndProc;
    wc.hInstance     = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"DlpClipboardListener";
    g_clipWndClass   = RegisterClassExW(&wc);
    if (!g_clipWndClass) return;

    g_clipWnd = CreateWindowExW(
        0, L"DlpClipboardListener", L"DlpClipboard",
        0, 0, 0, 0, 0,
        HWND_MESSAGE, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (!g_clipWnd) return;

    AddClipboardFormatListener(g_clipWnd);

    MSG msg;
    while (g_running.load()) {
        while (PeekMessageW(&msg, g_clipWnd, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    RemoveClipboardFormatListener(g_clipWnd);
    DestroyWindow(g_clipWnd);
    g_clipWnd = nullptr;

    UnregisterClassW(L"DlpClipboardListener", GetModuleHandleW(nullptr));
    g_clipWndClass = 0;
}

// ── Detection 3: Process existence watcher ────────────────────────────────────
//
// Polls every 200ms using CreateToolhelp32Snapshot — detects screenshot tools
// regardless of foreground state (ScreenClippingHost.exe is a transparent
// overlay that never becomes the foreground window).
//
// g_processActive is held true for the full process lifetime. On each poll:
//  - if any process found → set true, NotifyIfChanged()
//  - if none found       → set false, NotifyIfChanged()
// This drives the overlay on/off in sync with the tool being open or closed.

static bool IsProcessRunning(const wchar_t* name) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    bool found = false;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                found = true;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return found;
}

static void ProcessWatcherThreadProc() {
    while (g_running.load()) {
        bool anyRunning = false;
        for (const wchar_t* proc : kScreenshotProcesses) {
            if (IsProcessRunning(proc)) {
                anyRunning = true;
                break;
            }
        }

        bool prev = g_processActive.exchange(anyRunning, std::memory_order_acq_rel);
        if (prev != anyRunning) {
            // Process state changed — notify immediately.
            NotifyIfChanged();
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    g_processActive.store(false, std::memory_order_release);
    NotifyIfChanged();
}

// ── Keypress watchdog ─────────────────────────────────────────────────────────
// Auto-clears g_keypressActive after KEYPRESS_CLEAR_MS with no new trigger.
// Calls NotifyIfChanged() when it clears, so the browser receives active:false.

static void KeypressWatchdogThreadProc() {
    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        if (g_keypressActive.load(std::memory_order_acquire)) {
            int64_t last = g_keypressTriggerMs.load(std::memory_order_relaxed);
            if (NowMs() - last >= KEYPRESS_CLEAR_MS) {
                g_keypressActive.store(false, std::memory_order_release);
                NotifyIfChanged(); // tell browser active:false if process also gone
            }
        }
    }
}

// ── Thread handles ────────────────────────────────────────────────────────────

static std::thread g_kbThread;
static std::thread g_clipThread;
static std::thread g_procThread;
static std::thread g_watchdogThread;

// ── Public API ────────────────────────────────────────────────────────────────

void ScreenshotDetector_Start(ScreenshotNotifyFn notify) {
    g_notify = std::move(notify);
    s_lastNotified = false;
    g_running.store(true);
    g_kbThread       = std::thread(KeyboardHookThreadProc);
    g_clipThread     = std::thread(ClipboardListenerThreadProc);
    g_procThread     = std::thread(ProcessWatcherThreadProc);
    g_watchdogThread = std::thread(KeypressWatchdogThreadProc);
}

void ScreenshotDetector_Stop() {
    g_running.store(false);

    if (g_kbThreadId) PostThreadMessageW(g_kbThreadId, WM_QUIT, 0, 0);
    if (g_clipWnd)    PostMessageW(g_clipWnd, WM_QUIT, 0, 0);

    if (g_kbThread.joinable())       g_kbThread.join();
    if (g_clipThread.joinable())     g_clipThread.join();
    if (g_procThread.joinable())     g_procThread.join();
    if (g_watchdogThread.joinable()) g_watchdogThread.join();
}

bool ScreenshotDetector_IsActive() {
    return g_processActive.load(std::memory_order_acquire) ||
           g_keypressActive.load(std::memory_order_acquire);
}
