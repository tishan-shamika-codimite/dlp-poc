#pragma once
#include <windows.h>
#include <cstdint>

// ════════════════════════════════════════════════════════════════════════════
//  ScreenCaptureProtection  —  DLP Screen-Capture & Screen-Share Blocker
// ════════════════════════════════════════════════════════════════════════════
//
//  When a sensitive document is opened in a viewer process (Adobe Acrobat,
//  Foxit Reader, etc.) the DLP engine must prevent screen-capture tools
//  (Snipping Tool, PrintScreen, Win+Shift+S) and screen-sharing applications
//  (Teams, Zoom, OBS, …) from capturing the document's content.
//
//  This module achieves that goal using the native Windows
//  SetWindowDisplayAffinity API with the WDA_EXCLUDEFROMCAPTURE flag
//  (Windows 10 2004 / build 19041 or later).
//
//  When active, the protected window:
//    • Appears BLACK / blank in all screen-capture APIs (GDI, DXGI, WinRT)
//    • Cannot be recorded by OBS, Teams screen-share, DXGI desktop dup., etc.
//    • The PrintScreen key and Snipping Tool capture only a black rectangle
//      where the protected window was.
//
//  Protection is automatically REMOVED when the protected window is destroyed
//  (document closed) by a background monitor thread that polls IsWindow().
//
// ────────────────────────────────────────────────────────────────────────────
//  Lifecycle
// ────────────────────────────────────────────────────────────────────────────
//
//   ScreenCaptureProtection_Install()   — starts the background monitor
//   ScreenCaptureProtection_Remove()    — stops the monitor, unprotects all
//
// ────────────────────────────────────────────────────────────────────────────
//  Per-window / per-process API
// ────────────────────────────────────────────────────────────────────────────

// Arm WDA_EXCLUDEFROMCAPTURE on a single HWND.
// Thread-safe; safe to call from any thread including a MinHook detour.
// If the window already has protection, the call is a no-op.
// Returns TRUE on success, FALSE if SetWindowDisplayAffinity fails.
BOOL ScreenCapture_ProtectWindow(HWND hwnd);

// Remove WDA_EXCLUDEFROMCAPTURE from a single HWND (set back to WDA_NONE).
// Thread-safe.  No-op if the window was not in the protected set.
// Returns TRUE on success (or if the window was already gone).
BOOL ScreenCapture_UnprotectWindow(HWND hwnd);

// Enumerate every top-level window belonging to `pid` and arm protection on
// each one.  Useful when a viewer process already has its window open at the
// moment a sensitive file is detected inside it.
// Returns the number of windows successfully protected (0 = none found).
UINT ScreenCapture_ProtectProcess(DWORD pid);

// Remove protection from every window that belongs to `pid`.
UINT ScreenCapture_UnprotectProcess(DWORD pid);

// Returns the number of windows currently under active protection.
UINT ScreenCapture_GetProtectedCount();

// ────────────────────────────────────────────────────────────────────────────
//  Module lifecycle (called from dllmain.cpp)
// ────────────────────────────────────────────────────────────────────────────

// Starts the background window-monitor thread.
// Must be called once from DLL_PROCESS_ATTACH (outside DllMain — use a
// worker thread, or call after MH_Initialize() returns).
void ScreenCaptureProtection_Install();

// Signals the monitor thread to stop, waits for it (up to 3 s), then calls
// SetWindowDisplayAffinity(hwnd, WDA_NONE) on every remaining protected window.
// Call from DLL_PROCESS_DETACH before MH_Uninitialize().
void ScreenCaptureProtection_Remove();
