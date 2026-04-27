#pragma once
#include <functional>

// ── ScreenshotDetector ────────────────────────────────────────────────────────
//
// Detects screenshot attempts at the OS level using three complementary methods:
//
//  1. WH_KEYBOARD_LL global low-level keyboard hook
//       Fires synchronously before the OS acts on the key.
//       Catches: PrintScreen, Alt+PrintScreen, Ctrl+PrintScreen, Win+Shift+S.
//       Calls the notify callback IMMEDIATELY — zero poll delay.
//
//  2. AddClipboardFormatListener (WM_CLIPBOARDUPDATE)
//       Fires whenever any process writes an image to the clipboard.
//       Catches: Win+Shift+S (after snip), Snipping Tool, ShareX, Greenshot,
//                and any other tool that places a bitmap on the clipboard.
//       Also calls the notify callback immediately on detection.
//
//  3. Process existence watcher (200 ms poll via CreateToolhelp32Snapshot)
//       Detects known screenshot processes regardless of foreground/focus state.
//       Catches: SnippingTool.exe, ScreenClippingHost.exe, ScreenSketch.exe,
//                ShareX.exe, Greenshot.exe.
//       g_processActive stays true for the entire process lifetime — overlay
//       is held up until the user closes the tool.
//
// The notify callback is called immediately on any state change (true OR false),
// bypassing the main poll loop entirely. The poll loop in main.cpp is kept as
// a fallback reconciliation pass but is not on the critical path for latency.
//
// Call sequence:
//   ScreenshotDetector_Start(callback);  // once at startup
//   // callback fires immediately on state changes
//   ScreenshotDetector_Stop();           // removes hooks, stops threads

using ScreenshotNotifyFn = std::function<void(bool active)>;

void ScreenshotDetector_Start(ScreenshotNotifyFn notify);
void ScreenshotDetector_Stop();
bool ScreenshotDetector_IsActive();
