#pragma once
#include <atomic>

// Monitors Zoom / Teams for active screen sharing using two complementary methods:
//
//  1. Process + window-title poll (every 1 s) — works without DLL injection.
//  2. Named pipe reader (\\.\pipe\DlpScreenShare) — receives signals from
//     ScreenShareHook.cpp that is injected into Zoom/Teams by DlpInjector.
//
// Both methods update the same shared atomic bool so the caller just reads
// ScreenShareDetector_IsSharing().

// Start background detection threads. Call once at startup.
void ScreenShareDetector_Start();

// Stop background threads. Blocks until they exit.
void ScreenShareDetector_Stop();

// Returns true if any detection method considers screen sharing active.
bool ScreenShareDetector_IsSharing();
