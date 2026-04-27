#pragma once

// Installs MinHook detours on screen-capture APIs (BitBlt, DXGI Desktop Duplication)
// so the DLL can detect when Zoom or Teams begins screen sharing and signal the
// Native Messaging Host via a named pipe: \\.\pipe\DlpScreenShare
//
// Protocol written to the pipe (null-terminated ASCII):
//   "SHARING=1\n"   - screen share started
//   "SHARING=0\n"   - screen share stopped
//
// Call Install() before MH_EnableHook(MH_ALL_HOOKS).
// Call Remove()  from DLL_PROCESS_DETACH.

void ScreenShareHook_Install();
void ScreenShareHook_Remove();
