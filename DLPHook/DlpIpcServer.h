#pragma once
// ════════════════════════════════════════════════════════════════════════════
//  DlpIpcServer.h  —  Named Pipe Server  (UI / Main Process Side)
// ════════════════════════════════════════════════════════════════════════════
//
//  Lives inside the DLL injected into the *UI process* (e.g. main chrome.exe,
//  Acrobat.exe).  Its job:
//
//    1. Create a secure Named Pipe  \\.\pipe\DLP_<AppTag>_<ThisPid>
//    2. Wait for worker processes (renderers, AcroCEF) to connect
//    3. Receive DLP_IPC_MESSAGE, validate it, dispatch to EnforcePolicy()
//    4. EnforcePolicy runs SetWindowDisplayAffinity in THIS process context
//       (which owns the HWNDs) — no sandbox restriction applies here
//    5. Send back Ack / Nack
//    6. Loop back to accept the next connection
//
//  Security Hardening
//  ──────────────────
//  • Pipe DACL: only SYSTEM and the SID of the UI process's token may connect
//  • FILE_FLAG_FIRST_PIPE_INSTANCE: prevents another process creating an
//    identically-named pipe before us (pipe-squatting attack)
//  • PIPE_REJECT_REMOTE_CLIENTS: no network-originated connections
//  • GetNamedPipeClientProcessId + IL check on every new connection
//  • Per-connection handler thread: server loop is never blocked by a slow client
//
// ════════════════════════════════════════════════════════════════════════════

#include <windows.h>

// Start the pipe server background thread.
// `appTag`  — short label used in the pipe name, e.g. L"Chrome"
// `uiPid`   — PID of THIS process (the UI / parent process)
// Returns TRUE if the server thread started successfully.
BOOL DlpIpcServer_Start(const wchar_t* appTag, DWORD uiPid);

// Signal the server to stop and wait for it to drain (up to 3 s).
// Call from DLL_PROCESS_DETACH.
void DlpIpcServer_Stop();

// Returns TRUE if the server is currently running.
BOOL DlpIpcServer_IsRunning();
