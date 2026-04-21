#pragma once
// ════════════════════════════════════════════════════════════════════════════
//  DlpIpcClient.h  —  Named Pipe Client  (Worker / Renderer Process Side)
// ════════════════════════════════════════════════════════════════════════════
//
//  Lives inside the DLL injected into *worker processes* (Chrome renderers,
//  AcroCEF.exe, etc.).  When a sensitive file is detected via the CreateFileW
//  hook, instead of attempting SetWindowDisplayAffinity (which fails in the
//  sandbox), the worker calls DlpIpcClient_NotifySensitiveFileOpened() which:
//
//    1. Finds the Named Pipe created by the UI-process server
//    2. Connects, sends a validated DLP_IPC_MESSAGE
//    3. Waits for Ack / Nack from the UI process
//    4. Returns the response — if Nack or timeout, caller should DENY the open
//       (fail-closed principle)
//
//  The UI process PID is discovered via NtQueryInformationProcess
//  (ParentProcessId) — the parent of a renderer is always the browser process.
//
// ════════════════════════════════════════════════════════════════════════════

#include <windows.h>
#include <cstdint>

// Initialise the client for this worker process.
// Discovers the UI (parent) process PID and builds the target pipe name.
// `appTag` must match the tag used by DlpIpcServer_Start() in the UI process
// (e.g. L"Chrome", L"Acrobat").
// Returns TRUE on success.  Must be called before any Send function.
BOOL DlpIpcClient_Init(const wchar_t* appTag);

// Send a "sensitive file opened" notification to the UI process.
// `categories` is a DlpIpcCategory bitmask of the detected data types.
// `filePath`   is the file that triggered the detection (logged only; may be nullptr).
//
// Returns TRUE (Ack received) or FALSE (Nack, timeout, or pipe error).
// If FALSE, callers in FileUploadHook should treat the file open as DENIED
// (fail-closed: better to block than to silently allow unprotected access).
BOOL DlpIpcClient_NotifySensitiveFileOpened(uint32_t categories, const wchar_t* filePath);

// Send a "sensitive file closed" notification (optional; used for reference
// counting on the server side if a richer policy is implemented later).
BOOL DlpIpcClient_NotifySensitiveFileClosed(const wchar_t* filePath);

// Tear down any cached state.  Call from DLL_PROCESS_DETACH.
void DlpIpcClient_Shutdown();
