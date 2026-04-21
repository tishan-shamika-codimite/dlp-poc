#include "pch.h"
#include "DlpIpcServer.h"
#include "DlpIpc.h"
#include "ScreenCaptureProtection.h"
#include "DlpCommon.h"

#include <sddl.h>       // ConvertStringSecurityDescriptorToSecurityDescriptorW
#include <string>
#include <atomic>
#include <mutex>

#pragma comment(lib, "advapi32.lib")

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 1 — Module state
// ════════════════════════════════════════════════════════════════════════════

static HANDLE         g_hStopEvent  = nullptr;  // Manual-reset; signalled on Stop()
static HANDLE         g_hServerThread = nullptr;
static std::atomic<bool> g_running{ false };

static std::wstring   g_pipeName;               // Built once in Start()
static DWORD          g_uiPid = 0;

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 2 — Restricted pipe security descriptor
// ════════════════════════════════════════════════════════════════════════════
//
//  SDDL DACL: Allow Generic-Read + Generic-Write to:
//    SY = SYSTEM
//    OW = Owner (the logged-in user — same account for both UI process and
//         all worker/renderer processes it spawns)
//
//  We intentionally OMIT the SACL mandatory label line
//  "S:(ML;;NW;;;LW)" that was in the original design.
//
//  WHY: Writing a SACL requires SE_SECURITY_PRIVILEGE on the caller's token.
//  An injected DLL thread never holds that privilege, so
//  ConvertStringSecurityDescriptorToSecurityDescriptorW with a SACL string
//  succeeds (it just parses the string) but CreateNamedPipe then calls
//  NtCreateNamedPipeFile which enforces the privilege check and returns
//  STATUS_PRIVILEGE_NOT_HELD → Win32 ERROR_ACCESS_DENIED (GLE=5).
//
//  Low-IL Chrome renderers CAN already connect to a pipe owned by the same
//  user with no mandatory label because:
//    • The renderer's token is the SAME user SID as the browser (just
//      different IL).  The DACL "Allow OW" grants access based on user SID,
//      not IL.
//    • Only WRITE-UP (Low IL writing to High IL object) is blocked by default
//      integrity policy.  A Low-IL process writing to a Medium-IL owned pipe
//      is allowed UNLESS the pipe has an explicit "no-write-up" SACL.
//    • Since we omit the SACL, the default integrity policy (no restriction)
//      applies — Low IL → Medium IL pipe writes are permitted.

static BOOL BuildPipeSecurityAttributes(SECURITY_ATTRIBUTES* pSa, PSECURITY_DESCRIPTOR* ppSd) {
    // DACL only — no SACL (avoids SE_SECURITY_PRIVILEGE requirement)
    static const wchar_t kSddl[] =
        L"D:(A;;GRGW;;;SY)(A;;GRGW;;;OW)";

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            kSddl,
            SDDL_REVISION_1,
            ppSd,
            nullptr))
    {
        char buf[128];
        wsprintfA(buf, "[DLP][IpcServer] ConvertStringSD failed GLE=%lu — using default SA",
                  GetLastError());
        OutputDebugStringA(buf);
        return FALSE;
    }

    pSa->nLength              = sizeof(SECURITY_ATTRIBUTES);
    pSa->lpSecurityDescriptor = *ppSd;
    pSa->bInheritHandle       = FALSE;
    return TRUE;
}

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 3 — Client integrity level check
// ════════════════════════════════════════════════════════════════════════════
//
//  We accept Low-IL (Chrome renderer) through High-IL (Acrobat, elevated).
//  We reject AppContainer tokens that Chrome uses for its GPU process on newer
//  Windows versions — those processes should not need to open files directly.

static BOOL VerifyClientIntegrityLevel(HANDLE hPipe) {
    HANDLE hToken = nullptr;

    // Impersonate the client so we can inspect its token
    if (!ImpersonateNamedPipeClient(hPipe)) {
        OutputDebugStringA("[DLP][IpcServer] ImpersonateNamedPipeClient failed");
        return FALSE;  // Fail-closed
    }

    BOOL ok = FALSE;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)) {
        RevertToSelf();
        OutputDebugStringA("[DLP][IpcServer] OpenThreadToken failed after impersonation");
        return FALSE;
    }

    // Query the mandatory integrity level
    DWORD dwInfoLen = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &dwInfoLen);

    if (dwInfoLen > 0) {
        auto* pLevel = static_cast<TOKEN_MANDATORY_LABEL*>(
            HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwInfoLen));

        if (pLevel) {
            if (GetTokenInformation(hToken, TokenIntegrityLevel, pLevel, dwInfoLen, &dwInfoLen)) {
                const DWORD il = *GetSidSubAuthority(
                    pLevel->Label.Sid,
                    *GetSidSubAuthorityCount(pLevel->Label.Sid) - 1);

                // Accept Low IL (0x1000) and above; reject Untrusted (0x0000)
                // which is reserved for AppContainer processes we do not expect.
                ok = (il >= SECURITY_MANDATORY_LOW_RID);

                if (!ok) {
                    char buf[128];
                    wsprintfA(buf,
                        "[DLP][IpcServer] Rejected client with IL=0x%X (below Low)", il);
                    OutputDebugStringA(buf);
                }
            }
            HeapFree(GetProcessHeap(), 0, pLevel);
        }
    }

    CloseHandle(hToken);
    RevertToSelf();
    return ok;
}

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 4 — Policy enforcement (runs in UI process context)
// ════════════════════════════════════════════════════════════════════════════
//
//  This function executes inside the UI process that OWNS the HWNDs.
//  SetWindowDisplayAffinity succeeds here because:
//    • We are NOT sandboxed
//    • We are calling SetWDA on windows that belong to this very process
//    • No cross-process window handle manipulation is involved

static void EnforcePolicy(const DLP_IPC_MESSAGE* pMsg) {
    const DlpIpcMsgType msgType = static_cast<DlpIpcMsgType>(pMsg->dwMsgType);

    switch (msgType) {

    case DlpIpcMsgType::SensitiveFileOpened: {
        // Arm screen-capture protection on all windows owned by this (UI) process.
        const UINT nProtected = ScreenCapture_ProtectProcess(g_uiPid);

        char dbg[256];
        wsprintfA(dbg,
            "[DLP][IpcServer] SensitiveFileOpened from worker PID=%lu — "
            "armed WDA_EXCLUDEFROMCAPTURE on %u window(s) in UI PID=%lu",
            pMsg->dwSenderPid, nProtected, g_uiPid);
        OutputDebugStringA(dbg);

        if (nProtected > 0) {
            // Build a user-visible notification showing which categories were
            // detected inside the worker process.  The alert is shown from
            // the UI process context, so MessageBoxW works correctly.
            std::wstring msg =
                L"Sensitive document protection active.\n\n"
                L"A worker process opened a file containing sensitive data:";

            if (pMsg->dwCategories & static_cast<uint32_t>(DlpIpcCategory::PCI))
                msg += L"\n  \u2022 Payment card data (PCI)";
            if (pMsg->dwCategories & static_cast<uint32_t>(DlpIpcCategory::PII))
                msg += L"\n  \u2022 Personal identity information (PII)";
            if (pMsg->dwCategories & static_cast<uint32_t>(DlpIpcCategory::PHI))
                msg += L"\n  \u2022 Protected health information (PHI)";
            if (pMsg->dwCategories & static_cast<uint32_t>(DlpIpcCategory::Financial))
                msg += L"\n  \u2022 Banking or tax information (Financial)";

            if (pMsg->dwPathLen > 0) {
                msg += L"\n\nFile: ";
                msg += pMsg->wszFilePath;
            }

            msg += L"\n\nScreen capture and screen sharing have been "
                   L"disabled for this window by Browser Bridge DLP.";

            NotifyUser(std::move(msg));
        } else {
            // No windows found yet (process may still be starting up).
            // Schedule a retry on a background thread — same pattern as
            // the direct-inject path in FileUploadHook.cpp.
            struct RetryCtx { DWORD uiPid; };
            auto* pCtx = new RetryCtx{ g_uiPid };

            HANDLE hRetry = CreateThread(nullptr, 0,
                [](LPVOID param) -> DWORD {
                    auto* ctx = static_cast<RetryCtx*>(param);
                    for (int i = 0; i < 8; ++i) {
                        Sleep(500);
                        const UINT n = ScreenCapture_ProtectProcess(ctx->uiPid);
                        if (n > 0) {
                            OutputDebugStringA("[DLP][IpcServer] Retry succeeded — "
                                               "window found and protected");
                            NotifyUser(
                                L"Sensitive document protection active.\n\n"
                                L"Screen capture and screen sharing have been "
                                L"disabled for this window by Browser Bridge DLP.");
                            break;
                        }
                    }
                    delete ctx;
                    return 0;
                },
                pCtx, 0, nullptr);

            if (hRetry) CloseHandle(hRetry);
            else        delete pCtx;
        }
        break;
    }

    case DlpIpcMsgType::SensitiveFileClosed: {
        // Lift protection when the worker reports it is done with the file.
        // NOTE: A more sophisticated policy would keep a reference count and
        //       only lift protection when the count reaches zero.  For this
        //       implementation we lift immediately.
        ScreenCapture_UnprotectProcess(g_uiPid);
        OutputDebugStringA("[DLP][IpcServer] SensitiveFileClosed — protection lifted");
        break;
    }

    case DlpIpcMsgType::Heartbeat:
        // No action needed; the receive loop already handles the Ack reply.
        break;

    default: {
        char buf[64];
        wsprintfA(buf, "[DLP][IpcServer] Unknown msgType=%u — ignored", pMsg->dwMsgType);
        OutputDebugStringA(buf);
        break;
    }
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 5 — Per-connection handler thread
// ════════════════════════════════════════════════════════════════════════════
//
//  Each connected worker process gets its own handler thread so that a slow
//  or misbehaving worker does not block the server loop from accepting new
//  connections from other workers.

struct ConnectionCtx {
    HANDLE hPipe;   // Connected, overlapped-capable pipe handle
};

static DWORD WINAPI ConnectionHandlerThread(LPVOID lpParam) {
    auto* pCtx = static_cast<ConnectionCtx*>(lpParam);
    HANDLE hPipe = pCtx->hPipe;
    delete pCtx;

    char dbg[128];

    // ── Verify client integrity level before reading any data ─────────────────
    if (!VerifyClientIntegrityLevel(hPipe)) {
        OutputDebugStringA("[DLP][IpcServer] Connection rejected: IL check failed");
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
        return 1;
    }

    // ── Read the message ──────────────────────────────────────────────────────
    DLP_IPC_MESSAGE msg = {};
    DWORD bytesRead = 0;
    const BOOL readOk = ReadFile(
        hPipe,
        &msg,
        sizeof(msg),
        &bytesRead,
        nullptr);

    if (!readOk || bytesRead != sizeof(DLP_IPC_MESSAGE)) {
        wsprintfA(dbg,
            "[DLP][IpcServer] ReadFile failed or size mismatch "
            "(read=%lu expected=%lu GLE=%lu)",
            bytesRead, static_cast<DWORD>(sizeof(DLP_IPC_MESSAGE)), GetLastError());
        OutputDebugStringA(dbg);
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
        return 1;
    }

    // ── Validate the message (magic, version, PID, HMAC) ─────────────────────
    if (!DlpIpc_ValidateMessage(&msg, hPipe)) {
        OutputDebugStringA("[DLP][IpcServer] Message validation FAILED — sending Nack");

        DLP_IPC_MESSAGE resp = {};
        DlpIpc_BuildMessage(&resp, DlpIpcMsgType::Nack, 0, g_uiPid, nullptr);
        DWORD written = 0;
        WriteFile(hPipe, &resp, sizeof(resp), &written, nullptr);

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
        return 1;
    }

    wsprintfA(dbg,
        "[DLP][IpcServer] Valid message from PID=%lu type=%u categories=0x%X",
        msg.dwSenderPid, msg.dwMsgType, msg.dwCategories);
    OutputDebugStringA(dbg);

    // ── Dispatch to policy enforcement ───────────────────────────────────────
    EnforcePolicy(&msg);

    // ── Send Ack ──────────────────────────────────────────────────────────────
    DLP_IPC_MESSAGE resp = {};
    DlpIpc_BuildMessage(&resp, DlpIpcMsgType::Ack, 0, g_uiPid, nullptr);
    DWORD written = 0;
    if (!WriteFile(hPipe, &resp, sizeof(resp), &written, nullptr)) {
        wsprintfA(dbg, "[DLP][IpcServer] WriteFile(Ack) failed GLE=%lu", GetLastError());
        OutputDebugStringA(dbg);
    }

    // ── Clean up ──────────────────────────────────────────────────────────────
    FlushFileBuffers(hPipe);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    return 0;
}

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 6 — Server accept loop thread
// ════════════════════════════════════════════════════════════════════════════

static DWORD WINAPI ServerThreadProc(LPVOID /*param*/) {
    OutputDebugStringA("[DLP][IpcServer] Server thread started");

    PSECURITY_DESCRIPTOR pSd = nullptr;
    SECURITY_ATTRIBUTES  sa  = {};

    if (!BuildPipeSecurityAttributes(&sa, &pSd)) {
        // Fall back to default SA (less secure, but better than not running at all)
        OutputDebugStringA("[DLP][IpcServer] WARNING: using default pipe SA (DACL build failed)");
    }

    // Track whether we have successfully created the FIRST pipe instance yet.
    // This is a local (not static) bool — each ServerThreadProc invocation
    // has its own state.  FILE_FLAG_FIRST_PIPE_INSTANCE is passed ONLY on the
    // very first CreateNamedPipe call; if that fails (e.g. a stale pipe from a
    // previous crash still exists in the kernel), we retry WITHOUT the flag so
    // that we can attach as a second instance and still serve clients.
    bool firstInstance = true;

    while (g_running.load(std::memory_order_relaxed)) {

        // ── Create a new pipe instance ────────────────────────────────────────
        const DWORD openMode =
            PIPE_ACCESS_DUPLEX
            | FILE_FLAG_OVERLAPPED
            | (firstInstance ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0);

        HANDLE hPipe = CreateNamedPipeW(
            g_pipeName.c_str(),
            openMode,
            PIPE_TYPE_MESSAGE
            | PIPE_READMODE_MESSAGE
            | PIPE_WAIT
            | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            kPipeBufferBytes,
            kPipeBufferBytes,
            0,
            pSd ? &sa : nullptr);

        if (hPipe == INVALID_HANDLE_VALUE) {
            const DWORD gle = GetLastError();
            if (firstInstance && gle == ERROR_ACCESS_DENIED) {
                // FILE_FLAG_FIRST_PIPE_INSTANCE failed — a stale pipe instance
                // from a previous crash may still exist, OR the DACL is too
                // restrictive.  Drop the first-instance flag and retry once.
                OutputDebugStringA("[DLP][IpcServer] First-instance pipe create failed "
                                   "(GLE=5) — retrying without FIRST_PIPE_INSTANCE flag");
                firstInstance = false;
                continue;
            }

            char buf[192];
            wsprintfA(buf, "[DLP][IpcServer] CreateNamedPipe failed GLE=%lu pipe=%S",
                      gle, g_pipeName.c_str());
            OutputDebugStringA(buf);

            if (WaitForSingleObject(g_hStopEvent, 500) == WAIT_OBJECT_0)
                break;
            continue;
        }

        // Successfully created — all subsequent instances skip the first-instance flag
        firstInstance = false;

        // ── Wait for a client to connect (overlapped so we can honour stop) ──
        //
        //  We use an event + WaitForMultipleObjects so the stop event can
        //  interrupt a ConnectNamedPipe that is blocking waiting for a client.

        OVERLAPPED ov = {};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ov.hEvent) {
            CloseHandle(hPipe);
            continue;
        }

        const BOOL connected = ConnectNamedPipe(hPipe, &ov);
        const DWORD gle = GetLastError();

        if (!connected && gle == ERROR_IO_PENDING) {
            // Async pending — wait for either a connection or a stop signal
            HANDLE waitHandles[2] = { ov.hEvent, g_hStopEvent };
            DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);

            if (waitResult == WAIT_OBJECT_0 + 1) {
                // Stop was signalled — cancel the pending connect and exit
                CancelIo(hPipe);
                CloseHandle(ov.hEvent);
                CloseHandle(hPipe);
                break;
            }

            // Check if the overlapped connect actually succeeded
            DWORD transferred = 0;
            if (!GetOverlappedResult(hPipe, &ov, &transferred, FALSE)) {
                CloseHandle(ov.hEvent);
                CloseHandle(hPipe);
                continue;
            }
        } else if (!connected && gle != ERROR_PIPE_CONNECTED) {
            // Unexpected error
            char buf[128];
            wsprintfA(buf, "[DLP][IpcServer] ConnectNamedPipe failed GLE=%lu", gle);
            OutputDebugStringA(buf);
            CloseHandle(ov.hEvent);
            CloseHandle(hPipe);
            continue;
        }

        CloseHandle(ov.hEvent);

        // ── Dispatch to a handler thread ──────────────────────────────────────
        //  Give ownership of hPipe to the handler thread.
        auto* pCtx = new ConnectionCtx{ hPipe };
        HANDLE hHandler = CreateThread(nullptr, 0, ConnectionHandlerThread, pCtx, 0, nullptr);
        if (hHandler) {
            CloseHandle(hHandler); // Detach — handler cleans up hPipe
        } else {
            OutputDebugStringA("[DLP][IpcServer] CreateThread for handler failed");
            delete pCtx;
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
        }

        // Check stop event before looping back to create the next pipe instance
        if (WaitForSingleObject(g_hStopEvent, 0) == WAIT_OBJECT_0)
            break;
    }

    if (pSd) LocalFree(pSd);

    OutputDebugStringA("[DLP][IpcServer] Server thread exiting");
    g_running.store(false, std::memory_order_relaxed);
    return 0;
}

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 7 — Public API
// ════════════════════════════════════════════════════════════════════════════

BOOL DlpIpcServer_Start(const wchar_t* appTag, DWORD uiPid) {
    if (g_running.load())
        return TRUE; // Already running

    g_uiPid    = uiPid;
    g_pipeName = DlpIpc_BuildPipeName(appTag, uiPid);

    g_hStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_hStopEvent) {
        OutputDebugStringA("[DLP][IpcServer] CreateEvent failed");
        return FALSE;
    }

    g_running.store(true, std::memory_order_relaxed);

    g_hServerThread = CreateThread(nullptr, 0, ServerThreadProc, nullptr, 0, nullptr);
    if (!g_hServerThread) {
        OutputDebugStringA("[DLP][IpcServer] CreateThread failed");
        g_running.store(false, std::memory_order_relaxed);
        CloseHandle(g_hStopEvent);
        g_hStopEvent = nullptr;
        return FALSE;
    }

    char buf[256];
    wsprintfA(buf, "[DLP][IpcServer] Started — pipe: %S  uiPid=%lu",
              g_pipeName.c_str(), uiPid);
    OutputDebugStringA(buf);
    return TRUE;
}

void DlpIpcServer_Stop() {
    if (!g_running.load()) return;

    g_running.store(false, std::memory_order_relaxed);

    if (g_hStopEvent)
        SetEvent(g_hStopEvent);

    if (g_hServerThread) {
        // Wait up to 3 s for the server thread to exit cleanly
        const DWORD waitResult = WaitForSingleObject(g_hServerThread, 3000);
        if (waitResult == WAIT_TIMEOUT)
            OutputDebugStringA("[DLP][IpcServer] WARNING: server thread did not stop in time");

        CloseHandle(g_hServerThread);
        g_hServerThread = nullptr;
    }

    if (g_hStopEvent) {
        CloseHandle(g_hStopEvent);
        g_hStopEvent = nullptr;
    }

    OutputDebugStringA("[DLP][IpcServer] Stopped");
}

BOOL DlpIpcServer_IsRunning() {
    return g_running.load() ? TRUE : FALSE;
}
