#include "pch.h"
#include "MinHook.h"
#include "ClipboardHook.h"
#include "FileUploadHook.h"
#include "ScreenCaptureProtection.h"
#include "DlpCommon.h"
#include "DlpIpcServer.h"      // UI process: Named Pipe server
#include "DlpIpcClient.h"      // Worker process: Named Pipe client

// ════════════════════════════════════════════════════════════════════════════
//  Process Role Detection
// ════════════════════════════════════════════════════════════════════════════
//
//  The same DLPHook.dll is injected into BOTH the UI process (main Acrobat /
//  main chrome.exe) AND worker processes (AcroCEF, Chrome renderers).
//
//  On DLL_PROCESS_ATTACH we classify the current process and start the
//  appropriate IPC component:
//
//    UI process   → DlpIpcServer_Start() spins up the Named Pipe server
//    Worker proc  → DlpIpcClient_Init()  prepares the pipe client
//
//  The app tag is a short label embedded in the pipe name so that Acrobat and
//  Chrome never share a pipe, even if they are running simultaneously.
// ════════════════════════════════════════════════════════════════════════════

// Returns the lower-case exe filename (no path) for the current process.
// Duplicated here to avoid pulling in the full FileUploadHook translation unit
// at DllMain time.  The inline cache makes repeated calls free.
static const wchar_t* GetExeNameForRole() {
    static wchar_t lower[MAX_PATH] = {};
    static bool    resolved        = false;
    if (!resolved) {
        wchar_t exePath[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        const wchar_t* fileName = exePath;
        for (const wchar_t* p = exePath; *p; ++p)
            if (*p == L'\\' || *p == L'/') fileName = p + 1;
        size_t i = 0;
        for (; fileName[i] && i < MAX_PATH - 1; ++i)
            lower[i] = static_cast<wchar_t>(towlower(fileName[i]));
        lower[i]  = L'\0';
        resolved  = true;
    }
    return lower;
}

// Maps exe name → short app tag used in the pipe name.
// Returns nullptr if this process is not in any known family.
static const wchar_t* GetAppTag() {
    const wchar_t* exe = GetExeNameForRole();

    // ── Adobe Acrobat family ──────────────────────────────────────────────────
    if (wcscmp(exe, L"acrobat.exe")    == 0) return L"Acrobat";
    if (wcscmp(exe, L"acrord32.exe")   == 0) return L"Acrobat";
    if (wcscmp(exe, L"acrocef.exe")    == 0) return L"Acrobat";  // worker
    if (wcscmp(exe, L"acrocef_1.exe")  == 0) return L"Acrobat";  // worker

    // ── Browser family ────────────────────────────────────────────────────────
    if (wcscmp(exe, L"chrome.exe")   == 0) return L"Chrome";
    if (wcscmp(exe, L"msedge.exe")   == 0) return L"Edge";
    if (wcscmp(exe, L"firefox.exe")  == 0) return L"Firefox";
    if (wcscmp(exe, L"brave.exe")    == 0) return L"Brave";
    if (wcscmp(exe, L"opera.exe")    == 0) return L"Opera";
    if (wcscmp(exe, L"vivaldi.exe")  == 0) return L"Vivaldi";

    // ── Other monitored apps (Slack, Notepad, etc.) ───────────────────────────
    return L"Generic";
}

// Returns TRUE if this process is a sandboxed worker rather than the UI owner.
static bool IsWorkerRoleProcess() {
    // AcroCEF is always a worker
    const wchar_t* exe = GetExeNameForRole();
    if (wcscmp(exe, L"acrocef.exe")   == 0) return true;
    if (wcscmp(exe, L"acrocef_1.exe") == 0) return true;

    // Chrome sub-processes all carry --type=<role>; the main browser does not
    if (wcscmp(exe, L"chrome.exe")  == 0 ||
        wcscmp(exe, L"msedge.exe")  == 0 ||
        wcscmp(exe, L"brave.exe")   == 0 ||
        wcscmp(exe, L"opera.exe")   == 0 ||
        wcscmp(exe, L"vivaldi.exe") == 0)
    {
        const wchar_t* cmdLine = GetCommandLineW();
        if (cmdLine && wcsstr(cmdLine, L"--type=") != nullptr)
            return true;
    }

    return false;
}

// ════════════════════════════════════════════════════════════════════════════
//  DllMain
// ════════════════════════════════════════════════════════════════════════════

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID /*lpReserved*/) {
    switch (ul_reason_for_call) {

    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        if (MH_Initialize() != MH_OK)
            return FALSE;

        ClipboardHook_Install();
        FileUploadHook_Install();

        if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
            return FALSE;

        // ── Screen-capture protection (direct, non-worker processes only) ─────
        // Must be installed AFTER MH_EnableHook so that any Win32 calls made
        // from ScreenCaptureProtection_Install() go through the live hooks.
        // Worker processes do not call SetWDA directly — they use the IPC client
        // — so there is no point starting the monitor thread in them.
        if (!IsWorkerRoleProcess()) {
            ScreenCaptureProtection_Install();
        }

        // ── IPC role assignment ───────────────────────────────────────────────
        {
            const wchar_t* appTag = GetAppTag();

            if (IsWorkerRoleProcess()) {
                // ── Worker path: initialise IPC client ───────────────────────
                // DlpIpcClient_Init() is safe to call from DllMain because it
                // only resolves the parent PID and builds a string; it does NOT
                // create threads or call LoadLibrary.
                DlpIpcClient_Init(appTag);
                OutputDebugStringA("[DLP] Role: WORKER — IPC client initialised");
            } else {
                // ── UI process path: start IPC server ────────────────────────
                // DlpIpcServer_Start() spawns a background thread — safe to call
                // from DllMain because the thread proc does not call LoadLibrary
                // or re-enter the loader lock.
                DlpIpcServer_Start(appTag, GetCurrentProcessId());
                OutputDebugStringA("[DLP] Role: UI PROCESS — IPC server started");
            }
        }

        OutputDebugStringA("[DLP] All hooks installed and enabled");
        break;

    case DLL_PROCESS_DETACH:
        // ── Tear-down order matters ───────────────────────────────────────────
        // 1. Stop the IPC server/client first (no new events will arrive)
        DlpIpcServer_Stop();
        DlpIpcClient_Shutdown();

        // 2. Stop the screen-capture monitor and restore WDA_NONE on all windows
        //    BEFORE removing hooks, so the monitor's IsWindow() / SetWDA calls
        //    still reach intact Win32 code.
        ScreenCaptureProtection_Remove();

        FileUploadHook_Remove();
        ClipboardHook_Remove();
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        DlpCommon_Shutdown();
        OutputDebugStringA("[DLP] All hooks removed");
        break;
    }
    return TRUE;
}

