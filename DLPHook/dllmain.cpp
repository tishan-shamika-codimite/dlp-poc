#include "pch.h"
#include "MinHook.h"
#include "ClipboardHook.h"
#include "FileUploadHook.h"
#include "ScreenCaptureProtection.h"
#include "DlpCommon.h"

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

        // ── Screen-capture protection ─────────────────────────────────────────
        // Must be installed AFTER MH_EnableHook so that any Win32 calls made
        // from ScreenCaptureProtection_Install() go through the live hooks.
        // The function itself is safe to call from DllMain because it only
        // resolves a function pointer and starts a background thread — it does
        // not call LoadLibrary, CoCreateInstance, or any shell API that could
        // re-enter the loader lock.
        ScreenCaptureProtection_Install();

        OutputDebugStringA("[DLP] All hooks installed and enabled");
        break;

    case DLL_PROCESS_DETACH:
        // ── Tear-down order matters ───────────────────────────────────────────
        // 1. Stop the screen-capture monitor and restore WDA_NONE on all windows
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
