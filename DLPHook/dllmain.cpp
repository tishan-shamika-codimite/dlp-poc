#include "pch.h"
#include "MinHook.h"
#include "ClipboardHook.h"
#include "FileUploadHook.h"
#include "ScreenShareHook.h"
#include "DlpCommon.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID /*lpReserved*/) {
    switch (ul_reason_for_call) {

    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        if (MH_Initialize() != MH_OK)
            return FALSE;

        ClipboardHook_Install();
        FileUploadHook_Install();
        ScreenShareHook_Install();

        if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
            return FALSE;

        OutputDebugStringA("[DLP] All hooks installed and enabled");
        break;

    case DLL_PROCESS_DETACH:
        ScreenShareHook_Remove();
        FileUploadHook_Remove();
        ClipboardHook_Remove();
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        OutputDebugStringA("[DLP] All hooks removed");
        break;
    }
    return TRUE;
}
