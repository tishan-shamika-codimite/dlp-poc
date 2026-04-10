//#include "pch.h" // Required for Visual Studio DLL projects
//#include <windows.h>
//#include <iostream>
//#include <string>
//#include <vector>
//
//// --- MINHOOK SETUP ---
//#include "MinHook.h"
//
//// Link the correct library file based on build architecture
//#ifdef _M_X64
//#pragma comment(lib, "libMinHook.lib")
//#elif _M_IX86
//#pragma comment(lib, "libMinHook.x86.lib")
//#endif
//// ---------------------
//
//// Define the prototype of the original Windows function
//typedef HANDLE(WINAPI* GETCLIPBOARDDATA)(UINT);
//
//// Pointer to store the ORIGINAL function address
//GETCLIPBOARDDATA fpGetClipboardData = NULL;
//
//// Helper: Check if we should block the paste
//bool IsPasteAllowed() {
//    char path[MAX_PATH];
//    GetModuleFileNameA(NULL, path, MAX_PATH);
//    std::string fullPath = path;
//
//    // Convert to lowercase for easy comparison
//    for (auto& c : fullPath) c = tolower(c);
//
//    // POLICY:
//    // 1. Allow Slack
//    if (fullPath.find("slack.exe") != std::string::npos) return false;
//
//    // 2. Allow Notepad (for testing)
//    if (fullPath.find("Notepad.exe") != std::string::npos) return false;
//
//    if (fullPath.find("chrome.exe") != std::string::npos) return false;
//
//    // 3. Block everything else (Chrome, Word, etc.)
//    return false;
//}
//
//// Our "Fake" Function that Windows will run instead
//HANDLE WINAPI Detour_GetClipboardData(UINT uFormat) {
//
//    // 1. Security Check
//    if (!IsPasteAllowed()) {
//        // Log to Debug Output (View with Sysinternals DebugView)
//        OutputDebugStringA("[DLP] Blocked Paste Attempt!");
//
//        // 2. BLOCK: Return NULL. The app thinks clipboard is empty.
//        return NULL;
//    }
//
//    // 3. ALLOW: Call the original Windows function
//    return fpGetClipboardData(uFormat);
//}
//
//// DLL Entry Point (Runs when injected)
//BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
//    switch (ul_reason_for_call) {
//    case DLL_PROCESS_ATTACH:
//        // Initialize MinHook
//        if (MH_Initialize() != MH_OK) { return FALSE; }
//
//        // Create the Hook
//        // We tell MinHook to redirect "GetClipboardData" in user32.dll to our Detour function
//        if (MH_CreateHookApi(L"user32.dll", "GetClipboardData", &Detour_GetClipboardData, reinterpret_cast<LPVOID*>(&fpGetClipboardData)) != MH_OK) {
//            OutputDebugStringA("[DLP] Failed to create hook!");
//            return FALSE;
//        }
//
//        // Enable the Hook
//        if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
//            OutputDebugStringA("[DLP] Failed to enable hook!");
//            return FALSE;
//        }
//
//        OutputDebugStringA("[DLP] Hook Installed Successfully.");
//        break;
//
//    case DLL_PROCESS_DETACH:
//        // Clean up hooks to prevent crashes when closing
//        MH_DisableHook(MH_ALL_HOOKS);
//        MH_Uninitialize();
//        break;
//    }
//    return TRUE;
//}


#include "pch.h"
#include <windows.h>
#include <ole2.h>
#include <string>
#include <regex>
#include "MinHook.h"

#ifdef _M_X64
#pragma comment(lib, "libMinHook.lib")
#else
#pragma comment(lib, "libMinHook.x86.lib")
#endif

typedef HANDLE(WINAPI* GETCLIPBOARDDATA)(UINT);
typedef HRESULT(WINAPI* OLEGETCLIPBOARD)(LPDATAOBJECT*);
typedef HANDLE(WINAPI* SETCLIPBOARDDATA)(UINT, HANDLE);
typedef HRESULT(WINAPI* OLESETCLIPBOARD)(LPDATAOBJECT);

GETCLIPBOARDDATA fpGetClipboardData = NULL;
OLEGETCLIPBOARD fpOleGetClipboard = NULL;
SETCLIPBOARDDATA fpSetClipboardData = NULL;
OLESETCLIPBOARD fpOleSetClipboard = NULL;

// --- SENSITIVE DATA DETECTION ---

// Luhn algorithm: validates that a digit string is a plausible card number
static bool LuhnCheck(const std::string& digits) {
    if (digits.size() < 13 || digits.size() > 19) return false;
    int sum = 0;
    bool alternate = false;
    for (int i = (int)digits.size() - 1; i >= 0; --i) {
        if (!isdigit((unsigned char)digits[i])) return false;
        int n = digits[i] - '0';
        if (alternate) {
            n *= 2;
            if (n > 9) n -= 9;
        }
        sum += n;
        alternate = !alternate;
    }
    return (sum % 10 == 0);
}

// Returns true if the text contains a Luhn-valid credit card number pattern
static bool ContainsCreditCardData(const std::string& text) {
    // Match 13-19 digit sequences optionally separated by spaces or dashes
    static const std::regex cardPattern(R"(\b(?:\d[ \-]?){12,18}\d\b)");
    std::sregex_iterator it(text.begin(), text.end(), cardPattern);
    std::sregex_iterator end;
    while (it != end) {
        std::string match = it->str();
        // Strip separators to get raw digits
        std::string digits;
        for (char c : match)
            if (isdigit((unsigned char)c)) digits += c;
        if (LuhnCheck(digits)) return true;
        ++it;
    }
    return false;
}

static bool ContainsCreditCardData(const std::wstring& text) {
    // Credit card digits are all ASCII — explicit narrow conversion
    std::string narrow;
    narrow.reserve(text.size());
    for (wchar_t wc : text)
        narrow += static_cast<char>(wc);
    return ContainsCreditCardData(narrow);
}

// Read ANSI text from a clipboard HGLOBAL handle (does not take ownership)
static std::string ReadAnsiFromHandle(HANDLE hMem) {
    if (!hMem) return {};
    LPCCH ptr = static_cast<LPCCH>(GlobalLock(hMem));
    if (!ptr) return {};
    std::string text(ptr);
    GlobalUnlock(hMem);
    return text;
}

// Read Unicode text from a clipboard HGLOBAL handle (does not take ownership)
static std::wstring ReadUnicodeFromHandle(HANDLE hMem) {
    if (!hMem) return {};
    LPCWSTR ptr = static_cast<LPCWSTR>(GlobalLock(hMem));
    if (!ptr) return {};
    std::wstring text(ptr);
    GlobalUnlock(hMem);
    return text;
}

// Check a global memory handle for credit card data (supports CF_TEXT / CF_UNICODETEXT)
static bool HandleHasCreditCardData(UINT uFormat, HANDLE hMem) {
    if (uFormat == CF_UNICODETEXT)
        return ContainsCreditCardData(ReadUnicodeFromHandle(hMem));
    if (uFormat == CF_TEXT || uFormat == CF_OEMTEXT)
        return ContainsCreditCardData(ReadAnsiFromHandle(hMem));
    return false;
}

// --- USER NOTIFICATION ---

static DWORD WINAPI ShowBlockNotification(LPVOID lpParam) {
    const wchar_t* message = static_cast<const wchar_t*>(lpParam);
    MessageBoxW(NULL, message, L"Browser Bridge Security Alert", MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
    return 0;
}

static void NotifyUser(const wchar_t* message) {
    // Show MessageBox on a separate thread to avoid blocking the hooked application
    CreateThread(NULL, 0, ShowBlockNotification, (LPVOID)message, 0, NULL);
}

// --- HOOK DETOURS ---

HANDLE WINAPI Detour_GetClipboardData(UINT uFormat) {
    OutputDebugStringA("[DLP] GetClipboardData called");
    HANDLE hResult = fpGetClipboardData(uFormat);
    if (hResult && (uFormat == CF_TEXT || uFormat == CF_OEMTEXT || uFormat == CF_UNICODETEXT)) {
        if (HandleHasCreditCardData(uFormat, hResult)) {
            OutputDebugStringA("[DLP] BLOCKED paste - credit card data detected");
            NotifyUser(L"Paste blocked: Sensitive data detected.\nThis action has been prevented by Browser Bridge.");
            return NULL; // Clipboard memory is owned by the system; do not free
        }
    }
    return hResult;
}

HRESULT WINAPI Detour_OleGetClipboard(LPDATAOBJECT* ppDataObj) {
    OutputDebugStringA("[DLP] OleGetClipboard called");
    HRESULT hr = fpOleGetClipboard(ppDataObj);
    if (SUCCEEDED(hr) && ppDataObj && *ppDataObj) {
        FORMATETC fmt = { CF_UNICODETEXT, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
        STGMEDIUM stg = {};
        if (SUCCEEDED((*ppDataObj)->GetData(&fmt, &stg))) {
            bool sensitive = ContainsCreditCardData(ReadUnicodeFromHandle(stg.hGlobal));
            ReleaseStgMedium(&stg);
            if (sensitive) {
                OutputDebugStringA("[DLP] BLOCKED paste - credit card data detected (OLE)");
                NotifyUser(L"Paste blocked: Sensitive data detected.\nThis action has been prevented by Browser Bridge.");
                (*ppDataObj)->Release();
                *ppDataObj = NULL;
                return E_ACCESSDENIED;
            }
        }
    }
    return hr;
}

HANDLE WINAPI Detour_SetClipboardData(UINT uFormat, HANDLE hMem) {
    OutputDebugStringA("[DLP] SetClipboardData called");
    if (hMem && (uFormat == CF_TEXT || uFormat == CF_OEMTEXT || uFormat == CF_UNICODETEXT)) {
        if (HandleHasCreditCardData(uFormat, hMem)) {
            OutputDebugStringA("[DLP] BLOCKED copy - credit card data detected");
            NotifyUser(L"Copy blocked: Sensitive data detected.\nThis action has been prevented by Browser Bridge.");
            // Return NULL to signal failure; caller retains ownership and must free hMem
            return NULL;
        }
    }
    return fpSetClipboardData(uFormat, hMem);
}

HRESULT WINAPI Detour_OleSetClipboard(LPDATAOBJECT pDataObj) {
    OutputDebugStringA("[DLP] OleSetClipboard called");
    if (pDataObj) {
        FORMATETC fmt = { CF_UNICODETEXT, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
        STGMEDIUM stg = {};
        if (SUCCEEDED(pDataObj->GetData(&fmt, &stg))) {
            bool sensitive = ContainsCreditCardData(ReadUnicodeFromHandle(stg.hGlobal));
            ReleaseStgMedium(&stg);
            if (sensitive) {
                OutputDebugStringA("[DLP] BLOCKED copy - credit card data detected (OLE)");
                NotifyUser(L"Copy blocked: Sensitive data detected.\nThis action has been prevented by Browser Bridge.");
                return E_ACCESSDENIED;
            }
        }
    }
    return fpOleSetClipboard(pDataObj);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        if (MH_Initialize() != MH_OK) return FALSE;

        MH_CreateHookApi(L"user32.dll", "GetClipboardData", &Detour_GetClipboardData, (LPVOID*)&fpGetClipboardData);
        MH_CreateHookApi(L"user32.dll", "SetClipboardData", &Detour_SetClipboardData, (LPVOID*)&fpSetClipboardData);
        LoadLibrary(L"ole32.dll");
        MH_CreateHookApi(L"ole32.dll", "OleGetClipboard", &Detour_OleGetClipboard, (LPVOID*)&fpOleGetClipboard);
        MH_CreateHookApi(L"ole32.dll", "OleSetClipboard", &Detour_OleSetClipboard, (LPVOID*)&fpOleSetClipboard);

        MH_EnableHook(MH_ALL_HOOKS);
        OutputDebugStringA("[DLP] Hooks Installed (Std + OLE, Copy + Paste)");
        break;

    case DLL_PROCESS_DETACH:
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        break;
    }
    return TRUE;
}


//#include "pch.h"
//#include <windows.h>
//#include <ole2.h> 
//#include <string>
//#include <algorithm> // for transform
//#include "MinHook.h"
//
//// Link MinHook (Adjust filename if needed)
//#ifdef _M_X64
//#pragma comment(lib, "libMinHook.lib")
//#else
//#pragma comment(lib, "libMinHook.x86.lib")
//#endif
//
//// --- 1. FUNCTION DEFINITIONS ---
//typedef BOOL(WINAPI* OPENCLIPBOARD)(HWND);
//typedef HANDLE(WINAPI* GETCLIPBOARDDATA)(UINT);
//typedef HRESULT(WINAPI* OLEGETCLIPBOARD)(LPDATAOBJECT*);
//
//OPENCLIPBOARD fpOpenClipboard = NULL;
//GETCLIPBOARDDATA fpGetClipboardData = NULL;
//OLEGETCLIPBOARD fpOleGetClipboard = NULL;
//
//// --- 2. POLICY CHECK ---
//bool IsPasteAllowed() {
//    char path[MAX_PATH];
//    if (GetModuleFileNameA(NULL, path, MAX_PATH) == 0) return false;
//
//    std::string fullPath = path;
//    // Lowercase for safety
//    std::transform(fullPath.begin(), fullPath.end(), fullPath.begin(), ::tolower);
//
//    // ALLOW LIST
//    if (fullPath.find("slack.exe") != std::string::npos) return true;
//    if (fullPath.find("notepad.exe") != std::string::npos) return true;
//    if (fullPath.find("dlpinjector.exe") != std::string::npos) return true;
//
//    // BLOCK EVERYTHING ELSE (Chrome, Edge, Word, etc.)
//    return false;
//}
//
//// --- 3. DETOUR FUNCTIONS ---
//
//// [HOOK 1] OpenClipboard - The Master Gatekeeper
//// If we return FALSE here, the app thinks the clipboard is locked by someone else.
//BOOL WINAPI Detour_OpenClipboard(HWND hWndNewOwner) {
//    if (!IsPasteAllowed()) {
//        // OutputDebugStringA("[DLP] BLOCKED OpenClipboard");
//        return FALSE; // Fail the open request
//    }
//    return fpOpenClipboard(hWndNewOwner);
//}
//
//// [HOOK 2] GetClipboardData - The Standard Reader
//HANDLE WINAPI Detour_GetClipboardData(UINT uFormat) {
//    if (!IsPasteAllowed()) {
//        // OutputDebugStringA("[DLP] BLOCKED GetClipboardData");
//        return NULL; // Return empty
//    }
//    return fpGetClipboardData(uFormat);
//}
//
//// [HOOK 3] OleGetClipboard - The Modern Reader (Chrome often uses this)
//HRESULT WINAPI Detour_OleGetClipboard(LPDATAOBJECT* ppDataObj) {
//    if (!IsPasteAllowed()) {
//        // OutputDebugStringA("[DLP] BLOCKED OleGetClipboard");
//        *ppDataObj = NULL;
//        return E_ACCESSDENIED; // Return Access Denied Error
//    }
//    return fpOleGetClipboard(ppDataObj);
//}
//
//// --- 4. INSTALLATION ---
//BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
//    switch (ul_reason_for_call) {
//    case DLL_PROCESS_ATTACH:
//        // Initialize MinHook
//        if (MH_Initialize() != MH_OK) return FALSE;
//
//        // Hook User32 APIs (Safe to do directly)
//        MH_CreateHookApi(L"user32.dll", "OpenClipboard", &Detour_OpenClipboard, (LPVOID*)&fpOpenClipboard);
//        MH_CreateHookApi(L"user32.dll", "GetClipboardData", &Detour_GetClipboardData, (LPVOID*)&fpGetClipboardData);
//
//        // Hook OLE32 API
//        // NOTE: We do NOT use LoadLibrary here (avoids Loader Lock). 
//        // We rely on MH_CreateHookApi to find it if it's already loaded, 
//        // or we let it fail gracefully if OLE isn't used by the app yet.
//        MH_CreateHookApi(L"ole32.dll", "OleGetClipboard", &Detour_OleGetClipboard, (LPVOID*)&fpOleGetClipboard);
//
//        // Enable All
//        MH_EnableHook(MH_ALL_HOOKS);
//        break;
//
//    case DLL_PROCESS_DETACH:
//        MH_DisableHook(MH_ALL_HOOKS);
//        MH_Uninitialize();
//        break;
//    }
//    return TRUE;
//}