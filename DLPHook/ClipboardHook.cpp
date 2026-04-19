#include "pch.h"
#include "ClipboardHook.h"
#include "DlpCommon.h"
#include <ole2.h>
#include <string>
#include "MinHook.h"

// ── Function pointer typedefs ─────────────────────────────────────────────────

typedef HANDLE (WINAPI* FN_GetClipboardData)(UINT);
typedef HANDLE (WINAPI* FN_SetClipboardData)(UINT, HANDLE);
typedef HRESULT(WINAPI* FN_OleGetClipboard)(LPDATAOBJECT*);
typedef HRESULT(WINAPI* FN_OleSetClipboard)(LPDATAOBJECT);

static FN_GetClipboardData fpGetClipboardData = nullptr;
static FN_SetClipboardData fpSetClipboardData = nullptr;
static FN_OleGetClipboard  fpOleGetClipboard  = nullptr;
static FN_OleSetClipboard  fpOleSetClipboard  = nullptr;

// ── Clipboard memory helpers ──────────────────────────────────────────────────

static std::string ReadAnsiFromHandle(HANDLE hMem) {
    if (!hMem) return {};
    const char* ptr = static_cast<const char*>(GlobalLock(hMem));
    if (!ptr) return {};
    std::string text(ptr);
    GlobalUnlock(hMem);
    return text;
}

static std::wstring ReadUnicodeFromHandle(HANDLE hMem) {
    if (!hMem) return {};
    const wchar_t* ptr = static_cast<const wchar_t*>(GlobalLock(hMem));
    if (!ptr) return {};
    std::wstring text(ptr);
    GlobalUnlock(hMem);
    return text;
}

// ── DLP scan helpers ──────────────────────────────────────────────────────────

// Scan the text content held in a clipboard memory handle.
// Returns all DlpMatch results (one per triggered category).
static std::vector<DlpMatch> ScanClipboardHandle(UINT uFormat, HANDLE hMem) {
    switch (uFormat) {
    case CF_UNICODETEXT: return ScanText(ReadUnicodeFromHandle(hMem));
    case CF_TEXT:
    case CF_OEMTEXT:     return ScanText(ReadAnsiFromHandle(hMem));
    default:             return {};
    }
}

// Build the alert message shown to the user.
//  action  — e.g. L"Copy blocked"  or  L"Paste blocked"
//  matches — non-empty vector from ScanText()
//
// Single category:
//   "Copy blocked: Payment card data (PCI) detected.
//    This action has been prevented by Browser Bridge DLP."
//
// Multiple categories:
//   "Copy blocked: Multiple sensitive data types detected:
//    • Credit Card Number
//    • Social Security Number (SSN)
//    This action has been prevented by Browser Bridge DLP."
//
static std::wstring BuildClipboardAlert(const std::vector<DlpMatch>& matches,
                                        const wchar_t* action)
{
    // Defensive guard — callers check !matches.empty(), but protect against
    // future call-site mistakes that would produce a confusing empty alert.
    if (matches.empty()) {
        std::wstring msg = action;
        msg += L": Sensitive data detected.\nThis action has been prevented by Browser Bridge DLP.";
        return msg;
    }

    std::wstring msg = action;
    msg += L": ";

    if (matches.size() == 1) {
        msg += matches[0].categoryLabel;
        msg += L" detected.";
    } else {
        msg += L"Multiple sensitive data types detected:";
        for (const auto& m : matches) {
            msg += L"\n  \u2022 ";   // bullet character U+2022
            msg += m.patternName;
        }
    }

    msg += L"\nThis action has been prevented by Browser Bridge DLP.";
    return msg;
}

// ── Hook detours ──────────────────────────────────────────────────────────────

static HANDLE WINAPI Detour_GetClipboardData(UINT uFormat) {
    OutputDebugStringA("[DLP] GetClipboardData called");
    HANDLE hResult = fpGetClipboardData(uFormat);

    if (hResult && (uFormat == CF_TEXT || uFormat == CF_OEMTEXT || uFormat == CF_UNICODETEXT)) {
        const auto matches = ScanClipboardHandle(uFormat, hResult);
        if (!matches.empty()) {
            OutputDebugStringA("[DLP] BLOCKED paste — sensitive data detected");
            NotifyUser(BuildClipboardAlert(matches, L"Paste blocked"));
            return nullptr; // Clipboard memory is system-owned; do not free
        }
    }
    return hResult;
}

static HANDLE WINAPI Detour_SetClipboardData(UINT uFormat, HANDLE hMem) {
    OutputDebugStringA("[DLP] SetClipboardData called");

    if (hMem && (uFormat == CF_TEXT || uFormat == CF_OEMTEXT || uFormat == CF_UNICODETEXT)) {
        const auto matches = ScanClipboardHandle(uFormat, hMem);
        if (!matches.empty()) {
            OutputDebugStringA("[DLP] BLOCKED copy — sensitive data detected");
            NotifyUser(BuildClipboardAlert(matches, L"Copy blocked"));
            return nullptr; // Caller retains ownership of hMem; do not free here
        }
    }
    return fpSetClipboardData(uFormat, hMem);
}

static HRESULT WINAPI Detour_OleGetClipboard(LPDATAOBJECT* ppDataObj) {
    OutputDebugStringA("[DLP] OleGetClipboard called");
    HRESULT hr = fpOleGetClipboard(ppDataObj);

    if (SUCCEEDED(hr) && ppDataObj && *ppDataObj) {
        FORMATETC fmt = { CF_UNICODETEXT, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
        STGMEDIUM stg = {};
        if (SUCCEEDED((*ppDataObj)->GetData(&fmt, &stg))) {
            const auto matches = ScanText(ReadUnicodeFromHandle(stg.hGlobal));
            ReleaseStgMedium(&stg);
            if (!matches.empty()) {
                OutputDebugStringA("[DLP] BLOCKED paste — sensitive data detected (OLE)");
                NotifyUser(BuildClipboardAlert(matches, L"Paste blocked"));
                (*ppDataObj)->Release();
                *ppDataObj = nullptr;
                return E_ACCESSDENIED;
            }
        }
    }
    return hr;
}

static HRESULT WINAPI Detour_OleSetClipboard(LPDATAOBJECT pDataObj) {
    OutputDebugStringA("[DLP] OleSetClipboard called");

    if (pDataObj) {
        FORMATETC fmt = { CF_UNICODETEXT, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
        STGMEDIUM stg = {};
        if (SUCCEEDED(pDataObj->GetData(&fmt, &stg))) {
            const auto matches = ScanText(ReadUnicodeFromHandle(stg.hGlobal));
            ReleaseStgMedium(&stg);
            if (!matches.empty()) {
                OutputDebugStringA("[DLP] BLOCKED copy — sensitive data detected (OLE)");
                NotifyUser(BuildClipboardAlert(matches, L"Copy blocked"));
                return E_ACCESSDENIED;
            }
        }
    }
    return fpOleSetClipboard(pDataObj);
}

// ── Install / Remove ──────────────────────────────────────────────────────────

void ClipboardHook_Install() {
    MH_CreateHookApi(L"user32.dll", "GetClipboardData",
                     &Detour_GetClipboardData, reinterpret_cast<LPVOID*>(&fpGetClipboardData));
    MH_CreateHookApi(L"user32.dll", "SetClipboardData",
                     &Detour_SetClipboardData, reinterpret_cast<LPVOID*>(&fpSetClipboardData));

    // Ensure ole32.dll is loaded before attempting to hook its exports
    LoadLibraryW(L"ole32.dll");
    MH_CreateHookApi(L"ole32.dll", "OleGetClipboard",
                     &Detour_OleGetClipboard, reinterpret_cast<LPVOID*>(&fpOleGetClipboard));
    MH_CreateHookApi(L"ole32.dll", "OleSetClipboard",
                     &Detour_OleSetClipboard, reinterpret_cast<LPVOID*>(&fpOleSetClipboard));

    OutputDebugStringA("[DLP] ClipboardHook installed — multi-category scanner active (PCI/PII/PHI/Financial)");
}

void ClipboardHook_Remove() {
    // MinHook teardown is handled centrally in DllMain; no module state to release here
}
