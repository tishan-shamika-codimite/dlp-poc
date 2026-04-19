#include "pch.h"
#include "FileUploadHook.h"
#include "DlpCommon.h"
#include "PdfTextExtractor.h"
#include <string>
#include <shobjidl.h>
#include <commdlg.h>   // OPENFILENAMEW, LPOPENFILENAMEW, GetOpenFileNameW
#include "MinHook.h"
#include <psapi.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "comdlg32.lib")

// ── Configuration ─────────────────────────────────────────────────────────────

static constexpr DWORD kMaxScanBytes = 50 * 1024 * 1024; // 50 MB

static const wchar_t* kDocExtensions[] = {
    L".pdf", L".txt", L".csv", L".doc", L".docx",
    L".xls", L".xlsx", L".rtf", L".html", L".htm",
    L".xml", L".json", L".log", L".md"
};

// ── Function pointer typedefs ─────────────────────────────────────────────────

typedef HANDLE (WINAPI* FN_CreateFileW)(LPCWSTR, DWORD, DWORD,
                                        LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI* FN_GetOpenFileNameW)(LPOPENFILENAMEW);
typedef HRESULT(STDMETHODCALLTYPE* FN_FileDialogShow)(IModalWindow*, HWND);

static FN_CreateFileW       fpCreateFileW       = nullptr;
static FN_GetOpenFileNameW  fpGetOpenFileNameW  = nullptr;
static FN_FileDialogShow    fpFileDialogShow    = nullptr;

// ── Shared file helpers ───────────────────────────────────────────────────────

static bool HasDocumentExtension(LPCWSTR path) {
    if (!path) return false;

    const wchar_t* dot = nullptr;
    for (const wchar_t* p = path; *p; p++)
        if (*p == L'.') dot = p;
    if (!dot) return false;

    std::wstring ext(dot);
    for (auto& c : ext) c = towlower(c);

    for (const auto& docExt : kDocExtensions)
        if (ext == docExt) return true;
    return false;
}

static bool IsSystemPath(LPCWSTR path) {
    if (!path) return true;

    std::wstring lower(path);
    for (auto& c : lower) c = towlower(c);

    return lower.find(L"\\appdata\\")      != std::wstring::npos
        || lower.find(L"\\program files")  != std::wstring::npos
        || lower.find(L"\\windows\\")      != std::wstring::npos
        || lower.find(L"\\programdata\\")  != std::wstring::npos
        || lower.find(L"\\temp\\")         != std::wstring::npos
        || lower.find(L"\\tmp\\")          != std::wstring::npos
        || lower.find(L"\\cache\\")        != std::wstring::npos
        || lower.find(L"\\node_modules\\") != std::wstring::npos;
}

static bool ShouldScanFile(LPCWSTR path) {
    return path && HasDocumentExtension(path) && !IsSystemPath(path);
}

// Opens a read-only handle via the real CreateFileW, reads full content, closes.
static std::string ReadFileContent(LPCWSTR path) {
    HANDLE hScan = fpCreateFileW(
        path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hScan == INVALID_HANDLE_VALUE) return {};

    LARGE_INTEGER fileSize = {};
    if (!GetFileSizeEx(hScan, &fileSize)
        || fileSize.QuadPart <= 0
        || fileSize.QuadPart > kMaxScanBytes) {
        CloseHandle(hScan);
        return {};
    }

    const DWORD size = static_cast<DWORD>(fileSize.QuadPart);
    std::string buf(size, '\0');
    DWORD totalRead = 0;

    while (totalRead < size) {
        DWORD bytesRead = 0;
        if (!ReadFile(hScan, &buf[totalRead], size - totalRead,
                      &bytesRead, nullptr) || bytesRead == 0)
            break;
        totalRead += bytesRead;
    }

    CloseHandle(hScan);
    buf.resize(totalRead);
    return buf;
}

// ── DLP scan helper ───────────────────────────────────────────────────────────

// Read the file, extract text (handling PDF streams), and run the multi-
// category scanner.  Returns an empty vector if the file is clean or unreadable.
static std::vector<DlpMatch> ScanFile(LPCWSTR path) {
    const std::string content = ReadFileContent(path);
    if (content.empty()) return {};

    if (IsPdfFile(content)) {
        const std::string text = ExtractTextFromPdf(content);
        if (text.empty()) return {};
        return ScanText(text);
    }

    return ScanText(content);
}

// Build the alert message for a file-upload block.
//
// Single category:
//   "File upload blocked: Banking or tax information (Financial) detected
//    in the selected file.
//    This action has been prevented by Browser Bridge DLP."
//
// Multiple categories:
//   "File upload blocked: Multiple sensitive data types detected in the
//    selected file:
//    • Credit Card Number
//    • Social Security Number (SSN)
//    This action has been prevented by Browser Bridge DLP."
//
static std::wstring BuildFileAlert(const std::vector<DlpMatch>& matches,
                                   const wchar_t* context)
{
    // Defensive guard — callers check !matches.empty(), but protect against
    // future call-site mistakes that would produce a confusing empty alert.
    if (matches.empty()) {
        std::wstring msg = L"File ";
        msg += context;
        msg += L" blocked: Sensitive data detected in the selected file.\nThis action has been prevented by Browser Bridge DLP.";
        return msg;
    }

    std::wstring msg = L"File ";
    msg += context;
    msg += L" blocked: ";

    if (matches.size() == 1) {
        msg += matches[0].categoryLabel;
        msg += L" detected in the selected file.";
    } else {
        msg += L"Multiple sensitive data types detected in the selected file:";
        for (const auto& m : matches) {
            msg += L"\n  \u2022 ";   // bullet character U+2022
            msg += m.patternName;
        }
    }

    msg += L"\nThis action has been prevented by Browser Bridge DLP.";
    return msg;
}

// ── Hook 1: IFileOpenDialog::Show (modern Vista-style dialog) ─────────────────
// Hooked via COM vtable — intercepts BEFORE the browser sees the result.
// Returning ERROR_CANCELLED prevents the browser from adding the file to the
// upload UI, so no spinner ever appears.

static HRESULT STDMETHODCALLTYPE Detour_FileDialogShow(
    IModalWindow* pThis, HWND hwndOwner)
{
    HRESULT hr = fpFileDialogShow(pThis, hwndOwner);
    if (hr != S_OK) return hr; // user cancelled — pass through

    // Only intercept Open dialogs, not Save dialogs
    IFileOpenDialog* pOpenDialog = nullptr;
    if (FAILED(pThis->QueryInterface(IID_IFileOpenDialog,
                                     reinterpret_cast<void**>(&pOpenDialog))))
        return hr;

    std::vector<DlpMatch> matches;

    // ── Single file selection ──
    IShellItem* pItem = nullptr;
    if (SUCCEEDED(pOpenDialog->GetResult(&pItem))) {
        PWSTR filePath = nullptr;
        if (SUCCEEDED(pItem->GetDisplayName(SIGDN_FILESYSPATH, &filePath))) {
            if (ShouldScanFile(filePath))
                matches = ScanFile(filePath);
            CoTaskMemFree(filePath);
        }
        pItem->Release();
    }

    // ── Multi-file selection ──
    if (matches.empty()) {
        IShellItemArray* pItems = nullptr;
        if (SUCCEEDED(pOpenDialog->GetResults(&pItems))) {
            DWORD count = 0;
            pItems->GetCount(&count);
            for (DWORD i = 0; i < count && matches.empty(); i++) {
                IShellItem* pFileItem = nullptr;
                if (SUCCEEDED(pItems->GetItemAt(i, &pFileItem))) {
                    PWSTR filePath = nullptr;
                    if (SUCCEEDED(pFileItem->GetDisplayName(SIGDN_FILESYSPATH, &filePath))) {
                        if (ShouldScanFile(filePath))
                            matches = ScanFile(filePath);
                        CoTaskMemFree(filePath);
                    }
                    pFileItem->Release();
                }
            }
            pItems->Release();
        }
    }

    pOpenDialog->Release();

    if (!matches.empty()) {
        OutputDebugStringA("[DLP] BLOCKED file dialog — sensitive data detected in selected file");
        NotifyUser(BuildFileAlert(matches, L"upload"));
        // Tell the browser the user cancelled — no file enters the upload UI
        return HRESULT_FROM_WIN32(ERROR_CANCELLED);
    }

    return hr;
}

// ── Hook 2: GetOpenFileNameW (legacy file dialog) ─────────────────────────────

static BOOL WINAPI Detour_GetOpenFileNameW(LPOPENFILENAMEW lpofn) {
    BOOL result = fpGetOpenFileNameW(lpofn);
    if (!result || !lpofn || !lpofn->lpstrFile) return result;

    if (lpofn->Flags & OFN_ALLOWMULTISELECT) {
        // When OFN_ALLOWMULTISELECT is set there are two distinct return formats:
        //
        //   (a) Multi-file: lpstrFile = "dir\0file1\0file2\0\0"
        //       The first token is the directory; subsequent tokens are filenames.
        //
        //   (b) Single-file: lpstrFile = "C:\full\path\to\file.txt\0"
        //       lpstrFile contains only the complete path — no separate directory
        //       token.  The character immediately after the terminating NUL is
        //       either another NUL (zeroed buffer) or undefined buffer content.
        //
        // Previous code always executed the multi-file walk, so the single-file
        // case (b) was never scanned — a complete DLP bypass for legacy dialogs.
        const std::wstring firstToken(lpofn->lpstrFile);
        const wchar_t*     nextToken  = lpofn->lpstrFile + firstToken.size() + 1;

        if (*nextToken == L'\0') {
            // ── Case (b): single file selected ───────────────────────────────
            // firstToken is the full path; scan it directly.
            if (ShouldScanFile(firstToken.c_str())) {
                const auto matches = ScanFile(firstToken.c_str());
                    if (!matches.empty()) {
                        OutputDebugStringA("[DLP] BLOCKED GetOpenFileName (single via multi-select) — sensitive data detected");
                        NotifyUser(BuildFileAlert(matches, L"upload"));
                        SetLastError(0);
                        return FALSE;
                    }
            }
        } else {
            // ── Case (a): multiple files selected ────────────────────────────
            // firstToken is the directory; walk subsequent NUL-separated names.
            const std::wstring dir  = firstToken;
            const wchar_t*     file = nextToken;
            while (*file) {
                const std::wstring fullPath = dir + L"\\" + file;
                if (ShouldScanFile(fullPath.c_str())) {
                    const auto matches = ScanFile(fullPath.c_str());
                    if (!matches.empty()) {
                        OutputDebugStringA("[DLP] BLOCKED GetOpenFileName — sensitive data detected");
                        NotifyUser(BuildFileAlert(matches, L"upload"));
                        SetLastError(0);
                        return FALSE;
                    }
                }
                file += wcslen(file) + 1;
            }
        }
    } else {
        // Single file
        if (ShouldScanFile(lpofn->lpstrFile)) {
            const auto matches = ScanFile(lpofn->lpstrFile);
            if (!matches.empty()) {
                OutputDebugStringA("[DLP] BLOCKED GetOpenFileName — sensitive data detected");
                NotifyUser(BuildFileAlert(matches, L"upload"));
                SetLastError(0);
                return FALSE;
            }
        }
    }

    return result;
}

// ── Process-name helpers ──────────────────────────────────────────────────────
//
//  Used by the CreateFileW hook to distinguish PDF *viewer* processes (Acrobat,
//  Reader) from *uploader* processes (Chrome, Edge renderer, Slack) so we can
//  apply the correct policy:
//
//    Viewer process + sensitive PDF → ARM protection, ALLOW the open
//    Uploader process + sensitive PDF → ARM protection, BLOCK the open
//
//  We detect viewer processes by comparing the current process's EXE name (not
//  its full path) against a small allow-list.  The comparison is
//  case-insensitive to handle unusual capitalisation.

static bool IsViewerProcess() {
    static const wchar_t* kViewerExes[] = {
        L"acrobat.exe",
        L"acrord32.exe",
        L"foxitreader.exe",
        L"sumatrapdf.exe",
        L"evince.exe",
    };

    wchar_t exePath[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH)) return false;

    // Extract just the filename component
    const wchar_t* fileName = exePath;
    for (const wchar_t* p = exePath; *p; ++p)
        if (*p == L'\\' || *p == L'/') fileName = p + 1;

    // Case-insensitive compare
    wchar_t lower[MAX_PATH] = {};
    size_t i = 0;
    for (; fileName[i] && i < MAX_PATH - 1; ++i)
        lower[i] = static_cast<wchar_t>(towlower(fileName[i]));
    lower[i] = L'\0';

    for (const auto* viewer : kViewerExes)
        if (wcscmp(lower, viewer) == 0) return true;

    return false;
}

// ── Hook 3: CreateFileW ───────────────────────────────────────────────────────
//
//  Two distinct policies depending on the calling process:
//
//  VIEWER PROCESSES (Acrobat, Reader, Foxit, …)
//  ─────────────────────────────────────────────
//  When Acrobat opens a sensitive PDF we must NOT block the handle — that
//  would prevent the document from being rendered at all, which is the wrong
//  DLP outcome.  Instead we allow the open to proceed so the viewer can
//  display the document normally.
//
//  UPLOADER / BROWSER PROCESSES (Chrome renderer, Edge, Slack, …)
//  ───────────────────────────────────────────────────────────────
//  These processes should NOT be reading sensitive PDFs from disk; any such
//  read is almost certainly an upload or exfil attempt.  We block the open,
//  arm protection, and show the alert.
//
//  NOTE: This hook fires AFTER the browser has already rendered the file chip
//  and spinner (for upload flows), so the spinner will persist.  The dialog
//  hooks (1 & 2) are the preferred interception point; this hook is a last-
//  resort backstop for drag-and-drop and programmatic opens.

static HANDLE WINAPI Detour_CreateFileW(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile)
{
    if (lpFileName
        && (dwDesiredAccess & GENERIC_READ)
        && dwCreationDisposition == OPEN_EXISTING
        && ShouldScanFile(lpFileName))
    {
        // Scan using the real CreateFileW (fpCreateFileW) via ReadFileContent
        const std::string content = ReadFileContent(lpFileName);
        if (!content.empty()) {
            std::string textToScan = content;
            if (IsPdfFile(content))
                textToScan = ExtractTextFromPdf(content);

            const auto matches = ScanText(textToScan);
            if (!matches.empty()) {
                if (IsViewerProcess()) {
                    // ── Viewer policy: allow open ─────────────────────────────
                    // We allow the file to be opened so the viewer can render it.
                    OutputDebugStringA("[DLP] Sensitive content detected in viewer — open allowed");
                    // Fall through — let fpCreateFileW proceed normally.
                } else {
                    // ── Uploader/browser policy: block the open ───────────────
                    OutputDebugStringA("[DLP] BLOCKED CreateFileW — sensitive data detected in file");
                    NotifyUser(BuildFileAlert(matches, L"access"));
                    SetLastError(ERROR_ACCESS_DENIED);
                    return INVALID_HANDLE_VALUE;
                }
            }
        }
    }

    return fpCreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
                         lpSecurityAttributes, dwCreationDisposition,
                         dwFlagsAndAttributes, hTemplateFile);
}

// ── Deferred COM vtable hook installation ─────────────────────────────────────
// Cannot run during DllMain (loader lock), so a background thread does it.
// The sleep is deliberately short (200 ms) so the hook is in place well before
// the user can open a file picker — avoiding fallback to the CreateFileW hook
// which fires too late to suppress the browser's upload spinner.

static DWORD WINAPI FileDialogHookThread(LPVOID /*param*/) {
    // Give the host process a brief moment — much shorter than before so the
    // IFileOpenDialog::Show hook is installed well before the user can open a
    // file picker.  The original 1500 ms delay meant the hook was often still
    // absent when the first dialog opened, causing the CreateFileW fallback to
    // fire instead.  The fallback fires AFTER the browser has already rendered
    // the file-chip/spinner, so the spinner could never be removed.  With the
    // dialog hook in place the browser receives ERROR_CANCELLED before it ever
    // touches the file, so no spinner appears.
    Sleep(200);

    HRESULT hrInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hrInit) && hrInit != RPC_E_CHANGED_MODE) {
        OutputDebugStringA("[DLP] FileDialogHook: CoInitializeEx failed, skipping");
        return 1;
    }

    // Create a temporary IFileOpenDialog to read its vtable
    IFileOpenDialog* pDialog = nullptr;
    HRESULT hr = CoCreateInstance(
        CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
        IID_IFileOpenDialog, reinterpret_cast<void**>(&pDialog));

    if (SUCCEEDED(hr) && pDialog) {
        // IModalWindow::Show is at vtable index 3
        // (IUnknown: QI=0, AddRef=1, Release=2 | IModalWindow: Show=3)
        void** vtable  = *reinterpret_cast<void***>(pDialog);
        void*  showAddr = vtable[3];

        MH_STATUS status = MH_CreateHook(
            showAddr, &Detour_FileDialogShow,
            reinterpret_cast<LPVOID*>(&fpFileDialogShow));

        if (status == MH_OK) {
            MH_EnableHook(showAddr);
            OutputDebugStringA("[DLP] FileDialogHook: IFileOpenDialog::Show hooked successfully");
        } else {
            OutputDebugStringA("[DLP] FileDialogHook: MH_CreateHook failed");
        }

        pDialog->Release();
    } else {
        OutputDebugStringA("[DLP] FileDialogHook: CoCreateInstance failed");
    }

    if (SUCCEEDED(hrInit))
        CoUninitialize();

    return 0;
}

// ── Install / Remove ──────────────────────────────────────────────────────────

void FileUploadHook_Install() {
    // Hook 1 (deferred): IFileOpenDialog::Show via COM vtable
    HANDLE hThread = CreateThread(nullptr, 0, FileDialogHookThread, nullptr, 0, nullptr);
    if (hThread) CloseHandle(hThread);

    // Hook 2: Legacy file dialog (comdlg32.dll)
    MH_CreateHookApi(L"comdlg32.dll", "GetOpenFileNameW",
                     &Detour_GetOpenFileNameW,
                     reinterpret_cast<LPVOID*>(&fpGetOpenFileNameW));

    // Hook 3: CreateFileW fallback (drag-and-drop, programmatic opens)
    MH_CreateHookApi(L"kernel32.dll", "CreateFileW",
                     &Detour_CreateFileW,
                     reinterpret_cast<LPVOID*>(&fpCreateFileW));

    OutputDebugStringA("[DLP] FileUploadHook installed — multi-category scanner active (PCI/PII/PHI/Financial)");
}

void FileUploadHook_Remove() {
    // No module state to release
}

