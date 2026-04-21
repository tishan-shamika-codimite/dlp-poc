#include "pch.h"
#include "FileUploadHook.h"
#include "DlpCommon.h"
#include "PdfTextExtractor.h"
#include "ScreenCaptureProtection.h"
#include "DlpIpc.h"           // DlpIpcCategory bitmask
#include "DlpIpcClient.h"     // Worker → UI IPC send
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

    // ── Genuine system / infrastructure paths — skip scanning ────────────────
    //
    //  NOTE: We deliberately do NOT exclude \appdata\ here.
    //  Adobe Acrobat stores temporary PDF renders and recently-opened documents
    //  under C:\Users\<name>\AppData\Roaming\Adobe\...  — those ARE user
    //  documents and must be scanned.  The first line of the debug log
    //  confirmed Acrobat's working directory is AppData\Roaming.
    //
    //  We only exclude paths that are genuinely infrastructure (Windows
    //  binaries, third-party program files, and OS temp/cache directories
    //  that never contain user-authored documents).

    return lower.find(L"\\program files")    != std::wstring::npos
        || lower.find(L"\\program files (x86)") != std::wstring::npos
        || lower.find(L"\\windows\\")        != std::wstring::npos
        || lower.find(L"\\programdata\\")    != std::wstring::npos
        || lower.find(L"\\node_modules\\")   != std::wstring::npos
        // OS temp dirs only — NOT AppData\Local\Temp under user profile
        || lower.find(L"\\windows\\temp\\")  != std::wstring::npos
        || lower.find(L"\\windows\\tmp\\")   != std::wstring::npos;
}

static bool ShouldScanFile(LPCWSTR path) {
    if (!path) return false;
    if (!HasDocumentExtension(path)) return false;
    if (IsSystemPath(path)) {
        // Uncomment the line below temporarily to see which paths are filtered:
        // char buf[512]; wsprintfA(buf,"[DLP][SKIP] system path: %S", path); OutputDebugStringA(buf);
        return false;
    }
    return true;
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
//  Used by the CreateFileW hook to classify the calling process and apply the
//  correct DLP policy when a sensitive file is detected:
//
//    DEDICATED VIEWER (Acrobat, Foxit, …)
//      → ARM screen-capture protection, ALLOW the file open.
//        The user legitimately needs to read the document; we protect the
//        rendered surface so it cannot be screen-captured or screen-shared.
//
//    BROWSER VIEWER (Chrome, Edge, Firefox rendering a PDF inline)
//      → ARM screen-capture protection, ALLOW the file open.
//        Same rationale as dedicated viewers: the user opened the PDF
//        intentionally inside the browser's built-in renderer.  We must
//        protect the browser window just like an Acrobat window.
//        NOTE: Chrome runs as multiple processes (browser, renderer, GPU,
//        utility).  ALL of them are named "chrome.exe", so this classification
//        covers every process in the Chrome family.
//
//    ALL OTHER PROCESSES (Slack, scripts, unknown tools)
//      → ARM screen-capture protection, BLOCK the file open.
//        An unrecognised process reading a sensitive PDF from disk is treated
//        as a potential exfiltration attempt.

// Returns the lower-case EXE filename of the current process (no path).
static const wchar_t* GetCurrentExeName() {
    // Static buffer — safe because this is called after process init and the
    // result never changes for the lifetime of the process.
    static wchar_t lower[MAX_PATH] = {};
    static bool    resolved        = false;

    if (!resolved) {
        wchar_t exePath[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);

        // Extract just the filename component (after last backslash/slash)
        const wchar_t* fileName = exePath;
        for (const wchar_t* p = exePath; *p; ++p)
            if (*p == L'\\' || *p == L'/') fileName = p + 1;

        size_t i = 0;
        for (; fileName[i] && i < MAX_PATH - 1; ++i)
            lower[i] = static_cast<wchar_t>(towlower(fileName[i]));
        lower[i] = L'\0';

        resolved = true;
    }
    return lower;
}

// Dedicated PDF/document viewer applications.
// Policy: allow file open + arm screen-capture protection.
static bool IsDedicatedViewerProcess() {
    static const wchar_t* kDedicatedViewers[] = {
        L"acrobat.exe",
        L"acrord32.exe",
        L"foxitreader.exe",
        L"sumatrapdf.exe",
        L"evince.exe",
    };
    const wchar_t* exe = GetCurrentExeName();
    for (const auto* name : kDedicatedViewers)
        if (wcscmp(exe, name) == 0) return true;
    return false;
}

// Browser processes that have a built-in PDF viewer.
// Policy: allow file open + arm screen-capture protection on ALL browser
// windows belonging to this PID (the PDF renders inside the browser frame).
//
// Chrome architecture note: every Chrome process — browser, renderer, GPU,
// utility — is named "chrome.exe".  By matching on the exe name we correctly
// catch the renderer process that actually reads the PDF file off disk.
static bool IsBrowserViewerProcess() {
    static const wchar_t* kBrowserViewers[] = {
        L"chrome.exe",          // Google Chrome (all process types)
        L"msedge.exe",          // Microsoft Edge
        L"firefox.exe",         // Mozilla Firefox
        L"brave.exe",           // Brave Browser
        L"opera.exe",           // Opera
        L"vivaldi.exe",         // Vivaldi
    };
    const wchar_t* exe = GetCurrentExeName();
    for (const auto* name : kBrowserViewers)
        if (wcscmp(exe, name) == 0) return true;
    return false;
}

// Legacy helper retained for call-sites that only need a boolean "is this a
// trusted viewer?" answer without distinguishing browser vs. dedicated app.
static bool IsViewerProcess() {
    return IsDedicatedViewerProcess() || IsBrowserViewerProcess();
}

// ── Worker process detection ──────────────────────────────────────────────────
//
//  "Worker" processes are sandboxed sub-processes that cannot call
//  SetWindowDisplayAffinity on their own (their windows are owned by the
//  parent UI process).  When running inside a worker, the DLL must route
//  screen-capture enforcement requests through the IPC client instead of
//  calling ScreenCapture_ProtectProcess() directly.
//
//  Detection heuristic: Chrome renderer / utility processes pass a
//  --type=<renderer|utility|gpu-process> command-line argument.
//  AcroCEF processes are named "AcroCEF.exe" or "acrocef_1.exe".
//  All other processes (the main browser/app window) are treated as UI procs.

static bool IsWorkerProcess() {
    // ── AcroCEF worker processes ──────────────────────────────────────────────
    static const wchar_t* kCefWorkers[] = {
        L"acrocef.exe",
        L"acrocef_1.exe",
        L"acrobatnotification.exe",
    };
    const wchar_t* exe = GetCurrentExeName();
    for (const auto* name : kCefWorkers)
        if (wcscmp(exe, name) == 0) return true;

    // ── Chrome / Edge / Brave renderer detection via command line ────────────
    //  Chrome passes --type=renderer (or gpu-process, utility, etc.) to
    //  sub-processes.  The browser (UI) process has no --type argument.
    if (IsBrowserViewerProcess()) {
        const wchar_t* cmdLine = GetCommandLineW();
        if (cmdLine) {
            // Look for --type= which is present in all non-browser Chrome processes
            if (wcsstr(cmdLine, L"--type=") != nullptr)
                return true;
        }
    }

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
        char dbg[512];
        wsprintfA(dbg, "[DLP][CreateFileW] Scanning: %S", lpFileName);
        OutputDebugStringA(dbg);

        // Scan using the real CreateFileW (fpCreateFileW) via ReadFileContent
        const std::string content = ReadFileContent(lpFileName);
        if (!content.empty()) {
            std::string textToScan = content;
            if (IsPdfFile(content))
                textToScan = ExtractTextFromPdf(content);

            const auto matches = ScanText(textToScan);
            if (!matches.empty()) {
                if (IsDedicatedViewerProcess()) {
                    // ── Dedicated viewer policy: allow open + arm screen-capture ──
                    //
                    // For AcroCEF workers (sandboxed sub-process of Acrobat), we
                    // route through IPC just like browser renderers.
                    // For the main Acrobat.exe process, we protect directly.

                    // Build DlpIpcCategory bitmask
                    uint32_t categories = 0;
                    for (const auto& m : matches) {
                        switch (m.category) {
                        case DlpCategory::PCI:       categories |= static_cast<uint32_t>(DlpIpcCategory::PCI);       break;
                        case DlpCategory::PII:       categories |= static_cast<uint32_t>(DlpIpcCategory::PII);       break;
                        case DlpCategory::PHI:       categories |= static_cast<uint32_t>(DlpIpcCategory::PHI);       break;
                        case DlpCategory::Financial: categories |= static_cast<uint32_t>(DlpIpcCategory::Financial); break;
                        default: break;
                        }
                    }

                    if (IsWorkerProcess()) {
                        // ── AcroCEF sandboxed worker: delegate via IPC ────────
                        OutputDebugStringA("[DLP] Sensitive content in AcroCEF WORKER — "
                                           "routing to Acrobat UI process via IPC");

                        const BOOL ipcOk = DlpIpcClient_NotifySensitiveFileOpened(
                            categories, lpFileName);

                        if (!ipcOk) {
                            // Fail-closed: deny the open if IPC delegation failed
                            OutputDebugStringA("[DLP] FAIL-CLOSED: IPC to Acrobat UI failed — "
                                               "blocking file open in AcroCEF worker");
                            SetLastError(ERROR_ACCESS_DENIED);
                            return INVALID_HANDLE_VALUE;
                        }
                        // IPC OK — Acrobat UI process has armed protection.

                    } else {
                        // ── Main Acrobat.exe UI process: protect directly ─────
                        OutputDebugStringA("[DLP] Sensitive content detected in dedicated viewer — "
                                           "open allowed, arming screen-capture protection");

                        const DWORD currentPid = GetCurrentProcessId();
                        const UINT  protected_ = ScreenCapture_ProtectProcess(currentPid);

                        if (protected_ > 0) {
                            std::wstring msg =
                                L"Sensitive document protection active.\n\n"
                                L"This document contains ";
                            if (matches.size() == 1) {
                                msg += matches[0].categoryLabel;
                            } else {
                                msg += L"multiple types of sensitive data:";
                                for (const auto& m : matches) {
                                    msg += L"\n  \u2022 ";
                                    msg += m.patternName;
                                }
                            }
                            msg += L"\n\nScreen capture and screen sharing have been "
                                   L"disabled for this window by Browser Bridge DLP.";
                            NotifyUser(std::move(msg));
                        } else {
                            // Window not visible yet — retry on a background thread
                            struct RetryCtx {
                                DWORD pid;
                                std::vector<DlpMatch> matches;
                            };
                            auto* pCtx = new RetryCtx{ currentPid, matches };

                            HANDLE hRetry = CreateThread(nullptr, 0,
                                [](LPVOID param) -> DWORD {
                                    auto* ctx = static_cast<RetryCtx*>(param);
                                    for (int attempt = 0; attempt < 8; ++attempt) {
                                        Sleep(500);
                                        const UINT n = ScreenCapture_ProtectProcess(ctx->pid);
                                        if (n > 0) {
                                            OutputDebugStringA("[DLP][SCP] Retry: process window "
                                                               "found and protected");
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
                    }

                    // Fall through — let fpCreateFileW open the file normally.

                } else if (IsBrowserViewerProcess()) {
                    // ── Browser viewer policy: allow open + arm screen-capture ──
                    //
                    // Chrome/Edge/Firefox use a built-in PDF renderer.  The user
                    // deliberately navigated to or opened this PDF inside the
                    // browser, so we ALLOW the read (blocking it would show a
                    // broken PDF tab, not a useful DLP message).
                    //
                    // WORKER vs UI PATH:
                    //   Worker (renderer, gpu-process, --type= present):
                    //     Cannot call SetWindowDisplayAffinity — sandboxed.
                    //     Delegate to the IPC client; the UI-process server will
                    //     apply WDA_EXCLUDEFROMCAPTURE on the browser's HWNDs.
                    //     Fail-closed: if IPC fails, DENY the file open so we
                    //     never silently allow unprotected sensitive-data reads.
                    //
                    //   UI process (main browser, no --type= arg):
                    //     Owns the HWNDs — protect directly.

                    // Build the DlpIpcCategory bitmask from the DlpMatch results
                    uint32_t categories = 0;
                    for (const auto& m : matches) {
                        switch (m.category) {
                        case DlpCategory::PCI:       categories |= static_cast<uint32_t>(DlpIpcCategory::PCI);       break;
                        case DlpCategory::PII:       categories |= static_cast<uint32_t>(DlpIpcCategory::PII);       break;
                        case DlpCategory::PHI:       categories |= static_cast<uint32_t>(DlpIpcCategory::PHI);       break;
                        case DlpCategory::Financial: categories |= static_cast<uint32_t>(DlpIpcCategory::Financial); break;
                        default: break;
                        }
                    }

                    if (IsWorkerProcess()) {
                        // ── Sandboxed worker path: IPC → UI process ───────────
                        OutputDebugStringA("[DLP] Sensitive content in browser WORKER — "
                                           "routing to UI process via IPC");

                        const BOOL ipcOk = DlpIpcClient_NotifySensitiveFileOpened(
                            categories, lpFileName);

                        if (!ipcOk) {
                            // IPC failed or UI process returned Nack.
                            // Fail-closed: deny the file open to prevent
                            // unprotected access to sensitive content.
                            OutputDebugStringA("[DLP] FAIL-CLOSED: IPC send failed or Nack — "
                                               "blocking file open in worker");
                            SetLastError(ERROR_ACCESS_DENIED);
                            return INVALID_HANDLE_VALUE;
                        }
                        // IPC succeeded — UI process has armed protection.
                        // Allow the renderer to open and render the file.

                    } else {
                        // ── UI / main browser process path: direct protection ──
                        OutputDebugStringA("[DLP] Sensitive content detected in browser UI — "
                                           "open allowed, arming screen-capture protection on browser");

                        const DWORD currentPid = GetCurrentProcessId();
                        const UINT  protected_ = ScreenCapture_ProtectProcess(currentPid);

                        if (protected_ > 0) {
                            std::wstring msg =
                                L"Sensitive document protection active.\n\n"
                                L"This PDF contains ";
                            if (matches.size() == 1) {
                                msg += matches[0].categoryLabel;
                            } else {
                                msg += L"multiple types of sensitive data:";
                                for (const auto& m : matches) {
                                    msg += L"\n  \u2022 ";
                                    msg += m.patternName;
                                }
                            }
                            msg += L"\n\nScreen capture and screen sharing have been "
                                   L"disabled for this browser window by Browser Bridge DLP.";
                            NotifyUser(std::move(msg));
                        } else {
                            // Browser window not yet ready — schedule retry.
                            struct RetryCtx { DWORD pid; };
                            auto* pCtx = new RetryCtx{ currentPid };

                            HANDLE hRetry = CreateThread(nullptr, 0,
                                [](LPVOID param) -> DWORD {
                                    auto* ctx = static_cast<RetryCtx*>(param);
                                    for (int attempt = 0; attempt < 8; ++attempt) {
                                        Sleep(500);
                                        const UINT n = ScreenCapture_ProtectProcess(ctx->pid);
                                        if (n > 0) {
                                            OutputDebugStringA("[DLP][SCP] Retry: browser window "
                                                               "found and protected");
                                            NotifyUser(
                                                L"Sensitive document protection active.\n\n"
                                                L"Screen capture and screen sharing have been "
                                                L"disabled for this browser window by Browser Bridge DLP.");
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
                    }

                    // Fall through — let fpCreateFileW open the file normally.

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

