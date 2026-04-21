#include "pch.h"
#include "DlpIpc.h"

#include <bcrypt.h>
#include <string>
#include <mutex>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 1 — Shared-secret key storage
// ════════════════════════════════════════════════════════════════════════════
//
//  The key is stored in a dedicated non-pageable data section so that it does
//  not appear in user-mode crash dumps (MiniDumpWriteDump excludes non-default
//  sections by default) and is not swapped to the pagefile.
//
//  The injector service writes the 32-byte key into this variable inside the
//  target process's address space via WriteProcessMemory BEFORE CreateRemoteThread
//  is called.  This guarantees the key is present by the time DllMain runs.
//
//  NOTE: "#pragma section" + "__declspec(allocate(...))" is the MSVC-specific
//  way to place a variable into a named PE section.

#pragma section(".dlpkey", read, write, nopage)
__declspec(allocate(".dlpkey"))
uint8_t g_dlpIpcSharedSecret[32] = {
    // Default: all-zeros.  The injector always overwrites this before the DLL
    // is used.  A zero key means HMAC will still be computed (not skipped),
    // but a compromised process could forge messages if the injector fails to
    // write the real key.  The server-side validator logs a warning when it
    // detects an all-zero HMAC key.
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

void DlpIpc_SetSharedSecret(const uint8_t key[32]) {
    // SecureZeroMemory ensures the compiler does not optimise away the wipe
    // before the copy (important if called to rotate the key).
    SecureZeroMemory(g_dlpIpcSharedSecret, sizeof(g_dlpIpcSharedSecret));
    memcpy(g_dlpIpcSharedSecret, key, 32);
}

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 2 — BCrypt HMAC-SHA256 engine (cached handles)
// ════════════════════════════════════════════════════════════════════════════
//
//  BCryptOpenAlgorithmProvider is expensive (~0.5 ms).  We open the provider
//  once and cache it for the lifetime of the DLL.  The mutex serialises the
//  one-time initialisation; after that all HMAC computations run concurrently.

static BCRYPT_ALG_HANDLE  g_hHmacAlg  = nullptr;
static std::once_flag     g_hmacInit;

static bool EnsureHmacAlg() {
    std::call_once(g_hmacInit, []() {
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &g_hHmacAlg,
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            BCRYPT_ALG_HANDLE_HMAC_FLAG);  // open in HMAC mode

        if (!BCRYPT_SUCCESS(status)) {
            OutputDebugStringA("[DLP][IPC] BCryptOpenAlgorithmProvider(HMAC-SHA256) failed");
            g_hHmacAlg = nullptr;
        }
    });
    return g_hHmacAlg != nullptr;
}

BOOL DlpIpc_ComputeHmac(
    const void* pData,
    size_t      dataLen,
    uint8_t     outHmac[32])
{
    if (!EnsureHmacAlg()) return FALSE;

    BCRYPT_HASH_HANDLE hHash = nullptr;

    // Create an HMAC hash object with the shared secret as the key.
    // BCryptCreateHash copies the key internally; we do not need to keep our
    // copy alive after this call.
    NTSTATUS status = BCryptCreateHash(
        g_hHmacAlg,
        &hHash,
        nullptr, 0,                                 // let BCrypt allocate the object
        const_cast<PUCHAR>(g_dlpIpcSharedSecret),   // HMAC key
        static_cast<ULONG>(sizeof(g_dlpIpcSharedSecret)),
        0);

    if (!BCRYPT_SUCCESS(status) || !hHash) {
        OutputDebugStringA("[DLP][IPC] BCryptCreateHash failed");
        return FALSE;
    }

    BOOL ok = FALSE;

    // Hash the data
    status = BCryptHashData(
        hHash,
        reinterpret_cast<PUCHAR>(const_cast<void*>(pData)),
        static_cast<ULONG>(dataLen),
        0);

    if (!BCRYPT_SUCCESS(status)) {
        OutputDebugStringA("[DLP][IPC] BCryptHashData failed");
        goto cleanup;
    }

    // Finalise: write the 32-byte digest
    status = BCryptFinishHash(hHash, outHmac, 32, 0);
    if (!BCRYPT_SUCCESS(status)) {
        OutputDebugStringA("[DLP][IPC] BCryptFinishHash failed");
        goto cleanup;
    }

    ok = TRUE;

cleanup:
    BCryptDestroyHash(hHash);
    return ok;
}

// Constant-time comparison to prevent timing side-channel attacks.
// A naive memcmp short-circuits on the first mismatch, leaking information
// about how many leading bytes are correct.
static BOOL ConstantTimeEqual(const uint8_t* a, const uint8_t* b, size_t len) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

BOOL DlpIpc_VerifyHmac(
    const void*   pData,
    size_t        dataLen,
    const uint8_t expectedHmac[32])
{
    uint8_t computed[32] = {};
    if (!DlpIpc_ComputeHmac(pData, dataLen, computed))
        return FALSE;
    return ConstantTimeEqual(computed, expectedHmac, 32);
}

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 3 — Pipe name builder
// ════════════════════════════════════════════════════════════════════════════

std::wstring DlpIpc_BuildPipeName(const wchar_t* appTag, DWORD uiPid) {
    // Format: \\.\pipe\DLP_<AppTag>_<UIPid>
    // Example: \\.\pipe\DLP_Chrome_12345
    std::wstring name = kDlpPipePrefix;  // L"\\.\pipe\DLP_"
    name += appTag;
    name += L'_';
    name += std::to_wstring(uiPid);
    return name;
}

// ════════════════════════════════════════════════════════════════════════════
//  SECTION 4 — Message build / validate helpers
// ════════════════════════════════════════════════════════════════════════════

BOOL DlpIpc_BuildMessage(
    DLP_IPC_MESSAGE* pMsg,
    DlpIpcMsgType    msgType,
    uint32_t         categories,
    DWORD            uiPid,
    const wchar_t*   filePath)
{
    if (!pMsg) return FALSE;

    // Zero the entire struct so padding bytes are deterministic (important for
    // the HMAC — different padding bytes would produce different tags).
    ZeroMemory(pMsg, sizeof(*pMsg));

    pMsg->dwMagic      = kDlpIpcMagic;
    pMsg->dwVersion    = kDlpIpcVersion;
    pMsg->dwSenderPid  = GetCurrentProcessId();
    pMsg->dwUiPid      = uiPid;
    pMsg->dwMsgType    = static_cast<uint32_t>(msgType);
    pMsg->dwCategories = categories;
    pMsg->dwReserved   = 0;

    if (filePath) {
        // Safe copy — always null-terminated, never overflows
        const size_t srcLen = wcsnlen(filePath, MAX_PATH - 1);
        wcsncpy_s(pMsg->wszFilePath, MAX_PATH, filePath, srcLen);
        pMsg->dwPathLen = static_cast<uint32_t>(srcLen);
    }

    // Compute HMAC over everything EXCEPT the hmac field itself
    return DlpIpc_ComputeHmac(pMsg, kDlpIpcHmacCoverage, pMsg->hmac);
}

BOOL DlpIpc_ValidateMessage(
    const DLP_IPC_MESSAGE* pMsg,
    HANDLE                 hPipe)
{
    if (!pMsg) {
        OutputDebugStringA("[DLP][IPC] ValidateMessage: null message pointer");
        return FALSE;
    }

    // ── 1. Magic number ───────────────────────────────────────────────────────
    if (pMsg->dwMagic != kDlpIpcMagic) {
        OutputDebugStringA("[DLP][IPC] ValidateMessage: bad magic number — possible pipe squatter");
        return FALSE;
    }

    // ── 2. Protocol version ───────────────────────────────────────────────────
    if (pMsg->dwVersion != kDlpIpcVersion) {
        char buf[128];
        wsprintfA(buf, "[DLP][IPC] ValidateMessage: version mismatch (got %u, expected %u)",
                  pMsg->dwVersion, kDlpIpcVersion);
        OutputDebugStringA(buf);
        return FALSE;
    }

    // ── 3. Independent PID verification via kernel ────────────────────────────
    //  GetNamedPipeClientProcessId reads the PID from the kernel's pipe endpoint
    //  structure — it cannot be spoofed by the client process.
    if (hPipe && hPipe != INVALID_HANDLE_VALUE) {
        DWORD actualPid = 0;
        if (GetNamedPipeClientProcessId(hPipe, &actualPid)) {
            if (actualPid != pMsg->dwSenderPid) {
                char buf[128];
                wsprintfA(buf,
                    "[DLP][IPC] ValidateMessage: PID mismatch — "
                    "reported=%lu actual=%lu (possible impersonation)",
                    pMsg->dwSenderPid, actualPid);
                OutputDebugStringA(buf);
                return FALSE;
            }
        } else {
            // GetNamedPipeClientProcessId is only available on Vista+; should
            // always succeed in our target environment.
            OutputDebugStringA("[DLP][IPC] ValidateMessage: GetNamedPipeClientProcessId failed");
            // Non-fatal: continue with HMAC check rather than rejecting outright.
        }
    }

    // ── 4. HMAC integrity check ───────────────────────────────────────────────
    //  This catches message forgery even if a compromised renderer tries to
    //  send fabricated DLP events (e.g. fake "sensitive file opened" to trigger
    //  denial-of-service against the UI).
    if (!DlpIpc_VerifyHmac(pMsg, kDlpIpcHmacCoverage, pMsg->hmac)) {
        OutputDebugStringA("[DLP][IPC] ValidateMessage: HMAC verification FAILED — "
                           "message rejected (possible forgery or key mismatch)");
        return FALSE;
    }

    // ── 5. Warn if zero key is in use ─────────────────────────────────────────
    //  A zero key means the injector failed to write the real key — HMAC still
    //  provides structure validation but NOT authentication.
    {
        static const uint8_t kZeroKey[32] = {};
        if (ConstantTimeEqual(g_dlpIpcSharedSecret, kZeroKey, 32)) {
            OutputDebugStringA("[DLP][IPC] WARNING: HMAC validated with all-zero key — "
                               "injector may not have set the shared secret");
        }
    }

    return TRUE;
}

// ════════════════════════════════════════════════════════════════════════════
//  Exported address getter — used by InjectionEngine to locate the
//  g_dlpIpcSharedSecret variable inside the remote process via
//  GetProcAddress("DlpIpc_GetSharedSecretAddress") + offset calculation.
// ════════════════════════════════════════════════════════════════════════════
extern "C" __declspec(dllexport) void* DlpIpc_GetSharedSecretAddress() {
    return g_dlpIpcSharedSecret;
}
