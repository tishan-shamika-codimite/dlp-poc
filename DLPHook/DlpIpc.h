#pragma once
// ════════════════════════════════════════════════════════════════════════════
//  DlpIpc.h  —  Shared IPC Protocol: Named Pipe + HMAC-SHA256 Message Layer
// ════════════════════════════════════════════════════════════════════════════
#include <string>    // std::wstring used in DlpIpc_BuildPipeName signature
#include <cstddef>   // offsetof
//
//  Architecture Overview
//  ─────────────────────
//  Multi-process applications (Chrome, Adobe Acrobat/CEF) split work across
//  a privileged UI process and one or more sandboxed worker processes:
//
//    Chrome Browser (Medium IL) ←──── owns all top-level HWNDs
//         ↑ Named Pipe IPC
//    Chrome Renderer (Low IL)   ←──── hooks CreateFileW, sees the PDF bytes
//
//  The sandbox prevents the renderer from calling SetWindowDisplayAffinity on
//  the browser's HWNDs directly.  This IPC layer bridges that gap:
//
//    1. DLL in WORKER process   → detects sensitive file access
//    2. Sends DLP_IPC_MESSAGE   → over \\.\pipe\DLP_<AppName>_<UIPid>
//    3. DLL in UI process       → receives message, calls SetWDA on own HWNDs
//
//  Security Properties
//  ───────────────────
//  • FILE_FLAG_FIRST_PIPE_INSTANCE   prevents pipe squatting
//  • PIPE_REJECT_REMOTE_CLIENTS      blocks network-sourced connections
//  • Restricted DACL                 only SYSTEM + parent PID SID can connect
//  • GetNamedPipeClientProcessId()   server independently verifies caller PID
//  • HMAC-SHA256 over message body   prevents message forgery from compromised
//                                    renderers; key injected by DlpInjector
//  • Fail-closed                     if IPC send fails, worker denies the open
//
// ════════════════════════════════════════════════════════════════════════════

#include <windows.h>
#include <cstdint>

// ── Pipe naming ───────────────────────────────────────────────────────────────
//
//  One pipe instance per UI process.  Including the UI PID in the name means:
//    • Multiple Acrobat windows (different PIDs) each get their own pipe
//    • A renderer connecting to the wrong pipe gets an access-denied error
//      (the DACL on each pipe names the specific UI PID)
//
//  Format:  \\.\pipe\DLP_<AppTag>_<UIPid>
//  Example: \\.\pipe\DLP_Chrome_12345

static constexpr wchar_t kDlpPipePrefix[] = L"\\\\.\\pipe\\DLP_";
static constexpr DWORD   kPipeBufferBytes  = 4096;
static constexpr DWORD   kPipeConnectMs    = 500;   // client connect timeout
static constexpr DWORD   kPipeIoMs         = 1000;  // per-operation I/O timeout

// ── Message types ─────────────────────────────────────────────────────────────

enum class DlpIpcMsgType : uint32_t {
    // Worker → UI: a sensitive file was opened; arm screen-capture protection
    // and show the notification dialog from the UI process context.
    SensitiveFileOpened = 1,

    // Worker → UI: the sensitive file's handle has been closed / process is
    // done with it.  UI process MAY choose to lift protection if no other
    // sensitive files are open (policy decision).
    SensitiveFileClosed = 2,

    // UI → Worker (response): acknowledgement — protection was armed.
    Ack = 100,

    // UI → Worker (response): protection could not be armed (e.g. no windows
    // found yet).  Worker should retry after a short delay.
    Nack = 101,

    // Heartbeat / keep-alive (either direction)
    Heartbeat = 200,
};

// ── DLP classification bitmask (mirrors DlpCategory in DlpCommon.h) ──────────
//  Redefined here so DlpIpc.h remains self-contained and can be included in
//  translation units that do not pull in the full DlpCommon.h header.

enum class DlpIpcCategory : uint32_t {
    None      = 0,
    PCI       = 1 << 0,
    PII       = 1 << 1,
    PHI       = 1 << 2,
    Financial = 1 << 3,
    All       = 0xFFFFFFFFu,
};

// ── Wire-format message struct ────────────────────────────────────────────────
//
//  All fields are little-endian (native Windows byte order).
//  The struct is sent as a single atomic WriteFile / ReadFile operation using
//  PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, so partial reads never occur.
//
//  HMAC coverage: every byte from dwMagic through dwReserved (inclusive),
//  i.e. the first (sizeof(DLP_IPC_MESSAGE) - 32) bytes.

#pragma pack(push, 1)
struct DLP_IPC_MESSAGE {
    // ── Header (8 bytes) ──────────────────────────────────────────────────
    uint32_t    dwMagic;        // Must equal kDlpIpcMagic
    uint32_t    dwVersion;      // Must equal kDlpIpcVersion

    // ── Sender identity (8 bytes) ─────────────────────────────────────────
    uint32_t    dwSenderPid;    // Self-reported PID — server verifies independently
    uint32_t    dwUiPid;        // PID of the UI process this message targets

    // ── Message payload (16 + MAX_PATH*2 bytes) ───────────────────────────
    uint32_t    dwMsgType;      // DlpIpcMsgType
    uint32_t    dwCategories;   // DlpIpcCategory bitmask — which categories fired
    uint32_t    dwReserved;     // Zero-padded; reserved for future flags
    uint32_t    dwPathLen;      // Number of wchar_t characters in wszFilePath
                                // (NOT including the null terminator)
    wchar_t     wszFilePath[MAX_PATH]; // Sensitive file path (null-terminated)

    // ── HMAC-SHA256 authentication tag (32 bytes) ─────────────────────────
    //  Computed over all preceding fields (dwMagic … wszFilePath).
    //  Key = 32-byte shared secret set by DlpIpc_SetSharedSecret() at DLL
    //  load time.  The injector service writes the key into the remote process
    //  via WriteProcessMemory before the DLL's DllMain runs.
    uint8_t     hmac[32];
};
#pragma pack(pop)

static constexpr uint32_t kDlpIpcMagic   = 0xD1750C01u; // "DLP SOC 01" (hex safe, no float exponent)
static constexpr uint32_t kDlpIpcVersion = 0x00000002u;
static constexpr size_t   kDlpIpcHmacCoverage =
    offsetof(DLP_IPC_MESSAGE, hmac); // bytes covered by HMAC

// ── Shared-secret key management ─────────────────────────────────────────────
//
//  The 32-byte HMAC key is written into this global by the injector service
//  immediately after injection via WriteProcessMemory, before the DLL's
//  DllMain executes.  All IPC send/receive operations use this key.
//
//  The injector generates a fresh random key per target process family
//  (one key shared between the UI process and all its worker processes).
//
//  SECURITY: The key is stored in a non-pageable section (see DlpIpc.cpp) so
//  it does not appear in crash dumps or pagefile snapshots.

// g_dlpIpcSharedSecret is defined in DlpIpc.cpp inside the .dlpkey section.
// Other translation units within the DLL share it via normal linkage.
extern uint8_t g_dlpIpcSharedSecret[32];

// DlpIpc_GetSharedSecretAddress() — exported function the injector uses to
// locate g_dlpIpcSharedSecret inside the remote process via GetProcAddress.
// Returns the address of g_dlpIpcSharedSecret in the current process image.
// The injector computes the offset from the DLL base and applies it to the
// remote module base to find the address for WriteProcessMemory.
extern "C" __declspec(dllexport) void* DlpIpc_GetSharedSecretAddress();

// Call once from the injector after key derivation to copy the key into the
// current process image.  Also callable from DLL_PROCESS_ATTACH if the key
// was pre-written by the injector via WriteProcessMemory.
void DlpIpc_SetSharedSecret(const uint8_t key[32]);

// ── Pipe name builder ─────────────────────────────────────────────────────────
//
//  Builds the full pipe name for a given app tag and UI process PID.
//  Example: DlpIpc_BuildPipeName(L"Chrome", 12345)
//           → L"\\.\pipe\DLP_Chrome_12345"

std::wstring DlpIpc_BuildPipeName(const wchar_t* appTag, DWORD uiPid);

// ── HMAC-SHA256 (portable, no BCrypt dependency in DLL) ───────────────────────
//
//  Computes HMAC-SHA256 over `dataLen` bytes of `pData` using the shared secret.
//  Output written to `outHmac[32]`.  Returns TRUE on success.
//
//  Implementation uses BCrypt (CNG) which is available on all supported Windows
//  versions (Vista+).  The BCrypt handle is cached after first use.

BOOL DlpIpc_ComputeHmac(
    const void* pData,
    size_t      dataLen,
    uint8_t     outHmac[32]);

BOOL DlpIpc_VerifyHmac(
    const void*    pData,
    size_t         dataLen,
    const uint8_t  expectedHmac[32]);

// ── Message helpers ───────────────────────────────────────────────────────────

// Fills all header/payload fields and computes the HMAC authentication tag.
// Call this before DlpIpcClient_Send().
BOOL DlpIpc_BuildMessage(
    DLP_IPC_MESSAGE* pMsg,
    DlpIpcMsgType    msgType,
    uint32_t         categories,   // DlpIpcCategory bitmask
    DWORD            uiPid,
    const wchar_t*   filePath);    // may be nullptr for non-file messages

// Validates magic, version, sender PID (against the connected pipe client),
// and HMAC.  Returns FALSE and logs the failure reason on any mismatch.
BOOL DlpIpc_ValidateMessage(
    const DLP_IPC_MESSAGE* pMsg,
    HANDLE                 hPipe);   // server-side connected pipe handle
