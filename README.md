# DLP Clipboard Guard

A Windows **Data Loss Prevention (DLP)** proof-of-concept that intercepts clipboard operations system-wide to detect and block sensitive data — specifically credit card numbers — from being copied or pasted into any target application.

---

## What is this project?

This project demonstrates a **kernel-free, user-space DLP agent** for Windows. It silently monitors clipboard activity across monitored processes (browsers, chat clients, text editors) and automatically blocks any copy/paste operation that contains a valid credit card number.

The system is split into two components:

| Component | Type | Purpose |
|---|---|---|
| `DLPHook` | x64 DLL | Installs clipboard hooks inside a target process |
| `DlpInjector` | x64 EXE | Injects `DLPHook.dll` into all running target processes |

---

## Mechanism: DLL Injection + API Hooking

### 1. DLL Injection (`DlpInjector`)

The injector uses the classic **`CreateRemoteThread` + `LoadLibraryA`** injection technique:

1. Enumerates all running processes using `CreateToolhelp32Snapshot`.
2. For every instance of a target process (`chrome.exe`, `msedge.exe`, `Slack.exe`), it:
   - Opens the process with `OpenProcess(PROCESS_ALL_ACCESS, ...)`.
   - Allocates memory inside the target process with `VirtualAllocEx`.
   - Writes the full path of `DLPHook.dll` into that memory using `WriteProcessMemory`.
   - Spawns a remote thread inside the target via `CreateRemoteThread`, pointing it at `LoadLibraryA` — forcing the target process to load the DLL itself.

### 2. API Hooking (`DLPHook`)

Once loaded, `DLPHook.dll`'s `DllMain` uses **[MinHook](https://github.com/TsudaKageyu/minhook)** to redirect four Windows API functions to custom detour functions:

| Hooked API | Library | Covers |
|---|---|---|
| `GetClipboardData` | `user32.dll` | Standard paste (Win32) |
| `SetClipboardData` | `user32.dll` | Standard copy (Win32) |
| `OleGetClipboard` | `ole32.dll` | Paste via OLE (modern apps, browsers) |
| `OleSetClipboard` | `ole32.dll` | Copy via OLE (modern apps, browsers) |

MinHook works by **overwriting the first few bytes** of the target function with a `JMP` instruction pointing to the detour, while saving a trampoline back to the original function.

### 3. Sensitive Data Detection

Every clipboard read/write passes through a two-stage check:

1. **Regex scan** — extracts all digit sequences (13–19 digits, optionally separated by spaces or dashes) from the clipboard text (both `CF_TEXT` ANSI and `CF_UNICODETEXT` wide strings).
2. **Luhn algorithm** — validates each candidate against the [Luhn checksum](https://en.wikipedia.org/wiki/Luhn_algorithm) used by all major card networks to confirm it is a structurally valid card number.

If a match is found, the detour returns `NULL` (Win32 APIs) or `E_ACCESSDENIED` (OLE APIs), making the clipboard appear empty to the calling application. A debug string is emitted via `OutputDebugStringA` and is visible in tools like [Sysinternals DebugView](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview).

---

## How It Works — End-to-End Flow

```
[DlpInjector.exe]  (run as Administrator)
        │
        │  CreateRemoteThread → LoadLibraryA("DLPHook.dll")
        ▼
[Target Process: chrome.exe / Slack.exe / ...]
        │
        │  DllMain (DLL_PROCESS_ATTACH)
        ▼
[MinHook patches IAT/code of target process]
   GetClipboardData  →  Detour_GetClipboardData
   SetClipboardData  →  Detour_SetClipboardData
   OleGetClipboard   →  Detour_OleGetClipboard
   OleSetClipboard   →  Detour_OleSetClipboard
        │
        │  User copies/pastes text
        ▼
[Detour function runs]
   ├─ Regex: does text contain a 13–19 digit card-like pattern?
   ├─ Luhn:  is the digit string a valid card number?
   │
   ├─ YES → Block (return NULL / E_ACCESSDENIED)
   │         OutputDebugString("[DLP] BLOCKED")
   │
   └─ NO  → Forward to original Windows API
```

---

## Project Structure

```
Root/
├── DLPHook/            # The hook DLL
│   ├── dllmain.cpp     # Hook detours, Luhn check, DllMain
│   ├── pch.h / pch.cpp # Precompiled headers
│   └── packages/
│       └── minhook.1.3.3/   # MinHook NuGet package
│
└── DlpInjector/        # The injector EXE
    └── DlpInjector.cpp # Process enumeration & DLL injection
```

---

## Prerequisites

- Windows 10/11 x64
- Visual Studio 2019 or later (with Desktop C++ workload)
- **Administrator privileges** at runtime (required for `OpenProcess` on third-party processes)
- NuGet package `minhook.1.3.3` (already included under `DLPHook/packages/`)

---

## Build

1. Open `DLPHook/DLPHook.sln` in Visual Studio and build **x64 | Debug** (or Release).
2. Open `DlpInjector/DlpInjector.sln` and build **x64 | Release**.
3. Update the `dllPath` constant in `DlpInjector.cpp` to point to your compiled `DLPHook.dll`.

---

## Usage

1. Open the target applications (Chrome, Slack, Notepad, etc.).
2. Run `DlpInjector.exe` **as Administrator**.
3. The injector will report success/failure per process PID.
4. Attempt to copy or paste text containing a credit card number — the operation will be silently blocked.
5. Monitor `[DLP]` log entries with **Sysinternals DebugView** (`dbgview64.exe`, run as Administrator, enable *Capture Global Win32*).

---

## Limitations & Disclaimer

- This is a **proof-of-concept** and is **not production-ready**.
- Processes protected by anti-cheat software, sandboxing, or elevated integrity levels may reject injection.
- The hook is only active for the lifetime of the injected process; re-injection is needed after a process restart.
- Use only on systems you own or have explicit authorization to test on.
