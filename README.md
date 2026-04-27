# DLP Agent — Data Loss Prevention Proof of Concept

A full-stack, Windows-native Data Loss Prevention (DLP) system that operates at both the **browser** and **OS** level. It prevents sensitive data from being leaked via clipboard operations, file uploads, screen sharing, and screenshot capture — without requiring any changes to target applications.

---

## Table of Contents

- [System Overview](#system-overview)
- [Architecture Diagram](#architecture-diagram)
- [Component Deep-Dives](#component-deep-dives)
  - [BrowserExtension](#1-browserextension)
  - [DLPHook](#2-dlphook)
  - [DLPInjector](#3-dlpinjector)
  - [NativeMessagingHost](#4-nativemessaginghost)
  - [Installer](#5-installer)
- [Data Classification Engine](#data-classification-engine)
- [Detection Methods](#detection-methods)
  - [Screen Share Detection](#screen-share-detection)
  - [Screenshot Detection](#screenshot-detection)
  - [Clipboard Interception](#clipboard-interception)
  - [File Upload Interception](#file-upload-interception)
- [Communication Flows](#communication-flows)
- [Default Protected Domains](#default-protected-domains)
- [Prerequisites](#prerequisites)
- [Building the Project](#building-the-project)
  - [Step 1 — Build C++ Components](#step-1--build-c-components)
  - [Step 2 — Build the Browser Extension](#step-2--build-the-browser-extension)
  - [Step 3 — Build the MSI Installer](#step-3--build-the-msi-installer)
- [Installation & Deployment](#installation--deployment)
  - [Installing the MSI](#installing-the-msi)
  - [Loading the Browser Extension](#loading-the-browser-extension)
  - [Registering the Native Messaging Host](#registering-the-native-messaging-host)
  - [Running the Injector as a Windows Service](#running-the-injector-as-a-windows-service)
- [Running in Debug / Console Mode](#running-in-debug--console-mode)
- [Extension Popup — Settings UI](#extension-popup--settings-ui)
- [Project Structure](#project-structure)
- [Key Design Decisions](#key-design-decisions)
- [Known Limitations & Future Work](#known-limitations--future-work)
- [Disclaimer](#disclaimer)

---

## System Overview

The DLP Agent is composed of five tightly-coupled components:

| Component | Language | Role |
|---|---|---|
| **BrowserExtension** | TypeScript / Webpack | Manifest V3 Chrome/Edge extension — overlays sensitive pages, manages settings, communicates with the native host |
| **DLPHook** | C++ (Win32) | DLL injected into target processes — hooks Win32 APIs for clipboard, file upload, and screen share |
| **DLPInjector** | C++ (Win32) | Windows Service — continuously scans for and injects `DLPHook.dll` into target processes |
| **NativeMessagingHost** | C++ (Win32) | Bridge between the browser extension and the OS — detects screen shares and screenshots, forwards events to the extension |
| **Installer** | WiX v4 / PowerShell | Packages all components into a single MSI, registers the Windows Service and Native Messaging Host |

---

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                         Browser (Chrome / Edge)                  │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                  BrowserExtension (MV3)                  │    │
│  │                                                          │    │
│  │  background.ts ◄──── Native Messaging ────────────────┐ │    │
│  │      │                (stdio JSON)                     │ │    │
│  │      │ chrome.tabs.sendMessage()                       │ │    │
│  │      ▼                                                 │ │    │
│  │  content.ts ◄──── window.postMessage ──── inject.ts   │ │    │
│  │  (overlay UI)      (getDisplayMedia wrap)              │ │    │
│  └─────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────┬───────────┘
                                                       │ Chrome Native Messaging
                                                       │ (stdin/stdout JSON frames)
                                          ┌────────────▼────────────────┐
                                          │     NativeMessagingHost.exe  │
                                          │                              │
                                          │  ScreenShareDetector         │
                                          │   ├─ Window class poll       │
                                          │   └─ Named pipe (DLPHook)    │
                                          │                              │
                                          │  ScreenshotDetector          │
                                          │   ├─ WH_KEYBOARD_LL hook     │
                                          │   ├─ WM_CLIPBOARDUPDATE      │
                                          │   └─ Process watcher         │
                                          └──────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│                      Windows OS (System Level)                   │
│                                                                  │
│  ┌───────────────────┐      Injects DLPHook.dll                  │
│  │  DLPInjector.exe  │ ──────────────────────────────────────┐   │
│  │  (Windows Service)│                                       │   │
│  └───────────────────┘                                       │   │
│                                                              ▼   │
│           ┌────────────────────────────────────────────────────┐ │
│           │   Target Processes (chrome.exe, Zoom.exe, etc.)    │ │
│           │                                                    │ │
│           │   DLPHook.dll (injected)                           │ │
│           │    ├─ ClipboardHook   → SetClipboardData /         │ │
│           │    │                    GetClipboardData           │ │
│           │    │                    OleSetClipboard /          │ │
│           │    │                    OleGetClipboard            │ │
│           │    ├─ FileUploadHook  → IFileOpenDialog::Show      │ │
│           │    │                    GetOpenFileNameW           │ │
│           │    │                    CreateFileW                │ │
│           │    └─ ScreenShareHook → IDXGIOutputDuplication     │ │
│           │                         ::AcquireNextFrame         │ │
│           │                       Named Pipe: DlpScreenShare   │ │
│           └────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

---

## Component Deep-Dives

### 1. BrowserExtension

A **Manifest V3** Chrome/Edge extension written in TypeScript and bundled with Webpack. It provides both the DLP enforcement UI inside the browser and the settings management interface.

#### Source Files

| File | Description |
|---|---|
| `src/background.ts` | Service Worker — manages the native host connection, tracks sharing state, broadcasts blur/unblur to content scripts |
| `src/content.ts` | Content Script — injects and manages the full-viewport overlay on protected pages |
| `src/inject.ts` | Main-World Script — wraps `navigator.mediaDevices.getDisplayMedia` to intercept browser-based screen shares |
| `src/popup.ts` | Popup UI — lets users view share status, toggle the extension, and manage the protected domain list |
| `src/types.ts` | Shared TypeScript interfaces and default settings |
| `manifest.json` | Extension manifest (MV3, permissions, content scripts, icons) |

#### background.ts — Service Worker

The central coordinator. Its responsibilities:

- **Native Host Connection** — Connects to `com.dlp.screenshare` via `chrome.runtime.connectNative()`. Implements exponential backoff reconnection (starting at 3 s, capping at 30 s) so it survives host crashes.
- **Dual Sharing State** — Maintains two independent booleans:
  - `isSharingActive` — set by the native host when Zoom/Teams desktop apps are sharing.
  - `isBrowserSharingActive` — set by `inject.ts` when `getDisplayMedia` is granted in any tab.
  - The overlay is shown when **either** is true and hidden only when **both** are false.
- **Tab Broadcasting** — On share state change, queries all open tabs and sends `blur`/`unblur` messages to those whose URL matches a protected domain. Supports wildcard domains (e.g. `*.github.com`).
- **Screenshot Forwarding** — Relays `screenshot-flash` messages (with `active: true/false`) from the native host to sensitive tabs.
- **Navigation Listener** — Listens for `chrome.tabs.onUpdated` to blur tabs that navigate to a sensitive page while sharing is already active.
- **Settings Persistence** — Reads/writes `DlpSettings` to `chrome.storage.sync`, making the domain list available across devices.

#### content.ts — Content Script

Injected at `document_start` into every page. Manages the visual DLP enforcement overlay.

**Overlay Design:**
- Full-viewport `position: fixed` `<div>` with `z-index: 2147483647` (maximum possible).
- `rgba(15,15,15,0.97)` background with `backdrop-filter: blur(12px)` — page content is completely obscured.
- Cannot be dismissed by the user (intentional DLP enforcement).
- Appended to `<html>` (not `<body>`) to survive SPA route changes.
- A `MutationObserver` guard watches for DOM changes and immediately re-injects the overlay if a page script removes it.

**Two Independent Overlay States:**
1. `overlayActive` — Persistent. Driven by screen-share detection. Stays on until sharing stops.
2. `screenshotOverlayOn` — Held while any screenshot process is running. Hidden when the process exits.

**Screenshot Fallback:** A `keydown` listener on `PrintScreen` triggers a 3-second timed overlay flash when the native host is not running.

**Browser Share Bridge:** Listens for `window.postMessage` events from `inject.ts` (verified by `source === 'dlp-inject'` and `e.source === window`) and forwards them to `background.ts` via `chrome.runtime.sendMessage`.

#### inject.ts — Main-World Script

Runs in `"world": "MAIN"` so it has direct access to the page's real `navigator.mediaDevices` object. It wraps `getDisplayMedia` before any meeting platform code loads.

- Maintains an `activeShareCount` to handle the case where a tab calls `getDisplayMedia` more than once (e.g., a restarted share).
- Posts `DLP_SHARE_STARTED` when the first stream is granted.
- Posts `DLP_SHARE_STOPPED` when the count returns to zero (all video tracks ended or `stream inactive`).
- If the user cancels the picker (`NotAllowedError`), no message is sent — no overlay appears.
- Preserves `getDisplayMedia.name` and `length` for compatibility with meeting platform code that inspects these properties.

#### popup.ts — Settings Popup

- Displays the current combined share detection state (live).
- Allows toggling the extension on/off.
- Allows adding/removing protected domains. Supports pasting full URLs (strips protocol and path automatically).
- Persists settings via `background.ts` → `chrome.storage.sync`.

#### types.ts — Shared Types

Defines the message contracts between all extension scripts:

```typescript
// Native Host → Background
NativeMessage: { type: 'screenshare' | 'screenshot' | 'pong'; active?: boolean }

// Background → Content Script
ContentMessage: { action: 'blur' | 'unblur' | 'screenshot-flash'; active: boolean }

// Settings object stored in chrome.storage.sync
DlpSettings: { blockedDomains: string[]; enabled: boolean }
```

---

### 2. DLPHook

A C++ Win32 DLL that is injected into target processes by `DLPInjector`. It uses [MinHook](https://github.com/TsudaKageyu/minhook) to patch Windows API function pointers at the machine-code level.

#### Entry Point — dllmain.cpp

On `DLL_PROCESS_ATTACH`, MinHook is initialized and three hook groups are installed in sequence:

```
MH_Initialize()
ClipboardHook_Install()
FileUploadHook_Install()
ScreenShareHook_Install()
MH_EnableHook(MH_ALL_HOOKS)
```

On `DLL_PROCESS_DETACH`, all hooks are removed and MinHook is uninitialized cleanly.

#### ClipboardHook.cpp

Hooks four Win32/OLE APIs to intercept all clipboard read and write operations:

| Hooked API | DLL | Direction | Action |
|---|---|---|---|
| `SetClipboardData` | user32.dll | Copy (write) | Scan text before it reaches the clipboard — block if sensitive |
| `GetClipboardData` | user32.dll | Paste (read) | Scan text being read from clipboard — block paste if sensitive |
| `OleSetClipboard` | ole32.dll | Copy via OLE | Scan Unicode text from `IDataObject` — return `E_ACCESSDENIED` if sensitive |
| `OleGetClipboard` | ole32.dll | Paste via OLE | Scan Unicode text from `IDataObject` — `Release()` the object and return `E_ACCESSDENIED` if sensitive |

**Alert Deduplication:** A 1-second cooldown (`NOTIFY_COOLDOWN_MS`) suppresses alert storms from applications (such as Adobe Acrobat) that call multiple clipboard APIs for a single logical copy action.

**Alert Format:**
- Single match: `"Copy blocked: Payment card data (PCI) detected."`
- Multiple matches: `"Copy blocked: Multiple sensitive data types detected: • Credit Card Number • Social Security Number (SSN)"`

#### FileUploadHook.cpp

Hooks three separate APIs to catch file uploads at different interception points:

**Hook 1 — `IFileOpenDialog::Show` (COM vtable, deferred)**
The primary interception point. Fires a background thread 200 ms after injection to install a COM vtable patch on `IFileOpenDialog::Show` (vtable index 3). When the user confirms a file selection in the Vista-style file picker:
- Intercepts single and multi-file selections.
- Scans each file for sensitive content.
- Returns `HRESULT_FROM_WIN32(ERROR_CANCELLED)` if blocked — the browser sees a user cancellation and never renders the upload spinner.

**Hook 2 — `GetOpenFileNameW` (comdlg32.dll)**
Handles the legacy `OPENFILENAMEW` dialog. Correctly handles both single-file and multi-file selection (`OFN_ALLOWMULTISELECT`) with proper NUL-separated filename parsing. Returns `FALSE` with `SetLastError(0)` to simulate user cancellation.

**Hook 3 — `CreateFileW` (kernel32.dll)**
A last-resort backstop for drag-and-drop and programmatic file opens. Applies a **dual policy**:
- **Viewer processes** (Acrobat, AcroRd32, Foxit, SumatraPDF, Evince) — sensitive file detected but the open is **allowed** so the document can be rendered.
- **Uploader/browser processes** (Chrome, Edge, Slack, etc.) — returns `INVALID_HANDLE_VALUE` with `ERROR_ACCESS_DENIED`.

**File Scanning:**
- Scans up to 50 MB per file.
- Supported extensions: `.pdf`, `.txt`, `.csv`, `.doc`, `.docx`, `.xls`, `.xlsx`, `.rtf`, `.html`, `.htm`, `.xml`, `.json`, `.log`, `.md`.
- System paths (`AppData`, `Program Files`, `Windows`, `Temp`, `node_modules`, etc.) are excluded to reduce noise.
- PDF files are detected by their magic bytes and text is extracted via `PdfTextExtractor` before scanning.

#### ScreenShareHook.cpp

Detects active screen capture by hooking the **DXGI Desktop Duplication API** at the COM vtable level — a precise, per-frame signal that is only active during real GPU-level screen capture.

**Why DXGI?**
Modern Zoom and Teams use `IDXGIOutputDuplication::AcquireNextFrame` (vtable index 8) in a tight loop to pull GPU frames for encoding. Hooking this gives a definitive signal with zero false positives from unrelated operations like window repaints (unlike hooking `BitBlt`/`StretchBlt`).

**Vtable Patch Process:**
1. Create a temporary `ID3D11Device` (hardware, falling back to WARP).
2. Walk: `IDXGIDevice` → `IDXGIAdapter` → `IDXGIOutput1`.
3. Call `DuplicateOutput()` to obtain an `IDXGIOutputDuplication` instance.
4. Read its vtable and use MinHook to patch slot 8 (`AcquireNextFrame`).
5. Release the temporary duplicator — the patch persists in all instances.

**Inactivity Watchdog:**
Since `AcquireNextFrame` returns `DXGI_ERROR_WAIT_TIMEOUT` normally during an active share (no new frame), sharing "stopped" is not detected by a failed call. Instead, a watchdog thread clears the sharing flag if no **successful** frame acquisition has been seen for 6 seconds (`INACTIVITY_TIMEOUT_SEC`).

**Named Pipe Notification:**
State transitions (`SHARING=1\n`, `SHARING=0\n`) are written to the named pipe `\\.\pipe\DlpScreenShare`, which is read by the `NativeMessagingHost`'s `ScreenShareDetector`.

---

### 3. DLPInjector

A C++ Win32 executable that runs as a Windows Service and continuously monitors the system for target processes, injecting `DLPHook.dll` into each one it finds.

#### Target Processes

The injection engine targets these processes by default (`InjectionEngine.cpp`):

```
Slack.exe, chrome.exe, msedge.exe, notepad.exe,
Acrobat.exe, AcroRd32.exe, Zoom.exe, ms-teams.exe, Teams.exe
```

#### Injection Mechanism

Classic `CreateRemoteThread` + `LoadLibraryA` injection:
1. `OpenProcess(PROCESS_ALL_ACCESS, ...)` to get a handle.
2. `VirtualAllocEx` to allocate memory in the target process.
3. `WriteProcessMemory` to write the DLL path string.
4. `CreateRemoteThread` targeting `LoadLibraryA` with the remote path as the argument.
5. `WaitForSingleObject` (2 s timeout) for the thread to complete.

#### Scan Loop

- Runs every **3 seconds** (`kScanIntervalMs`).
- Maintains a set of already-injected PIDs to avoid double-injection.
- Every 10 scan cycles (`kPruneCycleCount`), prunes PIDs of processes that have exited — preventing false "already injected" matches if the OS reuses a PID.
- Resolves `DLPHook.dll` relative to its own executable's directory at startup.

#### Windows Service Lifecycle

Registered as an **auto-start** service under the `LocalSystem` account (`kServiceName = L"DlpService"`). Responds to `SERVICE_CONTROL_STOP`. Requests `SeDebugPrivilege` on startup to allow injection into processes owned by other users.

#### CLI Usage

```
DlpInjector.exe --install      # Install and start the Windows service
DlpInjector.exe --uninstall    # Stop and remove the Windows service
DlpInjector.exe --console      # Run in console mode for debugging (Ctrl+C to stop)
DlpInjector.exe                # Called by SCM when running as a service
```

---

### 4. NativeMessagingHost

A C++ Win32 executable that acts as the bridge between the browser extension and the OS. The browser extension spawns it automatically via the Chrome/Edge **Native Messaging** protocol. It communicates exclusively via stdin/stdout using 4-byte length-prefixed JSON frames (binary mode).

#### JSON Message Protocol

```jsonc
// NativeMessagingHost → Extension
{ "type": "screenshare", "active": true  }   // Desktop share started
{ "type": "screenshare", "active": false }   // Desktop share stopped
{ "type": "screenshot",  "active": true  }   // Screenshot attempt detected
{ "type": "screenshot",  "active": false }   // Screenshot process closed
{ "type": "pong" }                           // Response to ping from extension

// Extension → NativeMessagingHost
{ "type": "ping" }                           // Keepalive check
```

#### ScreenShareDetector.cpp

Uses two independent detection methods. Either source asserting `true` is sufficient; both must independently clear before sharing is considered stopped.

**Method 1 — Window Class Poll (1 s interval)**
Calls `EnumWindows` only when a target process (`Zoom.exe`, `CptHost.exe`, `ms-teams.exe`, `Teams.exe`, `slack.exe`) is running. Checks specific window classes identified via live enumeration testing:

*Tier 1 — Visible only during active share (class exists in both states, visibility differs):*
- `sharing frame` (CptHost.exe) — Zoom's screen-capture subprocess window.
- `ZPFloatControlPanelMgrClass` (Zoom.exe) — Meeting control panel manager.
- `ZPFloatToolbarClass` (Zoom.exe) — "Screen sharing meeting controls" floating toolbar.
- `SingleWindowBorderClass` (slack.exe) — Slack's border overlay (process ownership verified).

*Tier 2 — Windows that only exist during active share:*
- `ZPAnnotateEntryPointClass` — Annotation entry point.
- `ZoomAnnoWindowWndClass` — Annotation overlay window.
- `MSTeamsSharing` — Teams transparent sharing overlay.
- `MSTeamsRdpWindowClass` — Teams RDP sharing window.

**Method 2 — Named Pipe Reader**
Reads `SHARING=1\n` / `SHARING=0\n` signals written by `ScreenShareHook.cpp` inside the injected processes via `\\.\pipe\DlpScreenShare`.

Applies a **2-second confirmation delay** (`PIPE_CONFIRM_MS`) before asserting `true` — prevents false positives from Zoom/Teams briefly calling `AcquireNextFrame` during internal video renderer initialization unrelated to screen sharing.

#### ScreenshotDetector.cpp

Three independent detection mechanisms running concurrently:

**Detection 1 — Low-Level Keyboard Hook (`WH_KEYBOARD_LL`)**
Installed system-wide via `SetWindowsHookExW`. Fires **before** the OS acts on the key:
- `VK_SNAPSHOT` (PrintScreen, Alt+PrintScreen, Ctrl+PrintScreen) → immediate notify.
- `Win+Shift+S` → fires before `ScreenClippingHost.exe` is even launched.
- Runs its own message loop thread to service the hook.

**Detection 2 — Clipboard Image Listener (`WM_CLIPBOARDUPDATE`)**
A hidden message-only window (`HWND_MESSAGE`) with `AddClipboardFormatListener`. Fires when any process writes `CF_BITMAP`, `CF_DIB`, or `CF_DIBV5` to the clipboard — covers cases where PrintScreen goes straight to the clipboard without a process launch.

**Detection 3 — Process Existence Watcher (200 ms poll)**
Polls for running screenshot tool processes using `CreateToolhelp32Snapshot`:
- `SnippingTool.exe` — Classic Snipping Tool & Windows 11 integrated tool.
- `ScreenClippingHost.exe` — Win+Shift+S snip overlay (Windows 10/11).
- `ScreenSketch.exe` — Snip & Sketch (older Windows builds).
- `ShareX.exe` — ShareX.
- `Greenshot.exe` — Greenshot.

Holds `g_processActive = true` for the **full process lifetime** — the overlay stays up while the tool is open, not just for a brief flash.

**Keypress Watchdog:**
Auto-clears the keypress signal after 3 seconds (`KEYPRESS_CLEAR_MS`) if no screenshot process is detected (handles the plain PrintScreen-to-clipboard case where no long-lived process exists).

**Notify Callback:**
All three detection methods call `NotifyIfChanged()` immediately on every state transition. The combined `IsActive()` state is pushed to the browser extension with zero poll delay.

#### RegistrySetup.cpp

Handles registration of the Native Messaging Host for both Chrome and Edge under `HKCU`:

- Writes the JSON manifest to `%LOCALAPPDATA%\DlpAgent\com.dlp.screenshare.json`.
- Registers the manifest path under:
  - `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.dlp.screenshare`
  - `HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.dlp.screenshare`
- `RegistrySetup_EnsureRegistered()` is called automatically on each startup — self-heals if the registry was deleted.
- `--register [extension-id]` preserves the extension ID from an existing manifest if no new ID is supplied.

```
NativeMessagingHost.exe --register <extension-id>   # Register for Chrome + Edge
NativeMessagingHost.exe --unregister                # Remove registry keys + manifest
```

---

### 5. Installer

A **WiX Toolset v4** project that packages all compiled artifacts into a single MSI. A PowerShell script (`Build-Installer.ps1`) automates the full build pipeline.

#### What Gets Installed

| File | Destination |
|---|---|
| `DlpInjector.exe` | `%ProgramFiles%\DlpAgent\` |
| `DLPHook.dll` | `%ProgramFiles%\DlpAgent\` |
| `NativeMessagingHost.exe` | `%ProgramFiles%\DlpAgent\` |
| `com.dlp.screenshare.json` | `%ProgramFiles%\DlpAgent\` |

#### What Gets Configured

- Registers `DlpService` as an auto-start Windows Service (LocalSystem account).
- Configures service recovery: restart on 1st, 2nd, and 3rd failure (60 s delay, reset after 1 day).
- Writes Chrome NM host registry key: `HKLM\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.dlp.screenshare`
- Writes Edge NM host registry key: `HKLM\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.dlp.screenshare`
- MajorUpgrade element handles silent removal of previous versions before reinstalling.

#### Build Script — Build-Installer.ps1

```powershell
# Build with default Release configuration
.\Installer\Build-Installer.ps1

# Build Debug configuration
.\Installer\Build-Installer.ps1 -Configuration Debug
```

The script validates that `DlpInjector.exe` and `DLPHook.dll` exist before attempting to build. Output: `Installer\bin\Release\DlpAgent.msi`.

---

## Data Classification Engine

The `DlpCommon.cpp` / `DlpCommon.h` module implements a **multi-category sensitive data scanner** used by both `ClipboardHook` and `FileUploadHook`.

### Data Categories

| Category | Bitmask | What It Detects |
|---|---|---|
| `PCI` | `1 << 0` | Payment card numbers, CVV codes, card expiry dates |
| `PII` | `1 << 1` | Social Security Numbers (SSN), passport numbers, addresses |
| `PHI` | `1 << 2` | Patient IDs, medical record numbers, health insurance IDs, diagnoses |
| `Financial` | `1 << 3` | Bank routing numbers, account numbers, EIN, ITIN, tax data |

### Scanning

`ScanText()` is overloaded for both `std::string` (ANSI/UTF-8) and `std::wstring` (Unicode). It:
- Accepts an optional `DlpCategory` bitmask to restrict which categories are checked (defaults to `DlpCategory::All`).
- Returns a `std::vector<DlpMatch>` — at most one match per triggered category (highest-confidence pattern wins within each category).
- Results are used to build informative alert messages and determine whether to block the action.

---

## Detection Methods

### Screen Share Detection

The system uses a **defense-in-depth** approach with three complementary detection layers:

```
Layer 1 (DLPHook — in-process):
  IDXGIOutputDuplication::AcquireNextFrame vtable hook
  → Fires on every GPU frame capture
  → Named pipe signal: SHARING=1 / SHARING=0
  → 6s inactivity watchdog clears state

Layer 2 (NativeMessagingHost — out-of-process poll):
  EnumWindows for known sharing-indicator window classes
  → 1s poll interval
  → Only runs when Zoom/Teams/Slack process is alive

Layer 3 (BrowserExtension — in-browser):
  navigator.mediaDevices.getDisplayMedia wrapper
  → Covers Google Meet, Zoom Web, Teams Web, Webex
  → Zero-latency — fires on stream grant, not on poll
```

Any one of these layers asserting `true` is sufficient to trigger the content overlay. Clearing requires all active layers to return `false`.

### Screenshot Detection

Three concurrent, complementary mechanisms:

```
Mechanism 1: WH_KEYBOARD_LL keyboard hook
  → PrintScreen (all variants), Win+Shift+S
  → Fires BEFORE OS acts on the key
  → Zero latency to browser

Mechanism 2: WM_CLIPBOARDUPDATE clipboard listener
  → Fires when any image is written to clipboard
  → Covers plain PrintScreen → clipboard path

Mechanism 3: Screenshot process watcher (200ms poll)
  → SnippingTool.exe, ScreenClippingHost.exe, ScreenSketch.exe, ShareX.exe, Greenshot.exe
  → Holds overlay for full tool process lifetime
```

### Clipboard Interception

The clipboard hook intercepts at **four API levels**:

```
Win32:  SetClipboardData / GetClipboardData   (CF_TEXT, CF_OEMTEXT, CF_UNICODETEXT)
OLE:    OleSetClipboard / OleGetClipboard     (CF_UNICODETEXT via IDataObject)
```

All text is scanned by `ScanText()` before the operation completes. Sensitive content causes the API to return an error (`nullptr` for Win32, `E_ACCESSDENIED` for OLE) and a user-visible alert is shown.

### File Upload Interception

Three-layer defense covering all common upload paths:

```
Layer 1: IFileOpenDialog::Show (COM vtable)
  → Modern Vista+ file picker (used by all Chromium browsers)
  → Intercepts BEFORE browser renders upload UI
  → Returns ERROR_CANCELLED to cancel silently

Layer 2: GetOpenFileNameW (comdlg32.dll)
  → Legacy file picker
  → Handles single and multi-file selection

Layer 3: CreateFileW (kernel32.dll)
  → Last-resort backstop for drag-and-drop
  → Viewer policy: allow open (Acrobat, Foxit, etc.)
  → Uploader policy: block open (Chrome, Slack, etc.)
```

---

## Communication Flows

### Flow 1 — Desktop Screen Share (Zoom/Teams desktop app)

```
1. DLPHook.dll (in Zoom.exe):
   AcquireNextFrame succeeds → writes "SHARING=1\n" to \\.\pipe\DlpScreenShare

2. NativeMessagingHost:
   PipeThreadProc reads pipe → waits 2s confirmation → sets g_sharingPipe=true
   Main loop detects state change → writes {"type":"screenshare","active":true} to stdout

3. BrowserExtension background.ts:
   nativePort.onMessage → isSharingActive = true
   broadcastToSensitiveTabs(true) → sends {action:'blur',active:true} to all sensitive tabs

4. BrowserExtension content.ts:
   onMessage → showOverlay() → full-page DLP overlay appears
```

### Flow 2 — Browser Screen Share (Google Meet, Zoom Web)

```
1. inject.ts (in page JS world):
   getDisplayMedia() called → stream granted → onShareStarted()
   window.postMessage({type:'DLP_SHARE_STARTED', source:'dlp-inject'})

2. content.ts (isolated world):
   window.addEventListener('message') → e.source===window, e.data.source==='dlp-inject'
   chrome.runtime.sendMessage({action:'browserShareStarted'})

3. background.ts:
   onMessage → isBrowserSharingActive = true
   broadcastToSensitiveTabs(true)

4. content.ts:
   showOverlay()
```

### Flow 3 — Screenshot Attempt

```
1. NativeMessagingHost ScreenshotDetector:
   WH_KEYBOARD_LL: PrintScreen pressed → TriggerKeypress() → NotifyIfChanged()
   OR: ScreenClippingHost.exe spawned → g_processActive=true → NotifyIfChanged()
   g_notify(true) → NM_WriteMessage({"type":"screenshot","active":true})

2. background.ts:
   nativePort.onMessage → type==='screenshot', active===true
   broadcastScreenshotFlash(true)

3. content.ts:
   onMessage → action==='screenshot-flash', active===true
   showScreenshotFlash() — different overlay message: "Screenshot Blocked"

4. NativeMessagingHost (when process exits):
   g_processActive=false → NotifyIfChanged() → g_notify(false)
   NM_WriteMessage({"type":"screenshot","active":false})

5. content.ts:
   hideScreenshotFlash()
```

---

## Default Protected Domains

Out of the box, the following domains trigger the DLP overlay when screen sharing or a screenshot attempt is detected:

| Domain | Service |
|---|---|
| `mail.google.com` | Gmail |
| `github.com` | GitHub |
| `gitlab.com` | GitLab |
| `dev.azure.com` | Azure DevOps |
| `bitbucket.org` | Bitbucket |
| `outlook.live.com` | Outlook Web |
| `outlook.office.com` | Outlook / Microsoft 365 |
| `drive.google.com` | Google Drive |
| `docs.google.com` | Google Docs / Sheets / Slides |

Domains can be added or removed at any time via the extension popup. Wildcard prefixes such as `*.github.com` are supported.

---

## Prerequisites

### For Building

| Tool | Purpose | Minimum Version |
|---|---|---|
| **Visual Studio** | C++ components (DLPHook, DLPInjector, NativeMessagingHost) | 2019 or 2022 with "Desktop development with C++" workload |
| **Windows SDK** | Win32 API headers and libraries | 10.0.19041 or later |
| **Node.js** | BrowserExtension build toolchain | 18.x LTS or later |
| **npm** | Package manager for BrowserExtension | Bundled with Node.js |
| **.NET SDK** | Required by WiX v4 installer | 6.x or later |
| **WiX Toolset v4** | MSI installer generation | 4.x (auto-restored by `dotnet tool restore`) |

### For Running

| Requirement | Details |
|---|---|
| **Windows 10/11** | x64, required for DXGI Desktop Duplication |
| **Administrator rights** | Required for injector service installation and `SeDebugPrivilege` |
| **Chrome or Edge** | For the browser extension (Manifest V3) |
| **DirectX 11** | Required by `ScreenShareHook` (D3D11 device creation) |

---

## Building the Project

### Step 1 — Build C++ Components

Open each Visual Studio solution file and build for **x64 | Release**:

```
DLPHook\DLPHook.sln              → produces DLPHook\x64\Release\DLPHook.dll
DLPInjector\DLPInjector.sln      → produces DLPInjector\x64\Release\DlpInjector.exe
NativeMessagingHost\NativeMessagingHost.sln  → produces NativeMessagingHost\x64\Release\NativeMessagingHost.exe
```

**Important:** Build `DLPHook` first, as `DLPInjector` references `DLPHook.dll` at runtime.

All three projects require the MinHook library (included via NuGet in `packages.config`). Visual Studio restores it automatically on first build.

### Step 2 — Build the Browser Extension

```powershell
cd BrowserExtension
npm install
npm run build        # Production bundle → dist/
npm run dev          # Development watch mode (source maps, unminified)
```

Output files are written to `BrowserExtension/dist/`:
- `background.js`
- `content.js`
- `inject.js`
- `popup.js`

### Step 3 — Build the MSI Installer

After all three C++ components and the browser extension have been built:

```powershell
cd Installer
.\Build-Installer.ps1              # Release configuration
.\Build-Installer.ps1 -Configuration Debug  # Debug configuration
```

The script:
1. Verifies `.NET SDK` is installed.
2. Checks that `DlpInjector.exe` and `DLPHook.dll` exist.
3. Runs `dotnet tool restore` to install WiX if needed.
4. Runs `dotnet build -c Release` to produce the MSI.

Output: `Installer\bin\Release\DlpAgent.msi`

---

## Installation & Deployment

### Installing the MSI

```powershell
# Silent install
msiexec /i DlpAgent.msi /qn

# Silent install with verbose log
msiexec /i DlpAgent.msi /qn /l*v install.log

# Silent uninstall
msiexec /x DlpAgent.msi /qn
```

The MSI:
1. Copies `DlpInjector.exe`, `DLPHook.dll`, `NativeMessagingHost.exe`, and `com.dlp.screenshare.json` to `%ProgramFiles%\DlpAgent\`.
2. Registers and starts the `DlpService` Windows Service.
3. Writes the NM host registry keys for Chrome and Edge under `HKLM`.

### Loading the Browser Extension

1. Open Chrome and navigate to `chrome://extensions`.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked**.
4. Select the `BrowserExtension` folder (which contains `manifest.json` and the `dist/` and `public/` directories).
5. Note the **Extension ID** shown on the extension card.

For Edge: Navigate to `edge://extensions` and follow the same steps.

### Registering the Native Messaging Host

After loading the unpacked extension, register the NM host with the actual extension ID:

```powershell
# Replace <EXTENSION_ID> with the ID from chrome://extensions
"%ProgramFiles%\DlpAgent\NativeMessagingHost.exe" --register <EXTENSION_ID>
```

This writes the manifest to `%LOCALAPPDATA%\DlpAgent\com.dlp.screenshare.json` and updates the registry keys. The host auto-registers itself on startup if the registry key is missing, but the extension ID will be a placeholder (`REPLACE_WITH_YOUR_EXTENSION_ID`) until explicitly set.

**Note for production deployment:** Update `com.dlp.screenshare.json` with the published Chrome Web Store extension ID before distributing the MSI.

### Running the Injector as a Windows Service

The MSI handles service registration automatically. For manual management:

```powershell
# Install and start the service
DlpInjector.exe --install

# Stop and remove the service
DlpInjector.exe --uninstall

# Check service status
sc query DlpService

# Start/stop manually
sc start DlpService
sc stop DlpService
```

The service requires **Administrator** rights to install. It runs as `LocalSystem` and requests `SeDebugPrivilege` to inject into all user-space processes.

---

## Running in Debug / Console Mode

Each component supports debug output without full system deployment.

### DLPInjector — Console Mode

```powershell
# Run as Administrator
DlpInjector.exe --console
```

Prints injection activity to the console. Press `Ctrl+C` to stop. Useful for verifying that `DLPHook.dll` is being found and injected correctly.

### DLPHook — Debug Output

The DLL emits `OutputDebugStringA` messages for every hook event. View them with [DebugView](https://docs.microsoft.com/en-us/sysinternals/downloads/debugview) from Sysinternals:

```
[DLP] All hooks installed and enabled
[DLP] ClipboardHook installed — multi-category scanner active (PCI/PII/PHI/Financial)
[DLP] FileUploadHook installed — multi-category scanner active (PCI/PII/PHI/Financial)
[DLP] ScreenShareHook installed (DXGI AcquireNextFrame only)
[DLP] GetClipboardData called
[DLP] BLOCKED paste — sensitive data detected
[DLP] ScreenShare: sharing STARTED (DXGI)
[DLP] ScreenShare: sharing STOPPED (DXGI inactivity)
```

### NativeMessagingHost — Manual Test

The host reads 4-byte-length-prefixed JSON from stdin. A quick manual test:

```powershell
# Verify registration
"%ProgramFiles%\DlpAgent\NativeMessagingHost.exe" --register

# Unregister
"%ProgramFiles%\DlpAgent\NativeMessagingHost.exe" --unregister
```

### Browser Extension — DevTools

1. Go to `chrome://extensions`.
2. Click the **"Service Worker"** link under the DLP extension.
3. The DevTools console shows all `[DLP]` prefixed log messages from `background.ts`.

Content script logs appear in the DevTools console of the page where the content script is running.

---

## Extension Popup — Settings UI

Click the DLP Shield icon in the browser toolbar to open the settings popup.

| Section | Description |
|---|---|
| **Status indicator** | Green dot = no sharing detected. Red dot = screen sharing active. |
| **Enable toggle** | Globally enables or disables the extension without removing it. |
| **Protected domains** | List of hostnames that trigger the overlay. Supports wildcard prefix `*.domain.com`. |
| **Add domain** | Type a hostname or paste a full URL (protocol and path are stripped automatically). Press Enter or click Add. |
| **Remove domain** | Click the `×` button next to any domain. |
| **Save** | Persists the current settings to `chrome.storage.sync`. Changes take effect immediately and trigger re-broadcast of the current sharing state to all sensitive tabs. |

Settings are synced across devices if Chrome Sync is enabled.

---

## Project Structure

```
dlp-poc/
│
├── BrowserExtension/               # Chrome/Edge Manifest V3 extension
│   ├── src/
│   │   ├── background.ts           # Service Worker (native host, tab messaging)
│   │   ├── content.ts              # Content Script (DLP overlay UI)
│   │   ├── inject.ts               # Main-World Script (getDisplayMedia wrapper)
│   │   ├── popup.ts                # Settings popup logic
│   │   └── types.ts                # Shared TypeScript interfaces
│   ├── public/
│   │   ├── popup.html              # Popup HTML template
│   │   └── icons/                  # Extension icons (16, 48, 128px)
│   ├── dist/                       # Webpack build output (generated)
│   ├── manifest.json               # Extension manifest (MV3)
│   ├── package.json                # npm build scripts and devDependencies
│   ├── tsconfig.json               # TypeScript configuration
│   └── webpack.config.js           # Webpack bundler configuration
│
├── DLPHook/                        # C++ DLL — injected into target processes
│   ├── dllmain.cpp                 # DLL entry point — MinHook init/teardown
│   ├── ClipboardHook.cpp/h         # Win32/OLE clipboard API hooks
│   ├── FileUploadHook.cpp/h        # File dialog, legacy dialog, CreateFileW hooks
│   ├── ScreenShareHook.cpp/h       # DXGI AcquireNextFrame vtable hook
│   ├── DlpCommon.cpp/h             # Multi-category sensitive data scanner
│   ├── PdfTextExtractor.cpp/h      # PDF content extraction for scanning
│   ├── Inflate.cpp/h               # zlib inflate for compressed PDF streams
│   ├── DLPHook.sln                 # Visual Studio solution
│   └── DLPHook.vcxproj             # Visual Studio project (x64)
│
├── DLPInjector/                    # C++ Windows Service — DLL injector
│   ├── DLPInjector.cpp             # Entry point and console mode
│   ├── ServiceMain.cpp/h           # Windows Service lifecycle
│   ├── InjectionEngine.cpp/h       # CreateRemoteThread DLL injection loop
│   ├── Config.h                    # Service name constants
│   ├── Logger.cpp/h                # File/debug logging
│   └── DLPInjector.sln             # Visual Studio solution
│
├── NativeMessagingHost/            # C++ Native Messaging Host
│   ├── main.cpp                    # Entry point — message loop, CLI args
│   ├── ScreenShareDetector.cpp/h   # Dual-method share detection (poll + pipe)
│   ├── ScreenshotDetector.cpp/h    # Keyboard hook + clipboard + process watcher
│   ├── RegistrySetup.cpp/h         # Chrome/Edge NM host registry management
│   ├── JsonMessage.cpp/h           # Native Messaging frame read/write
│   ├── com.dlp.screenshare.json    # NM host manifest template
│   └── NativeMessagingHost.sln     # Visual Studio solution
│
├── Installer/                      # WiX v4 MSI installer
│   ├── Package.wxs                 # WiX package definition
│   ├── DlpAgent.wixproj            # WiX project file
│   ├── Build-Installer.ps1         # PowerShell build automation script
│   └── DlpAgent.sln                # Visual Studio solution
│
├── icon.png                        # Source icon (used to generate extension icons)
├── icon16.png                      # Extension icon 16×16
├── icon48.png                      # Extension icon 48×48
├── icon128.png                     # Extension icon 128×128
└── README.md                       # This file
```

---

## Key Design Decisions

| Decision | Rationale |
|---|---|
| **DXGI AcquireNextFrame hook (not BitBlt)** | `BitBlt`/`StretchBlt` fire on every window repaint, producing constant false positives. `AcquireNextFrame` is only called during real GPU-level screen capture. |
| **Dual sharing detection (hook + window poll)** | If the injected hook fails (Remote Desktop, headless VM, access denied), the window class poll still works. Defense in depth. |
| **Named pipe for hook → host communication** | Allows the hook DLL running inside a sandboxed browser renderer process to signal the NativeMessagingHost without shared memory or registry writes. |
| **2-second pipe confirmation delay** | Prevents false positives from Zoom/Teams briefly calling AcquireNextFrame during internal compositing unrelated to user-facing screen sharing. |
| **Overlay on `<html>` not `<body>`** | SPAs frequently replace `<body>` on navigation. Attaching to `documentElement` ensures the overlay survives route changes. |
| **MutationObserver guard on overlay** | Prevents a hostile or misbehaving page from silently removing the overlay div. The guard re-injects it within the same microtask. |
| **Main-world inject.ts for getDisplayMedia** | Content scripts run in an isolated world and cannot access the real `navigator.mediaDevices` before meeting platforms have wrapped it. Main-world injection gets there first. |
| **Viewer vs. uploader policy in FileUploadHook** | Blocking Acrobat from opening its own files would prevent legitimate document viewing. The policy split allows DLP for upload paths while preserving normal viewer operation. |
| **COM vtable patch for IFileOpenDialog** | The dialog hook intercepts before the browser renders the upload UI. The CreateFileW fallback fires too late — the upload spinner is already visible. |
| **`chrome.storage.sync` for settings** | Allows the protected domain list to be shared across the user's devices via Chrome Sync without a backend service. |

---

## Known Limitations & Future Work

**Current Limitations:**
- Injection requires `SeDebugPrivilege` (Administrator). Processes protected by PPL (Protected Process Light), such as anti-cheat software, cannot be injected.
- DXGI Desktop Duplication is unavailable in Remote Desktop (RDP) sessions and headless/virtual display environments. The window-class poll still works in these environments.
- The PDF text extractor handles standard compressed text streams but does not support encrypted or password-protected PDFs, nor PDF portfolios.
- The `getDisplayMedia` wrapper covers browser-based meeting platforms but does not cover native Windows display capture APIs (`CaptureService`, `Windows.Media.Capture`) used by some Electron apps.
- The extension ID must be manually set in the NM host manifest after loading the unpacked extension. The MSI installer uses a placeholder ID that must be replaced for production.
- Content scripts do not run in sandboxed iframes (`sandbox` attribute without `allow-scripts`).

**Potential Improvements:**
- Add a policy server integration for centralised domain list and rule management.
- Implement HTTPS communication with a cloud DLP policy engine for real-time sensitive data classification updates.
- Add per-user audit logging of blocked events to a central SIEM.
- Support macOS (separate implementation: `DYLD_INSERT_LIBRARIES` injection, `CGDisplayStream` API hook).
- Support print-to-file as an exfiltration vector.
- Add watermarking of sensitive pages when viewed to deter manual transcription.
- Replace the placeholder extension ID workflow with automatic ID discovery via the NM host protocol.

---

## Disclaimer

This project is a **Proof of Concept** intended for security research, education, and evaluation purposes only.

- It should **not** be deployed in a production environment without a thorough security review, stability testing under load, and compatibility validation across your target application versions.
- DLL injection and kernel-level API hooking are powerful and potentially destabilising techniques. Incorrectly applied hooks can cause crashes, data corruption, or system instability in target processes.
- Deployment of monitoring software on employee endpoints may be subject to local privacy laws, employment regulations, and corporate policy requirements. Ensure you have the appropriate legal basis before deploying.
- The `LocalSystem` service account used by `DLPInjector` has broad system privileges. Harden the installation directory with appropriate ACLs before production use to prevent DLL hijacking.
- The NM host and injector do not authenticate each other. A malicious local process could write to `\\.\pipe\DlpScreenShare` to trigger false positives or suppress true detections.
