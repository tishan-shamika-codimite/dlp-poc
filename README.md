# DLP Agent — Browser Bridge

A Windows **Data Loss Prevention (DLP)** system that prevents sensitive data (credit card numbers) from being copied or pasted through browsers and other applications on domain-joined machines.

---

## Overview

The DLP Agent runs as a Windows Service on enterprise workstations. It continuously monitors target applications and injects a hook DLL that intercepts clipboard operations. When a user attempts to copy or paste data containing valid credit card numbers, the operation is silently blocked.

**Target applications:** Chrome, Edge, Slack

---

## Architecture

```
Active Directory GPO
        │
        ▼
Install-DlpService.ps1  (runs at machine startup as SYSTEM)
        │
        ▼
DlpInjector.exe          (Windows Service — monitors processes)
        │
        ▼
DLPHook.dll              (injected into target processes — hooks clipboard APIs)
```

### Components

| Component | Description |
|---|---|
| **DlpInjector.exe** | Windows Service that enumerates running processes every 3 seconds and injects the hook DLL into target applications via remote thread creation (`CreateRemoteThread` + `LoadLibraryA`). |
| **DLPHook.dll** | In-process DLL that uses [MinHook](https://github.com/TsudaKageworyu/minhook) to detour clipboard APIs. Scans clipboard content for credit card patterns and validates them with the Luhn algorithm. |
| **Deploy scripts** | PowerShell scripts for GPO-based installation and uninstallation across domain machines. |

---

## How It Works

### 1. DLL Injection

The service runs with `SeDebugPrivilege`, which allows it to inject across user sessions. For each target process it:

1. Opens the process with `PROCESS_ALL_ACCESS`
2. Allocates memory in the target process (`VirtualAllocEx`)
3. Writes the DLL path into that memory
4. Creates a remote thread that calls `LoadLibraryA` to load `DLPHook.dll`

### 2. API Hooking

Once loaded, `DLPHook.dll` hooks four clipboard functions using MinHook:

| Hooked API | Source DLL | Purpose |
|---|---|---|
| `GetClipboardData` | user32.dll | Intercepts paste (standard) |
| `SetClipboardData` | user32.dll | Intercepts copy (standard) |
| `OleGetClipboard` | ole32.dll | Intercepts paste (OLE/modern apps like Chrome) |
| `OleSetClipboard` | ole32.dll | Intercepts copy (OLE) |

### 3. Sensitive Data Detection

When a clipboard operation is intercepted, the hook:

1. Extracts text from the clipboard handle (supports `CF_TEXT`, `CF_OEMTEXT`, `CF_UNICODETEXT`)
2. Scans for sequences of 13–19 digits (with optional dashes/spaces)
3. Validates each match using the **Luhn algorithm** to confirm it is a real credit card number
4. If a valid card number is found, blocks the operation:
   - `GetClipboardData` → returns `NULL` (clipboard appears empty)
   - `SetClipboardData` → returns `FALSE` (copy fails silently)
   - OLE functions → return `E_ACCESSDENIED`

---

## Integration with Windows Active Directory

The DLP Agent is designed for centralized deployment and management through **Active Directory Group Policy Objects (GPO)**.

### Deployment via GPO Startup Script

1. An administrator places `DlpInjector.exe`, `DLPHook.dll`, and the install script on a **domain network share** (default: `\\DC-SERVER\DlpDeploy`).
2. A **Computer Startup Script GPO** is created and linked to the target Organizational Units (OUs).
3. When a domain-joined machine boots, Group Policy executes `Install-DlpService.ps1` under the **SYSTEM** account before any user logs on.

### What the Install Script Does

```
Machine boot
  → GPO evaluates computer OU membership in AD
    → Startup script runs as SYSTEM
      → Copies binaries from domain share to C:\Program Files\DlpAgent
        → Registers and starts DlpService (auto-start)
```

- **Version checking** — compares file timestamps; only updates if the network share has newer binaries.
- **Automatic updates** — on next reboot, the script detects newer files, stops the service, replaces binaries, and restarts.
- **Logging** — writes to `%SystemRoot%\Temp\DlpInstall.log`.

### AD Authentication

- The machine account authenticates to the domain share using its **Kerberos/NTLM** computer credentials — no user credentials are needed.
- NTFS and share permissions on `\\DC-SERVER\DlpDeploy` control which machines can pull the agent.
- The service runs as **LocalSystem**, which has the necessary privileges for cross-process DLL injection.

### Centralized Management

| Task | How |
|---|---|
| Deploy to new machines | Link the GPO to additional OUs |
| Update the agent | Replace binaries on the network share; machines pick up changes on next reboot |
| Remove the agent | Run `Uninstall-DlpService.ps1` via GPO or manually |
| Scope enforcement | Use AD security filtering or WMI filters on the GPO |

---

## Project Structure

```
Root/
├── DLPHook/                    # Hook DLL project
│   ├── dllmain.cpp             # Hook implementation & credit card detection
│   ├── framework.h             # Windows API includes
│   └── DLPHook.vcxproj         # Visual Studio project
│
├── DlpInjector/                # Windows Service project
│   ├── DlpInjector.cpp         # Entry point (service/console modes)
│   ├── ServiceMain.cpp/.h      # SCM integration & privilege management
│   ├── InjectionEngine.cpp/.h  # Process monitoring & DLL injection
│   ├── Logger.cpp/.h           # Windows Event Log wrapper
│   └── DlpInjector.sln         # Visual Studio solution
│
└── Deploy/                     # Deployment scripts
    ├── Install-DlpService.ps1  # GPO startup install/update script
    └── Uninstall-DlpService.ps1
```

---

## Building

**Requirements:**
- Visual Studio 2022 (v143 toolset)
- Windows SDK
- NuGet (MinHook 1.3.3 is restored automatically)

Open `DlpInjector/DlpInjector.sln` in Visual Studio and build for `Release | x64` (or `x86` depending on target machines).

---

## Service Usage

```powershell
# Install as a service
DlpInjector.exe --install

# Run in console/debug mode
DlpInjector.exe --console

# Check service status
DlpInjector.exe --status

# Uninstall the service
DlpInjector.exe --uninstall
```

Events are logged to the Windows **Application** event log under the source `DlpService`.