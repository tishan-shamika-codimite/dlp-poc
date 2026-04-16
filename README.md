# DLP Agent — Browser Bridge

A Windows **Data Loss Prevention (DLP)** system that prevents sensitive data (credit card numbers) from being copied or pasted through browsers and other applications on domain-joined machines.

---

## Overview

The DLP Agent runs as a Windows Service on enterprise workstations. It continuously monitors target applications and injects a hook DLL that intercepts clipboard operations. When a user attempts to copy or paste data containing valid credit card numbers, the operation is silently blocked.

**Target applications:** Chrome, Edge, Slack, Notepad, Adobe Acrobat

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
├── Deploy/                     # Deployment scripts
│   ├── Install-DlpService.ps1  # GPO startup install/update script
│   └── Uninstall-DlpService.ps1
│
└── Installer/                  # WiX v4 MSI installer project
    ├── Package.wxs             # WiX package definition
    ├── DlpAgent.wixproj        # MSI project file
    └── Build-Installer.ps1     # PowerShell build script
```

---

## MSI Installer

The `Installer/` directory contains a **WiX v4** project that builds an MSI for enterprise deployment.

### Prerequisites

- **.NET SDK 6.0+**
- **Visual Studio 2022** with C++ workload (build the DLP projects first)

### Building the MSI

**Option 1: PowerShell script (Recommended)**

```powershell
# Build both C++ projects in Visual Studio (Release | x64) first, then:
.\Installer\Build-Installer.ps1
```

**Option 2: Command line**

```bash
cd Installer
dotnet build -c Release
```

**Option 3: Visual Studio**

1. Open `Installer\DlpAgent.wixproj` in Visual Studio 2022
2. Ensure the WiX extension is installed
3. Build the project

The MSI is generated at `Installer\bin\x64\Release\DlpAgent.msi`.

### Installation Commands

```powershell
# Silent install
msiexec /i DlpAgent.msi /qn

# Silent install with logging
msiexec /i DlpAgent.msi /qn /l*v C:\Windows\Temp\DlpInstall.log

# Silent uninstall
msiexec /x DlpAgent.msi /qn

# Interactive install (for testing)
msiexec /i DlpAgent.msi
```

### Active Directory Deployment via MSI

An alternative to the startup-script approach is GPO **Software Installation**:

**1. Copy MSI to network share**

```powershell
New-SmbShare -Name "DlpDeploy" -Path "C:\DlpDeploy" -ReadAccess "Domain Computers"
Copy-Item ".\Installer\bin\x64\Release\DlpAgent.msi" "\\DC-SERVER\DlpDeploy\"
```

**2. Create GPO for software installation**

1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Create a new GPO or edit an existing one
3. Navigate to: `Computer Configuration > Policies > Software Settings > Software Installation`
4. Right-click → **New > Package**
5. Browse to `\\DC-SERVER\DlpDeploy\DlpAgent.msi`
6. Select **Assigned** deployment method
7. Link the GPO to target OUs

**3. Verify deployment**

```powershell
# Check service
Get-Service DlpService

# Check installed programs
Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*DLP*" }
```

### Customization

Before production deployment, update `Installer\Package.wxs`:

1. **Generate new GUIDs** — run `[guid]::NewGuid()` in PowerShell and replace `UpgradeCode` and component GUIDs.
2. **Update company info** — set `Manufacturer` and `ProductName`.
3. **Version management** — increment `ProductVersion` for each release; keep `UpgradeCode` the same to enable upgrades.

### Troubleshooting

```powershell
# MSI install fails — check log
msiexec /i DlpAgent.msi /l*v install.log
Get-Content install.log | Select-String -Pattern "error|failed" -Context 2

# Service doesn't start — check event log
Get-EventLog -LogName Application -Source DlpService -Newest 10

# Build fails — ensure C++ projects are built first
# DlpInjector.sln → Release | x64
# DLPHook.sln     → Release | x64
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

# Start the service (first time after install)
sc start DlpService

# Run in console/debug mode
DlpInjector.exe --console

# Check service status
DlpInjector.exe --status

# Uninstall the service
DlpInjector.exe --uninstall
```

Events are logged to the Windows **Application** event log under the source `DlpService`.