<#
.SYNOPSIS
    Build all DLP Screen Share Blocker components.

.DESCRIPTION
    Builds:
      1. DLPHook.dll          (Visual Studio — x64 Release)
      2. DlpInjector.exe      (Visual Studio — x64 Release)
      3. NativeMessagingHost.exe (Visual Studio — x64 Release)
      4. Browser Extension    (npm install + webpack build)

.EXAMPLE
    .\Build-All.ps1
    .\Build-All.ps1 -SkipCpp      # Only build the browser extension
    .\Build-All.ps1 -SkipExtension # Only build C++ components
#>

param(
    [switch]$SkipCpp,
    [switch]$SkipExtension
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSCommandPath -Parent

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "    OK: $msg"   -ForegroundColor Green }
function Write-Fail($msg) { Write-Host "    FAIL: $msg" -ForegroundColor Red; exit 1 }

# ── Locate MSBuild ────────────────────────────────────────────────────────────

function Find-MSBuild {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) { Write-Fail "vswhere.exe not found. Install Visual Studio 2022." }
    $vsPath = & $vswhere -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe |
              Select-Object -First 1
    if (-not $vsPath) { Write-Fail "MSBuild not found via vswhere." }
    return $vsPath
}

# ── Build C++ projects ────────────────────────────────────────────────────────

if (-not $SkipCpp) {
    Write-Step "Locating MSBuild..."
    $msbuild = Find-MSBuild
    Write-OK $msbuild

    $projects = @(
        @{ Name = "DLPHook";             Sln = "DLPHook\DLPHook.sln" },
        @{ Name = "DlpInjector";         Sln = "DlpInjector\DlpInjector.sln" },
        @{ Name = "NativeMessagingHost"; Sln = "NativeMessagingHost\NativeMessagingHost.sln" }
    )

    foreach ($p in $projects) {
        Write-Step "Building $($p.Name)..."
        $slnPath = Join-Path $root $p.Sln
        if (-not (Test-Path $slnPath)) { Write-Fail "Solution not found: $slnPath" }

        & $msbuild $slnPath /p:Configuration=Release /p:Platform=x64 /m /nologo /verbosity:minimal
        if ($LASTEXITCODE -ne 0) { Write-Fail "$($p.Name) build failed." }
        Write-OK "$($p.Name) built successfully."
    }
}

# ── Build Browser Extension ───────────────────────────────────────────────────

if (-not $SkipExtension) {
    Write-Step "Building browser extension..."
    $extDir = Join-Path $root "browser-extension"

    if (-not (Test-Path (Join-Path $extDir "node_modules"))) {
        Write-Step "Running npm install..."
        Push-Location $extDir
        npm install
        if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Fail "npm install failed." }
        Pop-Location
        Write-OK "npm install complete."
    }

    Push-Location $extDir
    npm run build
    $exitCode = $LASTEXITCODE
    Pop-Location

    if ($exitCode -ne 0) { Write-Fail "webpack build failed." }
    Write-OK "Browser extension built → browser-extension/dist/"
}

# ── Summary ───────────────────────────────────────────────────────────────────

Write-Host "`n" -NoNewline
Write-Host "============================================================" -ForegroundColor White
Write-Host "  Build complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor White
Write-Host @"

  Outputs:
    DLPHook\x64\Release\DLPHook.dll
    DlpInjector\x64\Release\DlpInjector.exe
    NativeMessagingHost\x64\Release\NativeMessagingHost.exe
    browser-extension\dist\  (background.js, content.js, popup.js)

  Next steps:
    1. Register the Native Messaging Host (run once per user):
       NativeMessagingHost.exe --register

    2. Load the browser extension (unpacked) in Chrome/Edge:
       chrome://extensions → Enable Developer Mode → Load unpacked
       Select: browser-extension\  (the folder containing manifest.json)

    3. Copy the Extension ID shown in chrome://extensions into:
       NativeMessagingHost\com.dlp.screenshare.json
       (replace REPLACE_WITH_YOUR_EXTENSION_ID)
       Then re-run:  NativeMessagingHost.exe --register

    4. Install the Windows Service:
       DlpInjector.exe --install
       net start DlpService

    5. Build the MSI (optional):
       cd Installer && dotnet build -c Release

"@ -ForegroundColor Gray
