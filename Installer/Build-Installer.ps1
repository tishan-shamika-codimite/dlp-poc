# Build-Installer.ps1
# Builds the DLP Agent MSI installer
# Requires: .NET SDK and WiX v4

param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

Write-Host "=== DLP Agent Installer Build ===" -ForegroundColor Cyan
Write-Host "Configuration: $Configuration"

# Check prerequisites
Write-Host "`nChecking prerequisites..." -ForegroundColor Yellow

# Check for .NET SDK
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    Write-Error ".NET SDK is not installed. Download from https://dotnet.microsoft.com/download"
    exit 1
}

$dotnetVersion = dotnet --version
Write-Host "  .NET SDK: $dotnetVersion"

# Verify build outputs exist
$injectorExe = Join-Path $RootDir "DlpInjector\x64\$Configuration\DlpInjector.exe"
$hookDll = Join-Path $RootDir "DLPHook\x64\$Configuration\DLPHook.dll"

if (-not (Test-Path $injectorExe)) {
    Write-Error "DlpInjector.exe not found at: $injectorExe`nBuild the DlpInjector project first in Visual Studio ($Configuration | x64)."
    exit 1
}

if (-not (Test-Path $hookDll)) {
    Write-Error "DLPHook.dll not found at: $hookDll`nBuild the DLPHook project first in Visual Studio ($Configuration | x64)."
    exit 1
}

Write-Host "  DlpInjector.exe: Found" -ForegroundColor Green
Write-Host "  DLPHook.dll: Found" -ForegroundColor Green

# Install WiX tool if needed (first run only)
Write-Host "`nRestoring WiX toolset..." -ForegroundColor Yellow
Push-Location $ScriptDir
try {
    dotnet tool restore 2>&1 | Out-Null

    # Build the MSI
    Write-Host "`nBuilding MSI installer..." -ForegroundColor Yellow
    dotnet build -c $Configuration

    if ($LASTEXITCODE -ne 0) {
        Write-Error "MSI build failed"
        exit 1
    }

    $msiPath = Join-Path $ScriptDir "bin\$Configuration\DlpAgent.msi"
    if (Test-Path $msiPath) {
        $msiSize = [math]::Round((Get-Item $msiPath).Length / 1MB, 2)
        Write-Host "`n=== Build Successful ===" -ForegroundColor Green
        Write-Host "MSI Location: $msiPath"
        Write-Host "Size: $msiSize MB"
        Write-Host "`nDeployment options:"
        Write-Host "  - Silent install: msiexec /i DlpAgent.msi /qn"
        Write-Host "  - With logging:   msiexec /i DlpAgent.msi /qn /l*v install.log"
        Write-Host "  - Uninstall:      msiexec /x DlpAgent.msi /qn"
    }
    else {
        Write-Error "MSI file not found at expected location: $msiPath"
        exit 1
    }
}
finally {
    Pop-Location
}
