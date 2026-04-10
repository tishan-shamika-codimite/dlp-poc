#Requires -RunAsAdministrator
# Install-DlpService.ps1
# Deployed via Group Policy to install the DLP Agent on domain machines.
# This script runs as SYSTEM under a GPO Startup Script.

param(
    [string]$NetworkSource = "\\DC-SERVER\DlpDeploy",  # Change to your actual share path
    [string]$LocalInstallDir = "$env:ProgramFiles\DlpAgent"
)

$LogFile = "$env:SystemRoot\Temp\DlpInstall.log"

function Write-Log {
    param([string]$Message)
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    Add-Content -Path $LogFile -Value $entry
}

Write-Log "=== DLP Agent deployment started ==="
Write-Log "Source: $NetworkSource"
Write-Log "Target: $LocalInstallDir"

# ---------------------------------------------------
# 1. Check if already installed and up to date
# ---------------------------------------------------
$localExe = Join-Path $LocalInstallDir "DlpInjector.exe"
$remoteExe = Join-Path $NetworkSource "DlpInjector.exe"

if (Test-Path $localExe) {
    $localVersion = (Get-Item $localExe).LastWriteTime
    $remoteVersion = (Get-Item $remoteExe).LastWriteTime

    if ($localVersion -ge $remoteVersion) {
        # Check if service is running
        $svc = Get-Service -Name "DlpService" -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            Write-Log "DLP Agent is already installed and up to date. Skipping."
            exit 0
        }
    }
    else {
        Write-Log "Update detected. Stopping service for upgrade..."
        Stop-Service -Name "DlpService" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
}

# ---------------------------------------------------
# 2. Copy files from network share
# ---------------------------------------------------
try {
    if (-not (Test-Path $NetworkSource)) {
        Write-Log "ERROR: Network share not accessible: $NetworkSource"
        exit 1
    }

    if (-not (Test-Path $LocalInstallDir)) {
        New-Item -ItemType Directory -Path $LocalInstallDir -Force | Out-Null
        Write-Log "Created install directory: $LocalInstallDir"
    }

    Copy-Item -Path "$NetworkSource\DlpInjector.exe" -Destination $LocalInstallDir -Force
    Copy-Item -Path "$NetworkSource\DLPHook.dll" -Destination $LocalInstallDir -Force
    Write-Log "Files copied successfully."
}
catch {
    Write-Log "ERROR: Failed to copy files - $_"
    exit 1
}

# ---------------------------------------------------
# 3. Install and start the service
# ---------------------------------------------------
try {
    # Uninstall old service if it exists (handles path changes)
    $existingSvc = Get-Service -Name "DlpService" -ErrorAction SilentlyContinue
    if ($existingSvc) {
        Write-Log "Removing existing service..."
        & $localExe --uninstall 2>&1 | ForEach-Object { Write-Log $_ }
        Start-Sleep -Seconds 2
    }

    # Install the service
    Write-Log "Installing DLP service..."
    & $localExe --install 2>&1 | ForEach-Object { Write-Log $_ }

    # Start the service
    Start-Sleep -Seconds 1
    Start-Service -Name "DlpService"
    Write-Log "DLP service started."

    # Verify
    $svc = Get-Service -Name "DlpService" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Write-Log "SUCCESS: DLP Agent is running."
    }
    else {
        Write-Log "WARNING: Service installed but not running. Status: $($svc.Status)"
    }
}
catch {
    Write-Log "ERROR: Service installation failed - $_"
    exit 1
}

Write-Log "=== DLP Agent deployment completed ==="
exit 0
