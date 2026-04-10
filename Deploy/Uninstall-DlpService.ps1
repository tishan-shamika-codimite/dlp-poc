#Requires -RunAsAdministrator
# Uninstall-DlpService.ps1
# Removes the DLP Agent from a domain machine.

param(
    [string]$LocalInstallDir = "$env:ProgramFiles\DlpAgent"
)

$LogFile = "$env:SystemRoot\Temp\DlpUninstall.log"

function Write-Log {
    param([string]$Message)
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    Add-Content -Path $LogFile -Value $entry
}

Write-Log "=== DLP Agent removal started ==="

$localExe = Join-Path $LocalInstallDir "DlpInjector.exe"

# Stop and uninstall the service
if (Test-Path $localExe) {
    Stop-Service -Name "DlpService" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    & $localExe --uninstall 2>&1 | ForEach-Object { Write-Log $_ }
    Write-Log "Service uninstalled."
}

# Remove files
if (Test-Path $LocalInstallDir) {
    Remove-Item -Path $LocalInstallDir -Recurse -Force
    Write-Log "Install directory removed."
}

Write-Log "=== DLP Agent removal completed ==="
exit 0
