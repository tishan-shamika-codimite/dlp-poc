Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public class WinEnum2 {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc proc, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr hWnd, EnumWindowsProc proc, IntPtr lParam);
    [DllImport("user32.dll")] public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
}
'@

Write-Host "=== Zoom-related processes ===" -ForegroundColor Cyan
$zoomProcs = Get-Process | Where-Object { $_.Name -imatch "zoom|cpt" }
$zoomProcs | Select-Object Name, Id | Format-Table -AutoSize

$zoomPids = $zoomProcs | Select-Object -ExpandProperty Id

Write-Host "=== ALL window classes from Zoom/CptHost processes ===" -ForegroundColor Cyan
Write-Host "(These are ALL classes, to find what is unique to sharing)" -ForegroundColor Yellow
Write-Host ""

[WinEnum2]::EnumWindows(
    [WinEnum2+EnumWindowsProc]{
        param([IntPtr]$hwnd, [IntPtr]$lp)
        $pid2 = [uint32]0
        [WinEnum2]::GetWindowThreadProcessId($hwnd, [ref]$pid2) | Out-Null
        if ($script:zoomPids -contains [int]$pid2) {
            $sb = New-Object System.Text.StringBuilder 512
            [WinEnum2]::GetClassName($hwnd, $sb, 512) | Out-Null
            $cls = $sb.ToString()
            $tbsb = New-Object System.Text.StringBuilder 256
            [WinEnum2]::GetWindowText($hwnd, $tbsb, 256) | Out-Null
            $title = $tbsb.ToString()
            $pname = try { (Get-Process -Id ([int]$pid2) -ErrorAction Stop).Name } catch { "?" }
            $vis = [WinEnum2]::IsWindowVisible($hwnd)
            Write-Host ("{0,-55} vis={1,-5} title='{2}' [PID={3}/{4}]" -f $cls, $vis, $title, $pid2, $pname)
        }
        return $true
    },
    [IntPtr]::Zero
)

Write-Host ""
Write-Host "=== Windows Graphics Capture: checking for active capture sessions ===" -ForegroundColor Cyan
# Check if any process has a handle to the DXGIOutputDuplication-related named objects
$captureRelated = Get-Process | Where-Object {
    try {
        $handles = $_ | Select-Object -ExpandProperty Modules -ErrorAction Stop
        $false
    } catch { $false }
}

# Alternative: check for known WGC/DXGI mutex/event names via handle enumeration
# We use a simpler proxy: check if dwm.exe has unusual CPU (it spikes during capture)
$dwm = Get-Process -Name "dwm" -ErrorAction SilentlyContinue
if ($dwm) {
    Write-Host ("dwm.exe CPU time: {0}" -f $dwm.TotalProcessorTime)
    Write-Host ("dwm.exe Working Set: {0} MB" -f [math]::Round($dwm.WorkingSet64/1MB, 1))
}

Write-Host ""
Write-Host "=== CptHost.exe window details ===" -ForegroundColor Cyan
$cptProc = Get-Process -Name "CptHost" -ErrorAction SilentlyContinue
if ($cptProc) {
    Write-Host "CptHost PID: $($cptProc.Id)"
    Write-Host "CptHost CPU: $($cptProc.TotalProcessorTime)"
    Write-Host "CptHost Threads: $($cptProc.Threads.Count)"
    [WinEnum2]::EnumWindows(
        [WinEnum2+EnumWindowsProc]{
            param([IntPtr]$hwnd, [IntPtr]$lp)
            $pid2 = [uint32]0
            [WinEnum2]::GetWindowThreadProcessId($hwnd, [ref]$pid2) | Out-Null
            if ([int]$pid2 -eq $script:cptProc.Id) {
                $sb = New-Object System.Text.StringBuilder 512
                [WinEnum2]::GetClassName($hwnd, $sb, 512) | Out-Null
                $cls = $sb.ToString()
                Write-Host "  CptHost window class: $cls"
            }
            return $true
        },
        [IntPtr]::Zero
    )
} else {
    Write-Host "CptHost.exe is NOT running"
}
