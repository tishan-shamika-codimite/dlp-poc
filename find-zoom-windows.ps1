Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public class WinEnum {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc proc, IntPtr lParam);
    [DllImport("user32.dll")] public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
}
'@

Write-Host "=== Zoom-related processes ===" -ForegroundColor Cyan
Get-Process | Where-Object { $_.Name -imatch "zoom" } | Select-Object Name, Id | Format-Table -AutoSize

Write-Host "=== Window classes matching ZP / Zoom / Share / Meeting / Screen ===" -ForegroundColor Cyan
[WinEnum]::EnumWindows(
    [WinEnum+EnumWindowsProc]{
        param([IntPtr]$hwnd, [IntPtr]$lp)
        $sb = New-Object System.Text.StringBuilder 512
        [WinEnum]::GetClassName($hwnd, $sb, 512) | Out-Null
        $cls = $sb.ToString()
        if ($cls -imatch "ZP|Zoom|Share|Meeting|Screen") {
            $pid2 = [uint32]0
            [WinEnum]::GetWindowThreadProcessId($hwnd, [ref]$pid2) | Out-Null
            $pname = try { (Get-Process -Id ([int]$pid2) -ErrorAction Stop).Name } catch { "?" }
            Write-Host ("{0,-50} [PID={1} / {2}]" -f $cls, $pid2, $pname)
        }
        return $true
    },
    [IntPtr]::Zero
)
