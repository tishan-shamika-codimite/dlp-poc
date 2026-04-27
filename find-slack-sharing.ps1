# find-slack-sharing.ps1
#
# Diagnostic script to capture all Slack-related window and process state.
# Run this script TWICE and compare the output to identify windows/signals
# that are ONLY present when Slack is actively sharing a screen.
#
# Usage:
#   1. Open Slack. Do NOT start a screen share.
#      .\find-slack-sharing.ps1 | Tee-Object not-sharing.txt
#
#   2. Start a screen share in Slack (Huddle or call).
#      .\find-slack-sharing.ps1 | Tee-Object sharing.txt
#
#   3. Diff the two outputs:
#      Compare-Object (Get-Content not-sharing.txt) (Get-Content sharing.txt)
#      -- or --
#      diff not-sharing.txt sharing.txt   (if you have Unix diff available)
#
# What to look for in the diff:
#   - Window classes that appear ONLY in sharing.txt           → reliable Tier-2 signal
#   - Window classes where vis=True changes to vis=False/True  → reliable Tier-1 signal
#   - New processes (slack helper / renderer PIDs)             → process-spawn signal
# ---------------------------------------------------------------------------

Add-Type @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public class SlackWinEnum {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc proc, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr hWnd, EnumWindowsProc proc, IntPtr lParam);
    [DllImport("user32.dll")] public static extern int  GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern int  GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
    [DllImport("user32.dll")] public static extern IntPtr GetParent(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool IsZoomed(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern long GetWindowLong(IntPtr hWnd, int nIndex);
}
'@

$GWL_STYLE    = -16
$GWL_EXSTYLE  = -20
$WS_CHILD     = 0x40000000L

# ── Helper: resolve class + title + visibility for a given HWND ───────────────
function Get-WindowInfo($hwnd, $pid2) {
    $sbCls   = New-Object System.Text.StringBuilder 512
    $sbTitle = New-Object System.Text.StringBuilder 512
    [SlackWinEnum]::GetClassName($hwnd, $sbCls, 512)   | Out-Null
    [SlackWinEnum]::GetWindowText($hwnd, $sbTitle, 512) | Out-Null
    $pname = try { (Get-Process -Id ([int]$pid2) -ErrorAction Stop).Name } catch { '?' }
    [PSCustomObject]@{
        HWND    = ('0x{0:X8}' -f $hwnd.ToInt64())
        Class   = $sbCls.ToString()
        Title   = $sbTitle.ToString()
        Visible = [SlackWinEnum]::IsWindowVisible($hwnd)
        PID     = [int]$pid2
        Process = $pname
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Write-Host ''
Write-Host ('=' * 70) -ForegroundColor White
Write-Host "  SLACK SCREEN-SHARE DIAGNOSTIC  —  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host ('=' * 70) -ForegroundColor White

# ── Section 1: All Slack-related processes ────────────────────────────────────
Write-Host ''
Write-Host '=== Section 1: Slack-related processes ===' -ForegroundColor Cyan

$slackProcs = Get-Process | Where-Object { $_.Name -imatch 'slack' }
if (-not $slackProcs) {
    Write-Host 'No Slack processes found. Is Slack running?' -ForegroundColor Red
} else {
    $slackProcs |
        Select-Object Name, Id,
            @{N='CPU(s)';  E={ [math]::Round($_.TotalProcessorTime.TotalSeconds, 2) }},
            @{N='WS(MB)';  E={ [math]::Round($_.WorkingSet64 / 1MB, 1) }},
            @{N='Threads'; E={ $_.Threads.Count }},
            @{N='Title';   E={ $_.MainWindowTitle }} |
        Format-Table -AutoSize
}

$slackPids = $slackProcs | Select-Object -ExpandProperty Id

# ── Section 2: Top-level windows owned by any Slack PID ──────────────────────
Write-Host '=== Section 2: Top-level windows owned by slack.exe PIDs ===' -ForegroundColor Cyan
Write-Host '    Format: Class  vis=<T/F>  title="<title>"  [PID=<pid>/<name>]' -ForegroundColor DarkGray
Write-Host ''

$topLevelWindows = [System.Collections.Generic.List[object]]::new()

[SlackWinEnum]::EnumWindows(
    [SlackWinEnum+EnumWindowsProc]{
        param([IntPtr]$hwnd, [IntPtr]$lp)
        $pid2 = [uint32]0
        [SlackWinEnum]::GetWindowThreadProcessId($hwnd, [ref]$pid2) | Out-Null
        if ($script:slackPids -contains [int]$pid2) {
            $info = Get-WindowInfo $hwnd $pid2
            $script:topLevelWindows.Add($info)
            Write-Host ('{0,-55} vis={1,-5} title="{2}" [PID={3}/{4}]' -f
                $info.Class, $info.Visible, $info.Title, $info.PID, $info.Process)
        }
        return $true
    },
    [IntPtr]::Zero
) | Out-Null

Write-Host ''
Write-Host "  Total top-level Slack windows: $($topLevelWindows.Count)" -ForegroundColor DarkGray

# ── Section 3: Keyword-filtered system-wide window scan ──────────────────────
Write-Host ''
Write-Host '=== Section 3: System-wide windows with Slack/Share/Screen/Huddle/Call keywords ===' -ForegroundColor Cyan
Write-Host '    (Catches Slack helper processes not in the main process list)' -ForegroundColor DarkGray
Write-Host ''

[SlackWinEnum]::EnumWindows(
    [SlackWinEnum+EnumWindowsProc]{
        param([IntPtr]$hwnd, [IntPtr]$lp)
        $sbCls   = New-Object System.Text.StringBuilder 512
        $sbTitle = New-Object System.Text.StringBuilder 512
        [SlackWinEnum]::GetClassName($hwnd, $sbCls, 512)    | Out-Null
        [SlackWinEnum]::GetWindowText($hwnd, $sbTitle, 512) | Out-Null
        $cls   = $sbCls.ToString()
        $title = $sbTitle.ToString()

        # Match on class name OR window title
        if ($cls   -imatch 'slack|share|screen|huddle|screenshare' -or
            $title -imatch 'slack|screen share|sharing|huddle') {
            $pid2 = [uint32]0
            [SlackWinEnum]::GetWindowThreadProcessId($hwnd, [ref]$pid2) | Out-Null
            $pname = try { (Get-Process -Id ([int]$pid2) -ErrorAction Stop).Name } catch { '?' }
            $vis   = [SlackWinEnum]::IsWindowVisible($hwnd)
            Write-Host ('{0,-55} vis={1,-5} title="{2}" [PID={3}/{4}]' -f
                $cls, $vis, $title, $pid2, $pname)
        }
        return $true
    },
    [IntPtr]::Zero
) | Out-Null

# ── Section 4: Child window deep-scan on each top-level Slack window ──────────
Write-Host ''
Write-Host '=== Section 4: Child windows of top-level Slack windows (deep scan) ===' -ForegroundColor Cyan
Write-Host '    (Only windows with non-empty titles or unusual classes are shown)' -ForegroundColor DarkGray
Write-Host ''

# Re-collect HWNDs into a list we can iterate
$topHwnds = [System.Collections.Generic.List[IntPtr]]::new()

[SlackWinEnum]::EnumWindows(
    [SlackWinEnum+EnumWindowsProc]{
        param([IntPtr]$hwnd, [IntPtr]$lp)
        $pid2 = [uint32]0
        [SlackWinEnum]::GetWindowThreadProcessId($hwnd, [ref]$pid2) | Out-Null
        if ($script:slackPids -contains [int]$pid2) {
            $script:topHwnds.Add($hwnd)
        }
        return $true
    },
    [IntPtr]::Zero
) | Out-Null

foreach ($topHwnd in $topHwnds) {
    $sbParentCls   = New-Object System.Text.StringBuilder 512
    $sbParentTitle = New-Object System.Text.StringBuilder 512
    [SlackWinEnum]::GetClassName($topHwnd, $sbParentCls, 512)    | Out-Null
    [SlackWinEnum]::GetWindowText($topHwnd, $sbParentTitle, 512) | Out-Null
    $parentCls   = $sbParentCls.ToString()
    $parentTitle = $sbParentTitle.ToString()

    $childBuf = [System.Collections.Generic.List[string]]::new()

    [SlackWinEnum]::EnumChildWindows(
        $topHwnd,
        [SlackWinEnum+EnumWindowsProc]{
            param([IntPtr]$hwnd, [IntPtr]$lp)
            $sbCls   = New-Object System.Text.StringBuilder 512
            $sbTitle = New-Object System.Text.StringBuilder 512
            [SlackWinEnum]::GetClassName($hwnd, $sbCls, 512)    | Out-Null
            [SlackWinEnum]::GetWindowText($hwnd, $sbTitle, 512) | Out-Null
            $cls   = $sbCls.ToString()
            $title = $sbTitle.ToString()
            $vis   = [SlackWinEnum]::IsWindowVisible($hwnd)
            $pid2  = [uint32]0
            [SlackWinEnum]::GetWindowThreadProcessId($hwnd, [ref]$pid2) | Out-Null

            # Only record children that have a title OR a non-generic class
            if ($title -ne '' -or $cls -notmatch '^(#|Chrome_)') {
                $line = ('    CHILD  {0,-50} vis={1,-5} title="{2}" [PID={3}]' -f
                    $cls, $vis, $title, $pid2)
                $script:childBuf.Add($line)
            }
            return $true
        },
        [IntPtr]::Zero
    ) | Out-Null

    if ($childBuf.Count -gt 0) {
        Write-Host ("  PARENT [{0}]  class='{1}'  title='{2}'" -f
            ('0x{0:X8}' -f $topHwnd.ToInt64()), $parentCls, $parentTitle) -ForegroundColor Yellow
        $childBuf | ForEach-Object { Write-Host $_ }
        Write-Host ''
    }
}

# ── Section 5: Windows Graphics Capture — active capture sessions ─────────────
Write-Host '=== Section 5: Windows Graphics Capture / DWM activity ===' -ForegroundColor Cyan
Write-Host ''

$dwm = Get-Process -Name 'dwm' -ErrorAction SilentlyContinue
if ($dwm) {
    Write-Host ("  dwm.exe  CPU={0,8}s   WS={1,6} MB   Threads={2}" -f
        [math]::Round($dwm.TotalProcessorTime.TotalSeconds, 2),
        [math]::Round($dwm.WorkingSet64 / 1MB, 1),
        $dwm.Threads.Count)
} else {
    Write-Host '  dwm.exe not found' -ForegroundColor DarkGray
}

# WGC uses a per-session named kernel object under \Sessions\<n>\BaseNamedObjects\
# We can't easily enumerate kernel handles from PowerShell without a helper DLL,
# but we CAN check whether any slack.exe has a handle count spike (WGC opens
# several handles when a capture session is active).
Write-Host ''
Write-Host '  Slack process handle counts (spikes during WGC capture):' -ForegroundColor DarkGray
$slackProcs | Sort-Object HandleCount -Descending |
    Select-Object Name, Id,
        @{N='Handles';  E={ $_.HandleCount }},
        @{N='WS(MB)';   E={ [math]::Round($_.WorkingSet64 / 1MB, 1) }},
        @{N='CPU(s)';   E={ [math]::Round($_.TotalProcessorTime.TotalSeconds, 2) }} |
    Format-Table -AutoSize

# ── Section 6: Named pipe check ───────────────────────────────────────────────
Write-Host '=== Section 6: Named pipes potentially related to Slack screen share ===' -ForegroundColor Cyan
Write-Host ''

try {
    $pipes = [System.IO.Directory]::GetFiles('\\.\pipe\') |
        Where-Object { $_ -imatch 'slack|share|screen|capture|wgc|dlp' }
    if ($pipes) {
        $pipes | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-Host '  No matching named pipes found.' -ForegroundColor DarkGray
    }
} catch {
    Write-Host "  Could not enumerate named pipes: $_" -ForegroundColor DarkGray
}

# ── Section 7: Slack renderer / GPU processes (Electron sub-processes) ────────
Write-Host ''
Write-Host '=== Section 7: All slack.exe sub-processes with command-line type hints ===' -ForegroundColor Cyan
Write-Host '    (Look for --type=renderer, --type=gpu-process, utility processes)' -ForegroundColor DarkGray
Write-Host ''

$slackProcs | ForEach-Object {
    $proc = $_
    try {
        $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction Stop).CommandLine
        # Extract --type=<value> if present
        $typeMatch = [regex]::Match($cmdLine, '--type=(\S+)')
        $typeVal   = if ($typeMatch.Success) { $typeMatch.Groups[1].Value } else { '(main)' }
        Write-Host ('  PID={0,-7} type={1,-25} WS={2,6}MB  {3}' -f
            $proc.Id,
            $typeVal,
            [math]::Round($proc.WorkingSet64 / 1MB, 1),
            $proc.MainWindowTitle)
    } catch {
        Write-Host ('  PID={0,-7} (could not read command line)' -f $proc.Id)
    }
}

# ── Footer ────────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host ('=' * 70) -ForegroundColor White
Write-Host '  END OF REPORT' -ForegroundColor White
Write-Host ('=' * 70) -ForegroundColor White
Write-Host ''
Write-Host 'Next steps:' -ForegroundColor Green
Write-Host '  1. Run this script while NOT sharing  →  .\find-slack-sharing.ps1 | Tee-Object not-sharing.txt'
Write-Host '  2. Start a Slack screen share, then   →  .\find-slack-sharing.ps1 | Tee-Object sharing.txt'
Write-Host '  3. Compare:  Compare-Object (Get-Content not-sharing.txt) (Get-Content sharing.txt)'
Write-Host ''
