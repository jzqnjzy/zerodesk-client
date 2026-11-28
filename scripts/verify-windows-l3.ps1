# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 ZeroDesk Contributors
#
# ZeroDesk Windows L2/L3 Verification Harness (WIN-L3-01 .. WIN-L3-12)
#
# PROBE-NOT-PATCH (Strictly Read-Only & Idempotent):
#   - NEVER modifies HKLM registry, NEVER installs drivers/services, NEVER requests UAC elevation,
#     NEVER initiates network connections, and NEVER dumps process environment variables.
#   - All emitted JSON strings pass through Scrub-Text() to strip local user/host/repo paths,
#     and hardware adapter LUIDs are hashed to the first 8 lowercase hex chars of SHA-256.
#   - Anti-forgery redline: `-Mode ci` and CI runners (`CI=true|1`, `GITHUB_ACTIONS=true|1`) are
#     code-level forbidden from emitting status `PASS`.
#
# Exit Codes:
#   0  = CI mode with 0 FAIL | -DryRun on non-Windows | strict-l3 with 12/12 PASS
#   10 = strict-l3 mode with 0 FAIL and >=1 non-PASS item (e.g. L2_NATIVE_PASS / PENDING_PHYSICAL_L3)
#   20 = At least one item reported FAIL
#   30 = Script/runtime error, invalid arguments, or CI anti-forgery invariant violation
#   40 = Unsupported platform (non-Windows host without -DryRun)

[CmdletBinding()]
param(
    [string]$Mode = 'ci',
    [string]$Output = 'zerodesk-windows-l3-report.json',
    [string]$DiagBin = '',
    [string]$WatchdogBin = '',
    [switch]$DryRun,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Show-Usage {
    @"
Usage: verify-windows-l3.ps1 [-Mode ci|strict-l3] [-Output <path|->] [-DiagBin <path>] [-WatchdogBin <path>] [-DryRun] [-Help]

Options:
  -Mode <ci|strict-l3>  Verification mode (default: ci). CI mode and CI runners NEVER emit PASS.
                        Automated strict-l3 preserves L2_NATIVE_PASS on headless Win32 probes and
                        exits 10 whenever physical GPU/DXGI/MF items remain PENDING_PHYSICAL_L3
                        until verified on real NVIDIA/AMD/Intel Windows hardware.
  -Output <path|->      Output JSON report path (default: zerodesk-windows-l3-report.json; '-' = stdout).
  -DiagBin <path>       Optional path to zerodesk-win-diag.exe.
  -WatchdogBin <path>   Optional path to zerodesk-hid-watchdog.exe.
  -DryRun               Emit schema-valid SKIPPED_UNSUPPORTED_PLATFORM report on non-Windows hosts (exit 0).
  -Help                 Show this help message and exit 0.

Exit codes:
  0  = Pass / CI green (0 FAIL) / non-Windows -DryRun
  10 = strict-l3 incomplete (0 FAIL, <12 PASS)
  20 = Verification failure (>=1 FAIL)
  30 = Script error / invalid CLI argument / anti-forgery violation
  40 = Unsupported platform (non-Windows without -DryRun)
"@ | Write-Output
}

if ($Help) {
    Show-Usage
    exit 0
}

if ($Mode -ne 'ci' -and $Mode -ne 'strict-l3') {
    [Console]::Error.WriteLine("ERROR: invalid -Mode '$Mode' (expected 'ci' or 'strict-l3')")
    exit 30
}

$RepoRoot = ''
$StartedAtUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$CiEnvVal = if ($null -ne $env:CI) { $env:CI.Trim().ToLowerInvariant() } else { '' }
$GhEnvVal = if ($null -ne $env:GITHUB_ACTIONS) { $env:GITHUB_ACTIONS.Trim().ToLowerInvariant() } else { '' }
$IsCiRunner = ($CiEnvVal -eq 'true' -or $CiEnvVal -eq '1' -or $GhEnvVal -eq 'true' -or $GhEnvVal -eq '1')
$IsWindowsHost = ($env:OS -eq 'Windows_NT') -or ($PSVersionTable.Platform -eq 'Win32NT')

function Get-SafeProp {
    param(
        [object]$Obj,
        [string]$Name,
        [object]$Default = $null
    )
    if ($null -eq $Obj) {
        return $Default
    }
    $prop = $Obj.PSObject.Properties[$Name]
    if ($null -eq $prop) {
        return $Default
    }
    return $prop.Value
}

function Test-HasProp {
    param(
        [object]$Obj,
        [string]$Name
    )
    if ($null -eq $Obj) {
        return $false
    }
    return ($null -ne $Obj.PSObject.Properties[$Name])
}

function Get-ShortSha256 {
    param([string]$InputText)
    if ([string]::IsNullOrEmpty($InputText)) {
        return $null
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputText)
        $hash = $sha.ComputeHash($bytes)
        $hex = ([System.BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
        return $hex.Substring(0, 8)
    } finally {
        $sha.Dispose()
    }
}

function Scrub-Text {
    param([string]$Text)
    if ($null -eq $Text) {
        return ''
    }
    $s = $Text
    if (-not [string]::IsNullOrEmpty($RepoRoot)) {
        $s = [System.Text.RegularExpressions.Regex]::Replace(
            $s,
            '(?i)' + [System.Text.RegularExpressions.Regex]::Escape($RepoRoot),
            '<REPO>'
        )
        $repoSlash = $RepoRoot -replace '\\', '/'
        $s = [System.Text.RegularExpressions.Regex]::Replace(
            $s,
            '(?i)' + [System.Text.RegularExpressions.Regex]::Escape($repoSlash),
            '<REPO>'
        )
    }
    if (-not [string]::IsNullOrEmpty($env:USERPROFILE)) {
        $s = [System.Text.RegularExpressions.Regex]::Replace(
            $s,
            '(?i)' + [System.Text.RegularExpressions.Regex]::Escape($env:USERPROFILE),
            '<HOME>'
        )
        $profSlash = $env:USERPROFILE -replace '\\', '/'
        $s = [System.Text.RegularExpressions.Regex]::Replace(
            $s,
            '(?i)' + [System.Text.RegularExpressions.Regex]::Escape($profSlash),
            '<HOME>'
        )
    }
    if (-not [string]::IsNullOrEmpty($env:HOME)) {
        $s = [System.Text.RegularExpressions.Regex]::Replace(
            $s,
            '(?i)' + [System.Text.RegularExpressions.Regex]::Escape($env:HOME),
            '<HOME>'
        )
    }
    $macUsersPrefix = '/Us' + 'ers/'
    $s = [System.Text.RegularExpressions.Regex]::Replace($s, '(?i)[A-Z]:\\Users\\[^\\\s"''/]+', '<HOME>')
    $s = [System.Text.RegularExpressions.Regex]::Replace($s, ('(?i)[A-Z]:' + [System.Text.RegularExpressions.Regex]::Escape($macUsersPrefix) + '[^/\s"'']+'), '<HOME>')
    $s = [System.Text.RegularExpressions.Regex]::Replace($s, '(?i)/home/[^/\s"'']+', '<HOME>')
    $s = [System.Text.RegularExpressions.Regex]::Replace($s, ('(?i)' + [System.Text.RegularExpressions.Regex]::Escape($macUsersPrefix) + '[^/\s"'']+'), '<HOME>')
    if (-not [string]::IsNullOrEmpty($env:COMPUTERNAME)) {
        $s = [System.Text.RegularExpressions.Regex]::Replace(
            $s,
            '(?i)\b' + [System.Text.RegularExpressions.Regex]::Escape($env:COMPUTERNAME) + '\b',
            '<HOST>'
        )
    }
    if (-not [string]::IsNullOrEmpty($env:USERNAME)) {
        $s = [System.Text.RegularExpressions.Regex]::Replace(
            $s,
            '(?i)\b' + [System.Text.RegularExpressions.Regex]::Escape($env:USERNAME) + '\b',
            '<USER>'
        )
    }
    return $s
}

function Resolve-TargetBinary {
    param(
        [string]$ExplicitPath,
        [string]$BinaryName
    )
    if (-not [string]::IsNullOrEmpty($ExplicitPath)) {
        return $ExplicitPath
    }
    $roots = @()
    if (-not [string]::IsNullOrEmpty($env:CARGO_TARGET_DIR)) {
        $roots += $env:CARGO_TARGET_DIR
    }
    if (-not [string]::IsNullOrEmpty($env:RUNNER_TEMP)) {
        $roots += (Join-Path $env:RUNNER_TEMP 'target')
    }
    if (-not [string]::IsNullOrEmpty($RepoRoot)) {
        $roots += (Join-Path $RepoRoot 'libs\zerodesk_core\target')
        $roots += (Join-Path $RepoRoot 'target')
    }
    $relDirs = @(
        'release',
        'debug',
        'x86_64-pc-windows-msvc\release',
        'x86_64-pc-windows-msvc\debug'
    )
    foreach ($root in $roots) {
        foreach ($rel in $relDirs) {
            $cand = Join-Path (Join-Path $root $rel) $BinaryName
            if (Test-Path -LiteralPath $cand) {
                return $cand
            }
        }
    }
    return ''
}

$Checklist = @(
    @{ id = 'WIN-L3-01'; title = 'Single-Command Diagnostics (zerodesk-win-diag)'; requires_hardware = $true;  requires_elevation = $false },
    @{ id = 'WIN-L3-02'; title = 'DXGI Multi-Monitor Capture, Cursor & Mode/DPI Switch'; requires_hardware = $true;  requires_elevation = $false },
    @{ id = 'WIN-L3-03'; title = 'UAC / Lock Screen Pause & Resume'; requires_hardware = $true;  requires_elevation = $true  },
    @{ id = 'WIN-L3-04'; title = 'Media Foundation HW MFT LUID-Bound D3D11 NV12 Zero-Copy + First-IDR Gate'; requires_hardware = $true;  requires_elevation = $false },
    @{ id = 'WIN-L3-05'; title = 'Mid-Stream HW MFT Failure -> Bounded Reinit -> Explicit Renegotiation'; requires_hardware = $true;  requires_elevation = $false },
    @{ id = 'WIN-L3-06'; title = 'WinHidKeyMap Physical Keyboard & Mouse Round-Trip'; requires_hardware = $true;  requires_elevation = $false },
    @{ id = 'WIN-L3-07'; title = 'Watchdog PROC_THREAD_ATTRIBUTE_HANDLE_LIST Grandchild-Spawn EOF'; requires_hardware = $false; requires_elevation = $false },
    @{ id = 'WIN-L3-08'; title = 'Watchdog WaitForMultipleObjects + GetProcessTimes PID-Reuse Guard + Single-Batch Torture Test'; requires_hardware = $false; requires_elevation = $false },
    @{ id = 'WIN-L3-09'; title = 'Watchdog Heartbeat-Timeout Release on Frozen Host'; requires_hardware = $false; requires_elevation = $false },
    @{ id = 'WIN-L3-10'; title = 'OpenInputDesktop / SetThreadDesktop & UIPI Elevated-Window Negative Test'; requires_hardware = $true;  requires_elevation = $true  },
    @{ id = 'WIN-L3-11'; title = 'Cross-OS E2E Session'; requires_hardware = $true;  requires_elevation = $false },
    @{ id = 'WIN-L3-12'; title = '30-Minute 1080p60 Hardware Soak Test'; requires_hardware = $true;  requires_elevation = $false }
)

function New-ReportItem {
    param(
        [hashtable]$Spec,
        [string]$Status,
        [string]$Evidence,
        [int]$DurationMs,
        [string]$HardwareFingerprint = $null
    )
    $validStatuses = @(
        'PASS',
        'FAIL',
        'L2_NATIVE_PASS',
        'PENDING_PHYSICAL_L3',
        'SKIPPED_NO_HARDWARE',
        'SKIPPED_UNSUPPORTED_PLATFORM'
    )
    if ($validStatuses -notcontains $Status) {
        throw "Invalid status '$Status' for $($Spec.id)"
    }
    if (($Mode -eq 'ci' -or $IsCiRunner) -and $Status -eq 'PASS') {
        throw "ANTI-FORGERY VIOLATION: ci mode / CI runner forbids emitting status PASS (item=$($Spec.id))"
    }
    if ($Status -eq 'PASS' -and ([string]::IsNullOrEmpty($HardwareFingerprint) -or $HardwareFingerprint -notmatch '^[0-9a-f]{8}$')) {
        throw "ANTI-FORGERY VIOLATION: status PASS requires an 8-hex-char hardware_fingerprint (item=$($Spec.id))"
    }
    $obj = [ordered]@{
        id                 = $Spec.id
        title              = $Spec.title
        status             = $Status
        evidence           = (Scrub-Text $Evidence)
        duration_ms        = [Math]::Max(0, [int]$DurationMs)
        requires_hardware  = [bool]$Spec.requires_hardware
        requires_elevation = [bool]$Spec.requires_elevation
    }
    if (-not [string]::IsNullOrEmpty($HardwareFingerprint)) {
        $obj['hardware_fingerprint'] = $HardwareFingerprint
    }
    return $obj
}

function Write-ReportAtomic {
    param(
        [System.Collections.IDictionary]$ReportObj,
        [string]$TargetPath
    )
    # Final anti-forgery gate prior to emission
    if ($ReportObj['mode'] -eq 'ci' -or $ReportObj['ci_runner']) {
        if ($ReportObj['summary']['pass'] -ne 0) {
            throw "ANTI-FORGERY VIOLATION: CI report summary.pass must be 0"
        }
        foreach ($it in $ReportObj['items']) {
            if ($it['status'] -eq 'PASS') {
                throw "ANTI-FORGERY VIOLATION: CI report item $($it['id']) cannot have status PASS"
            }
        }
    }
    $json = $ReportObj | ConvertTo-Json -Depth 10
    if ($TargetPath -eq '-') {
        Write-Output $json
        return
    }
    $resolvedOut = $TargetPath
    if (-not [System.IO.Path]::IsPathRooted($resolvedOut)) {
        $resolvedOut = Join-Path (Get-Location).Path $resolvedOut
    }
    $parentDir = Split-Path -Parent $resolvedOut
    if (-not [string]::IsNullOrEmpty($parentDir) -and -not (Test-Path -LiteralPath $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }
    $tmpFile = Join-Path $parentDir ('.' + (Split-Path -Leaf $resolvedOut) + '.tmp.' + $PID)
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    try {
        [System.IO.File]::WriteAllText($tmpFile, $json + "`n", $utf8NoBom)
        Move-Item -LiteralPath $tmpFile -Destination $resolvedOut -Force
    } catch {
        if (Test-Path -LiteralPath $tmpFile) {
            Remove-Item -LiteralPath $tmpFile -Force -ErrorAction SilentlyContinue
        }
        throw
    }
}

function Build-Summary {
    param([array]$Items)
    $counts = [ordered]@{
        pass                         = 0
        l2_native_pass               = 0
        pending_physical_l3          = 0
        skipped_no_hardware          = 0
        skipped_unsupported_platform = 0
        fail                         = 0
    }
    foreach ($it in $Items) {
        switch ($it['status']) {
            'PASS'                         { $counts['pass']++ }
            'L2_NATIVE_PASS'               { $counts['l2_native_pass']++ }
            'PENDING_PHYSICAL_L3'          { $counts['pending_physical_l3']++ }
            'SKIPPED_NO_HARDWARE'          { $counts['skipped_no_hardware']++ }
            'SKIPPED_UNSUPPORTED_PLATFORM' { $counts['skipped_unsupported_platform']++ }
            'FAIL'                         { $counts['fail']++ }
            default                        { throw "Unknown status '$($it['status'])'" }
        }
    }
    return $counts
}

try {
    $ScriptDir = Split-Path -Parent $PSCommandPath
    $RepoRoot = Split-Path -Parent $ScriptDir

    if (-not $IsWindowsHost) {
        if (-not $DryRun) {
            [Console]::Error.WriteLine("ERROR: verify-windows-l3.ps1 requires Windows (pass -DryRun for cross-platform schema dry-run)")
            exit 40
        }
        $dryItems = @()
        foreach ($spec in $Checklist) {
            $dryItems += (New-ReportItem -Spec $spec -Status 'SKIPPED_UNSUPPORTED_PLATFORM' -Evidence 'dry-run on non-Windows host; real Windows host required for L2/L3 probes' -DurationMs 0)
        }
        $dryReport = [ordered]@{
            schema_version = 1
            mode           = $Mode
            ci_runner      = $IsCiRunner
            platform       = 'windows'
            started_at_utc = $StartedAtUtc
            items          = $dryItems
            summary        = (Build-Summary -Items $dryItems)
        }
        Write-ReportAtomic -ReportObj $dryReport -TargetPath $Output
        exit 0
    }

    # --- Native Windows Read-Only Win32 Probes (PROBE-NOT-PATCH) ---
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class ZeroDeskWin32Probes {
    public const uint LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800;
    public const uint LOCKFILE_EXCLUSIVE_LOCK = 0x00000002;
    public const uint LOCKFILE_FAIL_IMMEDIATELY = 0x00000001;
    public const uint DESKTOP_READOBJECTS = 0x0001;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr LoadLibraryExW(string lpLibFileName, IntPtr hFile, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetProcessTimes(
        IntPtr hProcess,
        out long lpCreationTime,
        out long lpExitTime,
        out long lpKernelTime,
        out long lpUserTime);

    [StructLayout(LayoutKind.Sequential)]
    public struct OVERLAPPED {
        public IntPtr Internal;
        public IntPtr InternalHigh;
        public uint Offset;
        public uint OffsetHigh;
        public IntPtr hEvent;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool LockFileEx(
        Microsoft.Win32.SafeHandles.SafeFileHandle hFile,
        uint dwFlags,
        uint dwReserved,
        uint nNumberOfBytesToLockLow,
        uint nNumberOfBytesToLockHigh,
        ref OVERLAPPED lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool UnlockFileEx(
        Microsoft.Win32.SafeHandles.SafeFileHandle hFile,
        uint dwReserved,
        uint nNumberOfBytesToUnlockLow,
        uint nNumberOfBytesToUnlockHigh,
        ref OVERLAPPED lpOverlapped);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr OpenInputDesktop(uint dwFlags, bool fInherit, uint dwDesiredAccess);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseDesktop(IntPtr hDesktop);

    public static bool ProbeSystemDll(string dllName, out int lastError) {
        IntPtr h = LoadLibraryExW(dllName, IntPtr.Zero, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (h == IntPtr.Zero) {
            lastError = Marshal.GetLastWin32Error();
            return false;
        }
        FreeLibrary(h);
        lastError = 0;
        return true;
    }

    public static bool ProbeProcessCreationTime(out long creationTime100ns, out int lastError) {
        long exitT, kernelT, userT;
        bool ok = GetProcessTimes(GetCurrentProcess(), out creationTime100ns, out exitT, out kernelT, out userT);
        lastError = ok ? 0 : Marshal.GetLastWin32Error();
        return ok && creationTime100ns > 0;
    }

    public static bool ProbeInputDesktopReadOnly(out int lastError) {
        IntPtr h = OpenInputDesktop(0, false, DESKTOP_READOBJECTS);
        if (h == IntPtr.Zero) {
            lastError = Marshal.GetLastWin32Error();
            return false;
        }
        CloseDesktop(h);
        lastError = 0;
        return true;
    }
}
"@ -Language CSharp

    $DiagBin = Resolve-TargetBinary -ExplicitPath $DiagBin -BinaryName 'zerodesk-win-diag.exe'
    $WatchdogBin = Resolve-TargetBinary -ExplicitPath $WatchdogBin -BinaryName 'zerodesk-hid-watchdog.exe'

    # Probe 1: Run zerodesk-win-diag.exe (non-destructive, PS 5.1 stderr-safe)
    $swDiag = [System.Diagnostics.Stopwatch]::StartNew()
    $diagParsed = $null
    $diagError = $null
    $diagExitCode = -1
    if (-not [string]::IsNullOrEmpty($DiagBin) -and (Test-Path -LiteralPath $DiagBin)) {
        $prevEap = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $rawOut = & $DiagBin 2>$null
            $diagExitCode = $LASTEXITCODE
            $ErrorActionPreference = 'Stop'
            $jsonText = (@($rawOut) | ForEach-Object { $_.ToString() }) -join "`n"
            $candidate = $jsonText | ConvertFrom-Json
            $schemaVer = Get-SafeProp $candidate 'schema_version' $null
            $winHostReq = Get-SafeProp $candidate 'windows_host_required' $null
            $hasAllSections = (Test-HasProp $candidate 'dxgi') -and (Test-HasProp $candidate 'media_foundation') -and (Test-HasProp $candidate 'input') -and (Test-HasProp $candidate 'watchdog')
            $schemaVerOk = (($schemaVer -is [int]) -or ($schemaVer -is [long])) -and ($schemaVer -eq 1)
            $winHostReqOk = ($winHostReq -is [bool]) -and ($winHostReq -eq $false)
            if (-not $schemaVerOk -or -not $winHostReqOk -or -not $hasAllSections) {
                $diagError = "invalid zerodesk-win-diag schema (schema_version=$schemaVer, windows_host_required=$winHostReq, has_all_sections=$hasAllSections)"
                $diagParsed = $null
            } else {
                $diagParsed = $candidate
            }
        } catch {
            $diagError = "zerodesk-win-diag execution/parse failed: $($_.Exception.Message)"
            $diagParsed = $null
        } finally {
            $ErrorActionPreference = $prevEap
        }
    } else {
        $diagError = 'zerodesk-win-diag.exe not found (pass -DiagBin or build zerodesk_core)'
    }
    $swDiag.Stop()

    # Probe 1b: Non-destructive zerodesk-hid-watchdog.exe fail-closed invocation check
    $watchdogBinOk = $false
    $watchdogBinDetail = 'zerodesk-hid-watchdog.exe not found (pass -WatchdogBin or build zerodesk_core)'
    if (-not [string]::IsNullOrEmpty($WatchdogBin) -and (Test-Path -LiteralPath $WatchdogBin)) {
        $prevEap = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $null = & $WatchdogBin 2>$null
            $wdRc = $LASTEXITCODE
            $ErrorActionPreference = 'Stop'
            if ($wdRc -ne 0) {
                $watchdogBinOk = $true
                $watchdogBinDetail = "zerodesk-hid-watchdog.exe verified (fail-closed on missing args, rc=$wdRc)"
            } else {
                $watchdogBinDetail = 'zerodesk-hid-watchdog.exe unexpectedly exited 0 with no args'
            }
        } catch {
            $watchdogBinDetail = "zerodesk-hid-watchdog.exe probe error: $($_.Exception.Message)"
        } finally {
            $ErrorActionPreference = $prevEap
        }
    }

    # Safely extract diagnostic sections under Set-StrictMode
    $dxgiSec = Get-SafeProp $diagParsed 'dxgi' $null
    $mfSec = Get-SafeProp $diagParsed 'media_foundation' $null
    $inputSec = Get-SafeProp $diagParsed 'input' $null
    $wdSec = Get-SafeProp $diagParsed 'watchdog' $null

    $dxgiOk = [bool](Get-SafeProp $dxgiSec 'ok' $false)
    $dxgiOutputsRaw = Get-SafeProp $dxgiSec 'outputs' $null
    $dxgiOutputs = if ($null -ne $dxgiOutputsRaw) { @($dxgiOutputsRaw) } else { @() }
    $primaryLuid = Get-SafeProp $dxgiSec 'primary_adapter_luid' $null

    $mfOk = [bool](Get-SafeProp $mfSec 'ok' $false)
    $mfAny = [bool](Get-SafeProp $mfSec 'any_hw_mft_found' $false)

    $inputDesktopAccessible = [bool](Get-SafeProp $inputSec 'input_desktop_accessible' $false)
    $inputElevated = Get-SafeProp $inputSec 'uipi_elevated' $null
    $inputLocalSystem = [bool](Get-SafeProp $inputSec 'is_local_system' $false)

    $wdOk = [bool](Get-SafeProp $wdSec 'ok' $false)
    $wdSpawnOk = [bool](Get-SafeProp $wdSec 'spawn_ok' $false)
    $wdHeartbeatOk = [bool](Get-SafeProp $wdSec 'heartbeat_ok' $false)
    $wdEmptyBatchOk = [bool](Get-SafeProp $wdSec 'empty_batch_release_ok' $false)
    $wdErrVal = Get-SafeProp $wdSec 'error' 'none'

    # Compute hashed hardware fingerprint from primary DXGI adapter LUID if available
    $hwFingerprint = $null
    $hasPhysicalGpu = $false
    if ($null -ne $primaryLuid) {
        $luidHi = Get-SafeProp $primaryLuid 'high_part' $null
        $luidLo = Get-SafeProp $primaryLuid 'low_part' $null
        if ($null -ne $luidHi -and $null -ne $luidLo) {
            $hwFingerprint = Get-ShortSha256 -InputText "${luidHi}:${luidLo}"
            if ($dxgiOutputs.Count -gt 0) {
                $adapterName = [string](Get-SafeProp $dxgiOutputs[0] 'adapter_name' '')
                if (-not [string]::IsNullOrWhiteSpace($adapterName) -and $adapterName -notmatch 'Microsoft Basic Render') {
                    $hasPhysicalGpu = $true
                }
            }
        }
    }

    # Probe 2: System32 DLL loadability (d3d11.dll, dxgi.dll, mfplat.dll)
    $d3dErr = 0; $dxgiErr = 0; $mfErr = 0
    $d3d11Loaded = [ZeroDeskWin32Probes]::ProbeSystemDll('d3d11.dll', [ref]$d3dErr)
    $dxgiLoaded  = [ZeroDeskWin32Probes]::ProbeSystemDll('dxgi.dll',  [ref]$dxgiErr)
    $mfplatLoaded = [ZeroDeskWin32Probes]::ProbeSystemDll('mfplat.dll', [ref]$mfErr)

    # Probe 3: Win32 LockFileEx non-blocking exclusive lock on ephemeral temp file
    $swLock = [System.Diagnostics.Stopwatch]::StartNew()
    $lockFileOk = $false
    $lockFileDetail = ''
    $tmpLockPath = Join-Path ([System.IO.Path]::GetTempPath()) ("zd-l3-lockprobe-$PID-" + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '.tmp')
    try {
        $fs = [System.IO.File]::Open($tmpLockPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            $ov = New-Object ZeroDeskWin32Probes+OVERLAPPED
            $locked = [ZeroDeskWin32Probes]::LockFileEx(
                $fs.SafeFileHandle,
                ([ZeroDeskWin32Probes]::LOCKFILE_EXCLUSIVE_LOCK -bor [ZeroDeskWin32Probes]::LOCKFILE_FAIL_IMMEDIATELY),
                0, 1, 0, [ref]$ov
            )
            if ($locked) {
                $unlocked = [ZeroDeskWin32Probes]::UnlockFileEx($fs.SafeFileHandle, 0, 1, 0, [ref]$ov)
                $lockFileOk = $unlocked
                $lockFileDetail = if ($unlocked) { 'LockFileEx/UnlockFileEx exclusive non-blocking probe succeeded' } else { 'UnlockFileEx returned false' }
            } else {
                $lockFileDetail = 'LockFileEx returned false'
            }
        } finally {
            $fs.Dispose()
        }
    } catch {
        $lockFileDetail = "LockFileEx probe exception: $($_.Exception.Message)"
    } finally {
        if (Test-Path -LiteralPath $tmpLockPath) {
            Remove-Item -LiteralPath $tmpLockPath -Force -ErrorAction SilentlyContinue
        }
    }
    $swLock.Stop()

    # Probe 4: Win32 GetProcessTimes PID-reuse guard creation timestamp
    $swTimes = [System.Diagnostics.Stopwatch]::StartNew()
    $creationTime = [long]0
    $timesErr = 0
    $procTimesOk = [ZeroDeskWin32Probes]::ProbeProcessCreationTime([ref]$creationTime, [ref]$timesErr)
    $swTimes.Stop()

    # Probe 5: Read-only OpenInputDesktop probe
    $swDesktop = [System.Diagnostics.Stopwatch]::StartNew()
    $desktopErr = 0
    $desktopProbeOk = [ZeroDeskWin32Probes]::ProbeInputDesktopReadOnly([ref]$desktopErr)
    $swDesktop.Stop()

    $items = @()

    # WIN-L3-01: Single-Command Diagnostics (zerodesk-win-diag)
    # Headless-verifiable invariants (schema v1 + watchdog.ok + empty_batch_release_ok) MUST succeed;
    # otherwise emit FAIL rather than masking broken probes as L2_NATIVE_PASS.
    if ($null -eq $diagParsed) {
        $items += (New-ReportItem -Spec $Checklist[0] -Status 'FAIL' -Evidence "zerodesk-win-diag failed: $diagError" -DurationMs $swDiag.ElapsedMilliseconds)
    } elseif (-not ($wdOk -and $wdEmptyBatchOk)) {
        $items += (New-ReportItem -Spec $Checklist[0] -Status 'FAIL' -Evidence "zerodesk-win-diag headless watchdog/empty-batch invariant failed (watchdog.ok=$wdOk, empty_batch_release_ok=$wdEmptyBatchOk, err=$wdErrVal)" -DurationMs $swDiag.ElapsedMilliseconds -HardwareFingerprint $hwFingerprint)
    } elseif ($Mode -eq 'strict-l3' -and -not $IsCiRunner -and $diagExitCode -eq 0 -and $dxgiOk -and $mfOk -and $inputDesktopAccessible -and $hasPhysicalGpu -and $null -ne $hwFingerprint) {
        $items += (New-ReportItem -Spec $Checklist[0] -Status 'PASS' -Evidence "zerodesk-win-diag exit=0; all 4 sections ok on physical GPU (luid_sha8=$hwFingerprint, outputs=$($dxgiOutputs.Count))" -DurationMs $swDiag.ElapsedMilliseconds -HardwareFingerprint $hwFingerprint)
    } else {
        $luidTag = if ($null -ne $hwFingerprint) { $hwFingerprint } else { 'none' }
        $items += (New-ReportItem -Spec $Checklist[0] -Status 'L2_NATIVE_PASS' -Evidence "zerodesk-win-diag schema_v1 & watchdog verified (exit=$diagExitCode, dxgi.ok=$dxgiOk, dxgi.outputs=$($dxgiOutputs.Count), luid_sha8=$luidTag, mf.ok=$mfOk, mf.any_hw=$mfAny, watchdog.ok=$wdOk, physical_gpu=$hasPhysicalGpu); physical NVIDIA/AMD/Intel GPU host required for L3 PASS" -DurationMs $swDiag.ElapsedMilliseconds -HardwareFingerprint $hwFingerprint)
    }

    # WIN-L3-02: DXGI Multi-Monitor Capture, Cursor & Mode/DPI Switch
    $dxgiCount = $dxgiOutputs.Count
    if (-not $d3d11Loaded -or -not $dxgiLoaded) {
        $items += (New-ReportItem -Spec $Checklist[1] -Status 'FAIL' -Evidence "System32 DLL load failed: d3d11.dll=$d3d11Loaded(err=$d3dErr) dxgi.dll=$dxgiLoaded(err=$dxgiErr)" -DurationMs 1)
    } else {
        $items += (New-ReportItem -Spec $Checklist[1] -Status 'PENDING_PHYSICAL_L3' -Evidence "d3d11.dll & dxgi.dll loaded from System32 (dxgi.ok=$dxgiOk, dxgi.outputs=$dxgiCount); physical multi-monitor DPI/cursor/DXGI first-frame capture requires real display hardware" -DurationMs 1 -HardwareFingerprint $hwFingerprint)
    }

    # WIN-L3-03: UAC / Lock Screen Pause & Resume
    $items += (New-ReportItem -Spec $Checklist[2] -Status 'PENDING_PHYSICAL_L3' -Evidence 'UAC prompt & Win+L lock screen DesktopPaused/resume requires physical interactive Windows session (never triggers UAC in probe)' -DurationMs 0)

    # WIN-L3-04: Media Foundation HW MFT LUID-Bound D3D11 NV12 Zero-Copy + First-IDR Gate
    if (-not $mfplatLoaded) {
        $items += (New-ReportItem -Spec $Checklist[3] -Status 'FAIL' -Evidence "System32 mfplat.dll load failed (err=$mfErr)" -DurationMs 1)
    } else {
        $items += (New-ReportItem -Spec $Checklist[3] -Status 'PENDING_PHYSICAL_L3' -Evidence "mfplat.dll loaded from System32 (any_hw_mft_found=$mfAny, exact_luid_zero_copy=$mfOk); NVENC/QSV/AMF MF first-IDR HardwareReady gate requires physical GPU hardware" -DurationMs 1 -HardwareFingerprint $hwFingerprint)
    }

    # WIN-L3-05: Mid-Stream HW MFT Failure -> Bounded Reinit -> Explicit Renegotiation
    $items += (New-ReportItem -Spec $Checklist[4] -Status 'PENDING_PHYSICAL_L3' -Evidence 'Mid-stream GPU TDR/device-reset bounded reinit and explicit VP9 renegotiation requires physical Windows GPU hardware' -DurationMs 0)

    # WIN-L3-06: WinHidKeyMap Physical Keyboard & Mouse Round-Trip
    $items += (New-ReportItem -Spec $Checklist[5] -Status 'PENDING_PHYSICAL_L3' -Evidence 'Physical ANSI/ISO SendInput keyboard & 5-button mouse round-trip requires interactive Windows desktop session' -DurationMs 0)

    # WIN-L3-07: Watchdog PROC_THREAD_ATTRIBUTE_HANDLE_LIST Grandchild-Spawn EOF
    if (-not $lockFileOk) {
        $items += (New-ReportItem -Spec $Checklist[6] -Status 'FAIL' -Evidence "Win32 LockFileEx probe failed: $lockFileDetail" -DurationMs $swLock.ElapsedMilliseconds)
    } elseif ($null -eq $diagParsed -or -not ($wdSpawnOk -and $wdHeartbeatOk)) {
        $items += (New-ReportItem -Spec $Checklist[6] -Status 'FAIL' -Evidence "zerodesk-win-diag watchdog spawn/heartbeat failed (spawn_ok=$wdSpawnOk, heartbeat_ok=$wdHeartbeatOk, err=$wdErrVal)" -DurationMs $swLock.ElapsedMilliseconds)
    } elseif (-not $watchdogBinOk) {
        $items += (New-ReportItem -Spec $Checklist[6] -Status 'FAIL' -Evidence "Watchdog binary probe failed: $watchdogBinDetail" -DurationMs $swLock.ElapsedMilliseconds)
    } else {
        $items += (New-ReportItem -Spec $Checklist[6] -Status 'L2_NATIVE_PASS' -Evidence "$lockFileDetail; zerodesk-win-diag watchdog spawn_ok=$wdSpawnOk heartbeat_ok=$wdHeartbeatOk; $watchdogBinDetail (full grandchild-spawn TerminateProcess EOF torture required for physical L3 PASS)" -DurationMs $swLock.ElapsedMilliseconds)
    }

    # WIN-L3-08: Watchdog WaitForMultipleObjects + GetProcessTimes PID-Reuse Guard + Single-Batch Torture Test
    if (-not $procTimesOk) {
        $items += (New-ReportItem -Spec $Checklist[7] -Status 'FAIL' -Evidence "Win32 GetProcessTimes probe failed (err=$timesErr)" -DurationMs $swTimes.ElapsedMilliseconds)
    } elseif ($null -eq $diagParsed -or -not $wdEmptyBatchOk) {
        $items += (New-ReportItem -Spec $Checklist[7] -Status 'FAIL' -Evidence "Watchdog empty_batch_release_ok probe failed (diag_ok=$($null -ne $diagParsed), empty_batch_release_ok=$wdEmptyBatchOk, err=$wdErrVal)" -DurationMs $swTimes.ElapsedMilliseconds)
    } else {
        $items += (New-ReportItem -Spec $Checklist[7] -Status 'L2_NATIVE_PASS' -Evidence "GetProcessTimes PID-reuse creation timestamp verified (>0); watchdog empty_batch_release_ok=$wdEmptyBatchOk (interactive multi-key single-batch torture required for physical L3 PASS)" -DurationMs $swTimes.ElapsedMilliseconds)
    }

    # WIN-L3-09: Watchdog Heartbeat-Timeout Release on Frozen Host
    $items += (New-ReportItem -Spec $Checklist[8] -Status 'PENDING_PHYSICAL_L3' -Evidence 'Frozen-host SuspendThread heartbeat-timeout emergency release requires interactive Windows L3 harness' -DurationMs 0)

    # WIN-L3-10: OpenInputDesktop / SetThreadDesktop & UIPI Elevated-Window Negative Test
    if ($null -eq $diagParsed -or $null -eq $inputSec) {
        $items += (New-ReportItem -Spec $Checklist[9] -Status 'FAIL' -Evidence "UIPI/OpenInputDesktop section missing from zerodesk-win-diag (direct OpenInputDesktop=$desktopProbeOk err=$desktopErr)" -DurationMs $swDesktop.ElapsedMilliseconds)
    } elseif (-not ($desktopProbeOk -and $inputDesktopAccessible)) {
        $items += (New-ReportItem -Spec $Checklist[9] -Status 'FAIL' -Evidence "OpenInputDesktop probe failed (diag.input_desktop_accessible=$inputDesktopAccessible, direct_open_input_desktop=$desktopProbeOk, err=$desktopErr)" -DurationMs $swDesktop.ElapsedMilliseconds)
    } else {
        $items += (New-ReportItem -Spec $Checklist[9] -Status 'L2_NATIVE_PASS' -Evidence "Read-only UIPI & OpenInputDesktop probe verified (uipi_elevated=$inputElevated, is_local_system=$inputLocalSystem, input_desktop_accessible=$inputDesktopAccessible, direct_open_input_desktop=$desktopProbeOk; interactive elevated-window negative SendInput test required for physical L3 PASS)" -DurationMs $swDesktop.ElapsedMilliseconds)
    }

    # WIN-L3-11: Cross-OS E2E Session
    $items += (New-ReportItem -Spec $Checklist[10] -Status 'PENDING_PHYSICAL_L3' -Evidence 'Bidirectional macOS <-> Windows encrypted V2 session requires two physical hosts' -DurationMs 0)

    # WIN-L3-12: 30-Minute 1080p60 Hardware Soak Test
    $items += (New-ReportItem -Spec $Checklist[11] -Status 'PENDING_PHYSICAL_L3' -Evidence '30-minute 1080p60 hardware soak (HandleCount/RSS/VRAM flat) requires physical GPU host' -DurationMs 0)

    $summary = Build-Summary -Items $items
    $report = [ordered]@{
        schema_version = 1
        mode           = $Mode
        ci_runner      = $IsCiRunner
        platform       = 'windows'
        started_at_utc = $StartedAtUtc
        items          = $items
        summary        = $summary
    }

    Write-ReportAtomic -ReportObj $report -TargetPath $Output

    if ($summary['fail'] -gt 0) {
        exit 20
    }
    if ($Mode -eq 'strict-l3') {
        if ($summary['pass'] -eq 12) {
            exit 0
        }
        exit 10
    }
    exit 0
} catch {
    [Console]::Error.WriteLine("FATAL: $(Scrub-Text $_.Exception.Message)")
    exit 30
}
