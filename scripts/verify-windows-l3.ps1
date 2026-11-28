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
#   - Anti-forgery redline: `-Mode ci` is code-level forbidden from emitting status `PASS`.
#
# Exit Codes:
#   0  = CI mode with 0 FAIL | -DryRun on non-Windows | strict-l3 with 12/12 PASS
#   10 = strict-l3 mode with 0 FAIL and >=1 non-PASS item (e.g. PENDING_PHYSICAL_L3)
#   20 = At least one item reported FAIL
#   30 = Script/runtime error, invalid arguments, or CI anti-forgery invariant violation
#   40 = Unsupported platform (non-Windows host without -DryRun)

[CmdletBinding()]
param(
    [string]$Mode = 'ci',
    [string]$Output = 'zerodesk-windows-l3-report.json',
    [string]$DiagBin = '',
    [switch]$DryRun,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Show-Usage {
    @"
Usage: verify-windows-l3.ps1 [-Mode ci|strict-l3] [-Output <path|->] [-DiagBin <path>] [-DryRun] [-Help]

Options:
  -Mode <ci|strict-l3>  Verification mode (default: ci). CI mode NEVER emits PASS.
  -Output <path|->      Output JSON report path (default: zerodesk-windows-l3-report.json; '-' = stdout).
  -DiagBin <path>       Optional path to zerodesk-win-diag.exe.
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

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$StartedAtUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$IsCiRunner = ($env:CI -eq 'true' -or $env:GITHUB_ACTIONS -eq 'true')
$IsWindowsHost = ($env:OS -eq 'Windows_NT') -or ($PSVersionTable.Platform -eq 'Win32NT')

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
        $s = $s.Replace($RepoRoot, '<REPO>')
        $s = $s.Replace(($RepoRoot -replace '\\', '/'), '<REPO>')
    }
    if (-not [string]::IsNullOrEmpty($env:USERPROFILE)) {
        $s = $s.Replace($env:USERPROFILE, '<HOME>')
        $s = $s.Replace(($env:USERPROFILE -replace '\\', '/'), '<HOME>')
    }
    if (-not [string]::IsNullOrEmpty($env:HOME)) {
        $s = $s.Replace($env:HOME, '<HOME>')
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
    if ($Mode -eq 'ci' -and $Status -eq 'PASS') {
        throw "ANTI-FORGERY VIOLATION: -Mode ci forbids emitting status PASS (item=$($Spec.id))"
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
    if ($ReportObj['mode'] -eq 'ci') {
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

    # Locate zerodesk-win-diag.exe if not explicitly provided
    if ([string]::IsNullOrEmpty($DiagBin)) {
        $candidates = @(
            (Join-Path $RepoRoot 'libs\zerodesk_core\target\release\zerodesk-win-diag.exe'),
            (Join-Path $RepoRoot 'libs\zerodesk_core\target\debug\zerodesk-win-diag.exe')
        )
        foreach ($cand in $candidates) {
            if (Test-Path -LiteralPath $cand) {
                $DiagBin = $cand
                break
            }
        }
    }

    # Probe 1: Run zerodesk-win-diag.exe (non-destructive)
    $swDiag = [System.Diagnostics.Stopwatch]::StartNew()
    $diagParsed = $null
    $diagError = $null
    $diagExitCode = -1
    if (-not [string]::IsNullOrEmpty($DiagBin) -and (Test-Path -LiteralPath $DiagBin)) {
        try {
            $rawOut = & $DiagBin 2>$null
            $diagExitCode = $LASTEXITCODE
            $jsonText = (@($rawOut) | ForEach-Object { $_.ToString() }) -join "`n"
            $diagParsed = $jsonText | ConvertFrom-Json
            if ($diagParsed.schema_version -ne 1 -or $diagParsed.windows_host_required -ne $false) {
                $diagError = "unexpected zerodesk-win-diag schema_version=$($diagParsed.schema_version) windows_host_required=$($diagParsed.windows_host_required)"
                $diagParsed = $null
            }
        } catch {
            $diagError = "zerodesk-win-diag execution/parse failed: $($_.Exception.Message)"
            $diagParsed = $null
        }
    } else {
        $diagError = 'zerodesk-win-diag.exe not found (pass -DiagBin or build zerodesk_core)'
    }
    $swDiag.Stop()

    # Compute hashed hardware fingerprint from primary DXGI adapter LUID if available
    $hwFingerprint = $null
    $hasPhysicalGpu = $false
    $dxgiOutputs = @()
    if ($null -ne $diagParsed -and $null -ne $diagParsed.dxgi) {
        if ($null -ne $diagParsed.dxgi.outputs) {
            $dxgiOutputs = @($diagParsed.dxgi.outputs)
        }
        if ($null -ne $diagParsed.dxgi.primary_adapter_luid) {
            $luid = $diagParsed.dxgi.primary_adapter_luid
            $luidStr = "$($luid.high_part):$($luid.low_part)"
            $hwFingerprint = Get-ShortSha256 -InputText $luidStr
            if ($dxgiOutputs.Count -gt 0) {
                $adapterName = [string]$dxgiOutputs[0].adapter_name
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
    if ($null -eq $diagParsed) {
        $items += (New-ReportItem -Spec $Checklist[0] -Status 'FAIL' -Evidence "zerodesk-win-diag failed: $diagError" -DurationMs $swDiag.ElapsedMilliseconds)
    } elseif ($Mode -eq 'strict-l3' -and $diagExitCode -eq 0 -and $diagParsed.dxgi.ok -and $diagParsed.media_foundation.ok -and $diagParsed.input.input_desktop_accessible -and $diagParsed.watchdog.ok -and $hasPhysicalGpu -and $null -ne $hwFingerprint) {
        $items += (New-ReportItem -Spec $Checklist[0] -Status 'PASS' -Evidence "zerodesk-win-diag exit=0; all 4 sections ok on physical GPU (luid_sha8=$hwFingerprint, outputs=$($dxgiOutputs.Count))" -DurationMs $swDiag.ElapsedMilliseconds -HardwareFingerprint $hwFingerprint)
    } elseif ($Mode -eq 'strict-l3') {
        $items += (New-ReportItem -Spec $Checklist[0] -Status 'PENDING_PHYSICAL_L3' -Evidence "zerodesk-win-diag schema_v1 valid (exit=$diagExitCode, dxgi.ok=$($diagParsed.dxgi.ok), mf.ok=$($diagParsed.media_foundation.ok), watchdog.ok=$($diagParsed.watchdog.ok), physical_gpu=$hasPhysicalGpu); requires physical NVIDIA/AMD/Intel GPU host for PASS" -DurationMs $swDiag.ElapsedMilliseconds -HardwareFingerprint $hwFingerprint)
    } else {
        $luidTag = if ($null -ne $hwFingerprint) { $hwFingerprint } else { 'none' }
        $items += (New-ReportItem -Spec $Checklist[0] -Status 'L2_NATIVE_PASS' -Evidence "zerodesk-win-diag schema_v1 verified on Windows runner (exit=$diagExitCode, dxgi.outputs=$($dxgiOutputs.Count), luid_sha8=$luidTag, mf.any_hw=$($diagParsed.media_foundation.any_hw_mft_found), watchdog.ok=$($diagParsed.watchdog.ok)); full GPU L3 PASS requires physical host" -DurationMs $swDiag.ElapsedMilliseconds -HardwareFingerprint $hwFingerprint)
    }

    # WIN-L3-02: DXGI Multi-Monitor Capture, Cursor & Mode/DPI Switch
    $dxgiCount = $dxgiOutputs.Count
    if (-not $d3d11Loaded -or -not $dxgiLoaded) {
        $items += (New-ReportItem -Spec $Checklist[1] -Status 'FAIL' -Evidence "System32 DLL load failed: d3d11.dll=$d3d11Loaded(err=$d3dErr) dxgi.dll=$dxgiLoaded(err=$dxgiErr)" -DurationMs 1)
    } else {
        $items += (New-ReportItem -Spec $Checklist[1] -Status 'PENDING_PHYSICAL_L3' -Evidence "d3d11.dll & dxgi.dll loaded from System32 (dxgi.outputs=$dxgiCount); physical multi-monitor DPI/cursor/DXGI first-frame capture requires real display hardware" -DurationMs 1 -HardwareFingerprint $hwFingerprint)
    }

    # WIN-L3-03: UAC / Lock Screen Pause & Resume
    $items += (New-ReportItem -Spec $Checklist[2] -Status 'PENDING_PHYSICAL_L3' -Evidence 'UAC prompt & Win+L lock screen DesktopPaused/resume requires physical interactive Windows session (never triggers UAC in probe)' -DurationMs 0)

    # WIN-L3-04: Media Foundation HW MFT LUID-Bound D3D11 NV12 Zero-Copy + First-IDR Gate
    $mfAny = if ($null -ne $diagParsed -and $null -ne $diagParsed.media_foundation) { [bool]$diagParsed.media_foundation.any_hw_mft_found } else { $false }
    $mfOk  = if ($null -ne $diagParsed -and $null -ne $diagParsed.media_foundation) { [bool]$diagParsed.media_foundation.ok } else { $false }
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
    $wdSpawnOk = ($null -ne $diagParsed -and $null -ne $diagParsed.watchdog -and $diagParsed.watchdog.spawn_ok -and $diagParsed.watchdog.heartbeat_ok)
    if (-not $lockFileOk) {
        $items += (New-ReportItem -Spec $Checklist[6] -Status 'FAIL' -Evidence "Win32 LockFileEx probe failed: $lockFileDetail" -DurationMs $swLock.ElapsedMilliseconds)
    } elseif ($null -ne $diagParsed -and -not $wdSpawnOk) {
        $wdErrVal = if ($null -ne $diagParsed.watchdog.PSObject.Properties['error']) { $diagParsed.watchdog.error } else { 'none' }
        $items += (New-ReportItem -Spec $Checklist[6] -Status 'FAIL' -Evidence "zerodesk-win-diag watchdog spawn/heartbeat failed (spawn_ok=$($diagParsed.watchdog.spawn_ok), heartbeat_ok=$($diagParsed.watchdog.heartbeat_ok), err=$wdErrVal)" -DurationMs $swLock.ElapsedMilliseconds)
    } elseif ($Mode -eq 'strict-l3') {
        $items += (New-ReportItem -Spec $Checklist[6] -Status 'PENDING_PHYSICAL_L3' -Evidence "$lockFileDetail; watchdog spawn+heartbeat ok; full grandchild-spawn TerminateProcess EOF torture required for strict-l3 PASS" -DurationMs $swLock.ElapsedMilliseconds)
    } else {
        $items += (New-ReportItem -Spec $Checklist[6] -Status 'L2_NATIVE_PASS' -Evidence "$lockFileDetail; zerodesk-win-diag watchdog spawn_ok=$wdSpawnOk heartbeat_ok=$wdSpawnOk (full grandchild-spawn TerminateProcess test deferred to physical L3)" -DurationMs $swLock.ElapsedMilliseconds)
    }

    # WIN-L3-08: Watchdog WaitForMultipleObjects + GetProcessTimes PID-Reuse Guard + Single-Batch Torture Test
    $wdEmptyBatchOk = ($null -ne $diagParsed -and $null -ne $diagParsed.watchdog -and $diagParsed.watchdog.empty_batch_release_ok)
    if (-not $procTimesOk) {
        $items += (New-ReportItem -Spec $Checklist[7] -Status 'FAIL' -Evidence "Win32 GetProcessTimes probe failed (err=$timesErr)" -DurationMs $swTimes.ElapsedMilliseconds)
    } elseif ($Mode -eq 'strict-l3') {
        $items += (New-ReportItem -Spec $Checklist[7] -Status 'PENDING_PHYSICAL_L3' -Evidence "GetProcessTimes creation_time_100ns>0 verified (empty_batch_release_ok=$wdEmptyBatchOk); interactive single-batch stuck-key torture required for strict-l3 PASS" -DurationMs $swTimes.ElapsedMilliseconds)
    } else {
        $items += (New-ReportItem -Spec $Checklist[7] -Status 'L2_NATIVE_PASS' -Evidence "GetProcessTimes PID-reuse creation timestamp verified (>0); watchdog empty_batch_release_ok=$wdEmptyBatchOk (interactive multi-key torture deferred to physical L3)" -DurationMs $swTimes.ElapsedMilliseconds)
    }

    # WIN-L3-09: Watchdog Heartbeat-Timeout Release on Frozen Host
    $items += (New-ReportItem -Spec $Checklist[8] -Status 'PENDING_PHYSICAL_L3' -Evidence 'Frozen-host SuspendThread heartbeat-timeout emergency release requires interactive Windows L3 harness' -DurationMs 0)

    # WIN-L3-10: OpenInputDesktop / SetThreadDesktop & UIPI Elevated-Window Negative Test
    if ($null -eq $diagParsed -or $null -eq $diagParsed.input) {
        $items += (New-ReportItem -Spec $Checklist[9] -Status 'FAIL' -Evidence "UIPI/OpenInputDesktop section missing from zerodesk-win-diag (direct OpenInputDesktop=$desktopProbeOk err=$desktopErr)" -DurationMs $swDesktop.ElapsedMilliseconds)
    } elseif ($Mode -eq 'strict-l3') {
        $items += (New-ReportItem -Spec $Checklist[9] -Status 'PENDING_PHYSICAL_L3' -Evidence "UIPI probe ok (uipi_elevated=$($diagParsed.input.uipi_elevated), is_local_system=$($diagParsed.input.is_local_system), input_desktop_accessible=$($diagParsed.input.input_desktop_accessible), direct_open_input_desktop=$desktopProbeOk); elevated-window negative SendInput test required for strict-l3 PASS" -DurationMs $swDesktop.ElapsedMilliseconds)
    } else {
        $items += (New-ReportItem -Spec $Checklist[9] -Status 'L2_NATIVE_PASS' -Evidence "Read-only UIPI & OpenInputDesktop probe completed (uipi_elevated=$($diagParsed.input.uipi_elevated), is_local_system=$($diagParsed.input.is_local_system), input_desktop_accessible=$($diagParsed.input.input_desktop_accessible), direct_open_input_desktop=$desktopProbeOk); interactive elevated-window negative test deferred to physical L3" -DurationMs $swDesktop.ElapsedMilliseconds)
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
