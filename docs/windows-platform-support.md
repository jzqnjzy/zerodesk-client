<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (c) 2026 ZeroDesk Contributors -->

# ZeroDesk Windows Platform Support (Phase 8B)

## 1. Architecture Overview

ZeroDesk's Windows platform layer follows a **thin-FFI / testable-logic** split inside `libs/zerodesk_core/src/os/`:

```
Cross-Platform Traits (`os/traits.rs`)
├── ScreenCapturer       ──► macOS: ScreenCaptureKit / CoreGraphics (`OsScreenCaptureAdapter`)
│                        ──► Windows: `WinDxgiCapturer` (`os/win_dxgi.rs`) + `os/win_dxgi_logic.rs`
├── HardwareCodec /      ──► macOS: VideoToolbox (`MacVtHardwareEncoder` / `MacVtHardwareDecoder`)
│   HardwareVideoEncoder ──► Windows: `WinMfHardwareEncoder` (`os/win_mf.rs`) + `os/win_mf_logic.rs`
├── OsInputInjector      ──► macOS: `MacOsHidSink` (`OsHidSinkInjector`)
│                        ──► Windows: `WinOsInputInjector` (`os/win_input.rs`) + `os/win_hid_keymap.rs`
└── HidWatchdogBackend   ──► macOS/Unix: `UnixHidWatchdogBackend` (`HidWatchdogSupervisor`)
                         ──► Windows: `WinHidWatchdogBackend` (`os/win_watchdog.rs`) + `os/win_watchdog_logic.rs`
```

All pure Windows state machines, HRESULT classifiers, adapter-LUID matchers, bidirectional HID-to-scancode tables, single-batch `SendInput` release builders, PID-reuse guards, and heartbeat trackers live in **platform-agnostic modules** (NOT `#[cfg(windows)]`) so `cargo test` on macOS exercises 100% of the logic deterministically.

### Key Module Map

| Layer | Pure Logic (Tested on macOS) | Thin `#[cfg(windows)]` FFI |
|---|---|---|
| DXGI Screen Capture | `libs/zerodesk_core/src/os/win_dxgi_logic.rs` | `libs/zerodesk_core/src/os/win_dxgi.rs` |
| Media Foundation HW Codec | `libs/zerodesk_core/src/os/win_mf_logic.rs` | `libs/zerodesk_core/src/os/win_mf.rs` |
| Keyboard / Mouse Mapping & Injection | `libs/zerodesk_core/src/os/win_hid_keymap.rs` | `libs/zerodesk_core/src/os/win_input.rs` |
| Independent HID Watchdog | `libs/zerodesk_core/src/os/win_watchdog_logic.rs` | `libs/zerodesk_core/src/os/win_watchdog.rs` + `src/bin/zerodesk-hid-watchdog.rs` |
| Built-in Diagnostics | `libs/zerodesk_core/src/os/win_diag.rs` | `libs/zerodesk_core/src/bin/zerodesk-win-diag.rs` |

---

## 2. Clean-Room & Hardware Design Policies

### 2.1 DXGI Desktop Duplication — 3-Class HRESULT Policy
`classify_dxgi_hresult(hr: i32) -> DxgiAction` classifies every `AcquireNextFrame` / `DuplicateOutput` HRESULT strictly into:
1. **`NormalTimeout`**: `DXGI_ERROR_WAIT_TIMEOUT` (`0x887A0027`) — no desktop update; stays `Active`.
2. **`RecreateDuplication`**: `DXGI_ERROR_ACCESS_LOST` (`0x887A0026`), `E_INVALIDARG` (`0x80070057`), `DXGI_ERROR_MODE_CHANGE_IN_PROGRESS` (`0x887A0025`), `DXGI_ERROR_DEVICE_REMOVED` (`0x887A0005`), `DXGI_ERROR_DEVICE_RESET` (`0x887A0007`) — exponential backoff recreate (`Recreating { backoff_ms, attempt }`).
3. **`PauseAndWaitDesktop`**: `DXGI_ERROR_UNSUPPORTED` (`0x887A0004`), `DXGI_ERROR_SESSION_DISCONNECTED` (`0x887A0028`), `E_ACCESSDENIED` (`0x80070005`) — UAC prompt / Win+L lock screen / RDP switch; transitions to `DesktopPaused` and probes for clean resume.
4. **`Fatal(hr)`**: unexpected errors fail closed.

RAII guards (`AcquiredFrameGuard`, `MappedStagingGuard`) ensure `ReleaseFrame()` and `Unmap()` run on every exit path.

### 2.2 Media Foundation Hardware-Only Policy (Zero Proprietary SDKs)
- **Zero NVENC / AMF / QSV SDKs**: Windows hardware video encoding uses **Windows Media Foundation ONLY** (`MFTEnumEx(MFT_CATEGORY_VIDEO_ENCODER, MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER, ...)` via Microsoft's MIT/Apache-2.0 `windows` crate). NVIDIA NVENC, AMD AMF, and Intel QSV are discovered solely through their OS-registered hardware MFTs.
- **Sync & Async Hardware MFT Support + `ICodecAPI`**: Detects `MF_TRANSFORM_ASYNC`, unlocks async MFTs via `MF_TRANSFORM_ASYNC_UNLOCK = 1`, and pumps `IMFMediaEventGenerator::GetEvent` (`METransformNeedInput` / `METransformHaveOutput`) with bounded deadlines (while preserving synchronous `ProcessInput`/`ProcessOutput` for sync MFTs). Wires `ICodecAPI` directly for force-IDR (`CODECAPI_AVEncVideoForceKeyFrame`) and live bitrate updates (`CODECAPI_AVEncCommonMeanBitRate`).
- **LUID-Matched D3D11 NV12 Zero-Copy**: `select_hw_mft_for_luid()` distinguishes `ExactLuidZeroCopy` (requiring both `MFT_ENUM_ADAPTER_LUID` match and `MF_SA_D3D11_AWARE`), `ExactLuidCpuUpload`, `CrossAdapterCopy`, and `LuidMismatchDiagnostic`. On D3D11 frames (`CapturedSurface::D3d11Texture(Arc<D3d11SharedFrame>)`), `WinMfHardwareEncoder` converts BGRA -> NV12 on GPU via `ID3D11VideoContext::VideoProcessorBlt` and submits `MFCreateDXGISurfaceBuffer` over `IMFDXGIDeviceManager` (`D3D11_CREATE_DEVICE_VIDEO_SUPPORT` + `ID3D11Multithread::SetMultithreadProtected(true)`).
- **First-IDR Readiness Gate**: Enumeration NEVER marks the encoder usable. `MfHwEncoderStateMachine` progresses `Enumerated -> Initialized -> WaitingFirstIdr` (with bounded `on_input_queued()` first-IDR frame timeout) and transitions to `HardwareReady` **ONLY** when the first IDR keyframe (`MFSampleExtension_CleanPoint`) encodes with `byte_len > 0`.
- **Non-Silent Degradation**: Mid-stream hardware failures execute bounded MFT reinitialization (`ReinitRetry(1..=2)`), requiring a fresh IDR to re-enter `HardwareReady` and resetting `reinit_attempts = 0` only after `STABLE_FRAMES_TO_RESET_REINIT` (30) consecutive good frames in `HardwareReady`. Exhausting the retry budget transitions to terminal idempotent `FailedNeedsRenegotiation` and emits explicit event `"hardware_encoder_failed_renegotiate_vp9"` — **NEVER** silently falling back to a software MFT.
- **CPU Color Conversion Scope**: `bgra_to_nv12()` / `bgra_to_i420()` in `win_mf_logic.rs` are strictly color-space conversion fallbacks when D3D11 Video Processor NV12 conversion is unavailable (emitting explicit `CpuColorConvertFallback` diagnostic event), NEVER software video encoders.

### 2.3 Input Injection, Watchdog Safety & UIPI Limitation
- **Atomic Single-Batch `SendInput` Release**: `build_release_batch()` constructs ONE contiguous batch covering every tracked USB HID key (with Pause `0x48` using `VK_PAUSE` without `KEYEVENTF_SCANCODE` so it never toggles NumLock), all 8 distinct left/right modifiers (`0xE0..=0xE7`), and all 5 mouse buttons (`Left`, `Right`, `Middle`, `X1`, `X2`). `execute_atomic_release_batch()` submits the entire slice in a single `SendInput(&inputs, size_of::<INPUT>() as i32)` OS call so Windows guarantees non-interleaving with other threads.
- **Input Desktop Binding**: Before every emergency release batch, `ScopedInputDesktop::enter()` calls `GetThreadDesktop` + `OpenInputDesktop(0, FALSE, DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS)` + `SetThreadDesktop(hdesk)` and restores/closes the desktop handle via `Drop`, preventing desktop switches from silently dropping releases.
- **Strict Handle Inheritance Isolation**: `WinHidWatchdogSupervisor` spawns `zerodesk-hid-watchdog.exe` with `STARTUPINFOEXW` + `InitializeProcThreadAttributeList` + `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_HANDLE_LIST)` + `EXTENDED_STARTUPINFO_PRESENT`, restricting inheritance strictly to `[cmd_read, ack_write]` so unrelated grandchild processes cannot leak pipe handles and block EOF. The session nonce travels strictly inside the `Hello` pipe frame (never exposed in process argv).
- **PID-Reuse Protection & Hang Detection**: `WinHidWatchdogSupervisor` records `(pid, GetProcessTimes creation_time_100ns)` and passes it to `zerodesk-hid-watchdog.exe`, which validates `is_same_process_instance()` on `OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION)`. Its main loop monitors `[parent_handle, pipe_event]` via `WaitForMultipleObjects` with bounded `WatchdogHeartbeatTracker` timeout, failing closed on `WAIT_FAILED` and draining final pipe frames cleanly on parent exit.
- **UIPI & Secure Desktop Limitation (Explicitly Documented)**: Without an installed Windows Service (`NT AUTHORITY\SYSTEM` / `S-1-5-18`, probed via `is_local_system()`) or a signed `uiAccess=true` binary installed in a trusted system directory (`Program Files`), Windows **User Interface Privilege Isolation (UIPI)** blocks `SendInput` targeting elevated (`Administrator`) windows and blocks `OpenInputDesktop` / injection on the Secure/UAC desktop (`Winlogon`). ZeroDesk surfaces `uipi_elevated` and `is_local_system` via `InputPrivilegeStatus` / `zerodesk-win-diag` and accounts for any `SendInput` shortfall in `ReleaseReport::residual_*`.

---

## 3. Built-in Diagnostic Tool (`zerodesk-win-diag`)

Run a single non-destructive diagnostic pass on Windows:

```powershell
.\zerodesk-win-diag.exe
# Optional: skip watchdog spawn self-test
.\zerodesk-win-diag.exe --skip-watchdog
```

The command exits `0` only when all non-skipped diagnostic sections succeed, and emits a versioned (`schema_version: 1`) path-redacted JSON report containing:
- DXGI adapters, attached outputs, `AdapterLuid`s, and multi-monitor layout;
- Media Foundation hardware-only (`MFT_ENUM_FLAG_HARDWARE`) H.264/HEVC/AV1 MFTs, `any_hw_mft_found`, and `ok` (true strictly when at least one codec achieves `ExactLuidZeroCopy` against the primary DXGI adapter);
- UIPI elevation status (`TokenElevation`), `is_local_system` (`S-1-5-18`), `OpenInputDesktop` probe result, and UIPI limitation note;
- Non-destructive `zerodesk-hid-watchdog` spawn, heartbeat, and empty-batch release self-test (run on a clean thread before DXGI/MF initialization).

---

## 4. 3-Tier Verification Status

> **RELEASE GATE POLICY**: **NO Windows installer, binary release, or production rollout is permitted until ALL L3 items (`WIN-L3-01` through `WIN-L3-12`) PASS on real Windows GPU hardware (NVIDIA, AMD, and Intel)!**

| Tier | Scope | Status | Notes |
|---|---|---|---|
| **L1** | macOS cross-check (`x86_64-pc-windows-msvc` `check` & `clippy -D warnings`) + macOS host `clippy -D warnings` + full macOS unit tests (including all Windows pure logic modules & shared HID keymap vectors) + macOS Swift/TSan/App regression + SPDX/license compliance | **PASS** | Verified locally on macOS host in Phase 8B (see PR/commit verification report). |
| **L2** | `cargo-xwin` cross-compile / link check against Windows CRT/SDK | **PARTIAL / CHECK-ONLY** | Local `cargo-xwin` SDK cache used for `x86_64-pc-windows-msvc` type-checking & `clippy -D warnings` via header shims; full Windows binary linking (`libvpx`/`aom`/`libyuv`/`libopus`/`libsodium` Windows static `.lib` artifacts) requires a Windows MSVC/vcpkg build environment (no proprietary Windows SDK blobs committed into the repo). |
| **L3** | Real Windows 10/11 GPU hardware verification (`WIN-L3-01` .. `WIN-L3-12`) | **PENDING (BLOCKING RELEASE)** | Must be executed on physical NVIDIA / AMD / Intel Windows hosts before any Windows release or installer. |

---

## 5. L3 Windows Real-Machine Verification Checklist (`WIN-L3-01` – `WIN-L3-12`)

- [ ] **`WIN-L3-01` — Single-Command Diagnostics (`zerodesk-win-diag`)**: Run `zerodesk-win-diag.exe` on physical NVIDIA, AMD, and Intel GPU Windows hosts; verify structured JSON lists all DXGI adapters/outputs/LUIDs, enumerates hardware MFTs via `MFT_ENUM_FLAG_HARDWARE` with exact LUID match, probes UIPI + `OpenInputDesktop`, and passes watchdog spawn/heartbeat/empty-batch self-test.
- [ ] **`WIN-L3-02` — DXGI Multi-Monitor Capture, Cursor & Mode/DPI Switch**: Verify multi-monitor selection across heterogeneous DPI monitors, cursor position + Monochrome/Color/MaskedColor shape fidelity, and clean automatic `IDXGIOutputDuplication` recreation on display resolution / refresh-rate / DPI change (`DXGI_ERROR_ACCESS_LOST` / `DXGI_ERROR_MODE_CHANGE_IN_PROGRESS`).
- [ ] **`WIN-L3-03` — UAC / Lock Screen Pause & Resume**: Trigger UAC elevation prompt and `Win+L` lock screen during an active capture session; verify `DXGI_ERROR_SESSION_DISCONNECTED` / `E_ACCESSDENIED` transitions cleanly to `DesktopPaused` without crash/spin and resumes capture cleanly upon unlock.
- [ ] **`WIN-L3-04` — Media Foundation HW MFT LUID-Bound D3D11 NV12 Zero-Copy + First-IDR Gate**: Verify `MFT_ENUM_ADAPTER_LUID` matches the DXGI capture adapter LUID, `IMFDXGIDeviceManager` zero-copy NV12 encoding succeeds for H.264/HEVC, and `HardwareReady` is reported ONLY after the first `MFSampleExtension_CleanPoint` IDR frame encodes cleanly.
- [ ] **`WIN-L3-05` — Mid-Stream HW MFT Failure -> Bounded Reinit -> Explicit Renegotiation**: Inject GPU TDR / device reset (`DXGI_ERROR_DEVICE_RESET`) or forced MFT failure mid-stream; verify bounded reinit retries (up to 2) followed by explicit `"hardware_encoder_failed_renegotiate_vp9"` session renegotiation with ZERO silent software MFT fallback.
- [ ] **`WIN-L3-06` — `WinHidKeyMap` Physical Keyboard & Mouse Round-Trip**: Verify ANSI & ISO keys (`VK_OEM_102`), extended navigation & arrow keys (`KEYEVENTF_EXTENDEDKEY`), numpad keys, all 8 distinct left/right modifiers (`L/R Ctrl/Shift/Alt/Win`), absolute virtual-desktop mouse positioning, wheel/hwheel, and all 5 mouse buttons (`Left`, `Right`, `Middle`, `X1`, `X2`).
- [ ] **`WIN-L3-07` — Watchdog `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` Grandchild-Spawn EOF**: Spawn a long-lived grandchild process from the host while holding keys down, then `TerminateProcess` the host; verify the grandchild did NOT inherit the watchdog pipe handle and the watchdog triggers immediate emergency release on pipe EOF / parent exit.
- [ ] **`WIN-L3-08` — Watchdog `WaitForMultipleObjects` + `GetProcessTimes` PID-Reuse Guard + Single-Batch Torture Test**: Hold multiple keys + modifiers + mouse buttons simultaneously and hard-kill the host repeatedly; verify `GetProcessTimes` creation-time validation prevents false triggers on PID reuse and ONE atomic `SendInput` batch leaves zero stuck keys or buttons.
- [ ] **`WIN-L3-09` — Watchdog Heartbeat-Timeout Release on Frozen Host**: Freeze the host process (`SuspendThread` / debugger break so process stays alive with open pipe) while holding keys; verify `WatchdogHeartbeatTracker` fires after `heartbeat_timeout_ms` and executes full emergency batch release.
- [ ] **`WIN-L3-10` — `OpenInputDesktop` / `SetThreadDesktop` & UIPI Elevated-Window Negative Test**: Verify emergency release succeeds across desktop switch via `OpenInputDesktop`/`SetThreadDesktop`, and verify negative UIPI behavior (standard user host targeting an elevated `Administrator` window reports `uipi_elevated: false` and surfaces `SendInput` shortfall in `residual_*` without crashing).
- [ ] **`WIN-L3-11` — Cross-OS E2E Session**: Establish end-to-end encrypted V2 sessions in both directions (macOS controller <-> Windows controlled host, and Windows controller <-> macOS controlled host) verifying video, HID input, emergency escape hotkey (`Ctrl+Alt+Win+Escape` / `Ctrl+Opt+Cmd+Escape`), and clean teardown.
- [ ] **`WIN-L3-12` — 30-Minute 1080p60 Hardware Soak Test**: Run a sustained 30-minute 1080p60 session on real GPU hardware verifying stable frame pacing, end-to-end latency, zero COM/GDI/HANDLE leaks (`HandleCount` flat), and bounded RSS/VRAM usage.
