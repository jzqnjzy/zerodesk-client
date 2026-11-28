<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (c) 2026 ZeroDesk Contributors -->

# ZeroDesk Linux Platform Support (Phase 9B)

## 1. Architecture Overview

ZeroDesk's Linux platform backend mirrors the Phase 8B Windows **thin-FFI / testable-logic** split inside `libs/zerodesk_core/src/os/`:

```
Cross-Platform Traits (`os/traits.rs`)
├── ScreenCapturer       ──► macOS:   ScreenCaptureKit / CoreGraphics (`OsScreenCaptureAdapter`)
│                        ──► Windows: `WinDxgiCapturer` (`os/win_dxgi.rs` + `os/win_dxgi_logic.rs`)
│                        ──► Linux:   `LinuxScreenCapturer` (`os/linux_capture.rs` + `os/linux_capture_logic.rs`)
│                                     ├── Wayland: `xdg-desktop-portal` ScreenCast + PipeWire (`dlopen("libpipewire-0.3.so.0")`)
│                                     └── X11:     `XShm` + `XRandR` + `XFixes` (`dlopen("libX11.so.6")` + `libXext/Xrandr/Xfixes`)
├── HardwareCodec /      ──► macOS:   VideoToolbox (`MacVtHardwareEncoder` / `MacVtHardwareDecoder`)
│   HardwareVideoEncoder ──► Windows: `WinMfHardwareEncoder` (`os/win_mf.rs` + `os/win_mf_logic.rs`)
│                        ──► Linux:   `LinuxVaapiHardwareEncoder` (`os/linux_vaapi.rs` + `os/linux_vaapi_logic.rs`)
│                                     └── Runtime `dlopen("libva.so.2")` + `dlopen("libva-drm.so.2")` (Intel iHD/i965 & AMD Mesa radeonsi ONLY)
├── OsInputInjector      ──► macOS:   `MacOsHidSink` (`OsHidSinkInjector`)
│                        ──► Windows: `WinOsInputInjector` (`os/win_input.rs` + `os/win_hid_keymap.rs`)
│                        ──► Linux:   `LinuxOsInputInjector` (`os/linux_input.rs` + `os/linux_hid_keymap.rs`)
└── HidWatchdogBackend   ──► macOS:   `UnixHidWatchdogBackend` (`kqueue EVFILT_PROC NOTE_EXIT`)
                         ──► Windows: `WinHidWatchdogBackend` (`WaitForMultipleObjects` + `GetProcessTimes`)
                         ──► Linux:   `LinuxHidWatchdogBackend` (`os/linux_watchdog.rs` + `os/linux_watchdog_logic.rs` + `zerodesk-hid-watchdog`)
```

All Linux state machines, session detectors, PipeWire/XShm bounds validators, VA-API driver allowlist & stability-window logic, bidirectional HID-to-`evdev` tables, 3-tier input access degradation plans, dual-layer stuck-key release planners, `/proc/<pid>/stat` parsers, and `/proc/self/fd` leak auditors live in **platform-agnostic modules** compiled and unit-tested on macOS, Windows, and Linux.

### Key Module Map

| Layer | Pure Logic (Tested on macOS & Linux) | Thin `#[cfg(target_os = "linux")]` Runtime FFI (Zero `.so` Link) |
|---|---|---|
| Dynamic Loader | — | `libs/zerodesk_core/src/os/linux_dl.rs` |
| Screen Capture | `libs/zerodesk_core/src/os/linux_capture_logic.rs` | `libs/zerodesk_core/src/os/linux_capture.rs` |
| VA-API HW Codec | `libs/zerodesk_core/src/os/linux_vaapi_logic.rs` | `libs/zerodesk_core/src/os/linux_vaapi.rs` |
| Keymap & Input | `libs/zerodesk_core/src/os/linux_hid_keymap.rs` | `libs/zerodesk_core/src/os/linux_input.rs` |
| Independent Watchdog | `libs/zerodesk_core/src/os/linux_watchdog_logic.rs` | `libs/zerodesk_core/src/os/linux_watchdog.rs` + `src/bin/zerodesk-hid-watchdog.rs` |
| Built-in Diagnostics | `libs/zerodesk_core/src/os/linux_diag.rs` | `libs/zerodesk_core/src/bin/zerodesk-linux-diag.rs` |

---

## 2. Clean-Room, License & Zero-Linkage Guarantees

- **100% AGPL-3.0-only Clean-Room**: Zero copied Linux kernel headers; all `evdev` (`KEY_*`, `BTN_*`, `EV_*`), `uinput` (`UI_SET_*`, `UI_DEV_SETUP`), `PR_SET_PDEATHSIG`, `SYS_pidfd_open`, and VA-API (`VAStatus`, `VAProfile`, `VAEntrypoint`) ABI constants are hand-written clean-room definitions.
- **Zero New Third-Party Dependencies**: Reuses workspace `libc`, `serde`, `serde_json`, `hex`, and `rand_core`; zero GPL-2.0 crates introduced.
- **Zero Proprietary SDKs**: Zero Intel MediaSDK and zero proprietary NVENC SDKs. VA-API targets open-source Intel (`iHD`, `i965`) and AMD Mesa (`radeonsi`) hardware stacks exclusively.
- **Zero Compile-Time `.so` Linkage**: All Linux desktop/media shared objects (`libva.so.2`, `libva-drm.so.2`, `libpipewire-0.3.so.0`, `libX11.so.6`, `libXext.so.6`, `libXrandr.so.2`, `libXfixes.so.3`, `libXtst.so.6`) are loaded at runtime via `DynLib` (`dlopen(RTLD_NOW | RTLD_LOCAL)`).

---

## 3. Wayland / X11 Permission Boundary Matrix

ZeroDesk enforces a strict **3-tier Linux input degradation chain** (`resolve_linux_input_access_plan`) and NEVER silently falls back or silently escalates privileges:

| Session | Screen Capture Backend | Default Input Backend | `/dev/uinput` Status | Security / UX Boundary |
|---|---|---|---|---|
| **Wayland** (`portal` present) | `xdg-desktop-portal` ScreenCast + PipeWire (DMA-BUF / MemFd SHM + restore token) | `org.freedesktop.portal.RemoteDesktop` | **Disabled by default** (`DisabledByDefault`) | Compositor-enforced consent prompt, active remote session notice required, emergency escape shortcut (`Ctrl+Alt+Super+Escape`). |
| **Wayland** (no `portal`) | Denied (`PermissionDenied(ScreenRecording)`) | **`ExplicitDeny`** | **Disabled by default** | NEVER silently falls back to `XTest` (cannot inject into native Wayland windows) or `/dev/uinput`. |
| **X11** (`XShm` + `XTest`) | `XShm` + `XRandR` + `XFixes` cursor | `X11 XTest` (`libXtst.so.6`) | **Disabled by default** | Operates within the user's X11 display cookie (`XAUTHORITY`) boundary. |
| **X11** (no `XTest`) | `XShm` + `XRandR` + `XFixes` | **`ExplicitDeny`** | **Disabled by default** | Fails closed with explicit diagnostic reason. |
| **Any / Headless** (explicit opt-in `--opt-in-uinput` + writable `/dev/uinput`) | Session-dependent | **`UinputRootEquivalentOptIn`** | **`OptInActiveHighPrivilegeWarning`** | **Root-equivalent input boundary**: emits mandatory high-privilege warning in diagnostics and logs; requires explicit user/admin opt-in AND narrow udev ACLs. If requested without write permission, logs `OptInRequestedPermissionDenied` and falls back explicitly to the standard chain. |

---

## 4. VA-API Open-Source Hardware Codec Policy

1. **Open-Source Hardware Allowlist (`VaapiDriverClass`)**:
   - **Allowed**: `IntelIhd` (`Intel iHD` / `intel-media-driver`), `IntelI965` (`Intel i965`), `AmdRadeonsiMesa` (`Mesa Gallium` / `radeonsi` AMD).
   - **Explicitly Rejected**: Software rasterizers (`llvmpipe`, `swrast`, `softpipe`, `lavapipe`, `virgl`) and proprietary/unknown bridges (`nvidia`, `vdpau`, `nvenc`, `mediasdk`, unknown/empty).
2. **Strict First-IDR Readiness Gate**:
   - `vaInitialize` / `vaCreateConfig` NEVER marks the encoder `HardwareReady`.
   - Transitions to `HardwareReady` **ONLY** when the first IDR keyframe produces `byte_len > 0` within both frame-count (`15` frames) and wall-clock (`2000ms`) ceilings while in `WaitingFirstIdr`.
3. **30-Frame Stability Window (`STABLE_FRAMES_TO_RESET_REINIT = 30`)**:
   - Mid-stream `NeedsReinit` VA-API errors execute bounded retries (default max `2`).
   - `reinit_attempts` resets to `0` **ONLY** after 30 consecutive good frames in `HardwareReady`, preventing infinite hardware flapping.
   - Exhausting retries transitions to terminal idempotent `FailedNeedsRenegotiation` emitting `"hardware_encoder_failed_renegotiate_vp9"` — **NEVER** silently switching to software encoding.
4. **Phase 9A QoE Integration**:
   - `validate_and_clamp_rate_control()` validates and clamps `qoe::EncoderTarget` (`media_bitrate_kbps`, `fps_cap`, even-aligned `width`/`height`, `force_idr`) onto safe VA-API hardware bounds.

---

## 5. Independent HID Watchdog: Dual-Layer Release & Anti-PID-Reuse

### 5.1 Dual-Layer Stuck-Key Release Guarantee
Both parent `SIGKILL` and the emergency escape hotkey (`Ctrl+Alt+Super+Escape`) execute ONE unified dual-layer release plan (`LinuxWatchdogShadowSet::build_dual_layer_release_plan`):

1. **Layer 1 (Primary — Mandatory)**: Explicitly injects `EV_KEY` (`value = 0`) for **every** tracked pressed key in the authoritative shadow set, **all 8 left/right modifiers** (`0xE0..=0xE7`) unconditionally, and **all 5 mouse buttons** (`BTN_LEFT..BTN_EXTRA`), followed immediately by **`EV_SYN / SYN_REPORT`** (or `XTestFakeKeyEvent(..., 0)` + `XTestFakeButtonEvent(..., 0)` + `XFlush` on X11).
2. **Layer 2 (Secondary Backup ONLY)**: Strictly **after** `SYN_REPORT` flushes, destroys and closes `uinput_fd` (`UI_DEV_DESTROY` + `close`). Kernel auto-release on `uinput` close is strictly defense-in-depth and NEVER relied upon as the sole release path.
3. **Release SLA**: Target full release latency **`<= 500ms`** from parent `SIGKILL` or emergency hotkey.

### 5.2 Anti-PID-Reuse & Fork-Race Hardening
- **`fork()` -> `PR_SET_PDEATHSIG` Race Guard**: Immediately after `fork()`, the child arms `prctl(PR_SET_PDEATHSIG, SIGTERM)` and **immediately** validates `getppid() == expected_ppid` (`ForkRaceGuardStateMachine`), catching any parent death in the microsecond window between `fork()` and `prctl()`, followed by the ready-pipe `Hello`/`Ready` handshake.
- **Primary Parent Monitor (`LinuxParentMonitorMode::PidFd`)**: Uses `syscall(SYS_pidfd_open, parent_pid, 0)` + `poll([cmd_fd, pidfd])` (Linux >= 5.3) — kernel-guaranteed immunity against PID reuse.
- **Legacy Fallback (`LinuxParentMonitorMode::FallbackLegacyProcStat`)**: Used ONLY when `pidfd_open` is unsupported (`ENOSYS` on pre-5.3 kernels). Verifies BOTH `getppid() == expected_ppid` AND `/proc/<pid>/stat` **field 22 (`starttime`)**, safely parsing `comm` fields containing spaces and nested parentheses via first-`(` / last-`)` scanning (`parse_proc_stat`).
- **Zero Descriptor Leaks**: All supervisor pipes use `O_CLOEXEC`; the watchdog audits `/proc/self/fd` (`audit_open_fds_for_close`) after dropping its `ReadDir` handle and closes every unexpected fd outside `[0, 1, 2, cmd_fd, ack_fd, lock_fd, uinput_fd, pidfd]`.

---

## 6. Built-in Diagnostic Tool (`zerodesk-linux-diag`)

```bash
# Default redacted JSON output
./zerodesk-linux-diag --json

# Human-readable summary
./zerodesk-linux-diag --summary

# Optional flags on Linux hosts
./zerodesk-linux-diag --skip-watchdog
./zerodesk-linux-diag --opt-in-uinput
```

---

## 7. 3-Tier Verification Status

> **RELEASE GATE POLICY**: **NO Linux binary release, AppImage/deb/rpm package, or production rollout is permitted until ALL 12 L3 items (`LIN-L3-01` through `LIN-L3-12`) PASS on real Linux Intel/AMD Wayland and X11 desktop hardware!**

| Tier | Scope | Status | Notes |
|---|---|---|---|
| **L1** | macOS cross-check (`x86_64-unknown-linux-gnu` `check` & `clippy -D warnings` including `zerodesk-linux-diag` with ZERO host Linux `.so`s) + macOS full unit/integration tests (`linux_*_logic`, 3-platform `hid_keymap_vectors`) + Windows `cargo xwin` regression + macOS Swift regression + 5/5 SPDX/license compliance | **PASS** | Verified locally on macOS host in Phase 9B. |
| **L2** | Full Linux ELF binary link & non-GPU Linux container test execution | **PENDING (Linux CI / Container)** | Cross-linking workspace C/media libs (`libvpx`/`aom`/`libyuv`/`libopus`/`libsodium`) requires a Linux toolchain/sysroot. |
| **L3** | Real Linux Intel & AMD GPU hardware verification (`LIN-L3-01` .. `LIN-L3-12`) | **PENDING (待 Linux 实机验收 — BLOCKING RELEASE)** | Cannot be forged or simulated on macOS; every item below MUST be executed on physical Linux hosts. |

---

## 8. L3 Linux Real-Machine Verification Checklist (`LIN-L3-01` – `LIN-L3-12`)

- [ ] **`LIN-L3-01` — Wayland `xdg-desktop-portal` ScreenCast + PipeWire Frame Arrival** *(待 Linux 实机验收)*: On GNOME/KDE Wayland, complete portal `CreateSession -> SelectSources -> Start`, verify PipeWire DMA-BUF and MemFd SHM frame arrival with row-by-row copy bounds checks, and verify restore token reuse & invalidation on user `AccessDenied`.
- [ ] **`LIN-L3-02` — X11 `XShm` Multi-Monitor + `XRandR` Hot-Switch + `XFixes` Cursor** *(待 Linux 实机验收)*: On multi-monitor X11 (including rotated 90°/270° monitor), verify monitor selection, `XFixesGetCursorImage` ARGB->BGRA cursor rendering, `XRandR` resolution/topology switch recovery, and `BadMatch` automatic `XShm` re-attach.
- [ ] **`LIN-L3-03` — VA-API Open-Source Driver Probe & Allowlist Enforcement** *(待 Linux 实机验收)*: On physical Intel (`iHD` / `i965`) and AMD (`Mesa radeonsi`) Linux hosts, verify `probe_vaapi_device()` accepts open-source hardware drivers and rejects `llvmpipe` / `swrast` (forced via `LIBVA_DRIVER_NAME`) with ZERO silent software fallback.
- [ ] **`LIN-L3-04` — VA-API First-IDR `HardwareReady` Gate** *(待 Linux 实机验收)*: Verify `LinuxVaapiHardwareEncoder` stays in `WaitingFirstIdr` until the first valid non-empty H.264/HEVC IDR keyframe is emitted, and fails explicitly if first-IDR frame/time budget is exceeded.
- [ ] **`LIN-L3-05` — VA-API 30-Frame Stability Window & Explicit Renegotiation** *(待 Linux 实机验收)*: Inject mid-stream VA-API context/GPU reset faults on Intel and AMD hardware; verify flapping before 30 good frames consumes bounded reinit budget (`2`), 30 consecutive good frames resets the counter, and budget exhaustion emits `"hardware_encoder_failed_renegotiate_vp9"` with ZERO silent software fallback.
- [ ] **`LIN-L3-06` — VA-API Dynamic Phase 9A QoE Bitrate / FPS / Force-IDR Control** *(待 Linux 实机验收)*: Drive `LinuxVaapiHardwareEncoder` with live `QoeEngine` `EncoderTarget` updates (bitrate steps, FPS cap changes, `force_idr`), verifying output bitrate tracks targets and immediate IDR generation on demand.
- [ ] **`LIN-L3-07` — `LinuxHidKeyMap` Physical Key & Mouse Injection + Portal/XTest Degradation** *(待 Linux 实机验收)*: Verify all 106 keys (ANSI + ISO `KEY_102ND`, keypad, F1-F12, Pause/PrintScreen, all 8 distinct L/R modifiers) and all 5 mouse buttons across Wayland portal RemoteDesktop, X11 XTest, and explicit opt-in `/dev/uinput`, plus verify `ExplicitDeny` when portal/XTest are absent and uinput is default-off.
- [ ] **`LIN-L3-08` — Opt-In `/dev/uinput` Permission & High-Privilege Warning Gate** *(待 Linux 实机验收)*: Verify `/dev/uinput` stays strictly `DisabledByDefault` even when writable, emits `OptInRequestedPermissionDenied` when opted in without udev write permission, and logs `UINPUT_ROOT_EQUIVALENT_WARNING` when explicitly opted in and writable.
- [ ] **`LIN-L3-09` — Independent Watchdog Parent `SIGKILL` Dual-Layer Release (`<= 500ms`)** *(待 Linux 实机验收)*: Hold multiple keys + modifiers + mouse buttons down, `kill -9` the host process repeatedly, verify `pidfd_open`+`poll` detects parent death immediately and executes Layer 1 explicit `EV_KEY=0` + `EV_SYN SYN_REPORT` BEFORE Layer 2 `close(uinput_fd)`, leaving zero stuck keys within `<= 500ms`.
- [ ] **`LIN-L3-10` — Watchdog Legacy `/proc/<pid>/stat` Fallback & Emergency Escape Hotkey** *(待 Linux 实机验收)*: Test `FallbackLegacyProcStat` (`starttime` PID-reuse guard with spaces/parentheses in process `comm`) and verify `Ctrl+Alt+Super+Escape` triggers the exact same full dual-layer release sequence.
- [ ] **`LIN-L3-11` — Watchdog Zero Descriptor Leak Audit (`/proc/self/fd`) & Fork-Race Check** *(待 Linux 实机验收)*: Spawn host with extra open fds, start watchdog, inspect `/proc/<watchdog_pid>/fd` to confirm ONLY `[0, 1, 2, cmd_fd, ack_fd, lock_fd, pidfd/uinput_fd]` remain open (`leaked_fds_detected == 0`) and confirm `PR_SET_PDEATHSIG` + `getppid()` verification prevents orphan watchdogs.
- [ ] **`LIN-L3-12` — `zerodesk-linux-diag` Real-Machine Audit & 30-Minute 1080p60 Soak** *(待 Linux 实机验收)*: Run `zerodesk-linux-diag --json` and `--summary` on physical Wayland + X11 hosts verifying path-redacted valid JSON, then execute a 30-minute 1080p60 cross-OS session (Linux <-> macOS/Windows) verifying flat FD/RSS/VRAM counts and clean teardown.
