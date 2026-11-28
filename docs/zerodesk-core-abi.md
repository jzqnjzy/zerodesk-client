<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (c) 2026 ZeroDesk Contributors -->

# ZeroDesk Core (`libs/zerodesk_core`) — C-ABI, Licensing & Platform Notes

## 1. Stable C-ABI Contract (`include/zerodesk_v2.h`)

- **ABI Version**: `zerodesk_v2_abi_version()` returns `1` (`ZERODESK_V2_ABI_VERSION` / `BRIDGE_ABI_VERSION` — C-ABI and JSON envelope `"v": 1`). Additive JSON-ABI v2 capabilities are advertised via `handshake` / `get_capabilities` / `BridgeSnapshot` with `"abi_version": 2` (`BRIDGE_JSON_ABI_V2`) and `"caps": [...]`.
- **Opaque Handle Table**: `zerodesk_v2_create(&handle)` allocates a monotonically increasing `uint64_t` handle (`0` is always invalid). Double-destroy and use-after-destroy deterministically return `ZERODESK_ERR_INVALID_HANDLE (-2)` without undefined behavior.
- **Panic Boundary**: Every `extern "C"` symbol is wrapped in `std::panic::catch_unwind` and returns `ZERODESK_ERR_PANIC (-10)` if a panic ever crosses the boundary.
- **Length-Prefixed UTF-8**: All string inputs take `(const uint8_t *ptr, size_t len)` and are strictly validated as UTF-8 (`ZERODESK_ERR_INVALID_UTF8 (-3)` on bad UTF-8; embedded NUL bytes are never silently truncated).
- **Owned Outputs**: All heap outputs return `ZeroDeskOwnedBuffer { ptr, len, cap }`. Callers **must** release non-empty buffers exclusively via `zerodesk_v2_buffer_free(buf)` (never via C `free()`).
- **Binary Entrypoints**:
  - `zerodesk_v2_send_clipboard_png(handle, data_ptr, data_len, out_reply_json)` validates PNG magic + IHDR dimensions without decoding pixels (no JSON base64 overhead).
  - `zerodesk_v2_send_file(handle, path_ptr, path_len, out_reply_json)` reads directly from the filesystem path.
- **Two-Phase Zero-Tear Frame Delivery**:
  1. `zerodesk_v2_frame_info(handle, &info)` reads latest frame dimensions, stride, `pixel_format` (`1 = BGRA8`, `2 = RGBA8`), `byte_len`, `pts_ms`, and `dropped_ui_frames` without copying pixels.
  2. `zerodesk_v2_take_latest_frame(handle, out_buf, out_cap, &info)` clones the `Arc<DecodedFrame>` under a short lock and copies pixels outside the lock. If `out_cap < info.byte_len`, it returns `ZERODESK_ERR_BUFFER_TOO_SMALL (-4)` and writes the required `byte_len` into `out_info` without modifying a single byte of `out_buf`.
- **Event Polling & Coalescing**:
  - `zerodesk_v2_poll_event_json` (non-blocking) and `zerodesk_v2_poll_event_json_timeout` (condition-variable wait, zero busy-spin).
  - `VideoFrameReady` is **synthesized on demand** from `FrameMailbox::latest_seq()` rather than pushed into the event queue, ensuring natural coalescing and zero critical-event queue starvation.
- **Error Codes**:
  - `0`: `ZERODESK_OK`
  - `-1`: `ZERODESK_ERR_INVALID_ARG`
  - `-2`: `ZERODESK_ERR_INVALID_HANDLE`
  - `-3`: `ZERODESK_ERR_INVALID_UTF8`
  - `-4`: `ZERODESK_ERR_BUFFER_TOO_SMALL`
  - `-5`: `ZERODESK_ERR_TIMEOUT`
  - `-6`: `ZERODESK_ERR_NO_EVENT`
  - `-7`: `ZERODESK_ERR_NO_FRAME`
  - `-8`: `ZERODESK_ERR_BUSY`
  - `-9`: `ZERODESK_ERR_INTERNAL`
  - `-10`: `ZERODESK_ERR_PANIC`

## 2. AGPL-3.0 Combined-Work Boundary

`libs/zerodesk_core` is licensed under **GNU AGPL-3.0-only**.
Exposing a C-ABI (`include/zerodesk_v2.h`) does **not** weaken or bypass AGPL-3.0 copyleft: linking `libzerodesk_core` (statically or dynamically) from a Flutter, Swift, C/C++, or Electron host application forms a single **AGPL-3.0 combined work**, and the corresponding source code of the combined work must be made available under GNU AGPL-3.0-only in compliance with AGPL-3.0 §5 and §13.

## 3. macOS Permissions & Platform Constraints

- **Screen Recording (`ScreenRecording`)**:
  - Preflighted non-interactively via `CGPreflightScreenCaptureAccess()` before calling `CGDisplayCreateImage`.
  - Missing permission fails closed with `PermissionDenied(ScreenRecording)` without popping interactive system prompts.
  - A `NULL` image after a passing preflight returns retryable `CaptureFailed`, never misreported as `PermissionDenied`.
  - Retina HiDPI `bytes_per_row` stride is passed directly into `libyuv` (`ARGBToI420`), and `CGImageGetBitmapInfo` is validated fail-closed.
- **Accessibility (`Accessibility`) & Real Input**:
  - Real OS HID injection is **triple-gated**: `cfg(target_os = "macos")` + opt-in Cargo feature `real-input` (never in `default`) + runtime `RealInputPermit` (`--real-os-input`) + `AXIsProcessTrusted()`.
  - Every new session starts in **View-Only** mode (`enable_os_input = false`, per-session only, never persisted). Enabling OS input requires BOTH Screen Recording and Accessibility permissions; otherwise all remote input is dropped immediately with stable status `"not_permitted"` and zero queuing/buffering.
  - **macOS TCC Responsible-Process Semantics (Developer Note)**: macOS TCC attributes `AXIsProcessTrusted()` to the *responsible process* performing `CGEventPost`. When launched via `ZeroDesk.app`, the spawned `zerodesk-hid-watchdog` subprocess inherits the `ZeroDesk.app` bundle identity; during CLI/dev runs (`cargo test` / `swift run`), child processes inherit the launching terminal (e.g. Terminal.app / iTerm2 / IDE). Accordingly, `get_permissions` / `permission_status` reports canonical `probe_source` values with strict precedence:
    1. `"watchdog"` (authoritative live probe from `zerodesk-hid-watchdog` subprocess, refreshed dynamically via IPC heartbeat and immediately reset to `false` on child exit),
    2. `"injector_process"` (authoritative probe from an in-process HID injector; legacy alias `"watchdog_or_injector_process"` accepted for backward compatibility),
    3. `"ui_process_hint"` (non-authoritative UI-process hint only; **fail-closed**: `ui_process_hint` can **NEVER** authorize `enable_os_input = true`, even when `accessibility_granted == true`).
  - `IsSecureEventInputEnabled()` is surfaced in `os-selftest` so UIs can warn when password/secure fields block synthetic input.
- **Microphone (`Microphone` / Audio)**:
  - `cpal` requests 48 kHz / 2 ch / `f32` with a lock-free, allocation-free SPSC ring buffer inside the CoreAudio callback.
  - Missing devices or rejected stream formats degrade gracefully to silent audio and emit `AudioStatusChanged { available: false, reason }` without aborting the session.
- **Clipboard (macOS 15.4+ Pasteboard Privacy Notice)**:
  - On macOS 15.4+, reading `NSPasteboard` text can trigger a user-visible paste notification. `os-selftest` strictly reads `NSPasteboard.changeCount` only (zero reads of clipboard contents, zero writes).
  - Live sessions pre-filter with `changeCount` + primary SHA-256 deduplication and one-shot anti-echo suppression (`A -> B -> A` safe). Clipboard text/bytes are never logged or included in snapshots/events.

## 4. Known Limitations

- **ANSI Positional Keycode Mapping**: `hid_usage_to_macos_keycode()` maps USB HID Usage Page `0x07` codes using a strict ANSI positional allowlist (unknown usages return `None` and are never injected). Non-ANSI physical ISO/JIS extra keys are deferred to a future layout-aware mapping pass.
- **In-Process `SIGKILL` Key-Release Limitation**: `EmergencyKeyReleaser` guarantees deterministic key/button release within `<= 500ms` across normal disconnect, heartbeat watchdog timeout, `SIGTERM`/cancel, and worker task panics (`catch_unwind`). However, an uncaught `SIGKILL` terminates the process immediately before any in-process handler can execute; an out-of-process watchdog helper subprocess to cover `SIGKILL` is planned for **Phase 6**.
