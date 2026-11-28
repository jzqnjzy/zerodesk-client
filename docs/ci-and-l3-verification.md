<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (c) 2026 ZeroDesk Contributors -->

# ZeroDesk 3-Platform CI & Honest L2/L3 Verification Guide

## 1. Three-Platform CI Architecture

The single-file workflow [`.github/workflows/zerodesk-ci.yml`](../.github/workflows/zerodesk-ci.yml) validates `libs/zerodesk_core` and platform artifacts across Linux, Windows, and macOS under strict least-privilege and branch isolation rules:

- **Branch Scope**: Triggers **only** on `zerodesk/main` (`push` and `pull_request`) plus manual `workflow_dispatch`. Upstream `master` is never triggered or modified.
- **Least Privilege**: Top-level `permissions: contents: read` with zero `write` scopes anywhere; every `actions/checkout` enforces `persist-credentials: false` and `submodules: recursive`. No `pull_request_target`, no `curl | bash`, and no unpinned third-party Actions.
- **Dependency Alignment**: In `libs/zerodesk_core/Cargo.toml`, `v2_client` is an unconditional crate dependency (not a Cargo feature), so native CI jobs run `zerodesk_core` with its real default feature set (`--locked`). Linux additionally enables `--features scrap/linux-pkg-config` to link system apt codec libraries deterministically without vcpkg overhead.

### Job Graph

| Job | Runner | Timeout | Scope |
|---|---|---|---|
| `compliance-linux` | `ubuntu-24.04` | 60m | Minimal `--no-install-recommends` apt deps, `./scripts/check-compliance.sh` (5/5), 11 Phase 8A ABI golden SHA-256 verification, native Linux `clippy -D warnings` + `cargo test`, `scripts/verify-linux-l3.sh --mode ci` + schema check, upload scrubbed report (14d retention). |
| `windows-native` | `windows-latest` | 90m | Pinned `vcpkg` static cache (`libvpx`, `aom`, `libyuv`, `opus`, `libsodium` for `x64-windows-static` with `./res/vcpkg` overlays), native MSVC `clippy -D warnings` + `cargo test`, `scripts/verify-windows-l3.ps1 -Mode ci` + schema check, upload scrubbed report (14d retention). |
| `macos-native` | `macos-15` | 60m | Homebrew `libsodium`/`libvpx`/`aom`/`opus` + cached pinned static `libyuv` (`ZERODESK_LIBYUV_PREFIX`), native `clippy -D warnings` + `cargo test`, `./scripts/build-macos-app.sh` + `codesign --verify --deep --strict`, `swift test --sanitize=thread`, upload scrubbed summary (14d retention). |
| `collect-artifacts` | `ubuntu-24.04` | 15m | Depends on all 3 platform jobs (`if: always()`), downloads scrubbed reports, publishes a GitHub Job Summary table, and fails if any upstream platform job failed. |

---

## 2. Pinned Action & Native Source Commit Registry

Every external GitHub Action and native C++ source dependency in `.github/workflows/zerodesk-ci.yml` is pinned to an immutable 40-character commit SHA verified via `git ls-remote`:

| Action / Dependency | Pinned Reference | Immutable Commit SHA |
|---|---|---|
| `actions/checkout` | `v7.0.1` | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/upload-artifact` | `v7.0.2` | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| `actions/download-artifact` | `v8.0.2` | `9000827ccba6bdab643e8b6fd33ac0654aef8333` |
| `actions/cache` | `v6.1.0` | `55cc8345863c7cc4c66a329aec7e433d2d1c52a9` |
| `dtolnay/rust-toolchain` | `stable` (`refs/heads/stable`) | `39008827e6b4319a349e9a42dfc90579dd25f1ca` |
| `Swatinem/rust-cache` | `v2.9.3` (`v2.9.3^{}`) | `d1527c8f67ef9af357290475d4af4b0fab8f12e0` |
| `microsoft/vcpkg` (Windows static libs) | `vcpkg.json` baseline | `9e593bb18ea69cc5095e012465dcd675a822ed0d` |
| `chromium/libyuv` (macOS static `libyuv.a`) | `res/vcpkg/libyuv/portfile.cmake` | `0faf8dd0e004520a61a603a4d2996d5ecc80dc3f` |

---

## 3. Honest L2 (Headless CI) vs L3 (Physical Hardware) Boundary

Headless GitHub Actions runners lack physical GPUs, multi-monitor displays, interactive desktop sessions, and physical HID pipelines. ZeroDesk enforces an **honest 6-state status machine** defined in [`scripts/l3-report-schema.json`](../scripts/l3-report-schema.json) (JSON Schema Draft 2020-12):

| Status | Meaning | Allowed in `--mode ci`? |
|---|---|---|
| `PASS` | Full physical hardware / interactive L3 verification succeeded with an 8-hex-char SHA-256 `hardware_fingerprint`. | **FORBIDDEN** (code-level abort exit `30` + schema rejection) |
| `L2_NATIVE_PASS` | Deterministic headless native OS probe succeeded on a real Windows/Linux runner (does **not** satisfy L3 release gate). | Yes |
| `PENDING_PHYSICAL_L3` | Requires physical GPU, real display, interactive session, or sustained soak on real hardware. | Yes |
| `SKIPPED_NO_HARDWARE` | Hardware-gated check skipped on a machine lacking the target device. | Yes |
| `SKIPPED_UNSUPPORTED_PLATFORM` | Cross-platform `--dry-run` / `-DryRun` on a non-target OS (e.g., macOS). | Yes |
| `FAIL` | Native probe failed, binary crashed, schema violated, or security invariant regressed. | Yes (fails CI with exit `20`) |

### PROBE-NOT-PATCH & Privacy Redaction Guarantees

Both [`scripts/verify-windows-l3.ps1`](../scripts/verify-windows-l3.ps1) and [`scripts/verify-linux-l3.sh`](../scripts/verify-linux-l3.sh) are strictly read-only and idempotent:
- **Zero OS mutations**: Never writes HKLM registry, never installs drivers/services, never calls `modprobe`, `systemctl enable`, `sudo`/`pkexec`, or UAC elevation, never initiates network calls, and never dumps environment variables.
- **Scrubbing (`scrub()` / `Scrub-Text`)**: Replaces home paths (`$HOME`, `%USERPROFILE%`), usernames, hostnames, and repository prefixes with `<HOME>`, `<USER>`, `<HOST>`, `<REPO>`. Hardware LUIDs / DRM render-node identifiers are hashed to the first 8 lowercase hex characters of SHA-256.
- **Atomic writes**: Reports are written to a sibling temp file and atomically moved into place (`Move-Item -Force` / `os.replace`).

### Unified Exit Code Contract

| Exit Code | Condition |
|---|---|
| `0` | `--mode ci` with `fail == 0`; OR cross-platform `--dry-run` / `-DryRun`; OR `--mode strict-l3` with `12/12 PASS`. |
| `10` | `--mode strict-l3` with `fail == 0` and at least one item not `PASS` (e.g., `PENDING_PHYSICAL_L3`). |
| `20` | At least one verification item reported `FAIL`. |
| `30` | Script error, invalid CLI arguments, or CI anti-forgery invariant violation. |
| `40` | Unsupported platform without `--dry-run` / `-DryRun`. |

### Windows & Linux L2 vs L3 Mapping

| IDs | Headless CI (`--mode ci`) | Physical Machine (`--mode strict-l3`) |
|---|---|---|
| `WIN-L3-01`, `07`, `08`, `10` | **`L2_NATIVE_PASS`** — Runs `zerodesk-win-diag.exe` schema v1 audit, Win32 `LockFileEx`, `GetProcessTimes`, `OpenInputDesktop` / UIPI read-only probes. | Physical GPU LUID `ExactLuidZeroCopy` (`WIN-L3-01` upgrades to `PASS` on physical GPU); `07`/`08`/`10` interactive torture & elevated-window tests required for `PASS`. |
| `WIN-L3-02..06`, `09`, `11`, `12` | **`PENDING_PHYSICAL_L3`** — Verifies `d3d11.dll`, `dxgi.dll`, and `mfplat.dll` System32 loadability (`02`, `04`), defers DXGI first-frame, NVENC/QSV/AMF IDR, UAC/Win+L, physical SendInput, frozen-host, cross-OS, and 30m soak. | Executed on physical NVIDIA, AMD, and Intel Windows 10/11 hosts. |
| `LIN-L3-08`, `09`, `10`, `11` | **`L2_NATIVE_PASS`** — Runs `zerodesk-linux-diag --json`, verifies `/dev/uinput` is `disabled_by_default`, exercises `zerodesk-hid-watchdog` lifecycle, `pidfd_open`, `PR_GET_PDEATHSIG`, `/proc/self/stat` field 22, and `/proc/self/fd` zero-leak audit (`leaked_fds_detected == 0`). | Physical udev ACL negative/warning test (`08`), physical `EV_KEY=0` + `SYN_REPORT` `<= 500ms` `SIGKILL` (`09`), escape hotkey (`10`), and multi-fd inheritance (`11`). |
| `LIN-L3-01..07`, `12` | **`PENDING_PHYSICAL_L3`** — Verifies `zerodesk-linux-diag --json` schema v1 (`12`), defers Wayland portal ScreenCast/PipeWire, X11 XShm/XRandR/XFixes, Intel iHD / AMD radeonsi VA-API IDR & QoE, physical key injection, and 30m soak. | Executed on physical Intel (`iHD`/`i965`) and AMD (`Mesa radeonsi`) Wayland + X11 hosts (`LIN-L3-03` auto-upgrades to `PASS` when an allowlisted open-source VA-API encoder is verified with a hardware fingerprint). |

---

## 4. Running Pre-Commit Local Checks & Physical `--strict-l3` Acceptance

### Local Pre-Commit Gate (macOS / Linux)

```bash
./scripts/check-ci-local.sh
```

This validates `.github/workflows/zerodesk-ci.yml` (YAML parse, 40-char SHA pinning, `contents: read`, `zerodesk/main`-only triggers), Bash syntax & Linux `--dry-run` + exit-40 behavior, PowerShell syntax/read-only/anti-forgery audit, JSON Schema Draft 2020-12 & 1-to-1 `WIN-L3-01..12` / `LIN-L3-01..12` alignment, `./scripts/check-compliance.sh` (5/5), and 0-byte integrity of all 11 Phase 8A ABI golden files.

### Physical Windows Host (`--strict-l3`)

1. Build release binaries on a physical Windows 10/11 host with an NVIDIA, AMD, or Intel GPU:
   ```powershell
   cargo build --manifest-path libs/zerodesk_core/Cargo.toml --release --bin zerodesk-win-diag --bin zerodesk-hid-watchdog --locked
   ```
2. Run the non-destructive diagnostic and L3 verification harness:
   ```powershell
   pwsh -NoProfile -File scripts/verify-windows-l3.ps1 `
     -Mode strict-l3 `
     -Output .\windows-strict-l3-report.json `
     -DiagBin .\libs\zerodesk_core\target\release\zerodesk-win-diag.exe
   ```
3. Inspect `windows-strict-l3-report.json`. Exit code `10` indicates automated checks succeeded without failures while manual physical/interactive items remain `PENDING_PHYSICAL_L3`; complete each checklist item in [`docs/windows-platform-support.md`](windows-platform-support.md) before any Windows release.

### Physical Linux Host (`--strict-l3`)

1. Build release binaries on a physical Linux host (Intel `iHD`/`i965` or AMD Mesa `radeonsi`, tested under both GNOME/KDE Wayland and X11):
   ```bash
   cargo build --manifest-path libs/zerodesk_core/Cargo.toml \
     --features scrap/linux-pkg-config \
     --release --bin zerodesk-linux-diag --bin zerodesk-hid-watchdog --locked
   ```
2. Run the non-destructive diagnostic and L3 verification harness:
   ```bash
   ./scripts/verify-linux-l3.sh \
     --mode strict-l3 \
     --output ./linux-strict-l3-report.json \
     --diag-bin ./libs/zerodesk_core/target/release/zerodesk-linux-diag \
     --watchdog-bin ./libs/zerodesk_core/target/release/zerodesk-hid-watchdog
   ```
3. Inspect `linux-strict-l3-report.json`. Complete all 12 items in [`docs/linux-platform-support.md`](linux-platform-support.md) on physical hardware before any Linux release.
