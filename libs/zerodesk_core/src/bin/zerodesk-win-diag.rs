// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! `zerodesk-win-diag` — Built-in non-destructive Windows platform diagnostic CLI.
//!
//! Outputs a single versioned JSON report covering:
//! 1. DXGI adapters, attached outputs, Adapter LUIDs, and multi-monitor layout;
//! 2. Media Foundation `MFTEnumEx(MFT_ENUM_FLAG_HARDWARE)` H.264/HEVC/AV1 MFTs
//!    and LUID match status against the primary DXGI adapter;
//! 3. UIPI elevation status, `OpenInputDesktop` probe, and non-destructive
//!    watchdog spawn + heartbeat + empty-batch release self-test.
//!
//! On non-Windows hosts, compiles cleanly and prints a structured JSON message
//! indicating that a Windows host is required.

// Standalone binary does not link `src/platform/macos.mm`, which provides `BackingScaleFactor`
// for `scrap::quartz::Display::scale()`.
#[cfg(target_os = "macos")]
#[no_mangle]
pub extern "C" fn BackingScaleFactor(display: u32) -> f32 {
    use std::ffi::c_void;
    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGDisplayPixelsWide(display: u32) -> usize;
        fn CGDisplayCopyDisplayMode(display: u32) -> *const c_void;
        fn CGDisplayModeGetPixelWidth(mode: *const c_void) -> usize;
        fn CGDisplayModeRelease(mode: *const c_void);
    }
    unsafe {
        let mode = CGDisplayCopyDisplayMode(display);
        if mode.is_null() {
            return 1.0;
        }
        let pixel_w = CGDisplayModeGetPixelWidth(mode);
        CGDisplayModeRelease(mode);
        let point_w = CGDisplayPixelsWide(display);
        if point_w == 0 || pixel_w == 0 {
            1.0
        } else {
            (pixel_w as f32 / point_w as f32).max(1.0)
        }
    }
}

use std::{
    env,
    io::{self, Write},
    process::ExitCode,
};
use zerodesk_core::os::win_diag::WinDiagReport;

#[cfg(windows)]
fn run_windows_diagnostics(skip_watchdog: bool) -> WinDiagReport {
    use zerodesk_core::os::{
        watchdog_supervisor::HidWatchdogConfig,
        win_diag::{
            WinDiagCodecProbe, WinDiagDxgiSection, WinDiagInputSection, WinDiagMfSection,
            WinDiagWatchdogSection, WIN_DIAG_SCHEMA_VERSION,
        },
        win_dxgi::enumerate_dxgi_outputs,
        win_input::{
            execute_atomic_release_batch, is_process_elevated, probe_input_desktop_accessible,
            WIN_UIPI_LIMITATION_NOTE,
        },
        win_mf::enumerate_hw_video_mfts,
        win_mf_logic::{select_hw_mft_for_luid, MfHwCodec},
        win_watchdog::WinHidWatchdogSupervisor,
    };

    // 1. DXGI adapter & multi-monitor output enumeration.
    let (dxgi_section, primary_luid) = match enumerate_dxgi_outputs() {
        Ok(outputs) => {
            let primary_luid = outputs
                .iter()
                .find(|o| o.is_primary)
                .or_else(|| outputs.first())
                .map(|o| o.adapter_luid);
            (
                WinDiagDxgiSection {
                    ok: !outputs.is_empty(),
                    primary_adapter_luid: primary_luid,
                    outputs,
                    error: None,
                },
                primary_luid,
            )
        }
        Err(e) => (
            WinDiagDxgiSection {
                ok: false,
                primary_adapter_luid: None,
                outputs: Vec::new(),
                error: Some(e.to_string()),
            },
            None,
        ),
    };

    // 2. Media Foundation hardware-only MFT enumeration + LUID match against primary DXGI adapter.
    let mut codec_probes = Vec::with_capacity(3);
    let mut mf_any_ok = false;
    for codec in [MfHwCodec::H264, MfHwCodec::Hevc, MfHwCodec::Av1] {
        match enumerate_hw_video_mfts(codec) {
            Ok(mfts) => {
                if !mfts.is_empty() {
                    mf_any_ok = true;
                }
                let luid_match =
                    primary_luid.map(|luid| select_hw_mft_for_luid(&mfts, codec, luid, false));
                codec_probes.push(WinDiagCodecProbe {
                    codec,
                    hardware_mfts: mfts,
                    luid_match,
                    error: None,
                });
            }
            Err(e) => {
                codec_probes.push(WinDiagCodecProbe {
                    codec,
                    hardware_mfts: Vec::new(),
                    luid_match: None,
                    error: Some(e.to_string()),
                });
            }
        }
    }
    let mf_section = WinDiagMfSection {
        ok: mf_any_ok,
        codecs: codec_probes,
        error: if mf_any_ok {
            None
        } else {
            Some("no Media Foundation hardware video encoder MFTs enumerated".into())
        },
    };

    // 3. Input / UIPI elevation + OpenInputDesktop probe.
    let elevated = is_process_elevated();
    let (desktop_ok, desktop_err) = match probe_input_desktop_accessible() {
        Ok(()) => (true, None),
        Err(e) => (false, Some(e.to_string())),
    };
    let input_section = WinDiagInputSection {
        uipi_elevated: elevated,
        input_desktop_accessible: desktop_ok,
        uipi_limitation_note: WIN_UIPI_LIMITATION_NOTE.to_string(),
        error: desktop_err,
    };

    // 4. Non-destructive watchdog spawn + heartbeat + empty-batch release self-test.
    let watchdog_section = if skip_watchdog {
        WinDiagWatchdogSection {
            tested: false,
            ok: true,
            spawn_ok: false,
            heartbeat_ok: false,
            empty_batch_release_ok: false,
            error: Some("skipped via --skip-watchdog".into()),
        }
    } else {
        let empty_batch_ok = execute_atomic_release_batch(&[]).is_ok();
        let cfg = HidWatchdogConfig {
            real_os_input: false,
            ..HidWatchdogConfig::default()
        };
        match WinHidWatchdogSupervisor::spawn(cfg) {
            Ok(sup) => {
                let hb_ok = sup.send_heartbeat().is_ok();
                sup.shutdown(None);
                WinDiagWatchdogSection {
                    tested: true,
                    ok: hb_ok && empty_batch_ok,
                    spawn_ok: true,
                    heartbeat_ok: hb_ok,
                    empty_batch_release_ok: empty_batch_ok,
                    error: if hb_ok {
                        None
                    } else {
                        Some("watchdog heartbeat failed".into())
                    },
                }
            }
            Err(e) => WinDiagWatchdogSection {
                tested: true,
                ok: false,
                spawn_ok: false,
                heartbeat_ok: false,
                empty_batch_release_ok: empty_batch_ok,
                error: Some(e.to_string()),
            },
        }
    };

    WinDiagReport {
        schema_version: WIN_DIAG_SCHEMA_VERSION,
        host_os: std::env::consts::OS.to_string(),
        windows_host_required: false,
        note: None,
        dxgi: Some(dxgi_section),
        media_foundation: Some(mf_section),
        input: Some(input_section),
        watchdog: Some(watchdog_section),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let skip_watchdog = args.iter().any(|a| a == "--skip-watchdog");

    #[cfg(windows)]
    let report = run_windows_diagnostics(skip_watchdog);

    #[cfg(not(windows))]
    let report = {
        let _ = skip_watchdog;
        WinDiagReport::non_windows_stub()
    };

    match serde_json::to_string_pretty(&report) {
        Ok(json) => {
            let mut out = io::stdout().lock();
            if writeln!(out, "{json}").is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(_) => ExitCode::FAILURE,
    }
}
