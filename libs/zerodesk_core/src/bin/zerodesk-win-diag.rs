// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! `zerodesk-win-diag` — Built-in non-destructive Windows platform diagnostic CLI.
//!
//! Outputs a single versioned JSON report covering:
//! 1. DXGI adapters, attached outputs, Adapter LUIDs, and multi-monitor layout;
//! 2. Media Foundation `MFTEnumEx(MFT_ENUM_FLAG_HARDWARE)` H.264/HEVC/AV1 MFTs
//!    and LUID zero-copy match status against the primary DXGI adapter;
//! 3. UIPI elevation + `LocalSystem` status, `OpenInputDesktop` probe, and
//!    non-destructive watchdog spawn + heartbeat + empty-batch release self-test.
//!
//! On non-Windows hosts, emits a clean static JSON stub without linking `zerodesk_core`
//! or platform screen-capture libraries.

use std::{
    io::{self, Write},
    process::ExitCode,
};

#[cfg(not(windows))]
const STUB_JSON_PREFIX: &str = "{\n  \"schema_version\": 1,\n  \"host_os\": \"";
#[cfg(not(windows))]
const STUB_JSON_SUFFIX: &str = "\",\n  \"windows_host_required\": true,\n  \"note\": \"zerodesk-win-diag requires a Windows host to probe DXGI, Media Foundation hardware MFTs, UIPI/OpenInputDesktop, and Windows watchdog handles\"\n}";

#[cfg(windows)]
fn run_windows_diagnostics(skip_watchdog: bool) -> zerodesk_core::os::win_diag::WinDiagReport {
    use std::thread;
    use zerodesk_core::os::{
        watchdog_supervisor::HidWatchdogConfig,
        win_diag::{
            sanitize_diag_text, WinDiagCodecProbe, WinDiagDxgiSection, WinDiagInputSection,
            WinDiagMfSection, WinDiagReport, WinDiagWatchdogSection, WIN_DIAG_SCHEMA_VERSION,
        },
        win_dxgi::enumerate_dxgi_outputs,
        win_input::{
            execute_atomic_release_batch, is_local_system, is_process_elevated,
            probe_input_desktop_accessible, WIN_UIPI_LIMITATION_NOTE,
        },
        win_mf::enumerate_hw_video_mfts,
        win_mf_logic::{select_hw_mft_for_luid, LuidMatchOutcome, MfHwCodec},
        win_watchdog::WinHidWatchdogSupervisor,
    };

    // Run empty-batch SendInput + OpenInputDesktop self-test on a fresh clean thread BEFORE
    // DXGI/MF initialization so SetThreadDesktop can never fail with ERROR_BUSY due to GPU hooks.
    let empty_batch_ok = if skip_watchdog {
        false
    } else {
        thread::Builder::new()
            .name("zd-win-diag-input".into())
            .spawn(|| execute_atomic_release_batch(&[]).is_ok())
            .ok()
            .and_then(|h| h.join().ok())
            .unwrap_or(false)
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
                error: Some(sanitize_diag_text(&e.to_string())),
            },
            None,
        ),
    };

    // 2. Media Foundation hardware-only MFT enumeration + LUID match against primary DXGI adapter.
    let mut codec_probes = Vec::with_capacity(3);
    let mut any_hw_mft_found = false;
    for codec in [MfHwCodec::H264, MfHwCodec::Hevc, MfHwCodec::Av1] {
        match enumerate_hw_video_mfts(codec) {
            Ok(mfts) => {
                if !mfts.is_empty() {
                    any_hw_mft_found = true;
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
                    error: Some(sanitize_diag_text(&e.to_string())),
                });
            }
        }
    }
    let mf_zero_copy_ok = codec_probes
        .iter()
        .any(|c| matches!(c.luid_match, Some(LuidMatchOutcome::ExactLuidZeroCopy { .. })));
    let mf_section = WinDiagMfSection {
        ok: mf_zero_copy_ok,
        any_hw_mft_found,
        codecs: codec_probes,
        error: if mf_zero_copy_ok {
            None
        } else if any_hw_mft_found {
            Some(
                "hardware video encoder MFT found, but none achieved ExactLuidZeroCopy against primary DXGI adapter"
                    .into(),
            )
        } else {
            Some("no Media Foundation hardware video encoder MFTs enumerated".into())
        },
    };

    // 3. Input / UIPI elevation + LocalSystem + OpenInputDesktop probe.
    let elevated = is_process_elevated();
    let local_system = is_local_system();
    let (desktop_ok, desktop_err) = match probe_input_desktop_accessible() {
        Ok(()) => (true, None),
        Err(e) => (false, Some(sanitize_diag_text(&e.to_string()))),
    };
    let input_section = WinDiagInputSection {
        uipi_elevated: elevated,
        is_local_system: local_system,
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
        let cfg = HidWatchdogConfig {
            real_os_input: false,
            ..HidWatchdogConfig::default()
        };
        match WinHidWatchdogSupervisor::spawn(cfg) {
            Ok(sup) => {
                let hb_ok = sup.send_heartbeat().is_ok();
                let _ = sup.shutdown(None);
                WinDiagWatchdogSection {
                    tested: true,
                    ok: hb_ok && empty_batch_ok,
                    spawn_ok: true,
                    heartbeat_ok: hb_ok,
                    empty_batch_release_ok: empty_batch_ok,
                    error: if hb_ok && empty_batch_ok {
                        None
                    } else if !hb_ok {
                        Some("watchdog heartbeat failed".into())
                    } else {
                        Some("empty-batch atomic release probe failed".into())
                    },
                }
            }
            Err(e) => WinDiagWatchdogSection {
                tested: true,
                ok: false,
                spawn_ok: false,
                heartbeat_ok: false,
                empty_batch_release_ok: empty_batch_ok,
                error: Some(sanitize_diag_text(&e.to_string())),
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
    #[cfg(windows)]
    {
        let skip_watchdog = std::env::args_os()
            .skip(1)
            .any(|a| a == std::ffi::OsStr::new("--skip-watchdog"));
        let report = run_windows_diagnostics(skip_watchdog);
        let all_ok = report.all_sections_ok();
        match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                let mut out = io::stdout().lock();
                if writeln!(out, "{json}").is_ok() && all_ok {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
            Err(_) => ExitCode::FAILURE,
        }
    }

    #[cfg(not(windows))]
    {
        let mut out = io::stdout().lock();
        if writeln!(
            out,
            "{STUB_JSON_PREFIX}{}{STUB_JSON_SUFFIX}",
            std::env::consts::OS
        )
        .is_ok()
        {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        }
    }
}
