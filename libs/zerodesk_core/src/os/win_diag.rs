// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Platform-agnostic structured JSON schema for `zerodesk-win-diag` diagnostics.
//!
//! Unit-tested on all platforms (including macOS) so the diagnostic schema stays
//! strictly versioned and deterministic before real Windows hardware runs.

use super::{
    win_dxgi_logic::{DxgiAdapterLuid, DxgiOutputDescriptor},
    win_mf_logic::{LuidMatchOutcome, MfHwCodec, MfHwMftDescriptor},
};
use serde::{Deserialize, Serialize};

pub const WIN_DIAG_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinDiagDxgiSection {
    pub ok: bool,
    pub primary_adapter_luid: Option<DxgiAdapterLuid>,
    pub outputs: Vec<DxgiOutputDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinDiagCodecProbe {
    pub codec: MfHwCodec,
    pub hardware_mfts: Vec<MfHwMftDescriptor>,
    pub luid_match: Option<LuidMatchOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinDiagMfSection {
    pub ok: bool,
    pub codecs: Vec<WinDiagCodecProbe>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinDiagInputSection {
    pub uipi_elevated: Option<bool>,
    pub input_desktop_accessible: bool,
    pub uipi_limitation_note: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinDiagWatchdogSection {
    pub tested: bool,
    pub ok: bool,
    pub spawn_ok: bool,
    pub heartbeat_ok: bool,
    pub empty_batch_release_ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Top-level redacted JSON report emitted by `zerodesk-win-diag`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinDiagReport {
    pub schema_version: u32,
    pub host_os: String,
    pub windows_host_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dxgi: Option<WinDiagDxgiSection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_foundation: Option<WinDiagMfSection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<WinDiagInputSection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watchdog: Option<WinDiagWatchdogSection>,
}

impl WinDiagReport {
    pub fn non_windows_stub() -> Self {
        Self {
            schema_version: WIN_DIAG_SCHEMA_VERSION,
            host_os: std::env::consts::OS.to_string(),
            windows_host_required: true,
            note: Some(
                "zerodesk-win-diag requires a Windows host to probe DXGI, Media Foundation hardware MFTs, UIPI/OpenInputDesktop, and Windows watchdog handles".into(),
            ),
            dxgi: None,
            media_foundation: None,
            input: None,
            watchdog: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::win_mf_logic::MfHwVendor;

    #[test]
    fn non_windows_stub_report_serializes_cleanly() {
        let report = WinDiagReport::non_windows_stub();
        assert_eq!(report.schema_version, WIN_DIAG_SCHEMA_VERSION);
        assert!(report.windows_host_required);
        let json = serde_json::to_string_pretty(&report).unwrap();
        let parsed: WinDiagReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, report);
    }

    #[test]
    fn full_windows_diag_report_round_trips_json_schema() {
        let luid = DxgiAdapterLuid::new(0xABCD, 0);
        let report = WinDiagReport {
            schema_version: WIN_DIAG_SCHEMA_VERSION,
            host_os: "windows".into(),
            windows_host_required: false,
            note: None,
            dxgi: Some(WinDiagDxgiSection {
                ok: true,
                primary_adapter_luid: Some(luid),
                outputs: vec![DxgiOutputDescriptor {
                    monitor_index: 0,
                    adapter_index: 0,
                    output_index: 0,
                    adapter_luid: luid,
                    adapter_name: "NVIDIA GeForce RTX".into(),
                    device_name: r"\\.\DISPLAY1".into(),
                    left: 0,
                    top: 0,
                    width: 1920,
                    height: 1080,
                    is_primary: true,
                    rotation_degrees: 0,
                }],
                error: None,
            }),
            media_foundation: Some(WinDiagMfSection {
                ok: true,
                codecs: vec![WinDiagCodecProbe {
                    codec: MfHwCodec::H264,
                    hardware_mfts: vec![MfHwMftDescriptor {
                        friendly_name: "NVIDIA H.264 Encoder MFT".into(),
                        codec: MfHwCodec::H264,
                        adapter_luid: Some(luid),
                        is_hardware: true,
                        supports_d3d11_aware: true,
                        vendor: MfHwVendor::Nvidia,
                    }],
                    luid_match: Some(LuidMatchOutcome::ExactLuidZeroCopy {
                        selected_index: 0,
                        adapter_luid: luid,
                        d3d11_aware: true,
                    }),
                    error: None,
                }],
                error: None,
            }),
            input: Some(WinDiagInputSection {
                uipi_elevated: Some(false),
                input_desktop_accessible: true,
                uipi_limitation_note: "Standard user process; UIPI blocks elevated/UAC windows"
                    .into(),
                error: None,
            }),
            watchdog: Some(WinDiagWatchdogSection {
                tested: true,
                ok: true,
                spawn_ok: true,
                heartbeat_ok: true,
                empty_batch_release_ok: true,
                error: None,
            }),
        };
        let json = serde_json::to_string(&report).unwrap();
        let decoded: WinDiagReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, report);
    }
}
