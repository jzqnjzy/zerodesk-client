// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Platform-agnostic structured JSON schema, validation, and path redaction
//! helpers for `zerodesk-win-diag` diagnostics.
//!
//! Unit-tested on all platforms (including macOS) so the diagnostic schema stays
//! strictly versioned and deterministic before real Windows hardware runs.

use super::{
    win_dxgi_logic::{DxgiAdapterLuid, DxgiOutputDescriptor},
    win_mf_logic::{LuidMatchOutcome, MfHwCodec, MfHwMftDescriptor},
};
use serde::{Deserialize, Serialize};

pub const WIN_DIAG_SCHEMA_VERSION: u32 = 1;

pub const NON_WINDOWS_DIAG_NOTE: &str = "zerodesk-win-diag requires a Windows host to probe DXGI, Media Foundation hardware MFTs, UIPI/OpenInputDesktop, and Windows watchdog handles";

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
    /// `true` ONLY when at least one hardware MFT achieved `ExactLuidZeroCopy`.
    pub ok: bool,
    /// `true` when any hardware video encoder MFT was enumerated (even if LUID mismatched).
    #[serde(default)]
    pub any_hw_mft_found: bool,
    pub codecs: Vec<WinDiagCodecProbe>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinDiagInputSection {
    pub uipi_elevated: Option<bool>,
    #[serde(default)]
    pub is_local_system: bool,
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

/// Redacts local user-home directory path segments (`C:\Users\<name>\`, `/Users/<name>/`,
/// `/home/<name>/`) from diagnostic text before serialization so reports never leak
/// local OS usernames.
pub fn sanitize_diag_text(raw: &str) -> String {
    let mut out = raw.to_string();
    for (prefix, sep) in [
        ("C:\\Users\\", '\\'),
        ("c:\\users\\", '\\'),
        ("/Users/", '/'),
        ("/home/", '/'),
    ] {
        loop {
            let Some(pos) = out.find(prefix) else {
                break;
            };
            let user_start = pos + prefix.len();
            let rest = &out[user_start..];
            let user_len = rest
                .find(|c: char| c == sep || c.is_whitespace() || c == '"' || c == '\'')
                .unwrap_or(rest.len());
            let mut replacement = String::from("<redacted-home>");
            if user_len > 0 && rest.as_bytes().get(user_len) == Some(&(sep as u8)) {
                replacement.push(sep);
                out.replace_range(pos..user_start + user_len + 1, &replacement);
            } else {
                out.replace_range(pos..user_start + user_len, &replacement);
            }
        }
    }
    out
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
            note: Some(NON_WINDOWS_DIAG_NOTE.into()),
            dxgi: None,
            media_foundation: None,
            input: None,
            watchdog: None,
        }
    }

    /// Validates structural invariants & redaction safety of a diagnostic report.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != WIN_DIAG_SCHEMA_VERSION {
            return Err(format!(
                "unsupported win_diag schema_version {} (expected {WIN_DIAG_SCHEMA_VERSION})",
                self.schema_version
            ));
        }
        if self.host_os.trim().is_empty() {
            return Err("host_os must be non-empty".into());
        }
        if self.windows_host_required {
            if self.dxgi.is_some()
                || self.media_foundation.is_some()
                || self.input.is_some()
                || self.watchdog.is_some()
            {
                return Err("non-Windows stub report must not populate Windows probe sections".into());
            }
        } else {
            if self.dxgi.is_none()
                || self.media_foundation.is_none()
                || self.input.is_none()
                || self.watchdog.is_none()
            {
                return Err("Windows diagnostic report must populate all 4 probe sections".into());
            }
            if let Some(mf) = &self.media_foundation {
                let has_zero_copy = mf.codecs.iter().any(|c| {
                    matches!(c.luid_match, Some(LuidMatchOutcome::ExactLuidZeroCopy { .. }))
                });
                if mf.ok && !has_zero_copy {
                    return Err(
                        "media_foundation.ok must only be true when ExactLuidZeroCopy matched".into(),
                    );
                }
            }
        }
        let serialized =
            serde_json::to_string(self).map_err(|e| format!("serialize failed: {e}"))?;
        let lower = serialized.to_ascii_lowercase();
        if lower.contains("c:\\\\users\\\\") || lower.contains("/users/") || lower.contains("/home/")
        {
            return Err("unredacted local user home path detected in WinDiagReport".into());
        }
        Ok(())
    }

    /// Returns `true` when every non-skipped Windows diagnostic section succeeded.
    pub fn all_sections_ok(&self) -> bool {
        if self.windows_host_required {
            return true;
        }
        let dxgi_ok = self.dxgi.as_ref().is_some_and(|s| s.ok);
        let mf_ok = self.media_foundation.as_ref().is_some_and(|s| s.ok);
        let input_ok = self
            .input
            .as_ref()
            .is_some_and(|s| s.input_desktop_accessible);
        let wd_ok = self
            .watchdog
            .as_ref()
            .is_some_and(|s| !s.tested || s.ok);
        dxgi_ok && mf_ok && input_ok && wd_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::win_mf_logic::MfHwVendor;

    #[test]
    fn non_windows_stub_report_validates_and_matches_cli_const_json_byte_for_byte() {
        let report = WinDiagReport::non_windows_stub();
        report.validate().unwrap();
        let rendered = serde_json::to_string_pretty(&report).unwrap();
        #[cfg(not(windows))]
        {
            let expected_cli = format!(
                "{{\n  \"schema_version\": 1,\n  \"host_os\": \"{}\",\n  \"windows_host_required\": true,\n  \"note\": \"{NON_WINDOWS_DIAG_NOTE}\"\n}}",
                std::env::consts::OS
            );
            assert_eq!(rendered, expected_cli);
        }
        let parsed: WinDiagReport = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed, report);
    }

    #[test]
    fn sanitize_diag_text_redacts_windows_and_unix_user_home_paths() {
        assert_eq!(
            sanitize_diag_text(r"binary not found: C:\Users\alice\AppData\Local\wd.exe"),
            r"binary not found: <redacted-home>\AppData\Local\wd.exe"
        );
        assert_eq!(
            sanitize_diag_text("missing /Users/bob/bin/watchdog"),
            "missing <redacted-home>/bin/watchdog"
        );
        assert_eq!(
            sanitize_diag_text("missing /home/carol/bin/watchdog"),
            "missing <redacted-home>/bin/watchdog"
        );
    }

    #[test]
    fn full_windows_diag_report_round_trips_and_validates_zero_copy_gate() {
        let luid = DxgiAdapterLuid::new(0xABCD, 0);
        let mut report = WinDiagReport {
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
                any_hw_mft_found: true,
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
                    }),
                    error: None,
                }],
                error: None,
            }),
            input: Some(WinDiagInputSection {
                uipi_elevated: Some(false),
                is_local_system: false,
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
        report.validate().unwrap();
        assert!(report.all_sections_ok());

        let json = serde_json::to_string(&report).unwrap();
        let decoded: WinDiagReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, report);

        // If media_foundation.ok is true without ExactLuidZeroCopy -> validate() rejects!
        report.media_foundation.as_mut().unwrap().codecs[0].luid_match =
            Some(LuidMatchOutcome::ExactLuidCpuUpload {
                selected_index: 0,
                adapter_luid: luid,
                diagnostic: "no d3d11".into(),
            });
        assert!(report.validate().is_err());
    }
}
