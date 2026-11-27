// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::controller::{
    BridgePersistedConfig, BRIDGE_ABI_VERSION, BRIDGE_MAX_CMD_JSON_BYTES,
};
use serde::{Deserialize, Serialize};

/// Parsed, validated command request accepted by `V2BridgeRuntime::exec_json`.
#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeCommandEnvelope {
    pub v: u32,
    pub cmd: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub config: Option<BridgePersistedConfig>,
    #[serde(default)]
    pub target_device_id_hex: Option<String>,
    #[serde(default)]
    pub incoming_id: Option<String>,
    #[serde(default)]
    pub session_id_hex: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub muted: Option<bool>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub mime_kind: Option<u8>,
    #[serde(default)]
    pub payload_b64: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub rel_name: Option<String>,
    #[serde(default)]
    pub file_size: Option<u64>,
    #[serde(default)]
    pub transfer_id: Option<u64>,
    #[serde(default)]
    pub drop_udp: Option<bool>,
    #[serde(default)]
    pub down: Option<bool>,
    #[serde(default)]
    pub modifiers: Option<u8>,
    #[serde(default)]
    pub usb_hid_usage: Option<u16>,
    #[serde(default)]
    pub unicode_scalar: Option<u32>,
    #[serde(default)]
    pub mouse_kind: Option<String>,
    #[serde(default)]
    pub x: Option<u16>,
    #[serde(default)]
    pub y: Option<u16>,
    #[serde(default)]
    pub dx: Option<i16>,
    #[serde(default)]
    pub dy: Option<i16>,
    #[serde(default)]
    pub buttons: Option<u8>,
    #[serde(default)]
    pub wheel_x: Option<i16>,
    #[serde(default)]
    pub wheel_y: Option<i16>,
    #[serde(default)]
    pub download_dir: Option<String>,
    #[serde(default)]
    pub ring_timeout_ms: Option<u64>,
}

/// Structured reply envelope returned synchronously by `V2BridgeRuntime::exec_json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeReplyEnvelope {
    pub v: u32,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub already_running: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub already_stopped: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_gen: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl RuntimeReplyEnvelope {
    pub fn ok(data: serde_json::Value) -> Self {
        Self {
            v: BRIDGE_ABI_VERSION,
            ok: true,
            accepted: None,
            already_running: None,
            already_stopped: None,
            cmd_id: None,
            session_gen: None,
            error_code: None,
            error: None,
            data: Some(data),
        }
    }

    pub fn accepted(cmd_id: u64, session_gen: u64) -> Self {
        Self {
            v: BRIDGE_ABI_VERSION,
            ok: true,
            accepted: Some(true),
            already_running: None,
            already_stopped: None,
            cmd_id: Some(cmd_id),
            session_gen: Some(session_gen),
            error_code: None,
            error: None,
            data: None,
        }
    }

    pub fn already_running(session_gen: u64) -> Self {
        Self {
            v: BRIDGE_ABI_VERSION,
            ok: true,
            accepted: None,
            already_running: Some(true),
            already_stopped: None,
            cmd_id: None,
            session_gen: Some(session_gen),
            error_code: None,
            error: None,
            data: None,
        }
    }

    pub fn already_stopped() -> Self {
        Self {
            v: BRIDGE_ABI_VERSION,
            ok: true,
            accepted: None,
            already_running: None,
            already_stopped: Some(true),
            cmd_id: None,
            session_gen: None,
            error_code: None,
            error: None,
            data: None,
        }
    }

    pub fn err(code: &str, msg: impl Into<String>) -> Self {
        Self {
            v: BRIDGE_ABI_VERSION,
            ok: false,
            accepted: None,
            already_running: None,
            already_stopped: None,
            cmd_id: None,
            session_gen: None,
            error_code: Some(code.to_string()),
            error: Some(msg.into()),
            data: None,
        }
    }

    pub fn to_json_string(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            r#"{"v":1,"ok":false,"error_code":"Internal","error":"failed to serialize reply"}"#
                .to_string()
        })
    }
}

/// Strictly validates raw JSON command input before forwarding to the actor.
/// Never panics on arbitrary bytes, huge payloads, invalid JSON, or wrong ABI version.
pub fn parse_and_validate_command(raw: &str) -> Result<RuntimeCommandEnvelope, RuntimeReplyEnvelope> {
    if raw.len() > BRIDGE_MAX_CMD_JSON_BYTES {
        return Err(RuntimeReplyEnvelope::err(
            "TooLarge",
            format!(
                "command JSON size {}B exceeds {BRIDGE_MAX_CMD_JSON_BYTES}B cap",
                raw.len()
            ),
        ));
    }
    if raw.contains('\0') {
        return Err(RuntimeReplyEnvelope::err(
            "InvalidArgument",
            "command JSON must not contain NUL bytes",
        ));
    }
    let env: RuntimeCommandEnvelope = serde_json::from_str(raw).map_err(|e| {
        RuntimeReplyEnvelope::err("InvalidJson", format!("malformed command envelope: {e}"))
    })?;
    if env.v != BRIDGE_ABI_VERSION {
        return Err(RuntimeReplyEnvelope::err(
            "UnsupportedAbiVersion",
            format!(
                "unsupported bridge ABI version {} (expected {BRIDGE_ABI_VERSION})",
                env.v
            ),
        ));
    }
    if env.cmd.trim().is_empty() || env.cmd.len() > 64 {
        return Err(RuntimeReplyEnvelope::err(
            "InvalidArgument",
            "command name must be 1..=64 bytes",
        ));
    }
    Ok(env)
}

/// Scans a serialized snapshot or event JSON string for forbidden canary secrets.
/// Returns `Ok(())` when clean, or `Err(matched_canary)` if any secret leaked.
pub fn scan_json_for_secret_canaries<'a>(
    serialized: &str,
    canaries: &[&'a str],
) -> Result<(), &'a str> {
    for &canary in canaries {
        if !canary.is_empty() && serialized.contains(canary) {
            return Err(canary);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_command_never_panics_on_garbage_or_bad_inputs() {
        for bad in [
            "",
            "{}",
            "not json at all!!!",
            r#"{"v":999999999999999999999999,"cmd":"snapshot"}"#,
            r#"{"v":2,"cmd":"snapshot"}"#,
            "{\"v\":1,\"cmd\":\"snap\0shot\"}",
            r#"{"v":1,"cmd":""}"#,
        ] {
            let err = parse_and_validate_command(bad).unwrap_err();
            assert!(!err.ok);
            assert!(err.error_code.is_some());
        }
        let ok = parse_and_validate_command(r#"{"v":1,"cmd":"snapshot","future_field":42}"#).unwrap();
        assert_eq!(ok.cmd, "snapshot");
    }
}
