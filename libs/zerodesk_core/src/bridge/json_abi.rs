// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::controller::{
    BridgePersistedConfig, BRIDGE_ABI_VERSION, BRIDGE_MAX_CMD_JSON_BYTES,
};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const MIN_RING_TIMEOUT_MS: u64 = 1_000;
pub const MAX_RING_TIMEOUT_MS: u64 = 120_000;

/// Parsed, validated command request accepted by `V2BridgeRuntime::exec_json`.
#[derive(Clone, Deserialize)]
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
    pub codec: Option<String>,
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
    pub down: Option<bool>,
    #[serde(default)]
    pub modifiers: Option<u8>,
    #[serde(default, alias = "usage_id")]
    pub usb_hid_usage: Option<u16>,
    #[serde(default)]
    pub unicode_scalar: Option<u32>,
    #[serde(default)]
    pub keys: Option<Vec<u16>>,
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
    #[serde(default, alias = "wheel_dx")]
    pub wheel_x: Option<i16>,
    #[serde(default, alias = "wheel_dy")]
    pub wheel_y: Option<i16>,
    #[serde(default)]
    pub download_dir: Option<String>,
    #[serde(default)]
    pub ring_timeout_ms: Option<u64>,
}

impl fmt::Debug for RuntimeCommandEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cfg_redacted = self.config.as_ref().map(|_| "<redacted>");
        let b64_redacted = self
            .payload_b64
            .as_ref()
            .map(|s| format!("<redacted len={}>", s.len()));
        let text_redacted = self
            .text
            .as_ref()
            .map(|s| format!("<redacted len={}>", s.len()));
        f.debug_struct("RuntimeCommandEnvelope")
            .field("v", &self.v)
            .field("cmd", &self.cmd)
            .field("path", &self.path)
            .field("config", &cfg_redacted)
            .field("target_device_id_hex", &self.target_device_id_hex)
            .field("incoming_id", &self.incoming_id)
            .field("session_id_hex", &self.session_id_hex)
            .field("reason", &self.reason)
            .field("muted", &self.muted)
            .field("mode", &self.mode)
            .field("codec", &self.codec)
            .field("mime_kind", &self.mime_kind)
            .field("payload_b64", &b64_redacted)
            .field("text", &text_redacted)
            .field("rel_name", &self.rel_name)
            .field("file_size", &self.file_size)
            .field("transfer_id", &self.transfer_id)
            .field("down", &self.down)
            .field("modifiers", &self.modifiers)
            .field("usb_hid_usage", &self.usb_hid_usage)
            .field("unicode_scalar", &self.unicode_scalar)
            .field("keys", &self.keys)
            .field("mouse_kind", &self.mouse_kind)
            .field("download_dir", &self.download_dir)
            .field("ring_timeout_ms", &self.ring_timeout_ms)
            .finish()
    }
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
    if env.cmd.is_empty()
        || env.cmd.len() > 64
        || !env
            .cmd
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        return Err(RuntimeReplyEnvelope::err(
            "InvalidArgument",
            "command name must be 1..=64 ASCII [A-Za-z0-9_.-] characters",
        ));
    }
    if let Some(ms) = env.ring_timeout_ms {
        if !(MIN_RING_TIMEOUT_MS..=MAX_RING_TIMEOUT_MS).contains(&ms) {
            return Err(RuntimeReplyEnvelope::err(
                "InvalidArgument",
                format!(
                    "ring_timeout_ms {ms} outside [{MIN_RING_TIMEOUT_MS}, {MAX_RING_TIMEOUT_MS}]"
                ),
            ));
        }
    }
    if let Some(scalar) = env.unicode_scalar {
        if scalar != 0 && char::from_u32(scalar).is_none() {
            return Err(RuntimeReplyEnvelope::err(
                "InvalidArgument",
                format!("unicode_scalar 0x{scalar:x} is not a valid Unicode scalar value"),
            ));
        }
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
            r#"{"v":1,"cmd":"bad cmd!"}"#,
            r#"{"v":1,"cmd":"../evil"}"#,
            r#"{"v":1,"cmd":"start_host","ring_timeout_ms":999}"#,
            r#"{"v":1,"cmd":"start_host","ring_timeout_ms":120001}"#,
            r#"{"v":1,"cmd":"send_hid_key","unicode_scalar":55296}"#,
            r#"{"v":1,"cmd":"send_hid_key","unicode_scalar":1114112}"#,
        ] {
            let err = parse_and_validate_command(bad).unwrap_err();
            assert!(!err.ok);
            assert!(err.error_code.is_some());
        }
        let ok = parse_and_validate_command(r#"{"v":1,"cmd":"snapshot","future_field":42}"#).unwrap();
        assert_eq!(ok.cmd, "snapshot");
        let ok_ring =
            parse_and_validate_command(r#"{"v":1,"cmd":"start_host","ring_timeout_ms":1000}"#)
                .unwrap();
        assert_eq!(ok_ring.ring_timeout_ms, Some(1000));
        let ok_unicode =
            parse_and_validate_command(r#"{"v":1,"cmd":"send_hid_key","unicode_scalar":65}"#)
                .unwrap();
        assert_eq!(ok_unicode.unicode_scalar, Some(65));

        let ok_aliases = parse_and_validate_command(
            r#"{"v":1,"cmd":"send_hid_mouse","mouse_kind":"wheel","wheel_dx":-3,"wheel_dy":5,"buttons":1}"#,
        )
        .unwrap();
        assert_eq!(ok_aliases.wheel_x, Some(-3));
        assert_eq!(ok_aliases.wheel_y, Some(5));

        let ok_key_alias = parse_and_validate_command(
            r#"{"v":1,"cmd":"key_down","usage_id":4,"modifiers":2}"#,
        )
        .unwrap();
        assert_eq!(ok_key_alias.usb_hid_usage, Some(4));
        assert_eq!(ok_key_alias.modifiers, Some(2));

        let ok_release = parse_and_validate_command(
            r#"{"v":1,"cmd":"release_all","keys":[4,224],"buttons":3,"reason":"windowResignedKey"}"#,
        )
        .unwrap();
        assert_eq!(ok_release.keys, Some(vec![4, 224]));
        assert_eq!(ok_release.buttons, Some(3));

        let ok_codec =
            parse_and_validate_command(r#"{"v":1,"cmd":"set_codec","codec":"auto"}"#).unwrap();
        assert_eq!(ok_codec.codec.as_deref(), Some("auto"));
    }

    #[test]
    fn command_envelope_debug_redacts_secrets_and_payloads() {
        let env = parse_and_validate_command(
            r#"{"v":1,"cmd":"send_clipboard","text":"TOP_SECRET_CLIP_CANARY","payload_b64":"U0VDUkVUX0I2NA=="}"#,
        )
        .unwrap();
        let dbg = format!("{env:?}");
        assert!(!dbg.contains("TOP_SECRET_CLIP_CANARY"));
        assert!(!dbg.contains("U0VDUkVUX0I2NA=="));
        assert!(dbg.contains("<redacted len="));
    }
}
