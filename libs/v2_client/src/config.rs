// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use crate::error::ClientError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeEndpointConfig {
    pub pop_id: String,
    pub udp_addr: String,
    pub ctrl_addr: String,
    pub tls443_addr: String,
    pub x25519_pub_hex: String,
    #[serde(default)]
    pub cert_hash_hex: Option<String>,
    #[serde(default)]
    pub bb_addr: Option<String>,
    #[serde(default)]
    pub dlq_path: Option<String>,
}

impl EdgeEndpointConfig {
    pub fn pop_id_bytes(&self) -> Result<[u8; 8], ClientError> {
        let raw = self.pop_id.as_bytes();
        if raw.len() != 8 {
            return Err(ClientError::Config(format!(
                "pop_id '{}' must be exactly 8 ASCII bytes",
                self.pop_id
            )));
        }
        let mut out = [0u8; 8];
        out.copy_from_slice(raw);
        Ok(out)
    }

    pub fn x25519_pub(&self) -> Result<[u8; 32], ClientError> {
        decode_hex_array::<32>(&self.x25519_pub_hex, "x25519_pub_hex")
    }

    /// Returns explicit `cert_hash_hex` if provided, otherwise computes the default
    /// `SHA-256(b"V2-EDGECERT-v1" || pop_id[8] || x25519_pub[32])`.
    pub fn edge_cert_hash(&self) -> Result<[u8; 32], ClientError> {
        if let Some(hex_str) = &self.cert_hash_hex {
            if !hex_str.is_empty() {
                return decode_hex_array::<32>(hex_str, "cert_hash_hex");
            }
        }
        let pop_id = self.pop_id_bytes()?;
        let pubkey = self.x25519_pub()?;
        Ok(default_edge_cert_hash(&pop_id, &pubkey))
    }
}

pub fn default_edge_cert_hash(pop_id: &[u8; 8], x25519_pub: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"V2-EDGECERT-v1");
    hasher.update(pop_id);
    hasher.update(x25519_pub);
    hasher.finalize().into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub cp_addr: String,
    #[serde(default)]
    pub cp_use_tls: bool,
    pub signaling_addr: String,
    #[serde(default)]
    pub admin_token: Option<String>,
    #[serde(default)]
    pub ca_der_path: Option<String>,
    pub edge_a: EdgeEndpointConfig,
    pub edge_b: EdgeEndpointConfig,
    #[serde(default)]
    pub tenant_zd_hex: Option<String>,
    #[serde(default)]
    pub tenant_zd_quota_hex: Option<String>,
    #[serde(default)]
    pub tenant_drone_hex: Option<String>,
}

impl ClusterConfig {
    pub fn from_file(path: &Path) -> Result<Self, ClientError> {
        let raw = std::fs::read_to_string(path)?;
        let cfg: Self = serde_json::from_str(&raw)?;
        Ok(cfg)
    }

    pub fn cp_base_url(&self) -> String {
        if self.cp_addr.starts_with("http://") || self.cp_addr.starts_with("https://") {
            return self.cp_addr.clone();
        }
        if self.cp_use_tls {
            format!("https://{}", self.cp_addr)
        } else {
            format!("http://{}", self.cp_addr)
        }
    }
}

pub fn decode_hex_array<const N: usize>(input: &str, field: &str) -> Result<[u8; N], ClientError> {
    let bytes = hex::decode(input)?;
    if bytes.len() != N {
        return Err(ClientError::Config(format!(
            "{field} expected {N} bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}
