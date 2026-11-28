// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Zero-dependency GF(2^8) Cauchy Reed-Solomon FEC, adaptive redundancy control,
//! and bounded-wait receiver reorder/recovery buffer.

use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
};

/// Primitive polynomial for GF(2^8): `x^8 + x^4 + x^3 + x^2 + 1` (`0x11D`).
pub const GF256_PRIMITIVE_POLY: u16 = 0x11D;
/// Maximum media data shards per FEC group (`k <= 16`).
pub const FEC_MAX_DATA_SHARDS: usize = 16;
/// Maximum RS parity shards per FEC group (`m <= 4`).
pub const FEC_MAX_PARITY_SHARDS: usize = 4;
/// Hard ceiling on FEC redundancy ratio relative to media bitrate (`<= 25%`).
pub const FEC_MAX_REDUNDANCY_RATIO: f64 = 0.25;
/// Consecutive confirmation duration required before toggling FEC ON/OFF (`>= 2000ms`).
pub const FEC_DEBOUNCE_MS: u64 = 2_000;
/// Lower bound on receiver FEC wait window (`5ms`).
pub const FEC_WAIT_MIN_MS: u64 = 5;
/// Upper bound on receiver FEC wait window (`40ms`).
pub const FEC_WAIT_MAX_MS: u64 = 40;
/// Maximum simultaneously tracked active FEC groups in `FecReorderBuffer`.
pub const FEC_REORDER_MAX_GROUPS: usize = 64;
/// Maximum retained extra-delay samples inside `FecReceiverStats` (bounded memory).
pub const FEC_EXTRA_DELAY_MAX_SAMPLES: usize = 1_024;

const fn build_gf256_tables() -> ([u8; 512], [u8; 256]) {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0usize;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if (x & 0x100) != 0 {
            x ^= GF256_PRIMITIVE_POLY;
        }
        i += 1;
    }
    let mut j = 0usize;
    while j < 255 {
        exp[j + 255] = exp[j];
        j += 1;
    }
    exp[510] = exp[0];
    exp[511] = exp[1];
    (exp, log)
}

const GF256_TABLES: ([u8; 512], [u8; 256]) = build_gf256_tables();
const GF_EXP: [u8; 512] = GF256_TABLES.0;
const GF_LOG: [u8; 256] = GF256_TABLES.1;

/// O(1) multiplication in GF(2^8) using precomputed `exp`/`log` tables (`0x11D`).
#[inline]
pub fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let idx = (GF_LOG[a as usize] as usize) + (GF_LOG[b as usize] as usize);
    GF_EXP[idx]
}

/// O(1) multiplicative inverse in GF(2^8). Returns `Err(FecError::DivisionByZero)` for `0`.
#[inline]
pub fn gf_inv(a: u8) -> Result<u8, FecError> {
    if a == 0 {
        return Err(FecError::DivisionByZero);
    }
    Ok(GF_EXP[255 - (GF_LOG[a as usize] as usize)])
}

/// Canonical Cauchy matrix entry `C[r][j] = inv((k + r) ^ j)` over GF(2^8).
#[inline]
pub fn cauchy_coeff(k: usize, r: usize, j: usize) -> Result<u8, FecError> {
    if k == 0 || k > FEC_MAX_DATA_SHARDS || j >= k || k + r > 255 {
        return Err(FecError::InvalidParams { k, m: r + 1 });
    }
    let denom = ((k + r) as u8) ^ (j as u8);
    gf_inv(denom)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FecError {
    InvalidParams { k: usize, m: usize },
    ShardTooLarge { index: usize, len: usize },
    ShardCountMismatch { expected: usize, actual: usize },
    InsufficientShards { needed: usize, have: usize },
    InvalidParityHeader { reason: &'static str },
    DataShardLengthMismatch { index: usize, expected: usize, actual: usize },
    DivisionByZero,
    SingularMatrix,
    InvalidShardIndex { index: usize, limit: usize },
}

impl fmt::Display for FecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParams { k, m } => write!(
                f,
                "invalid RS parameters k={k} (1..={FEC_MAX_DATA_SHARDS}), m={m} (1..={FEC_MAX_PARITY_SHARDS})"
            ),
            Self::ShardTooLarge { index, len } => {
                write!(f, "data shard {index} length {len} exceeds u16::MAX")
            }
            Self::ShardCountMismatch { expected, actual } => {
                write!(f, "shard slice length mismatch: expected {expected}, got {actual}")
            }
            Self::InsufficientShards { needed, have } => {
                write!(f, "insufficient shards for recovery: needed {needed}, have {have}")
            }
            Self::InvalidParityHeader { reason } => write!(f, "invalid RS parity header: {reason}"),
            Self::DataShardLengthMismatch {
                index,
                expected,
                actual,
            } => write!(
                f,
                "data shard {index} length mismatch: expected {expected}, got {actual}"
            ),
            Self::DivisionByZero => write!(f, "GF(2^8) multiplicative inverse of zero"),
            Self::SingularMatrix => write!(f, "singular GF(2^8) decoding matrix"),
            Self::InvalidShardIndex { index, limit } => {
                write!(f, "shard index {index} out of bounds (limit {limit})")
            }
        }
    }
}

impl std::error::Error for FecError {}

/// Systematic GF(2^8) Cauchy Reed-Solomon encoder/decoder (`k <= 16`, `m <= 4`).
///
/// - When `m == 1`, takes a zero-matrix-inversion lightweight XOR fast path.
/// - When `m >= 2`, uses a systematic Cauchy matrix with Gaussian elimination recovery.
/// - Unequal-length shards (including empty `0`-byte shards) are zero-padded internally and
///   restored to their exact original byte lengths via a compact `2 * k`-byte big-endian length
///   table prepended to each parity shard.
#[derive(Debug, Clone, Copy, Default)]
pub struct RsCodec;

impl RsCodec {
    /// Encodes `k` original media shards (`1..=16`) into `m` parity shards (`1..=4`).
    /// The `k` media shards themselves are sent unmodified (systematic code).
    pub fn encode(data_shards: &[&[u8]], m: usize) -> Result<Vec<Vec<u8>>, FecError> {
        let k = data_shards.len();
        if k == 0 || k > FEC_MAX_DATA_SHARDS || m == 0 || m > FEC_MAX_PARITY_SHARDS {
            return Err(FecError::InvalidParams { k, m });
        }

        let mut max_len = 0usize;
        let mut len_prefix = Vec::with_capacity(k * 2);
        for (idx, shard) in data_shards.iter().enumerate() {
            let len_u16 = u16::try_from(shard.len()).map_err(|_| FecError::ShardTooLarge {
                index: idx,
                len: shard.len(),
            })?;
            len_prefix.extend_from_slice(&len_u16.to_be_bytes());
            if shard.len() > max_len {
                max_len = shard.len();
            }
        }

        // Fast XOR path when m == 1: single parity shard is exact bytewise XOR of all k shards.
        if m == 1 {
            let mut parity = Vec::with_capacity(k * 2 + max_len);
            parity.extend_from_slice(&len_prefix);
            parity.resize(k * 2 + max_len, 0u8);
            let body = &mut parity[k * 2..];
            for shard in data_shards {
                for (dst, &src) in body.iter_mut().zip(shard.iter()) {
                    *dst ^= src;
                }
            }
            return Ok(vec![parity]);
        }

        let mut parities = Vec::with_capacity(m);
        for r in 0..m {
            let mut parity = Vec::with_capacity(k * 2 + max_len);
            parity.extend_from_slice(&len_prefix);
            parity.resize(k * 2 + max_len, 0u8);
            let body = &mut parity[k * 2..];
            for (j, shard) in data_shards.iter().enumerate() {
                let coeff = cauchy_coeff(k, r, j)?;
                if coeff == 1 {
                    for (dst, &src) in body.iter_mut().zip(shard.iter()) {
                        *dst ^= src;
                    }
                } else if coeff != 0 {
                    for (dst, &src) in body.iter_mut().zip(shard.iter()) {
                        *dst ^= gf_mul(coeff, src);
                    }
                }
            }
            parities.push(parity);
        }
        Ok(parities)
    }

    /// Recovers all `k` original data shards from any `>= k` surviving shards out of `k + m`.
    /// Indices `0..k` correspond to systematic data shards; `k..k+m` correspond to parity shards.
    pub fn decode(
        k: usize,
        m: usize,
        shards: &[Option<&[u8]>],
    ) -> Result<Vec<Vec<u8>>, FecError> {
        if k == 0 || k > FEC_MAX_DATA_SHARDS || m == 0 || m > FEC_MAX_PARITY_SHARDS {
            return Err(FecError::InvalidParams { k, m });
        }
        if shards.len() != k + m {
            return Err(FecError::ShardCountMismatch {
                expected: k + m,
                actual: shards.len(),
            });
        }

        // Fast path: all k original data shards arrived intact.
        if shards[0..k].iter().all(Option::is_some) {
            let mut out = Vec::with_capacity(k);
            for s in shards[0..k].iter().flatten() {
                out.push((*s).to_vec());
            }
            return Ok(out);
        }

        let present_count = shards.iter().filter(|s| s.is_some()).count();
        if present_count < k {
            return Err(FecError::InsufficientShards {
                needed: k,
                have: present_count,
            });
        }

        // Parse & cross-check original shard lengths from every present parity shard.
        let header_bytes = k * 2;
        let mut orig_lens: Option<Vec<usize>> = None;
        let mut max_len = 0usize;
        for parity in shards[k..k + m].iter().flatten() {
            if parity.len() < header_bytes {
                return Err(FecError::InvalidParityHeader {
                    reason: "parity shard shorter than length table",
                });
            }
            let body_len = parity.len() - header_bytes;
            let mut lens = Vec::with_capacity(k);
            for i in 0..k {
                let len_i = u16::from_be_bytes([parity[2 * i], parity[2 * i + 1]]) as usize;
                if len_i > body_len {
                    return Err(FecError::InvalidParityHeader {
                        reason: "declared shard length exceeds parity body length",
                    });
                }
                lens.push(len_i);
            }
            match &orig_lens {
                None => {
                    max_len = body_len;
                    orig_lens = Some(lens);
                }
                Some(prev) => {
                    if body_len != max_len || lens != *prev {
                        return Err(FecError::InvalidParityHeader {
                            reason: "inconsistent length tables across parity shards",
                        });
                    }
                }
            }
        }

        let orig_lens = orig_lens.ok_or(FecError::InsufficientShards {
            needed: k,
            have: present_count,
        })?;

        // Validate every present data shard matches its recorded length.
        for (idx, shard) in shards[0..k].iter().enumerate() {
            if let Some(bytes) = shard {
                if bytes.len() != orig_lens[idx] {
                    return Err(FecError::DataShardLengthMismatch {
                        index: idx,
                        expected: orig_lens[idx],
                        actual: bytes.len(),
                    });
                }
            }
        }

        // Fast XOR recovery path for m == 1 (exactly one data shard missing, parity 0 present).
        if m == 1 {
            let parity = shards[k].ok_or(FecError::InsufficientShards {
                needed: k,
                have: present_count,
            })?;
            let mut missing_idx = None;
            for (idx, shard) in shards[0..k].iter().enumerate() {
                if shard.is_none() {
                    if missing_idx.is_some() {
                        return Err(FecError::InsufficientShards {
                            needed: k,
                            have: present_count,
                        });
                    }
                    missing_idx = Some(idx);
                }
            }
            let Some(missing) = missing_idx else {
                // Already checked all-some above, defensive fallback.
                let mut out = Vec::with_capacity(k);
                for s in shards[0..k].iter().flatten() {
                    out.push((*s).to_vec());
                }
                return Ok(out);
            };
            let mut recovered_shard = parity[header_bytes..].to_vec();
            for (idx, shard) in shards[0..k].iter().enumerate() {
                if idx != missing {
                    if let Some(bytes) = shard {
                        for (dst, &src) in recovered_shard.iter_mut().zip(bytes.iter()) {
                            *dst ^= src;
                        }
                    }
                }
            }
            recovered_shard.truncate(orig_lens[missing]);
            let mut out = Vec::with_capacity(k);
            for (idx, shard) in shards[0..k].iter().enumerate() {
                if idx == missing {
                    out.push(recovered_shard.clone());
                } else if let Some(bytes) = shard {
                    out.push((*bytes).to_vec());
                }
            }
            return Ok(out);
        }

        // General Cauchy RS recovery via Gauss-Jordan inversion over GF(2^8).
        let mut chosen: Vec<(usize, Vec<u8>)> = Vec::with_capacity(k);
        for (idx, shard) in shards.iter().enumerate() {
            let Some(bytes) = shard else {
                continue;
            };
            if idx < k {
                let mut padded = Vec::with_capacity(max_len);
                padded.extend_from_slice(bytes);
                padded.resize(max_len, 0u8);
                chosen.push((idx, padded));
            } else {
                chosen.push((idx, bytes[header_bytes..].to_vec()));
            }
            if chosen.len() == k {
                break;
            }
        }
        if chosen.len() < k {
            return Err(FecError::InsufficientShards {
                needed: k,
                have: chosen.len(),
            });
        }

        let mut mat = vec![vec![0u8; k]; k];
        for (row, (idx, _)) in chosen.iter().enumerate() {
            if *idx < k {
                mat[row][*idx] = 1;
            } else {
                let r = *idx - k;
                for j in 0..k {
                    mat[row][j] = cauchy_coeff(k, r, j)?;
                }
            }
        }

        let inv = invert_gf256_matrix(&mut mat)?;

        let mut out = Vec::with_capacity(k);
        for (j, &orig_len) in orig_lens.iter().enumerate() {
            if let Some(present) = shards[j] {
                out.push(present.to_vec());
                continue;
            }
            let mut recovered = vec![0u8; max_len];
            for (row, (_, shard_data)) in chosen.iter().enumerate() {
                let coeff = inv[j][row];
                if coeff == 0 {
                    continue;
                }
                if coeff == 1 {
                    for (dst, &src) in recovered.iter_mut().zip(shard_data.iter()) {
                        *dst ^= src;
                    }
                } else {
                    for (dst, &src) in recovered.iter_mut().zip(shard_data.iter()) {
                        *dst ^= gf_mul(coeff, src);
                    }
                }
            }
            recovered.truncate(orig_len);
            out.push(recovered);
        }
        Ok(out)
    }
}

fn invert_gf256_matrix(mat: &mut [Vec<u8>]) -> Result<Vec<Vec<u8>>, FecError> {
    let k = mat.len();
    let mut inv = vec![vec![0u8; k]; k];
    for (i, row) in inv.iter_mut().enumerate() {
        row[i] = 1;
    }

    for col in 0..k {
        let pivot = (col..k)
            .find(|&r| mat[r][col] != 0)
            .ok_or(FecError::SingularMatrix)?;
        if pivot != col {
            mat.swap(col, pivot);
            inv.swap(col, pivot);
        }
        let scale = gf_inv(mat[col][col])?;
        if scale != 1 {
            for c in 0..k {
                mat[col][c] = gf_mul(mat[col][c], scale);
                inv[col][c] = gf_mul(inv[col][c], scale);
            }
        }
        for r in 0..k {
            if r == col {
                continue;
            }
            let factor = mat[r][col];
            if factor == 0 {
                continue;
            }
            for c in 0..k {
                mat[r][c] ^= gf_mul(factor, mat[col][c]);
                inv[r][c] ^= gf_mul(factor, inv[col][c]);
            }
        }
    }
    Ok(inv)
}

/// Output decision from `AdaptiveFecController`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct FecDecision {
    pub enabled: bool,
    pub redundancy_ratio: f64,
    pub observed_loss_rate: f64,
    pub switched_state: bool,
}

/// Adaptive FEC redundancy controller with loss-band mapping and 2000ms ON/OFF debounce.
///
/// Loss-band mapping:
/// - `< 1%` -> OFF (`0%`)
/// - `1%..3%` -> `5%`
/// - `3%..8%` -> `10%..15%`
/// - `> 8%` -> scales dynamically up to hard cap `25%`
///
/// Group constraints:
/// - `k <= 16` media packets per FEC group
/// - parity overhead strictly `<= 25%` of media bitrate
#[derive(Debug, Clone)]
pub struct AdaptiveFecController {
    enabled: bool,
    redundancy_ratio: f64,
    budget_ratio_cap: f64,
    last_loss_rate: f64,
    debounce_ms: u64,
    pending_target_enabled: Option<bool>,
    pending_since_ms: Option<u64>,
    media_bytes_budget_acc: u64,
    fec_bytes_budget_acc: u64,
}

impl Default for AdaptiveFecController {
    fn default() -> Self {
        Self::new()
    }
}

impl AdaptiveFecController {
    pub fn new() -> Self {
        Self::with_debounce_ms(FEC_DEBOUNCE_MS)
    }

    pub fn with_debounce_ms(debounce_ms: u64) -> Self {
        Self {
            enabled: false,
            redundancy_ratio: 0.0,
            budget_ratio_cap: FEC_MAX_REDUNDANCY_RATIO,
            last_loss_rate: 0.0,
            debounce_ms,
            pending_target_enabled: None,
            pending_since_ms: None,
            media_bytes_budget_acc: 0,
            fec_bytes_budget_acc: 0,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn redundancy_ratio(&self) -> f64 {
        self.redundancy_ratio
    }

    /// Effective redundancy ratio after applying any CC bitrate-floor budget cap.
    pub fn effective_redundancy_ratio(&self) -> f64 {
        if !self.enabled {
            0.0
        } else {
            self.redundancy_ratio
                .min(self.budget_ratio_cap)
                .clamp(0.0, FEC_MAX_REDUNDANCY_RATIO)
        }
    }

    /// Caps effective FEC redundancy to what actually fits inside `total_bitrate - media_bitrate`
    /// (for example when media hits the 300 kbps protection floor).
    pub fn set_budget_ratio_cap(&mut self, max_ratio: f64) {
        self.budget_ratio_cap = if max_ratio.is_finite() {
            max_ratio.clamp(0.0, FEC_MAX_REDUNDANCY_RATIO)
        } else {
            0.0
        };
    }

    pub fn media_bytes_budget_acc(&self) -> u64 {
        self.media_bytes_budget_acc
    }

    pub fn fec_bytes_budget_acc(&self) -> u64 {
        self.fec_bytes_budget_acc
    }

    /// Maps an observed packet loss rate to the target redundancy ratio (when FEC is active).
    pub fn target_ratio_for_loss(loss_rate: f64) -> f64 {
        let loss = if loss_rate.is_finite() {
            loss_rate.clamp(0.0, 1.0)
        } else {
            0.0
        };
        if loss < 0.01 {
            0.0
        } else if loss < 0.03 {
            0.05
        } else if loss <= 0.08 {
            // Smoothly map 3%..4.5% -> 10%..15%, holding 15% across 4.5%..8%.
            let t = ((loss - 0.03) / 0.015).clamp(0.0, 1.0);
            (0.10 + 0.05 * t).min(0.15)
        } else {
            // Continuous at 8% (0.15), scaling dynamically up to the hard 25% cap at >= 15% loss.
            let extra = ((loss - 0.08) / 0.07).clamp(0.0, 1.0);
            (0.15 + 0.10 * extra).min(FEC_MAX_REDUNDANCY_RATIO)
        }
    }

    /// Updates FEC state from a new packet loss sample at monotonic timestamp `now_ms`.
    pub fn on_loss_sample(&mut self, now_ms: u64, loss_rate: f64) -> FecDecision {
        let loss = if loss_rate.is_finite() {
            loss_rate.clamp(0.0, 1.0)
        } else {
            0.0
        };
        self.last_loss_rate = loss;
        let want_enabled = loss >= 0.01;
        let mut switched_state = false;

        if want_enabled != self.enabled {
            match (self.pending_target_enabled, self.pending_since_ms) {
                (Some(pending), Some(since)) if pending == want_enabled => {
                    if now_ms.saturating_sub(since) >= self.debounce_ms {
                        self.enabled = want_enabled;
                        self.pending_target_enabled = None;
                        self.pending_since_ms = None;
                        self.media_bytes_budget_acc = 0;
                        self.fec_bytes_budget_acc = 0;
                        switched_state = true;
                    }
                }
                _ => {
                    self.pending_target_enabled = Some(want_enabled);
                    self.pending_since_ms = Some(now_ms);
                }
            }
        } else {
            self.pending_target_enabled = None;
            self.pending_since_ms = None;
        }

        self.redundancy_ratio = if !self.enabled {
            0.0
        } else {
            let mapped = Self::target_ratio_for_loss(loss);
            // If currently debouncing toward OFF (< 1% loss), hold minimal 5% until confirmed.
            if mapped == 0.0 {
                0.05
            } else {
                mapped.min(FEC_MAX_REDUNDANCY_RATIO)
            }
        };

        FecDecision {
            enabled: self.enabled,
            redundancy_ratio: self.redundancy_ratio,
            observed_loss_rate: loss,
            switched_state,
        }
    }

    /// Atomically plans how many RS parity shards `m` to emit for a group of `k` media shards
    /// (`1 <= k <= 16`) and records the exact wire-byte budget (including the `2 * k` length-table
    /// header on every parity shard).
    ///
    /// Guarantees via overflow-free `u128` arithmetic that cumulative wire FEC bytes NEVER exceed
    /// `25.0%` of cumulative media bytes across tiny (`k < 4`), medium, unequal-length, or max groups.
    pub fn plan_group(&mut self, k: usize, group_media_bytes: u64, max_shard_len: usize) -> usize {
        if !self.enabled || k == 0 || group_media_bytes == 0 {
            return 0;
        }
        let eff_ratio = self.effective_redundancy_ratio();
        if eff_ratio <= 0.0 {
            self.media_bytes_budget_acc = self
                .media_bytes_budget_acc
                .saturating_add(group_media_bytes);
            return 0;
        }

        let k_clamped = k.min(FEC_MAX_DATA_SHARDS);
        let est_parity_per_shard =
            (2usize.saturating_mul(k_clamped).saturating_add(max_shard_len)) as u128;
        let group_media = u128::from(group_media_bytes);
        let acc_media_after = u128::from(self.media_bytes_budget_acc).saturating_add(group_media);
        let acc_fec_before = u128::from(self.fec_bytes_budget_acc);

        let desired = ((k_clamped as f64) * eff_ratio)
            .ceil()
            .clamp(1.0, FEC_MAX_PARITY_SHARDS as f64) as usize;
        let max_by_k = if k_clamped >= 4 {
            (k_clamped / 4).min(FEC_MAX_PARITY_SHARDS)
        } else {
            1
        };

        let mut chosen_m = 0usize;
        for cand_m in (1..=desired.min(max_by_k)).rev() {
            let cand_fec = (cand_m as u128).saturating_mul(est_parity_per_shard);
            // Prospective hard cap: cumulative wire FEC bytes * 4 <= cumulative media bytes (<= 25%).
            // Also enforces that tiny groups (k < 4) cannot burst ~100% overhead before >= 4*est_parity
            // of media has accumulated.
            if acc_fec_before
                .saturating_add(cand_fec)
                .saturating_mul(4)
                <= acc_media_after
            {
                chosen_m = cand_m;
                break;
            }
        }

        let chosen_fec_u64 = (chosen_m as u128)
            .saturating_mul(est_parity_per_shard)
            .min(u128::from(u64::MAX)) as u64;
        self.media_bytes_budget_acc = self
            .media_bytes_budget_acc
            .saturating_add(group_media_bytes);
        self.fec_bytes_budget_acc = self.fec_bytes_budget_acc.saturating_add(chosen_fec_u64);
        chosen_m
    }

    /// Read-only estimate of RS parity shards `m` for a group of `k` media shards (`1 <= k <= 16`)
    /// without mutating byte-budget accumulators. Prefer `plan_group` on the actual send path.
    pub fn parity_shards_for_group(&self, k: usize) -> usize {
        let eff_ratio = self.effective_redundancy_ratio();
        if !self.enabled || k == 0 || eff_ratio <= 0.0 {
            return 0;
        }
        let k_clamped = k.min(FEC_MAX_DATA_SHARDS);
        let max_by_cap = (k_clamped / 4).min(FEC_MAX_PARITY_SHARDS);
        if max_by_cap == 0 {
            let allow_tiny = self.media_bytes_budget_acc >= 4
                && u128::from(self.fec_bytes_budget_acc).saturating_mul(4)
                    < u128::from(self.media_bytes_budget_acc);
            return usize::from(allow_tiny);
        }
        let desired = (k_clamped as f64 * eff_ratio).ceil() as usize;
        desired.clamp(1, max_by_cap)
    }

    /// Records transmitted media & FEC bytes manually (for callers not using atomic `plan_group`).
    pub fn record_group_bytes(&mut self, media_bytes: u64, fec_bytes: u64) {
        self.media_bytes_budget_acc = self.media_bytes_budget_acc.saturating_add(media_bytes);
        self.fec_bytes_budget_acc = self.fec_bytes_budget_acc.saturating_add(fec_bytes);
    }
}

/// Selects an MTU-bounded slice size for packetizing a frame into RS-FEC groups.
///
/// Only splits medium frames into 9 slices when `redundancy_ratio >= 0.12` (so 1%–8% low-redundancy
/// bands are never degraded by over-splitting with `m = 0/1`). With `k = 9` and `m = 2`, exact wire
/// parity bytes `2 * (2*9 + S)` remain strictly `<= 25%` of `9 * S` for all `S >= 512`.
pub fn choose_fec_slice_size(frame_len: usize, redundancy_ratio: f64, mtu: usize) -> usize {
    let mtu = mtu.max(512);
    if !redundancy_ratio.is_finite() || redundancy_ratio < 0.12 || frame_len == 0 {
        return mtu;
    }
    let raw_slices = frame_len.div_ceil(mtu);
    if (4..9).contains(&raw_slices) && frame_len >= 4_608 {
        frame_len.div_ceil(9).clamp(512, mtu)
    } else {
        mtu
    }
}

/// Computes the receiver-side hard FEC decode wait timeout in milliseconds:
/// `clamp(2 * measured_jitter_ms, 5, 40)`, capped by `frame_interval_ms` (`1000 / fps`).
pub fn compute_fec_wait_ms(measured_jitter_ms: f64, fps: u32) -> u64 {
    let jitter = if measured_jitter_ms.is_finite() && measured_jitter_ms >= 0.0 {
        measured_jitter_ms
    } else {
        0.0
    };
    let clamped = (2.0 * jitter)
        .clamp(FEC_WAIT_MIN_MS as f64, FEC_WAIT_MAX_MS as f64)
        .round() as u64;
    let frame_interval_ms = (1_000u64 / u64::from(fps.max(1))).max(1);
    clamped.min(frame_interval_ms)
}

/// Result emitted when a group completes or expires inside `FecReorderBuffer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FecGroupOutcome {
    /// All `k` media shards arrived directly without waiting for parity recovery.
    CompleteDirect {
        group_id: u64,
        data_shards: Vec<Vec<u8>>,
        extra_delay_ms: u64,
    },
    /// At least one media shard was lost and recovered via GF(2^8) Cauchy RS parity.
    RecoveredViaFec {
        group_id: u64,
        data_shards: Vec<Vec<u8>>,
        recovered_packets: usize,
        extra_delay_ms: u64,
    },
    /// Hard timeout (`fec_wait_ms`) elapsed before `k` total shards arrived; caller must
    /// immediately fall back to NACK / drop without blocking for late FEC packets.
    TimedOutNeedsNack {
        group_id: u64,
        missing_data_indices: Vec<usize>,
        received_data_count: usize,
        k: usize,
    },
}

/// Cumulative receiver FEC recovery and latency statistics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FecReceiverStats {
    pub direct_complete_groups: u64,
    pub fec_recovered_groups: u64,
    pub fec_recovered_packets: u64,
    pub fec_timeout_groups: u64,
    pub duplicate_shards_ignored: u64,
    pub late_shards_ignored: u64,
    pub invalid_shards: u64,
    pub fec_extra_delay_ms_samples: VecDeque<u64>,
}

#[derive(Debug, Clone)]
struct ActiveFecGroup {
    k: usize,
    m: usize,
    first_arrival_ms: u64,
    last_data_arrival_ms: Option<u64>,
    deadline_ms: u64,
    data_shards: Vec<Option<Vec<u8>>>,
    parity_shards: Vec<Option<Vec<u8>>>,
    data_received: usize,
    parity_received: usize,
}

/// Receiver-side FEC reorder & recovery buffer with strict bounded wait timeout.
///
/// Guarantees:
/// - Duplicate shards are idempotently ignored.
/// - Complete data groups release immediately with `0ms` extra FEC delay.
/// - Recoverable groups decode as soon as `data_received + parity_received >= k`.
/// - Groups exceeding `fec_wait_ms` expire immediately on `poll_expired(now_ms)` and never block.
/// - Capacity evictions and corrupted-shard decode failures queue `TimedOutNeedsNack` into
///   `pending_outcomes` (drained via `drain_pending_outcomes` or `poll_expired`) without poisoning.
#[derive(Debug, Clone)]
pub struct FecReorderBuffer {
    groups: BTreeMap<u64, ActiveFecGroup>,
    completed_or_expired_ids: BTreeMap<u64, u64>,
    pending_outcomes: VecDeque<FecGroupOutcome>,
    max_seen_group_id: Option<u64>,
    max_groups: usize,
    stats: FecReceiverStats,
}

impl Default for FecReorderBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl FecReorderBuffer {
    pub fn new() -> Self {
        Self {
            groups: BTreeMap::new(),
            completed_or_expired_ids: BTreeMap::new(),
            pending_outcomes: VecDeque::new(),
            max_seen_group_id: None,
            max_groups: FEC_REORDER_MAX_GROUPS,
            stats: FecReceiverStats::default(),
        }
    }

    pub fn stats(&self) -> &FecReceiverStats {
        &self.stats
    }

    pub fn active_group_count(&self) -> usize {
        self.groups.len()
    }

    /// Drains any pending `TimedOutNeedsNack` outcomes queued by capacity eviction or
    /// corrupted-shard group retirement. Also drained automatically by `poll_expired`.
    pub fn drain_pending_outcomes(&mut self) -> Vec<FecGroupOutcome> {
        self.pending_outcomes.drain(..).collect()
    }

    /// Inserts a received media data shard (`shard_index in 0..k`) or parity shard
    /// (`is_parity = true, shard_index in 0..m`).
    #[allow(clippy::too_many_arguments)]
    pub fn push_shard(
        &mut self,
        group_id: u64,
        k: usize,
        m: usize,
        is_parity: bool,
        shard_index: usize,
        payload: Vec<u8>,
        now_ms: u64,
        measured_jitter_ms: f64,
        fps: u32,
    ) -> Result<Option<FecGroupOutcome>, FecError> {
        if k == 0 || k > FEC_MAX_DATA_SHARDS || m > FEC_MAX_PARITY_SHARDS {
            return Err(FecError::InvalidParams { k, m });
        }
        if is_parity {
            if m == 0 || shard_index >= m {
                return Err(FecError::InvalidShardIndex {
                    index: shard_index,
                    limit: m,
                });
            }
        } else if shard_index >= k {
            return Err(FecError::InvalidShardIndex {
                index: shard_index,
                limit: k,
            });
        }

        // Ignore late or duplicate shards for already-finished groups or IDs behind the watermark
        // so pruned historic group IDs can never resurrect as zombie groups.
        let watermark_span = (self.max_groups as u64).saturating_mul(8);
        if self.completed_or_expired_ids.contains_key(&group_id)
            || self
                .max_seen_group_id
                .is_some_and(|max_id| group_id.saturating_add(watermark_span) < max_id)
        {
            self.stats.late_shards_ignored = self.stats.late_shards_ignored.saturating_add(1);
            return Ok(None);
        }
        self.max_seen_group_id = Some(
            self.max_seen_group_id
                .map_or(group_id, |prev| prev.max(group_id)),
        );

        // Enforce bounded memory by evicting the oldest active group if full, queuing its
        // TimedOutNeedsNack outcome so NACK fallback is never silently lost.
        if !self.groups.contains_key(&group_id) && self.groups.len() >= self.max_groups {
            if let Some((&oldest_id, _)) = self.groups.iter().next() {
                if let Some(evicted) = self.groups.remove(&oldest_id) {
                    self.mark_finished(oldest_id, now_ms);
                    self.stats.fec_timeout_groups = self.stats.fec_timeout_groups.saturating_add(1);
                    self.pending_outcomes
                        .push_back(Self::build_timeout_outcome(oldest_id, &evicted));
                }
            }
        }

        let wait_ms = compute_fec_wait_ms(measured_jitter_ms, fps);
        let frame_interval_ms = (1_000u64 / u64::from(fps.max(1))).max(1);
        let group = self.groups.entry(group_id).or_insert_with(|| ActiveFecGroup {
            k,
            m,
            first_arrival_ms: now_ms,
            last_data_arrival_ms: None,
            deadline_ms: now_ms.saturating_add(wait_ms),
            data_shards: vec![None; k],
            parity_shards: vec![None; m],
            data_received: 0,
            parity_received: 0,
        });

        // Ignore inconsistent untrusted shard metadata without poisoning the active group.
        if group.k != k || group.m != m {
            self.stats.invalid_shards = self.stats.invalid_shards.saturating_add(1);
            return Ok(None);
        }

        if is_parity {
            if group.parity_shards[shard_index].is_some() {
                self.stats.duplicate_shards_ignored =
                    self.stats.duplicate_shards_ignored.saturating_add(1);
                return Ok(None);
            }
            group.parity_shards[shard_index] = Some(payload);
            group.parity_received += 1;
            let hard_cap = group
                .first_arrival_ms
                .saturating_add(frame_interval_ms.min(FEC_WAIT_MAX_MS));
            group.deadline_ms = now_ms.saturating_add(wait_ms).min(hard_cap);
        } else {
            if group.data_shards[shard_index].is_some() {
                self.stats.duplicate_shards_ignored =
                    self.stats.duplicate_shards_ignored.saturating_add(1);
                return Ok(None);
            }
            group.data_shards[shard_index] = Some(payload);
            group.data_received += 1;
            group.last_data_arrival_ms = Some(now_ms);
            // Anchor the FEC wait timeout to the latest arriving data shard of the group,
            // while still hard-capping total group lifetime at min(frame_interval_ms, 40ms).
            let hard_cap = group
                .first_arrival_ms
                .saturating_add(frame_interval_ms.min(FEC_WAIT_MAX_MS));
            group.deadline_ms = now_ms.saturating_add(wait_ms).min(hard_cap);
        }

        let direct_complete = group.data_received == group.k;
        let can_recover = group.m > 0 && group.data_received + group.parity_received >= group.k;

        // Case 1: all k media shards arrived directly -> release immediately with 0 extra delay.
        if direct_complete {
            if let Some(done) = self.groups.remove(&group_id) {
                self.mark_finished(group_id, now_ms);
                self.stats.direct_complete_groups =
                    self.stats.direct_complete_groups.saturating_add(1);
                let data_shards: Vec<Vec<u8>> = done.data_shards.into_iter().flatten().collect();
                return Ok(Some(FecGroupOutcome::CompleteDirect {
                    group_id,
                    data_shards,
                    extra_delay_ms: 0,
                }));
            }
        }

        // Case 2: data + parity >= k (with m > 0) -> decode immediately via Cauchy RS.
        if can_recover {
            let decode_attempt = {
                let Some(g) = self.groups.get(&group_id) else {
                    return Ok(None);
                };
                let recovered_packets = g.k.saturating_sub(g.data_received);
                let wait_origin_ms = g.last_data_arrival_ms.unwrap_or(g.first_arrival_ms);
                let extra_delay_ms = now_ms.saturating_sub(wait_origin_ms);

                let mut slice_refs: Vec<Option<&[u8]>> = Vec::with_capacity(g.k + g.m);
                for s in &g.data_shards {
                    slice_refs.push(s.as_deref());
                }
                for s in &g.parity_shards {
                    slice_refs.push(s.as_deref());
                }

                RsCodec::decode(g.k, g.m, &slice_refs)
                    .map(|recovered| (recovered_packets, extra_delay_ms, recovered))
            };

            match decode_attempt {
                Ok((recovered_packets, extra_delay_ms, recovered)) => {
                    self.groups.remove(&group_id);
                    self.mark_finished(group_id, now_ms);
                    self.stats.fec_recovered_groups =
                        self.stats.fec_recovered_groups.saturating_add(1);
                    self.stats.fec_recovered_packets = self
                        .stats
                        .fec_recovered_packets
                        .saturating_add(recovered_packets as u64);
                    self.push_extra_delay_sample(extra_delay_ms);

                    return Ok(Some(FecGroupOutcome::RecoveredViaFec {
                        group_id,
                        data_shards: recovered,
                        recovered_packets,
                        extra_delay_ms,
                    }));
                }
                Err(_) => {
                    // Corrupted / untrusted shard failed RS decode: retire the group cleanly
                    // with TimedOutNeedsNack and increment invalid_shards (zero poisoned group / error storm).
                    self.stats.invalid_shards = self.stats.invalid_shards.saturating_add(1);
                    if let Some(poisoned) = self.groups.remove(&group_id) {
                        self.mark_finished(group_id, now_ms);
                        self.stats.fec_timeout_groups =
                            self.stats.fec_timeout_groups.saturating_add(1);
                        self.pending_outcomes
                            .push_back(Self::build_timeout_outcome(group_id, &poisoned));
                    }
                    return Ok(None);
                }
            }
        }

        Ok(None)
    }

    /// Expires all incomplete groups whose hard deadline `deadline_ms <= now_ms`,
    /// returning both any previously queued eviction/corruption outcomes and newly expired groups.
    pub fn poll_expired(&mut self, now_ms: u64) -> Vec<FecGroupOutcome> {
        let mut outcomes = self.drain_pending_outcomes();
        let expired_ids: Vec<u64> = self
            .groups
            .iter()
            .filter(|(_, g)| now_ms >= g.deadline_ms)
            .map(|(&id, _)| id)
            .collect();

        outcomes.reserve(expired_ids.len());
        for id in expired_ids {
            if let Some(group) = self.groups.remove(&id) {
                self.mark_finished(id, now_ms);
                self.stats.fec_timeout_groups = self.stats.fec_timeout_groups.saturating_add(1);
                outcomes.push(Self::build_timeout_outcome(id, &group));
            }
        }
        outcomes
    }

    fn build_timeout_outcome(group_id: u64, group: &ActiveFecGroup) -> FecGroupOutcome {
        let missing_data_indices = group
            .data_shards
            .iter()
            .enumerate()
            .filter_map(|(idx, s)| if s.is_none() { Some(idx) } else { None })
            .collect();
        FecGroupOutcome::TimedOutNeedsNack {
            group_id,
            missing_data_indices,
            received_data_count: group.data_received,
            k: group.k,
        }
    }

    fn push_extra_delay_sample(&mut self, extra_delay_ms: u64) {
        while self.stats.fec_extra_delay_ms_samples.len() >= FEC_EXTRA_DELAY_MAX_SAMPLES {
            self.stats.fec_extra_delay_ms_samples.pop_front();
        }
        self.stats
            .fec_extra_delay_ms_samples
            .push_back(extra_delay_ms);
    }

    fn mark_finished(&mut self, group_id: u64, now_ms: u64) {
        self.completed_or_expired_ids.insert(group_id, now_ms);
        // Keep history bounded to avoid unbounded growth in long sessions.
        while self.completed_or_expired_ids.len() > self.max_groups * 8 {
            if let Some((&oldest, _)) = self.completed_or_expired_ids.iter().next() {
                self.completed_or_expired_ids.remove(&oldest);
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf256_tables_and_inverses_exhaustive() {
        let mut seen = [false; 256];
        for (i, &v) in GF_EXP.iter().enumerate().take(255) {
            assert_ne!(v, 0, "exp[{i}] must be nonzero");
            assert!(!seen[v as usize], "duplicate GF(2^8) generator power at {i}");
            seen[v as usize] = true;
            assert_eq!(GF_LOG[v as usize] as usize, i);
        }
        assert!(gf_inv(0).is_err());
        for a in 1u8..=255 {
            let inv = gf_inv(a).unwrap();
            assert_eq!(gf_mul(a, inv), 1, "a={a} inv={inv}");
            assert_eq!(gf_mul(a, 0), 0);
            assert_eq!(gf_mul(0, a), 0);
        }
    }

    #[test]
    fn rs_xor_fast_path_recovers_any_single_loss_unequal_and_empty() {
        let d0: Vec<u8> = vec![];
        let d1: Vec<u8> = vec![0xAA];
        let d2: Vec<u8> = (0u8..=250).collect();
        let d3: Vec<u8> = vec![0x55; 1200];
        let data: Vec<&[u8]> = vec![&d0, &d1, &d2, &d3];
        let parities = RsCodec::encode(&data, 1).unwrap();
        assert_eq!(parities.len(), 1);

        for drop_idx in 0..data.len() {
            let mut recv: Vec<Option<&[u8]>> = data.iter().copied().map(Some).collect();
            recv[drop_idx] = None;
            recv.push(Some(parities[0].as_slice()));
            let recovered = RsCodec::decode(data.len(), 1, &recv).unwrap();
            assert_eq!(recovered.len(), data.len());
            for (i, orig) in data.iter().enumerate() {
                assert_eq!(recovered[i].as_slice(), *orig, "drop_idx={drop_idx} shard={i}");
            }
        }
    }

    #[test]
    fn rs_cauchy_16_4_recovers_every_4_erasure_combination_including_mixed_parity() {
        let k = 16usize;
        let m = 4usize;
        let owned: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                let len = if i == 0 { 0 } else { (i * 73) % 1150 + 1 };
                (0..len)
                    .map(|j| ((i * 31 + j * 17 + 7) & 0xFF) as u8)
                    .collect()
            })
            .collect();
        let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
        let parities = RsCodec::encode(&refs, m).unwrap();
        assert_eq!(parities.len(), m);

        // Test several distinct 4-loss patterns: all data, burst data, mixed data + parity.
        let patterns: [[usize; 4]; 5] = [
            [0, 1, 2, 3],
            [12, 13, 14, 15],
            [0, 5, 10, 15],
            [2, 7, 16, 19],
            [4, 9, 14, 17],
        ];
        for lost in patterns {
            let mut recv: Vec<Option<&[u8]>> = Vec::with_capacity(k + m);
            for s in &refs {
                recv.push(Some(*s));
            }
            for p in &parities {
                recv.push(Some(p.as_slice()));
            }
            for idx in lost {
                recv[idx] = None;
            }
            let recovered = RsCodec::decode(k, m, &recv).unwrap();
            assert_eq!(recovered, owned, "failed recovery for pattern {lost:?}");
        }

        // Losing 5 shards (> m) must cleanly return InsufficientShards (never panic).
        let mut recv: Vec<Option<&[u8]>> = refs.iter().copied().map(Some).collect();
        recv.extend(parities.iter().map(|p| Some(p.as_slice())));
        for idx in [0, 1, 2, 3, 4] {
            recv[idx] = None;
        }
        assert!(matches!(
            RsCodec::decode(k, m, &recv),
            Err(FecError::InsufficientShards { needed: 16, have: 15 })
        ));
    }

    #[test]
    fn rs_boundary_validation_never_panics() {
        let empty: [&[u8]; 0] = [];
        assert!(matches!(
            RsCodec::encode(&empty, 1),
            Err(FecError::InvalidParams { k: 0, m: 1 })
        ));
        let d = [1u8, 2, 3];
        let one: [&[u8]; 1] = [&d];
        assert!(matches!(
            RsCodec::encode(&one, 0),
            Err(FecError::InvalidParams { k: 1, m: 0 })
        ));
        assert!(matches!(
            RsCodec::encode(&one, 5),
            Err(FecError::InvalidParams { k: 1, m: 5 })
        ));
        let too_many = vec![&d[..]; 17];
        assert!(matches!(
            RsCodec::encode(&too_many, 1),
            Err(FecError::InvalidParams { k: 17, m: 1 })
        ));
        // Corrupted short parity header
        let bad_parity = [0u8; 1];
        assert!(matches!(
            RsCodec::decode(2, 1, &[Some(&d), None, Some(&bad_parity)]),
            Err(FecError::InvalidParityHeader { .. })
        ));
    }

    #[test]
    fn adaptive_fec_loss_bands_and_2000ms_debounce() {
        let mut ctrl = AdaptiveFecController::new();
        assert!(!ctrl.is_enabled());

        // Transient spike (< 2000ms) must NOT toggle FEC ON.
        assert!(!ctrl.on_loss_sample(0, 0.05).enabled);
        assert!(!ctrl.on_loss_sample(1_500, 0.05).enabled);
        // Dropping back below 1% resets the debounce timer.
        assert!(!ctrl.on_loss_sample(1_800, 0.005).enabled);
        assert!(!ctrl.on_loss_sample(2_500, 0.05).enabled);
        // Sustained >= 2000ms enables FEC cleanly.
        assert!(!ctrl.on_loss_sample(4_400, 0.05).enabled);
        let d = ctrl.on_loss_sample(4_500, 0.05);
        assert!(d.enabled);
        assert!(d.switched_state);
        assert!((0.10..=0.15).contains(&d.redundancy_ratio));

        // 1%-3% band -> 5%
        let d_low = ctrl.on_loss_sample(5_000, 0.02);
        assert!(d_low.enabled);
        assert!((d_low.redundancy_ratio - 0.05).abs() < 1e-6);

        // > 8% band -> scales up to hard cap 25%
        let d_high = ctrl.on_loss_sample(5_500, 0.25);
        assert!(d_high.enabled);
        assert!((d_high.redundancy_ratio - 0.25).abs() < 1e-6);
        assert!(ctrl.parity_shards_for_group(16) <= 4);
        assert!(ctrl.parity_shards_for_group(12) <= 3);
        assert!(ctrl.parity_shards_for_group(8) <= 2);

        // Turning OFF also requires >= 2000ms below 1%.
        assert!(ctrl.on_loss_sample(6_000, 0.0).enabled);
        assert!(ctrl.on_loss_sample(7_999, 0.0).enabled);
        let d_off = ctrl.on_loss_sample(8_000, 0.0);
        assert!(!d_off.enabled);
        assert!(d_off.switched_state);
        assert_eq!(d_off.redundancy_ratio, 0.0);
    }

    #[test]
    fn fec_wait_clamp_and_reorder_buffer_timeout_and_duplicate_idempotency() {
        assert_eq!(compute_fec_wait_ms(0.0, 30), 5);
        assert_eq!(compute_fec_wait_ms(10.0, 30), 20);
        assert_eq!(compute_fec_wait_ms(25.0, 30), 33);
        assert_eq!(compute_fec_wait_ms(25.0, 60), 16);
        assert_eq!(compute_fec_wait_ms(30.0, 15), 40);

        let mut buf = FecReorderBuffer::new();
        let d0 = b"packet-zero".to_vec();
        let d1 = b"packet-one-longer".to_vec();
        let d2 = b"p2".to_vec();
        let d3 = b"packet-three".to_vec();
        let parities = RsCodec::encode(&[&d0, &d1, &d2, &d3], 1).unwrap();

        // Receive d0, duplicate d0 (idempotent), d2, d3, then parity -> recover d1!
        assert!(buf.push_shard(1, 4, 1, false, 0, d0.clone(), 100, 8.0, 30).unwrap().is_none());
        assert!(buf.push_shard(1, 4, 1, false, 0, d0.clone(), 101, 8.0, 30).unwrap().is_none());
        assert_eq!(buf.stats().duplicate_shards_ignored, 1);
        assert!(buf.push_shard(1, 4, 1, false, 2, d2.clone(), 102, 8.0, 30).unwrap().is_none());
        assert!(buf.push_shard(1, 4, 1, false, 3, d3.clone(), 103, 8.0, 30).unwrap().is_none());
        let out = buf
            .push_shard(1, 4, 1, true, 0, parities[0].clone(), 108, 8.0, 30)
            .unwrap();
        match out {
            Some(FecGroupOutcome::RecoveredViaFec {
                group_id: 1,
                data_shards,
                recovered_packets: 1,
                extra_delay_ms: 5,
            }) => {
                assert_eq!(data_shards, vec![d0.clone(), d1, d2, d3]);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
        assert_eq!(buf.stats().fec_recovered_packets, 1);
        assert_eq!(
            buf.stats()
                .fec_extra_delay_ms_samples
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![5]
        );

        // Group 2 loses 2 shards with m=1 -> must expire cleanly at first_arrival + fec_wait_ms.
        assert!(buf.push_shard(2, 4, 1, false, 0, d0, 200, 10.0, 30).unwrap().is_none());
        assert!(buf.poll_expired(219).is_empty());
        let expired = buf.poll_expired(220);
        assert_eq!(expired.len(), 1);
        assert!(matches!(
            &expired[0],
            FecGroupOutcome::TimedOutNeedsNack {
                group_id: 2,
                missing_data_indices,
                received_data_count: 1,
                k: 4,
            } if missing_data_indices == &vec![1, 2, 3]
        ));
    }

    #[test]
    fn choose_fec_slice_size_unlocks_two_parities_within_25pct_budget() {
        // Off and low-redundancy bands (< 12%) must NOT over-split frames.
        assert_eq!(choose_fec_slice_size(8_400, 0.0, 1_200), 1_200);
        assert_eq!(choose_fec_slice_size(8_400, 0.05, 1_200), 1_200);
        assert_eq!(choose_fec_slice_size(8_400, 0.10, 1_200), 1_200);
        // At >= 12% redundancy, splits medium frames to 9 slices so m=2 fits strictly <= 25% wire bytes.
        let sz = choose_fec_slice_size(8_400, 0.15, 1_200);
        assert!((512..=1_200).contains(&sz));
        let slices = 8_400usize.div_ceil(sz);
        assert_eq!(slices, 9);
        assert_eq!(choose_fec_slice_size(14_400, 0.25, 1_200), 1_200);
    }

    #[test]
    fn plan_group_strictly_enforces_25pct_wire_byte_cap_across_tiny_medium_and_max_groups() {
        // Verify continuity at 8% boundary.
        let at_8 = AdaptiveFecController::target_ratio_for_loss(0.08);
        let above_8 = AdaptiveFecController::target_ratio_for_loss(0.080_001);
        assert!((at_8 - 0.15).abs() < 1e-6);
        assert!((above_8 - 0.15).abs() < 1e-3);

        // Test tiny (k=1..3), medium (k=8..12), and max (k=16) groups at 25% target redundancy.
        for &(k, shard_len) in &[
            (1usize, 1_000usize),
            (2, 1_000),
            (3, 1_000),
            (8, 1_050),
            (9, 934),
            (12, 1_100),
            (16, 1_200),
        ] {
            let mut ctrl = AdaptiveFecController::with_debounce_ms(0);
            ctrl.on_loss_sample(0, 0.20);
            ctrl.on_loss_sample(1, 0.20);
            assert!(ctrl.is_enabled());

            let shards: Vec<Vec<u8>> = (0..k).map(|i| vec![(i as u8).wrapping_add(1); shard_len]).collect();
            let refs: Vec<&[u8]> = shards.iter().map(Vec::as_slice).collect();
            let group_media_bytes = (k * shard_len) as u64;

            let mut total_media = 0u128;
            let mut total_wire_fec = 0u128;
            for iter in 0..24 {
                let m = ctrl.plan_group(k, group_media_bytes, shard_len);
                let actual_fec_bytes = if m > 0 {
                    let parities = RsCodec::encode(&refs, m).unwrap();
                    assert_eq!(parities.len(), m);
                    parities.iter().map(|p| p.len() as u128).sum::<u128>()
                } else {
                    0u128
                };
                total_media += u128::from(group_media_bytes);
                total_wire_fec += actual_fec_bytes;
                assert!(
                    total_wire_fec * 4 <= total_media,
                    "k={k} iter={iter}: cumulative wire FEC bytes {total_wire_fec} exceeded 25% of media {total_media}"
                );
                if k < 4 && iter == 0 {
                    // Tiny groups MUST NOT burst ~100% overhead at stream start.
                    assert_eq!(m, 0, "tiny group k={k} must not emit parity on first group");
                }
                if k == 9 {
                    // k=9 with 934B shards unlocks m=2 on every group within <=25% wire bytes.
                    assert_eq!(m, 2);
                }
            }
            assert!(
                total_wire_fec > 0,
                "k={k} should emit parity once cumulative budget allows"
            );
        }
    }

    #[test]
    fn reorder_buffer_eviction_emits_pending_nack_and_watermark_blocks_zombie_resurrection() {
        let mut buf = FecReorderBuffer::new();
        // Fill buffer past FEC_REORDER_MAX_GROUPS (64) with incomplete groups -> oldest must evict
        // AND emit TimedOutNeedsNack into pending_outcomes (never silently dropped).
        for gid in 1..=(FEC_REORDER_MAX_GROUPS as u64 + 3) {
            assert!(buf
                .push_shard(gid, 4, 1, false, 0, b"payload".to_vec(), gid * 2, 5.0, 30)
                .unwrap()
                .is_none());
        }
        assert_eq!(buf.active_group_count(), FEC_REORDER_MAX_GROUPS);
        let evicted = buf.drain_pending_outcomes();
        assert_eq!(evicted.len(), 3);
        for (idx, outcome) in evicted.iter().enumerate() {
            assert!(matches!(
                outcome,
                FecGroupOutcome::TimedOutNeedsNack { group_id, .. } if *group_id == (idx as u64 + 1)
            ));
        }

        // Advance well beyond 8 * max_groups so completed_or_expired_ids prunes group 1,
        // then inject a late shard for group 1 -> watermark MUST reject it as late (no zombie!).
        let far_gid = (FEC_REORDER_MAX_GROUPS as u64) * 10 + 50;
        assert!(buf
            .push_shard(far_gid, 4, 1, false, 0, b"far".to_vec(), 5_000, 5.0, 30)
            .unwrap()
            .is_none());
        let late_before = buf.stats().late_shards_ignored;
        assert!(buf
            .push_shard(1, 4, 1, false, 1, b"zombie".to_vec(), 5_001, 5.0, 30)
            .unwrap()
            .is_none());
        assert_eq!(buf.stats().late_shards_ignored, late_before + 1);
        assert_eq!(buf.active_group_count(), FEC_REORDER_MAX_GROUPS);

        // Verify fec_extra_delay_ms_samples stays bounded at <= FEC_EXTRA_DELAY_MAX_SAMPLES.
        let mut cap_buf = FecReorderBuffer::new();
        let d0 = b"aaaa".to_vec();
        let d1 = b"bbbb".to_vec();
        let p = RsCodec::encode(&[&d0, &d1], 1).unwrap();
        for gid in 1..=(FEC_EXTRA_DELAY_MAX_SAMPLES as u64 + 50) {
            let _ = cap_buf
                .push_shard(gid, 2, 1, false, 0, d0.clone(), gid * 10, 5.0, 30)
                .unwrap();
            let _ = cap_buf
                .push_shard(gid, 2, 1, true, 0, p[0].clone(), gid * 10 + 2, 5.0, 30)
                .unwrap();
        }
        assert_eq!(
            cap_buf.stats().fec_extra_delay_ms_samples.len(),
            FEC_EXTRA_DELAY_MAX_SAMPLES
        );
    }

    #[test]
    fn reorder_buffer_handles_corrupted_parity_and_km_mismatch_without_error_storm() {
        let mut buf = FecReorderBuffer::new();
        let d0 = b"hello-0".to_vec();
        let d2 = b"hello-2".to_vec();
        let d3 = b"hello-3".to_vec();

        // Populate 3 of 4 data shards for group 10 (k=4, m=1).
        assert!(buf.push_shard(10, 4, 1, false, 0, d0, 100, 5.0, 30).unwrap().is_none());
        // Inject a mismatched k/m shard -> must NOT return Err or poison group 10!
        assert!(buf
            .push_shard(10, 5, 1, false, 1, b"bad-meta".to_vec(), 101, 5.0, 30)
            .unwrap()
            .is_none());
        assert_eq!(buf.stats().invalid_shards, 1);
        assert_eq!(buf.active_group_count(), 1);

        assert!(buf.push_shard(10, 4, 1, false, 2, d2, 102, 5.0, 30).unwrap().is_none());
        assert!(buf.push_shard(10, 4, 1, false, 3, d3, 103, 5.0, 30).unwrap().is_none());

        // Inject a corrupted/truncated parity shard -> must retire group cleanly with TimedOutNeedsNack,
        // return Ok(None), increment invalid_shards, and leave zero poisoned active group.
        let res = buf.push_shard(10, 4, 1, true, 0, vec![0xFF, 0xFF], 104, 5.0, 30);
        assert!(res.is_ok());
        assert!(res.unwrap().is_none());
        assert_eq!(buf.stats().invalid_shards, 2);
        assert_eq!(buf.active_group_count(), 0);

        let pending = buf.drain_pending_outcomes();
        assert_eq!(pending.len(), 1);
        assert!(matches!(
            &pending[0],
            FecGroupOutcome::TimedOutNeedsNack { group_id: 10, .. }
        ));

        // Subsequent shards for retired group 10 are ignored cleanly (no error storm).
        assert!(buf
            .push_shard(10, 4, 1, false, 1, b"late".to_vec(), 105, 5.0, 30)
            .unwrap()
            .is_none());
        assert_eq!(buf.stats().late_shards_ignored, 1);
    }
}
