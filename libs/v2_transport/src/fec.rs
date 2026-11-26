use crate::error::TransportError;

pub const SURVIVAL_RS_K: usize = 6;
pub const SURVIVAL_RS_M: usize = 4;

/// Multiplication in GF(2^8) with primitive polynomial `0x11D` (`x^8 + x^4 + x^3 + x^2 + 1`).
pub fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut acc = 0u8;
    for _ in 0..8 {
        if (b & 1) != 0 {
            acc ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1D;
        }
        b >>= 1;
    }
    acc
}

fn gf_pow(mut base: u8, mut exp: u16) -> u8 {
    let mut out = 1u8;
    while exp > 0 {
        if (exp & 1) != 0 {
            out = gf_mul(out, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    out
}

/// Multiplicative inverse in GF(2^8, `0x11D`). Returns `InvalidFraming` on `0`.
pub fn gf_inv(a: u8) -> Result<u8, TransportError> {
    if a == 0 {
        return Err(TransportError::InvalidFraming(
            "GF(2^8) inverse of zero".into(),
        ));
    }
    Ok(gf_pow(a, 254))
}

/// Canonical Cauchy matrix entry `C[r][j] = inv((k + r) ^ j)` per V2 spec `02-backbone-fec.md` §2.3.
pub fn cauchy_coeff(k: usize, r: usize, j: usize) -> Result<u8, TransportError> {
    if k == 0 || j >= k || k + r > 255 {
        return Err(TransportError::InvalidFraming(
            "invalid Cauchy RS dimensions".into(),
        ));
    }
    gf_inv(((k + r) as u8) ^ (j as u8))
}

/// Encodes `k` unequal-length shards into `m` Cauchy RS parity payloads:
/// `[u16_be(len_0) .. u16_be(len_{k-1})] || parity_data[max_len]`.
pub fn rs_cauchy_encode_unequal(
    data_shards: &[Vec<u8>],
    m: usize,
) -> Result<Vec<Vec<u8>>, TransportError> {
    let k = data_shards.len();
    if k == 0 || m == 0 || k + m > 255 {
        return Err(TransportError::InvalidFraming(
            "invalid RS(k, m) parameters".into(),
        ));
    }
    let mut max_len = 0usize;
    let mut len_prefix = Vec::with_capacity(k * 2);
    for shard in data_shards {
        let len_u16 = u16::try_from(shard.len())
            .map_err(|_| TransportError::InvalidFraming("RS shard exceeds u16::MAX".into()))?;
        len_prefix.extend_from_slice(&len_u16.to_be_bytes());
        max_len = max_len.max(shard.len());
    }

    let mut parities = Vec::with_capacity(m);
    for r in 0..m {
        let mut parity = Vec::with_capacity(k * 2 + max_len);
        parity.extend_from_slice(&len_prefix);
        parity.resize(k * 2 + max_len, 0u8);
        for (j, shard) in data_shards.iter().enumerate() {
            let coeff = cauchy_coeff(k, r, j)?;
            for (t, &byte) in shard.iter().enumerate() {
                parity[k * 2 + t] ^= gf_mul(coeff, byte);
            }
        }
        parities.push(parity);
    }
    Ok(parities)
}

/// Recovers all `k` original unequal-length shards from any `>= k` surviving shards
/// (`shards.len() == k + m`, indices `0..k` are data shards, `k..k+m` are parity shards).
pub fn rs_cauchy_decode_unequal(
    k: usize,
    m: usize,
    shards: &[Option<Vec<u8>>],
) -> Result<Vec<Vec<u8>>, TransportError> {
    if k == 0 || m == 0 || k + m > 255 || shards.len() != k + m {
        return Err(TransportError::InvalidFraming(
            "invalid RS(k, m) decode inputs".into(),
        ));
    }
    if shards[0..k].iter().all(Option::is_some) {
        let mut out = Vec::with_capacity(k);
        for bytes in shards[0..k].iter().flatten() {
            out.push(bytes.clone());
        }
        return Ok(out);
    }

    let mut orig_lens: Option<Vec<usize>> = None;
    let mut max_len = 0usize;
    for parity in shards[k..k + m].iter().flatten() {
        if parity.len() < k * 2 {
            return Err(TransportError::InvalidFraming(
                "RS parity shard shorter than length table".into(),
            ));
        }
        let body_len = parity.len() - k * 2;
        let mut lens = Vec::with_capacity(k);
        for i in 0..k {
            let lj = u16::from_be_bytes([parity[2 * i], parity[2 * i + 1]]) as usize;
            if lj > body_len {
                return Err(TransportError::InvalidFraming(
                    "RS parity shard length prefix exceeds payload".into(),
                ));
            }
            lens.push(lj);
        }
        match &orig_lens {
            None => {
                max_len = body_len;
                orig_lens = Some(lens);
            }
            Some(prev) => {
                if body_len != max_len || lens != *prev {
                    return Err(TransportError::InvalidFraming(
                        "inconsistent RS parity shard length table".into(),
                    ));
                }
            }
        }
    }
    let orig_lens = orig_lens.ok_or_else(|| {
        TransportError::InvalidFraming("insufficient RS parity shards for recovery".into())
    })?;

    let mut chosen: Vec<(usize, Vec<u8>)> = Vec::with_capacity(k);
    for (idx, shard) in shards.iter().enumerate() {
        let Some(bytes) = shard else {
            continue;
        };
        if idx < k {
            if bytes.len() > max_len || bytes.len() != orig_lens[idx] {
                return Err(TransportError::InvalidFraming(
                    "RS data shard length does not match parity table".into(),
                ));
            }
            let mut padded = bytes.clone();
            padded.resize(max_len, 0u8);
            chosen.push((idx, padded));
        } else {
            if bytes.len() != k * 2 + max_len {
                return Err(TransportError::InvalidFraming(
                    "RS parity shard length mismatch".into(),
                ));
            }
            chosen.push((idx, bytes[k * 2..].to_vec()));
        }
        if chosen.len() == k {
            break;
        }
    }
    if chosen.len() < k {
        return Err(TransportError::InvalidFraming(
            "fewer than k surviving RS shards".into(),
        ));
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

    let mut inv = vec![vec![0u8; k]; k];
    for (i, row) in inv.iter_mut().enumerate() {
        row[i] = 1;
    }
    for col in 0..k {
        let pivot = (col..k)
            .find(|&r| mat[r][col] != 0)
            .ok_or_else(|| TransportError::InvalidFraming("singular RS decoding matrix".into()))?;
        if pivot != col {
            mat.swap(col, pivot);
            inv.swap(col, pivot);
        }
        let scale = gf_inv(mat[col][col])?;
        for c in 0..k {
            mat[col][c] = gf_mul(mat[col][c], scale);
            inv[col][c] = gf_mul(inv[col][c], scale);
        }
        for r in 0..k {
            if r != col && mat[r][col] != 0 {
                let factor = mat[r][col];
                for c in 0..k {
                    mat[r][c] ^= gf_mul(factor, mat[col][c]);
                    inv[r][c] ^= gf_mul(factor, inv[col][c]);
                }
            }
        }
    }

    let mut recovered = Vec::with_capacity(k);
    for (j, &orig_len) in orig_lens.iter().enumerate() {
        if orig_len > max_len {
            return Err(TransportError::InvalidFraming(
                "RS original shard length exceeds max_len".into(),
            ));
        }
        let mut out = vec![0u8; max_len];
        for (row, (_, shard_data)) in chosen.iter().enumerate() {
            let coeff = inv[j][row];
            if coeff == 0 {
                continue;
            }
            for (dst, &src) in out.iter_mut().zip(shard_data.iter()) {
                *dst ^= gf_mul(coeff, src);
            }
        }
        out.truncate(orig_len);
        recovered.push(out);
    }
    Ok(recovered)
}

/// Convenience encoder for Survival Mode `RS(6, 4)` (returns all 10 shards: 6 data + 4 parity).
pub fn rs64_encode_block(data_shards: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, TransportError> {
    if data_shards.len() != SURVIVAL_RS_K {
        return Err(TransportError::InvalidFraming(
            "RS(6,4) requires exactly 6 data shards".into(),
        ));
    }
    let parities = rs_cauchy_encode_unequal(data_shards, SURVIVAL_RS_M)?;
    let mut all = Vec::with_capacity(SURVIVAL_RS_K + SURVIVAL_RS_M);
    all.extend(data_shards.iter().cloned());
    all.extend(parities);
    Ok(all)
}

/// Convenience decoder for Survival Mode `RS(6, 4)` (recovers all 6 data shards from any 6 of 10).
pub fn rs64_decode_block(shards: &[Option<Vec<u8>>]) -> Result<Vec<Vec<u8>>, TransportError> {
    rs_cauchy_decode_unequal(SURVIVAL_RS_K, SURVIVAL_RS_M, shards)
}
