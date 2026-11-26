// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::{
    bootstrap_live_pair, now_ms, parse_flag_value, percentile_ms, print_usage,
    BootstrappedSessions, ENCODER_QUALITY, HEIGHT, MIN_PSNR_DB, MIN_SSIM, WIDTH,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::PathBuf,
    process::ExitCode,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use v2_client::{ClientError, ClusterConfig};
use v2_e2e::{
    compute_y_psnr, compute_y_ssim, decode_hid_frame, encode_hid_frame, generate_animated_i420,
    parse_request_idr, parse_session_close, DesktopControllerSession, DesktopHostSession,
    HidEchoAck, HidPayload, I420Frame, KeyEvent, MouseEvent, MouseKind, SessionError,
    V2VideoDecoder, V2VideoEncoder, VideoCodec, CTRL_MSG_REQUEST_IDR, MOD_ALT, MOD_CTRL, MOD_META,
    MOD_SHIFT,
};
use v2_transport::{
    AssembledVideoFrame, TransportEvent, VideoFrameMeta, ACCESS_HDR_V11_LEN, AEAD_TAG_LEN,
    IDR_MIN_INTERVAL_MS, L3_HDR_LEN, L3_MTU_DEFAULT, L4_HDR_LEN, VIDEO_SLICE_META_LEN,
};

pub const IPV4_UDP_HEADER_BYTES: u64 = 28; // 20B IPv4 + 8B UDP
pub const IPV6_UDP_HEADER_BYTES: u64 = 48; // 40B IPv6 + 8B UDP
pub const MIN_WAN_ROUNDS: usize = 3;
pub const MIN_PROBES_PER_ROUND: usize = 200;
pub const BASELINE_JITTER_INCONCLUSIVE_MS: f64 = 50.0;
pub const DELTA_P50_GATE_MS: f64 = 25.0;
pub const DELTA_P95_GATE_MS: f64 = 50.0;
pub const LOADED_LOSS_GATE_PCT: f64 = 1.0;
pub const MIN_BG_LOAD_RATIO: f64 = 0.90;
pub const MAX_BG_WIRE_OVERHEAD_RATIO: f64 = 1.01;
pub const WAN_KEYFRAME_INTERVAL: usize = 30;
pub const MIN_VIDEO_DELIVERY_RATIO: f64 = 0.90;

const CTRL_MSG_WAN_VIDEO_EOS: u8 = 0x11;
const PROBE_ECHO_TIMEOUT: Duration = Duration::from_millis(1_500);
const LOADED_WARMUP_DURATION: Duration = Duration::from_millis(200);
const MIN_LOADED_PROBE_INTERVAL: Duration = Duration::from_millis(5);
const VIDEO_FRAME_INTERVAL: Duration = Duration::from_millis(33);
const VIDEO_EOS_DRAIN_TIMEOUT: Duration = Duration::from_millis(1_500);

#[derive(Debug, Clone)]
pub struct WanBenchArgs {
    pub config: PathBuf,
    pub ca_der: Option<PathBuf>,
    pub frames: usize,
    pub codec: VideoCodec,
    pub bg_mbps: f64,
    pub rounds: usize,
    pub probes_per_round: usize,
    pub max_wire_mbps: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WanBenchRoundMetrics {
    pub round: usize,
    pub status: String,
    pub inconclusive: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inconclusive_reason: Option<String>,
    pub probes_sent: usize,
    pub unloaded_received: usize,
    pub unloaded_lost: usize,
    pub unloaded_loss_pct: f64,
    pub unloaded_p50_ms: f64,
    pub unloaded_p95_ms: f64,
    pub unloaded_max_ms: f64,
    pub unloaded_jitter_ms: f64,
    pub unloaded_field_exact_match: bool,
    pub loaded_received: usize,
    pub loaded_lost: usize,
    pub loaded_loss_pct: f64,
    pub loaded_p50_ms: f64,
    pub loaded_p95_ms: f64,
    pub loaded_max_ms: f64,
    pub loaded_jitter_ms: f64,
    pub loaded_field_exact_match: bool,
    pub delta_p50_ms: f64,
    pub delta_p95_ms: f64,
    pub bg_raw_video_bytes_sent: u64,
    pub bg_wire_bytes_sent: u64,
    pub bg_udp_packets_sent: u64,
    pub bg_recv_video_frames: u64,
    pub wire_mbps: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WanHidPreemptionSummary {
    pub verdict: String,
    pub pass: bool,
    pub rounds_total: usize,
    pub valid_rounds: usize,
    pub inconclusive_rounds: usize,
    pub probes_per_round: usize,
    pub bg_target_mbps: f64,
    pub max_wire_mbps: f64,
    pub effective_target_wire_mbps: f64,
    pub wire_mbps: f64,
    pub min_round_wire_mbps: f64,
    pub max_round_wire_mbps: f64,
    pub unloaded_p50_ms: f64,
    pub unloaded_p95_ms: f64,
    pub unloaded_jitter_ms: f64,
    pub unloaded_loss_pct: f64,
    pub loaded_p50_ms: f64,
    pub loaded_p95_ms: f64,
    pub loaded_loss_pct: f64,
    pub delta_p50_ms: f64,
    pub delta_p95_ms: f64,
    pub delta_p50_threshold_ms: f64,
    pub delta_p95_threshold_ms: f64,
    pub baseline_jitter_limit_ms: f64,
    pub rounds: Vec<WanBenchRoundMetrics>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WanVideoTelemetry {
    pub codec: String,
    pub width: usize,
    pub height: usize,
    pub target_frames: usize,
    pub delivered_frames: usize,
    pub sha256_matched_frames: usize,
    pub dropped_or_corrupt_frames: usize,
    pub missing_frames: usize,
    pub decode_errors: usize,
    pub idr_requests_sent: usize,
    pub idr_frames_sent: usize,
    pub idr_frames_received: usize,
    pub forced_idr_frame_ids: Vec<u32>,
    pub sent_frame_ids_strictly_monotonic: bool,
    pub encode_ms_p50: f64,
    pub encode_ms_p95: f64,
    pub encode_ms_max: f64,
    pub decoded_min_psnr_db: f64,
    pub decoded_avg_psnr_db: f64,
    pub decoded_min_ssim: f64,
    pub decoded_avg_ssim: f64,
    pub loss_recovery_count: usize,
    pub recovery_ms: f64,
    pub recovery_ms_samples: Vec<f64>,
    pub unrecovered_loss_at_eof: bool,
    pub total_raw_bytes: u64,
    pub total_wire_bytes: u64,
    pub total_slices_sent: u64,
    pub wire_mbps: f64,
    pub elapsed_ms: f64,
    pub pass: bool,
}

#[derive(Debug, Serialize)]
pub struct WanBenchReport {
    pub pass: bool,
    pub verdict: String,
    pub width: usize,
    pub height: usize,
    pub ip_udp_overhead_bytes: u64,
    pub edge_a_ping_rtt_ms: f64,
    pub edge_b_ping_rtt_ms: f64,
    pub signaling_tcp_rtt_ms: f64,
    pub lease_renewals_ok: u64,
    pub lease_renewals_err: u64,
    pub hid_preemption: WanHidPreemptionSummary,
    pub video_telemetry: WanVideoTelemetry,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn ip_udp_overhead_bytes(is_ipv6: bool) -> u64 {
    if is_ipv6 {
        IPV6_UDP_HEADER_BYTES
    } else {
        IPV4_UDP_HEADER_BYTES
    }
}

/// Computes actual IP-layer wire bytes from UDP payload bytes (`UdpLinkStats::tx_bytes`,
/// which already includes V2 28B Access header + L3 16B header + 16B AEAD tag + L4 8B header)
/// plus per-packet IP+UDP header overhead (28B IPv4 / 48B IPv6).
pub fn actual_wire_bytes(udp_payload_bytes: u64, udp_packets: u64, is_ipv6: bool) -> u64 {
    udp_payload_bytes.saturating_add(udp_packets.saturating_mul(ip_udp_overhead_bytes(is_ipv6)))
}

/// Computes exact IP-layer wire bytes emitted by `UdpE2eeSession::send_video_frame`
/// for a frame of `raw_len` bytes at the given `l3_mtu`.
pub fn estimate_video_frame_wire_bytes(raw_len: usize, l3_mtu: usize, is_ipv6: bool) -> u64 {
    let slice_l3_overhead = L3_HDR_LEN + AEAD_TAG_LEN + L4_HDR_LEN + VIDEO_SLICE_META_LEN;
    let max_chunk = l3_mtu.saturating_sub(slice_l3_overhead).max(1);
    let slice_cnt = if raw_len == 0 {
        1usize
    } else {
        raw_len.div_ceil(max_chunk)
    };
    let per_slice_wire_overhead = (slice_l3_overhead as u64)
        .saturating_add(ACCESS_HDR_V11_LEN as u64)
        .saturating_add(ip_udp_overhead_bytes(is_ipv6));
    (raw_len as u64).saturating_add((slice_cnt as u64).saturating_mul(per_slice_wire_overhead))
}

pub fn wire_bytes_duration(wire_bytes: u64, target_wire_mbps: f64) -> Duration {
    if wire_bytes == 0 || !target_wire_mbps.is_finite() || target_wire_mbps <= 0.0 {
        return Duration::ZERO;
    }
    // 1 Mbps = 1_000_000 bits/sec => 1 byte takes 8_000 / mbps nanoseconds.
    let ns = (((wire_bytes as f64) * 8_000.0) / target_wire_mbps).ceil();
    if !ns.is_finite() || ns <= 0.0 {
        Duration::ZERO
    } else {
        Duration::from_nanos(ns.min(u64::MAX as f64) as u64)
    }
}

/// Pre-debit wire-byte pacer that strictly bounds sustained IP-layer transmit rate
/// to `<= target_wire_mbps` while preventing post-stall microbursts.
pub struct WireRatePacer {
    target_wire_mbps: f64,
    started_at: Instant,
    total_wire_bytes: u64,
    next_send_at: Instant,
}

impl WireRatePacer {
    pub fn new(target_wire_mbps: f64, initial_burst_wire_bytes: u64) -> Self {
        Self::with_start(target_wire_mbps, initial_burst_wire_bytes, Instant::now())
    }

    pub fn with_start(
        target_wire_mbps: f64,
        initial_burst_wire_bytes: u64,
        started_at: Instant,
    ) -> Self {
        let initial_delay = wire_bytes_duration(initial_burst_wire_bytes, target_wire_mbps);
        Self {
            target_wire_mbps,
            started_at,
            total_wire_bytes: 0,
            next_send_at: started_at + initial_delay,
        }
    }

    pub fn next_send_at(&self) -> Instant {
        self.next_send_at
    }

    pub fn total_wire_bytes(&self) -> u64 {
        self.total_wire_bytes
    }

    pub fn record_sent(&mut self, actual_wire_bytes: u64, next_burst_wire_bytes: u64, now: Instant) {
        self.total_wire_bytes = self.total_wire_bytes.saturating_add(actual_wire_bytes);
        let cumulative_due = self.started_at
            + wire_bytes_duration(
                self.total_wire_bytes.saturating_add(next_burst_wire_bytes),
                self.target_wire_mbps,
            );
        let min_gap = wire_bytes_duration(actual_wire_bytes, self.target_wire_mbps) / 2;
        self.next_send_at = cumulative_due.max(now + min_gap);
    }

    pub fn measured_wire_mbps(&self, now: Instant) -> f64 {
        let elapsed_secs = now.saturating_duration_since(self.started_at).as_secs_f64();
        if elapsed_secs <= 1e-6 {
            return 0.0;
        }
        ((self.total_wire_bytes as f64) * 8.0) / (elapsed_secs * 1_000_000.0)
    }
}

pub fn median_f64(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let n = sorted.len();
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        0.5 * (sorted[n / 2 - 1] + sorted[n / 2])
    }
}

pub fn parse_wan_bench_args(args: &[String]) -> Result<WanBenchArgs, String> {
    let mut config: Option<PathBuf> = None;
    let mut ca_der: Option<PathBuf> = None;
    let mut frames = 120usize;
    let mut codec = VideoCodec::Vp9;
    let mut bg_mbps = 8.0f64;
    let mut rounds = MIN_WAN_ROUNDS;
    let mut probes_per_round = MIN_PROBES_PER_ROUND;
    let mut max_wire_mbps = 8.0f64;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                config = Some(PathBuf::from(parse_flag_value(args, &mut i, "--config")?));
            }
            "--ca-der" => {
                ca_der = Some(PathBuf::from(parse_flag_value(args, &mut i, "--ca-der")?));
            }
            "--frames" => {
                frames = parse_flag_value(args, &mut i, "--frames")?
                    .parse::<usize>()
                    .map_err(|e| format!("invalid --frames: {e}"))?;
            }
            "--codec" => {
                let raw = parse_flag_value(args, &mut i, "--codec")?;
                codec = VideoCodec::parse_name(&raw).map_err(|e| e.to_string())?;
            }
            "--bg-mbps" => {
                bg_mbps = parse_flag_value(args, &mut i, "--bg-mbps")?
                    .parse::<f64>()
                    .map_err(|e| format!("invalid --bg-mbps: {e}"))?;
            }
            "--rounds" => {
                rounds = parse_flag_value(args, &mut i, "--rounds")?
                    .parse::<usize>()
                    .map_err(|e| format!("invalid --rounds: {e}"))?;
            }
            "--probes-per-round" => {
                probes_per_round = parse_flag_value(args, &mut i, "--probes-per-round")?
                    .parse::<usize>()
                    .map_err(|e| format!("invalid --probes-per-round: {e}"))?;
            }
            "--max-wire-mbps" => {
                max_wire_mbps = parse_flag_value(args, &mut i, "--max-wire-mbps")?
                    .parse::<f64>()
                    .map_err(|e| format!("invalid --max-wire-mbps: {e}"))?;
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
        i += 1;
    }

    let config = config.ok_or_else(|| "--config <cluster.json> is required".to_string())?;
    if frames == 0 {
        return Err("--frames must be >= 1".to_string());
    }
    if !bg_mbps.is_finite() || bg_mbps <= 0.0 {
        return Err("--bg-mbps must be finite and > 0".to_string());
    }
    if !max_wire_mbps.is_finite() || max_wire_mbps <= 0.0 {
        return Err("--max-wire-mbps must be finite and > 0".to_string());
    }
    if rounds < MIN_WAN_ROUNDS {
        return Err(format!(
            "--rounds must be >= {MIN_WAN_ROUNDS} (got {rounds})"
        ));
    }
    if probes_per_round < MIN_PROBES_PER_ROUND {
        return Err(format!(
            "--probes-per-round must be >= {MIN_PROBES_PER_ROUND} (got {probes_per_round})"
        ));
    }

    Ok(WanBenchArgs {
        config,
        ca_der,
        frames,
        codec,
        bg_mbps,
        rounds,
        probes_per_round,
        max_wire_mbps,
    })
}

fn build_wan_hid_probes(
    count: usize,
    base_ts_ms: u64,
    start_seq: u32,
) -> Vec<(u32, HidPayload)> {
    let keys: &[(u32, char, u8)] = &[
        (0x04, 'a', 0),
        (0x05, 'B', MOD_SHIFT),
        (0x06, 'c', MOD_CTRL),
        (0x16, 's', MOD_CTRL | MOD_SHIFT),
        (0x09, 'f', MOD_ALT),
        (0x17, 't', MOD_META),
        (0x1E, '1', 0),
        (0x28, '\n', 0),
        (0x2C, ' ', 0),
        (0x1D, 'Z', MOD_SHIFT | MOD_ALT),
    ];

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let seq = start_seq.wrapping_add(i as u32);
        let client_ts_ms = base_ts_ms.saturating_add(u64::from(seq));
        let payload = if i % 2 == 0 {
            let m = (i / 2) as u32;
            let kind = match m % 5 {
                0 => MouseKind::MoveAbs,
                1 => MouseKind::MoveRel,
                2 => MouseKind::Down,
                3 => MouseKind::Up,
                _ => MouseKind::Wheel,
            };
            let buttons = match kind {
                MouseKind::Down => 0x01,
                MouseKind::Up => 0x00,
                _ => (m as u8) & 0x07,
            };
            let (x_or_dx, y_or_dy, wheel_dx, wheel_dy) = match kind {
                MouseKind::MoveAbs => (100 + ((m % 30) as i32) * 37, 80 + ((m % 24) as i32) * 23, 0, 0),
                MouseKind::MoveRel => (((m % 11) as i32) * 3 - 15, 12 - ((m % 9) as i32) * 2, 0, 0),
                MouseKind::Down | MouseKind::Up => (640 + ((m % 20) as i32) * 5, 360 - ((m % 20) as i32) * 4, 0, 0),
                MouseKind::Wheel => (640, 360, -1, 3),
            };
            HidPayload::Mouse(MouseEvent {
                kind,
                buttons,
                x_or_dx,
                y_or_dy,
                wheel_dx,
                wheel_dy,
                client_ts_ms,
            })
        } else {
            let k_idx = i / 2;
            let (usage, ch, mods) = keys[(k_idx / 2) % keys.len()];
            let down = (k_idx % 2) == 0;
            HidPayload::Key(KeyEvent {
                down,
                modifiers: mods,
                usb_hid_usage: usage,
                unicode_scalar: ch as u32,
                client_ts_ms,
            })
        };
        out.push((seq, payload));
    }
    out
}

#[derive(Debug, Clone)]
pub struct RoundEvalInput {
    pub round: usize,
    pub probes_sent: usize,
    pub unloaded_rtts_us: Vec<u64>,
    pub unloaded_field_exact_match: bool,
    pub loaded_rtts_us: Vec<u64>,
    pub loaded_field_exact_match: bool,
    pub bg_raw_video_bytes_sent: u64,
    pub bg_wire_bytes_sent: u64,
    pub bg_udp_packets_sent: u64,
    pub bg_recv_video_frames: u64,
    pub wire_mbps: f64,
}

pub fn evaluate_round(input: RoundEvalInput) -> WanBenchRoundMetrics {
    let probes_sent = input.probes_sent.max(1);
    let unloaded_received = input.unloaded_rtts_us.len();
    let unloaded_lost = input.probes_sent.saturating_sub(unloaded_received);
    let unloaded_loss_pct = (unloaded_lost as f64) * 100.0 / (probes_sent as f64);
    let unloaded_p50_ms = percentile_ms(&input.unloaded_rtts_us, 0.50);
    let unloaded_p95_ms = percentile_ms(&input.unloaded_rtts_us, 0.95);
    let unloaded_max_ms = percentile_ms(&input.unloaded_rtts_us, 1.0);
    let unloaded_jitter_ms = unloaded_p95_ms - unloaded_p50_ms;

    let loaded_received = input.loaded_rtts_us.len();
    let loaded_lost = input.probes_sent.saturating_sub(loaded_received);
    let loaded_loss_pct = (loaded_lost as f64) * 100.0 / (probes_sent as f64);
    let loaded_p50_ms = percentile_ms(&input.loaded_rtts_us, 0.50);
    let loaded_p95_ms = percentile_ms(&input.loaded_rtts_us, 0.95);
    let loaded_max_ms = percentile_ms(&input.loaded_rtts_us, 1.0);
    let loaded_jitter_ms = loaded_p95_ms - loaded_p50_ms;

    let delta_p50_ms = loaded_p50_ms - unloaded_p50_ms;
    let delta_p95_ms = loaded_p95_ms - unloaded_p95_ms;

    let inconclusive_reason = if unloaded_received == 0 {
        Some("no unloaded P0 HID echo samples received".to_string())
    } else if unloaded_jitter_ms > BASELINE_JITTER_INCONCLUSIVE_MS {
        Some(format!(
            "noisy unloaded baseline: unloaded_p95 - unloaded_p50 = {unloaded_jitter_ms:.2} ms > {BASELINE_JITTER_INCONCLUSIVE_MS:.1} ms"
        ))
    } else {
        None
    };
    let inconclusive = inconclusive_reason.is_some();
    let status = if inconclusive {
        "INCONCLUSIVE".to_string()
    } else {
        "VALID".to_string()
    };

    WanBenchRoundMetrics {
        round: input.round,
        status,
        inconclusive,
        inconclusive_reason,
        probes_sent: input.probes_sent,
        unloaded_received,
        unloaded_lost,
        unloaded_loss_pct,
        unloaded_p50_ms,
        unloaded_p95_ms,
        unloaded_max_ms,
        unloaded_jitter_ms,
        unloaded_field_exact_match: input.unloaded_field_exact_match,
        loaded_received,
        loaded_lost,
        loaded_loss_pct,
        loaded_p50_ms,
        loaded_p95_ms,
        loaded_max_ms,
        loaded_jitter_ms,
        loaded_field_exact_match: input.loaded_field_exact_match,
        delta_p50_ms,
        delta_p95_ms,
        bg_raw_video_bytes_sent: input.bg_raw_video_bytes_sent,
        bg_wire_bytes_sent: input.bg_wire_bytes_sent,
        bg_udp_packets_sent: input.bg_udp_packets_sent,
        bg_recv_video_frames: input.bg_recv_video_frames,
        wire_mbps: input.wire_mbps,
    }
}

pub fn aggregate_rounds(
    rounds: Vec<WanBenchRoundMetrics>,
    probes_per_round: usize,
    bg_target_mbps: f64,
    max_wire_mbps: f64,
) -> WanHidPreemptionSummary {
    let effective_target_wire_mbps = bg_target_mbps.min(max_wire_mbps);
    let rounds_total = rounds.len();
    let valid: Vec<&WanBenchRoundMetrics> = rounds.iter().filter(|r| !r.inconclusive).collect();
    let valid_rounds = valid.len();
    let inconclusive_rounds = rounds_total.saturating_sub(valid_rounds);
    let min_valid_required = (rounds_total / 2) + 1;

    let all_wire_finite = rounds.iter().all(|r| r.wire_mbps.is_finite());
    let max_round_wire_mbps = if all_wire_finite {
        rounds.iter().map(|r| r.wire_mbps).fold(0.0f64, f64::max)
    } else {
        f64::NAN
    };
    let valid_wire_finite = valid.iter().all(|r| r.wire_mbps.is_finite());
    let min_round_wire_mbps = if valid.is_empty() {
        0.0
    } else if valid_wire_finite {
        valid
            .iter()
            .map(|r| r.wire_mbps)
            .fold(f64::INFINITY, f64::min)
    } else {
        f64::NAN
    };

    // Never mask a loaded-phase P0 blackout (unloaded worked, loaded received 0) as INCONCLUSIVE.
    let any_loaded_blackout = rounds
        .iter()
        .any(|r| r.unloaded_received > 0 && r.loaded_received == 0);
    if any_loaded_blackout {
        return WanHidPreemptionSummary {
            verdict: "FAIL".to_string(),
            pass: false,
            rounds_total,
            valid_rounds,
            inconclusive_rounds,
            probes_per_round,
            bg_target_mbps,
            max_wire_mbps,
            effective_target_wire_mbps,
            wire_mbps: median_f64(&rounds.iter().map(|r| r.wire_mbps).collect::<Vec<_>>()),
            min_round_wire_mbps,
            max_round_wire_mbps,
            unloaded_p50_ms: median_f64(
                &rounds.iter().map(|r| r.unloaded_p50_ms).collect::<Vec<_>>(),
            ),
            unloaded_p95_ms: median_f64(
                &rounds.iter().map(|r| r.unloaded_p95_ms).collect::<Vec<_>>(),
            ),
            unloaded_jitter_ms: median_f64(
                &rounds
                    .iter()
                    .map(|r| r.unloaded_jitter_ms)
                    .collect::<Vec<_>>(),
            ),
            unloaded_loss_pct: median_f64(
                &rounds
                    .iter()
                    .map(|r| r.unloaded_loss_pct)
                    .collect::<Vec<_>>(),
            ),
            loaded_p50_ms: median_f64(&rounds.iter().map(|r| r.loaded_p50_ms).collect::<Vec<_>>()),
            loaded_p95_ms: median_f64(&rounds.iter().map(|r| r.loaded_p95_ms).collect::<Vec<_>>()),
            loaded_loss_pct: median_f64(
                &rounds.iter().map(|r| r.loaded_loss_pct).collect::<Vec<_>>(),
            ),
            delta_p50_ms: median_f64(&rounds.iter().map(|r| r.delta_p50_ms).collect::<Vec<_>>()),
            delta_p95_ms: median_f64(&rounds.iter().map(|r| r.delta_p95_ms).collect::<Vec<_>>()),
            delta_p50_threshold_ms: DELTA_P50_GATE_MS,
            delta_p95_threshold_ms: DELTA_P95_GATE_MS,
            baseline_jitter_limit_ms: BASELINE_JITTER_INCONCLUSIVE_MS,
            rounds,
        };
    }

    if valid_rounds < min_valid_required {
        return WanHidPreemptionSummary {
            verdict: "INCONCLUSIVE".to_string(),
            pass: false,
            rounds_total,
            valid_rounds,
            inconclusive_rounds,
            probes_per_round,
            bg_target_mbps,
            max_wire_mbps,
            effective_target_wire_mbps,
            wire_mbps: median_f64(&rounds.iter().map(|r| r.wire_mbps).collect::<Vec<_>>()),
            min_round_wire_mbps,
            max_round_wire_mbps,
            unloaded_p50_ms: median_f64(
                &rounds.iter().map(|r| r.unloaded_p50_ms).collect::<Vec<_>>(),
            ),
            unloaded_p95_ms: median_f64(
                &rounds.iter().map(|r| r.unloaded_p95_ms).collect::<Vec<_>>(),
            ),
            unloaded_jitter_ms: median_f64(
                &rounds
                    .iter()
                    .map(|r| r.unloaded_jitter_ms)
                    .collect::<Vec<_>>(),
            ),
            unloaded_loss_pct: median_f64(
                &rounds
                    .iter()
                    .map(|r| r.unloaded_loss_pct)
                    .collect::<Vec<_>>(),
            ),
            loaded_p50_ms: median_f64(&rounds.iter().map(|r| r.loaded_p50_ms).collect::<Vec<_>>()),
            loaded_p95_ms: median_f64(&rounds.iter().map(|r| r.loaded_p95_ms).collect::<Vec<_>>()),
            loaded_loss_pct: median_f64(
                &rounds.iter().map(|r| r.loaded_loss_pct).collect::<Vec<_>>(),
            ),
            delta_p50_ms: median_f64(&rounds.iter().map(|r| r.delta_p50_ms).collect::<Vec<_>>()),
            delta_p95_ms: median_f64(&rounds.iter().map(|r| r.delta_p95_ms).collect::<Vec<_>>()),
            delta_p50_threshold_ms: DELTA_P50_GATE_MS,
            delta_p95_threshold_ms: DELTA_P95_GATE_MS,
            baseline_jitter_limit_ms: BASELINE_JITTER_INCONCLUSIVE_MS,
            rounds,
        };
    }

    let unloaded_p50_ms = median_f64(&valid.iter().map(|r| r.unloaded_p50_ms).collect::<Vec<_>>());
    let unloaded_p95_ms = median_f64(&valid.iter().map(|r| r.unloaded_p95_ms).collect::<Vec<_>>());
    let unloaded_jitter_ms =
        median_f64(&valid.iter().map(|r| r.unloaded_jitter_ms).collect::<Vec<_>>());
    let unloaded_loss_pct =
        median_f64(&valid.iter().map(|r| r.unloaded_loss_pct).collect::<Vec<_>>());
    let loaded_p50_ms = median_f64(&valid.iter().map(|r| r.loaded_p50_ms).collect::<Vec<_>>());
    let loaded_p95_ms = median_f64(&valid.iter().map(|r| r.loaded_p95_ms).collect::<Vec<_>>());
    let loaded_loss_pct = median_f64(&valid.iter().map(|r| r.loaded_loss_pct).collect::<Vec<_>>());
    let delta_p50_ms = median_f64(&valid.iter().map(|r| r.delta_p50_ms).collect::<Vec<_>>());
    let delta_p95_ms = median_f64(&valid.iter().map(|r| r.delta_p95_ms).collect::<Vec<_>>());
    let wire_mbps = median_f64(&valid.iter().map(|r| r.wire_mbps).collect::<Vec<_>>());

    let all_fields_exact = valid
        .iter()
        .all(|r| r.unloaded_field_exact_match && r.loaded_field_exact_match);
    let all_bg_traversed = valid
        .iter()
        .all(|r| r.bg_wire_bytes_sent > 0 && r.bg_recv_video_frames > 0);
    let all_loaded_loss_ok = valid.iter().all(|r| {
        r.loaded_received > 0 && (r.loaded_loss_pct - r.unloaded_loss_pct) <= LOADED_LOSS_GATE_PCT
    });
    let wire_rate_in_band = all_wire_finite
        && min_round_wire_mbps.is_finite()
        && max_round_wire_mbps.is_finite()
        && min_round_wire_mbps >= effective_target_wire_mbps * MIN_BG_LOAD_RATIO
        && max_round_wire_mbps <= effective_target_wire_mbps * MAX_BG_WIRE_OVERHEAD_RATIO;

    let pass = all_fields_exact
        && all_bg_traversed
        && all_loaded_loss_ok
        && wire_rate_in_band
        && delta_p50_ms <= DELTA_P50_GATE_MS
        && delta_p95_ms <= DELTA_P95_GATE_MS;

    WanHidPreemptionSummary {
        verdict: if pass {
            "PASS".to_string()
        } else {
            "FAIL".to_string()
        },
        pass,
        rounds_total,
        valid_rounds,
        inconclusive_rounds,
        probes_per_round,
        bg_target_mbps,
        max_wire_mbps,
        effective_target_wire_mbps,
        wire_mbps,
        min_round_wire_mbps,
        max_round_wire_mbps,
        unloaded_p50_ms,
        unloaded_p95_ms,
        unloaded_jitter_ms,
        unloaded_loss_pct,
        loaded_p50_ms,
        loaded_p95_ms,
        loaded_loss_pct,
        delta_p50_ms,
        delta_p95_ms,
        delta_p50_threshold_ms: DELTA_P50_GATE_MS,
        delta_p95_threshold_ms: DELTA_P95_GATE_MS,
        baseline_jitter_limit_ms: BASELINE_JITTER_INCONCLUSIVE_MS,
        rounds,
    }
}

enum ProbeOutcome {
    Received {
        rtt_us: u64,
        interleaved_video_frames: u64,
    },
    Lost {
        interleaved_video_frames: u64,
    },
}

async fn send_wan_hid_probe_and_await_echo(
    controller: &mut DesktopControllerSession,
    payload: &HidPayload,
    expected_echo_seq: u32,
    timeout: Duration,
) -> Result<ProbeOutcome, SessionError> {
    let sent = Instant::now();
    controller.send_hid_payload(payload).await?;
    let expected_ts = payload.client_ts_ms();
    let deadline = Instant::now() + timeout;
    let mut interleaved_video_frames = 0u64;

    loop {
        let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(ProbeOutcome::Lost {
                interleaved_video_frames,
            });
        };
        match controller.session_mut().recv_event(rem).await {
            Ok(TransportEvent::Hid(frame)) => match decode_hid_frame(&frame) {
                Ok(HidPayload::EchoAck(ack))
                    if ack.echo_seq == expected_echo_seq && ack.client_ts_ms == expected_ts =>
                {
                    let rtt_us = sent.elapsed().as_micros() as u64;
                    return Ok(ProbeOutcome::Received {
                        rtt_us,
                        interleaved_video_frames,
                    });
                }
                Ok(HidPayload::EchoAck(_)) => {
                    controller.skipped_stale_echo_acks =
                        controller.skipped_stale_echo_acks.saturating_add(1);
                }
                Ok(_) | Err(_) => {
                    controller.skipped_hid_events =
                        controller.skipped_hid_events.saturating_add(1);
                }
            },
            Ok(TransportEvent::VideoFrame(_)) => {
                interleaved_video_frames = interleaved_video_frames.saturating_add(1);
            }
            Ok(TransportEvent::Control(ctrl)) => {
                if let Some(error_code) = parse_session_close(&ctrl) {
                    return Err(SessionError::SessionClosed { error_code });
                }
                controller.skipped_control_events =
                    controller.skipped_control_events.saturating_add(1);
            }
            Ok(_) => {
                controller.skipped_other_events = controller.skipped_other_events.saturating_add(1);
            }
            Err(ClientError::Timeout(_)) => {
                return Ok(ProbeOutcome::Lost {
                    interleaved_video_frames,
                });
            }
            Err(e) => return Err(e.into()),
        }
    }
}

async fn drain_session_until_quiet(
    sess: &mut v2_client::UdpE2eeSession,
    quiet_dur: Duration,
    hard_end: Instant,
) -> Result<(), SessionError> {
    let mut last_activity = Instant::now();
    while Instant::now() < hard_end {
        let since_active = last_activity.elapsed();
        if since_active >= quiet_dur {
            break;
        }
        let wait = quiet_dur
            .saturating_sub(since_active)
            .min(hard_end.saturating_duration_since(Instant::now()))
            .min(Duration::from_millis(25));
        if wait.is_zero() {
            break;
        }
        match sess.recv_event(wait).await {
            Ok(TransportEvent::Control(ctrl)) => {
                if let Some(error_code) = parse_session_close(&ctrl) {
                    return Err(SessionError::SessionClosed { error_code });
                }
                last_activity = Instant::now();
            }
            Ok(_) => {
                last_activity = Instant::now();
            }
            Err(ClientError::Timeout(_)) => {}
            Err(e) => return Err(SessionError::from(e)),
        }
    }
    Ok(())
}

async fn drain_quiet_window(
    host: &mut DesktopHostSession,
    controller: &mut DesktopControllerSession,
    quiet_dur: Duration,
    max_dur: Duration,
) -> Result<(), SessionError> {
    controller.clear_pending_video();
    let hard_end = Instant::now() + max_dur;
    tokio::try_join!(
        drain_session_until_quiet(host.session_mut(), quiet_dur, hard_end),
        drain_session_until_quiet(controller.session_mut(), quiet_dur, hard_end),
    )?;
    Ok(())
}

fn verify_received_probes_exact_match(
    received: &[HidPayload],
    sent: &[(u32, HidPayload)],
) -> bool {
    let by_ts: HashMap<u64, &HidPayload> = sent
        .iter()
        .map(|(_, p)| (p.client_ts_ms(), p))
        .collect();
    received
        .iter()
        .all(|rx| by_ts.get(&rx.client_ts_ms()).is_some_and(|exp| *exp == rx))
}

#[allow(clippy::too_many_arguments)]
async fn run_wan_hid_round(
    host: &mut DesktopHostSession,
    controller: &mut DesktopControllerSession,
    round: usize,
    probes_per_round: usize,
    base_ts_ms: u64,
    next_global_seq: &mut u32,
    effective_target_wire_mbps: f64,
    bg_payload: &[u8],
    probe_timeout: Duration,
) -> Result<WanBenchRoundMetrics, SessionError> {
    let is_ipv6 = host
        .session()
        .udp_link()
        .is_some_and(|u| u.edge_addr().is_ipv6());
    let window_hard_deadline = Duration::from_secs(180).max(
        Duration::from_secs((probes_per_round as u64).saturating_mul(2)),
    );

    // Phase A: Unloaded P0 HID baseline.
    let unloaded_probes = build_wan_hid_probes(probes_per_round, base_ts_ms, *next_global_seq);
    *next_global_seq = next_global_seq.wrapping_add(probes_per_round as u32);

    let unloaded_done = Arc::new(AtomicBool::new(false));
    let unloaded_done_host = Arc::clone(&unloaded_done);
    let unloaded_host = async {
        let mut received = Vec::with_capacity(probes_per_round);
        let hard_deadline = Instant::now() + window_hard_deadline;
        while !unloaded_done_host.load(Ordering::Acquire) {
            if Instant::now() >= hard_deadline {
                return Err(ClientError::Timeout("wan-bench unloaded host timed out".into()).into());
            }
            match host
                .session_mut()
                .recv_event(Duration::from_millis(5))
                .await
            {
                Ok(TransportEvent::Hid(frame)) => {
                    if let Ok(payload) = decode_hid_frame(&frame) {
                        host.hid_frames_received = host.hid_frames_received.saturating_add(1);
                        let echo_seq = payload.client_ts_ms().wrapping_sub(base_ts_ms) as u32;
                        let ack = HidPayload::EchoAck(HidEchoAck {
                            echo_seq,
                            client_ts_ms: payload.client_ts_ms(),
                        });
                        let ack_frame = encode_hid_frame(&ack)?;
                        host.session_mut().send_hid(&ack_frame).await?;
                        received.push(payload);
                    } else {
                        host.malformed_hid_frames_dropped =
                            host.malformed_hid_frames_dropped.saturating_add(1);
                    }
                }
                Ok(TransportEvent::Control(ctrl)) => {
                    if let Some(error_code) = parse_session_close(&ctrl) {
                        return Err(SessionError::SessionClosed { error_code });
                    }
                }
                Ok(_) | Err(ClientError::Timeout(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok::<Vec<HidPayload>, SessionError>(received)
    };

    let unloaded_ctrl = async {
        let mut rtts_us = Vec::with_capacity(probes_per_round);
        for (seq, payload) in &unloaded_probes {
            match send_wan_hid_probe_and_await_echo(controller, payload, *seq, probe_timeout).await?
            {
                ProbeOutcome::Received { rtt_us, .. } => rtts_us.push(rtt_us),
                ProbeOutcome::Lost { .. } => {}
            }
        }
        unloaded_done.store(true, Ordering::Release);
        Ok::<Vec<u64>, SessionError>(rtts_us)
    };

    let (unloaded_rx, unloaded_rtts_us) = tokio::try_join!(unloaded_host, unloaded_ctrl)?;
    let unloaded_field_exact_match =
        verify_received_probes_exact_match(&unloaded_rx, &unloaded_probes);

    // Phase B: Immediately measure loaded P0 HID under wire-rate-paced P2 video saturation.
    let loaded_probes = build_wan_hid_probes(probes_per_round, base_ts_ms, *next_global_seq);
    *next_global_seq = next_global_seq.wrapping_add(probes_per_round as u32);

    let est_burst_wire_bytes =
        estimate_video_frame_wire_bytes(bg_payload.len(), L3_MTU_DEFAULT, is_ipv6);

    let loaded_done = Arc::new(AtomicBool::new(false));
    let loaded_done_host = Arc::clone(&loaded_done);
    let loaded_host = async {
        let mut received = Vec::with_capacity(probes_per_round);
        let mut pacer = WireRatePacer::new(effective_target_wire_mbps, est_burst_wire_bytes);
        let mut bg_frame_id = 50_000u32.wrapping_add((round as u32).wrapping_mul(100_000));
        let mut bg_raw_bytes = 0u64;
        let mut bg_udp_packets = 0u64;
        let mut measured_burst_wire = est_burst_wire_bytes;
        let hard_deadline = Instant::now() + window_hard_deadline;

        while !loaded_done_host.load(Ordering::Acquire) {
            let now = Instant::now();
            if now >= hard_deadline {
                return Err(ClientError::Timeout("wan-bench loaded host timed out".into()).into());
            }
            if now >= pacer.next_send_at() {
                let meta = VideoFrameMeta {
                    display_idx: 0,
                    codec_id: VideoCodec::Vp9.codec_id(),
                    frame_id: bg_frame_id,
                    ref_frame_id: bg_frame_id,
                    ltr_slot: 0,
                    is_idr: false,
                    is_ref: false,
                    max_age_ms: 200,
                };
                bg_frame_id = bg_frame_id.wrapping_add(1);

                let before_stats = host.session().data_plane().stats();
                let tx_bytes_before = before_stats.tx_bytes;
                let tx_pkts_before = before_stats.tx_packets;
                host.publish_raw_video(&meta, bg_payload).await?;
                let after_stats = host.session().data_plane().stats();
                let tx_bytes_delta = after_stats.tx_bytes.saturating_sub(tx_bytes_before);
                let tx_pkts_delta = after_stats.tx_packets.saturating_sub(tx_pkts_before);
                let burst_wire = actual_wire_bytes(tx_bytes_delta, tx_pkts_delta, is_ipv6);
                measured_burst_wire = measured_burst_wire.max(burst_wire);
                bg_raw_bytes = bg_raw_bytes.saturating_add(bg_payload.len() as u64);
                bg_udp_packets = bg_udp_packets.saturating_add(tx_pkts_delta);
                pacer.record_sent(burst_wire, measured_burst_wire, Instant::now());
            }

            let wait = pacer
                .next_send_at()
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(2));
            if !wait.is_zero() {
                match host.session_mut().recv_event(wait).await {
                    Ok(TransportEvent::Hid(frame)) => {
                        if let Ok(payload) = decode_hid_frame(&frame) {
                            host.hid_frames_received = host.hid_frames_received.saturating_add(1);
                            let echo_seq = payload.client_ts_ms().wrapping_sub(base_ts_ms) as u32;
                            let ack = HidPayload::EchoAck(HidEchoAck {
                                echo_seq,
                                client_ts_ms: payload.client_ts_ms(),
                            });
                            let ack_frame = encode_hid_frame(&ack)?;
                            host.session_mut().send_hid(&ack_frame).await?;
                            received.push(payload);
                        } else {
                            host.malformed_hid_frames_dropped =
                                host.malformed_hid_frames_dropped.saturating_add(1);
                        }
                    }
                    Ok(TransportEvent::Control(ctrl)) => {
                        if let Some(error_code) = parse_session_close(&ctrl) {
                            return Err(SessionError::SessionClosed { error_code });
                        }
                    }
                    Ok(_) | Err(ClientError::Timeout(_)) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }

        let end = Instant::now();
        let wire_mbps = pacer.measured_wire_mbps(end);
        Ok::<(Vec<HidPayload>, u64, u64, u64, f64), SessionError>((
            received,
            bg_raw_bytes,
            pacer.total_wire_bytes(),
            bg_udp_packets,
            wire_mbps,
        ))
    };

    let loaded_ctrl = async {
        let mut bg_recv_frames = 0u64;
        let warmup_end = Instant::now() + LOADED_WARMUP_DURATION;
        while Instant::now() < warmup_end {
            let rem = warmup_end.saturating_duration_since(Instant::now());
            match controller.session_mut().recv_event(rem).await {
                Ok(TransportEvent::VideoFrame(_)) => bg_recv_frames += 1,
                Ok(TransportEvent::Control(ctrl)) => {
                    if let Some(error_code) = parse_session_close(&ctrl) {
                        return Err(SessionError::SessionClosed { error_code });
                    }
                }
                Ok(_) => {}
                Err(ClientError::Timeout(_)) => break,
                Err(e) => return Err(SessionError::from(e)),
            }
        }

        let mut rtts_us = Vec::with_capacity(probes_per_round);
        for (seq, payload) in &loaded_probes {
            let probe_started = Instant::now();
            match send_wan_hid_probe_and_await_echo(controller, payload, *seq, probe_timeout).await?
            {
                ProbeOutcome::Received {
                    rtt_us,
                    interleaved_video_frames,
                } => {
                    bg_recv_frames = bg_recv_frames.saturating_add(interleaved_video_frames);
                    rtts_us.push(rtt_us);
                }
                ProbeOutcome::Lost {
                    interleaved_video_frames,
                } => {
                    bg_recv_frames = bg_recv_frames.saturating_add(interleaved_video_frames);
                }
            }

            // On fast LAN/loopback where RTT < 5ms, drain incoming P2 video for the remainder
            // of the minimum probe interval so kernel UDP buffers stay clear and wire rate stabilizes.
            let min_end = probe_started + MIN_LOADED_PROBE_INTERVAL;
            while Instant::now() < min_end {
                let rem = min_end.saturating_duration_since(Instant::now());
                match controller.session_mut().recv_event(rem).await {
                    Ok(TransportEvent::VideoFrame(_)) => bg_recv_frames += 1,
                    Ok(TransportEvent::Control(ctrl)) => {
                        if let Some(error_code) = parse_session_close(&ctrl) {
                            return Err(SessionError::SessionClosed { error_code });
                        }
                    }
                    Ok(_) => {}
                    Err(ClientError::Timeout(_)) => break,
                    Err(e) => return Err(SessionError::from(e)),
                }
            }
        }
        loaded_done.store(true, Ordering::Release);
        Ok::<(Vec<u64>, u64), SessionError>((rtts_us, bg_recv_frames))
    };

    let (
        (loaded_rx, bg_raw_video_bytes_sent, bg_wire_bytes_sent, bg_udp_packets_sent, wire_mbps),
        (loaded_rtts_us, bg_recv_video_frames),
    ) = tokio::try_join!(loaded_host, loaded_ctrl)?;
    let loaded_field_exact_match = verify_received_probes_exact_match(&loaded_rx, &loaded_probes);

    Ok(evaluate_round(RoundEvalInput {
        round,
        probes_sent: probes_per_round,
        unloaded_rtts_us,
        unloaded_field_exact_match,
        loaded_rtts_us,
        loaded_field_exact_match,
        bg_raw_video_bytes_sent,
        bg_wire_bytes_sent,
        bg_udp_packets_sent,
        bg_recv_video_frames,
        wire_mbps,
    }))
}

pub async fn run_wan_hid_preemption(
    host: &mut DesktopHostSession,
    controller: &mut DesktopControllerSession,
    rounds: usize,
    probes_per_round: usize,
    bg_mbps: f64,
    max_wire_mbps: f64,
) -> Result<WanHidPreemptionSummary, SessionError> {
    let effective_target_wire_mbps = bg_mbps.min(max_wire_mbps);

    // Pre-encode a real ~3.3 KB VP9 bitstream burst (~3 MTU slices) so wire-rate pacing
    // stays smooth and accurate without encoder stalls during P0 preemption windows.
    let mut bg_enc = V2VideoEncoder::new(
        VideoCodec::Vp9,
        WIDTH as u32,
        HEIGHT as u32,
        ENCODER_QUALITY,
        Some(WAN_KEYFRAME_INTERVAL),
    )?;
    let bg_frame = bg_enc.encode_i420(&generate_animated_i420(WIDTH, HEIGHT, 7), 0)?;
    let mut bg_payload = bg_frame.data;
    if bg_payload.len() < 3_000 {
        bg_payload.resize(3_000, 0x5A);
    } else if bg_payload.len() > 3_500 {
        bg_payload.truncate(3_300);
    }

    let base_ts_ms = now_ms();
    let mut next_global_seq = 1u32;
    let mut round_results = Vec::with_capacity(rounds);

    for round_idx in 1..=rounds {
        let metrics = run_wan_hid_round(
            host,
            controller,
            round_idx,
            probes_per_round,
            base_ts_ms,
            &mut next_global_seq,
            effective_target_wire_mbps,
            &bg_payload,
            PROBE_ECHO_TIMEOUT,
        )
        .await?;
        let round_verdict = if metrics.unloaded_received > 0 && metrics.loaded_received == 0 {
            "FAIL"
        } else if metrics.inconclusive {
            "INCONCLUSIVE"
        } else if metrics.delta_p50_ms <= DELTA_P50_GATE_MS
            && metrics.delta_p95_ms <= DELTA_P95_GATE_MS
            && (metrics.loaded_loss_pct - metrics.unloaded_loss_pct) <= LOADED_LOSS_GATE_PCT
            && metrics.wire_mbps.is_finite()
            && metrics.wire_mbps >= effective_target_wire_mbps * MIN_BG_LOAD_RATIO
            && metrics.wire_mbps <= effective_target_wire_mbps * MAX_BG_WIRE_OVERHEAD_RATIO
            && metrics.unloaded_field_exact_match
            && metrics.loaded_field_exact_match
            && metrics.bg_recv_video_frames > 0
        {
            "PASS"
        } else {
            "FAIL"
        };
        eprintln!(
            "[wan-bench] round {round_idx}/{rounds}: unloaded_p50={:.2}ms unloaded_p95={:.2}ms loaded_p50={:.2}ms loaded_p95={:.2}ms delta_p95={:.2}ms wire_mbps={:.2} verdict={round_verdict}",
            metrics.unloaded_p50_ms,
            metrics.unloaded_p95_ms,
            metrics.loaded_p50_ms,
            metrics.loaded_p95_ms,
            metrics.delta_p95_ms,
            metrics.wire_mbps,
        );
        round_results.push(metrics);

        // Drain any in-flight P2 video packets across the WAN before the next round's
        // unloaded baseline (or the real-codec video phase) begins.
        drain_quiet_window(
            host,
            controller,
            Duration::from_millis(100),
            Duration::from_millis(500),
        )
        .await?;
    }

    Ok(aggregate_rounds(
        round_results,
        probes_per_round,
        bg_mbps,
        max_wire_mbps,
    ))
}

#[derive(Debug, Clone)]
struct SentVideoMeta {
    idx: usize,
    frame_id: u32,
    sha256: [u8; 32],
    raw_bytes: usize,
}

async fn decode_on_blocking(
    decoder: &Arc<Mutex<V2VideoDecoder>>,
    frame: AssembledVideoFrame,
) -> Result<(AssembledVideoFrame, [u8; 32], I420Frame), SessionError> {
    let dec = Arc::clone(decoder);
    tokio::task::spawn_blocking(
        move || -> Result<(AssembledVideoFrame, [u8; 32], I420Frame), SessionError> {
            let sha256: [u8; 32] = Sha256::digest(&frame.data).into();
            let mut guard = dec
                .lock()
                .map_err(|_| SessionError::Protocol("video decoder mutex poisoned".into()))?;
            let i420 = guard.decode_assembled(&frame)?;
            Ok((frame, sha256, i420))
        },
    )
    .await
    .map_err(|e| SessionError::Protocol(format!("video decode blocking task failed: {e}")))?
}

pub async fn run_wan_video_telemetry(
    host: &mut DesktopHostSession,
    controller: &mut DesktopControllerSession,
    codec: VideoCodec,
    frames: usize,
    max_wire_mbps: f64,
) -> Result<WanVideoTelemetry, SessionError> {
    host.replace_encoder(V2VideoEncoder::new(
        codec,
        WIDTH as u32,
        HEIGHT as u32,
        ENCODER_QUALITY,
        Some(WAN_KEYFRAME_INTERVAL),
    )?);
    controller.clear_pending_video();

    let is_ipv6 = host
        .session()
        .udp_link()
        .is_some_and(|u| u.edge_addr().is_ipv6());
    let (meta_tx, mut meta_rx) = mpsc::unbounded_channel::<SentVideoMeta>();
    let send_done = Arc::new(AtomicBool::new(false));
    let recv_done = Arc::new(AtomicBool::new(false));
    let send_done_rx = Arc::clone(&send_done);
    let recv_done_tx = Arc::clone(&recv_done);

    let started = Instant::now();

    let send_task = async {
        let mut pacer = WireRatePacer::new(max_wire_mbps, 0);
        let mut encode_samples_us = Vec::with_capacity(frames);
        let mut total_raw_bytes = 0u64;
        let mut total_slices = 0u64;
        let mut idr_frames_sent = 0usize;
        let mut forced_idr_frame_ids = Vec::new();
        let mut prev_sent_frame_id: Option<u32> = None;
        let mut sent_frame_ids_strictly_monotonic = true;
        let mut force_next_idr = false;
        let mut last_forced_idr: Option<Instant> = None;
        let mut next_frame_at = Instant::now();

        for idx in 0..frames {
            let target_at = next_frame_at.max(pacer.next_send_at());
            while Instant::now() < target_at {
                let rem = target_at
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(5));
                if rem.is_zero() {
                    break;
                }
                match host.session_mut().recv_event(rem).await {
                    Ok(TransportEvent::Control(ctrl)) => {
                        if let Some(error_code) = parse_session_close(&ctrl) {
                            return Err(SessionError::SessionClosed { error_code });
                        }
                        if parse_request_idr(&ctrl).is_some()
                            && last_forced_idr.is_none_or(|t| {
                                t.elapsed() >= Duration::from_millis(IDR_MIN_INTERVAL_MS)
                            })
                        {
                            force_next_idr = true;
                        }
                    }
                    Ok(TransportEvent::RequestIdr { .. }) => {
                        if last_forced_idr
                            .is_none_or(|t| t.elapsed() >= Duration::from_millis(IDR_MIN_INTERVAL_MS))
                        {
                            force_next_idr = true;
                        }
                    }
                    Ok(_) | Err(ClientError::Timeout(_)) => {}
                    Err(e) => return Err(e.into()),
                }
            }

            let was_forced_idr = if force_next_idr {
                host.replace_encoder(V2VideoEncoder::new(
                    codec,
                    WIDTH as u32,
                    HEIGHT as u32,
                    ENCODER_QUALITY,
                    Some(WAN_KEYFRAME_INTERVAL),
                )?);
                last_forced_idr = Some(Instant::now());
                force_next_idr = false;
                true
            } else {
                false
            };

            let src = Arc::new(generate_animated_i420(WIDTH, HEIGHT, idx as u32));
            let before_stats = host.session().data_plane().stats();
            let tx_bytes_before = before_stats.tx_bytes;
            let tx_pkts_before = before_stats.tx_packets;
            let info = host.publish_i420_frame(src, (idx as i64) * 33).await?;
            if prev_sent_frame_id.is_some_and(|prev| info.meta.frame_id <= prev) {
                sent_frame_ids_strictly_monotonic = false;
            }
            prev_sent_frame_id = Some(info.meta.frame_id);
            if was_forced_idr && info.meta.is_idr {
                forced_idr_frame_ids.push(info.meta.frame_id);
            }
            let after_stats = host.session().data_plane().stats();
            let tx_bytes_delta = after_stats.tx_bytes.saturating_sub(tx_bytes_before);
            let tx_pkts_delta = after_stats.tx_packets.saturating_sub(tx_pkts_before);
            let frame_wire = actual_wire_bytes(tx_bytes_delta, tx_pkts_delta, is_ipv6);
            pacer.record_sent(frame_wire, 0, Instant::now());

            encode_samples_us.push(info.encode_us);
            total_raw_bytes = total_raw_bytes.saturating_add(info.raw_bytes as u64);
            total_slices = total_slices.saturating_add(info.slices_sent as u64);
            if info.meta.is_idr {
                idr_frames_sent += 1;
            }
            meta_tx
                .send(SentVideoMeta {
                    idx,
                    frame_id: info.meta.frame_id,
                    sha256: info.sha256,
                    raw_bytes: info.raw_bytes,
                })
                .map_err(|_| {
                    SessionError::Protocol("wan-bench video metadata channel closed".into())
                })?;

            next_frame_at = (next_frame_at + VIDEO_FRAME_INTERVAL).max(Instant::now());
        }

        host.session_mut()
            .send_control(CTRL_MSG_WAN_VIDEO_EOS, &(frames as u32).to_be_bytes())
            .await?;
        let eos_at = Instant::now();
        send_done.store(true, Ordering::Release);

        // Continue pumping link events until receiver finishes so late LegNacks still get serviced.
        let tail_deadline = Instant::now() + Duration::from_secs(5);
        while !recv_done_tx.load(Ordering::Acquire) && Instant::now() < tail_deadline {
            match host
                .session_mut()
                .recv_event(Duration::from_millis(10))
                .await
            {
                Ok(TransportEvent::Control(ctrl)) => {
                    if let Some(error_code) = parse_session_close(&ctrl) {
                        return Err(SessionError::SessionClosed { error_code });
                    }
                }
                Ok(_) | Err(ClientError::Timeout(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }

        let wire_mbps = pacer.measured_wire_mbps(eos_at);
        Ok::<(Vec<u64>, u64, u64, u64, usize, Vec<u32>, bool, f64), SessionError>((
            encode_samples_us,
            total_raw_bytes,
            pacer.total_wire_bytes(),
            total_slices,
            idr_frames_sent,
            forced_idr_frame_ids,
            sent_frame_ids_strictly_monotonic,
            wire_mbps,
        ))
    };

    let recv_task = async {
        let mut decoder = Arc::new(Mutex::new(V2VideoDecoder::new(codec)?));
        let mut sent_map: HashMap<u32, SentVideoMeta> = HashMap::with_capacity(frames);
        let mut delivered_frames = 0usize;
        let mut sha256_matched_frames = 0usize;
        let mut dropped_or_corrupt_frames = 0usize;
        let mut decode_errors = 0usize;
        let mut idr_requests_sent = 0usize;
        let mut idr_frames_received = 0usize;
        let mut min_psnr = f64::MAX;
        let mut sum_psnr = 0.0f64;
        let mut min_ssim = f64::MAX;
        let mut sum_ssim = 0.0f64;

        let mut last_clean_frame_id: Option<u32> = None;
        let mut in_loss_recovery: Option<Instant> = None;
        let mut recovery_ms_samples: Vec<f64> = Vec::new();
        let mut last_idr_req: Option<Instant> = None;
        let mut eos_received = false;
        let mut last_video_at = Instant::now();
        let hard_deadline =
            Instant::now() + Duration::from_secs(120).max(Duration::from_secs((frames as u64) * 2));

        loop {
            while let Ok(m) = meta_rx.try_recv() {
                sent_map.insert(m.frame_id, m);
            }
            if delivered_frames + dropped_or_corrupt_frames >= frames {
                break;
            }
            if Instant::now() >= hard_deadline {
                break;
            }
            if send_done_rx.load(Ordering::Acquire) {
                let drain_limit = if eos_received {
                    Duration::from_millis(400)
                } else {
                    VIDEO_EOS_DRAIN_TIMEOUT
                };
                if last_video_at.elapsed() >= drain_limit {
                    break;
                }
            }

            let wait = Duration::from_millis(50);
            match controller.session_mut().recv_event(wait).await {
                Ok(TransportEvent::VideoFrame(assembled)) => {
                    last_video_at = Instant::now();
                    while let Ok(m) = meta_rx.try_recv() {
                        sent_map.insert(m.frame_id, m);
                    }
                    let Some(meta) = sent_map.get(&assembled.frame_id).cloned() else {
                        // Ignore stale frames from an earlier phase/stream cleanly.
                        continue;
                    };

                    if assembled.is_idr {
                        idr_frames_received += 1;
                    }

                    // Verify dependency chain before feeding inter-frames into the decoder:
                    // if a reference frame was dropped on real WAN, drop dependent P-frames
                    // cleanly and wait for the next IDR to recover without corrupting state.
                    let missing_dep = !assembled.is_idr
                        && (in_loss_recovery.is_some()
                            || last_clean_frame_id != Some(assembled.ref_frame_id));
                    if missing_dep {
                        dropped_or_corrupt_frames += 1;
                        if in_loss_recovery.is_none() {
                            in_loss_recovery = Some(Instant::now());
                        }
                        if last_idr_req.is_none_or(|t| {
                            t.elapsed() >= Duration::from_millis(IDR_MIN_INTERVAL_MS)
                        }) {
                            let _ = controller
                                .session_mut()
                                .send_control(
                                    CTRL_MSG_REQUEST_IDR,
                                    &assembled.frame_id.to_be_bytes(),
                                )
                                .await;
                            idr_requests_sent += 1;
                            last_idr_req = Some(Instant::now());
                        }
                        continue;
                    }

                    // Check SHA-256 before decoding so corrupt frames are dropped cleanly.
                    let wire_sha: [u8; 32] = Sha256::digest(&assembled.data).into();
                    if assembled.data.len() != meta.raw_bytes || wire_sha != meta.sha256 {
                        dropped_or_corrupt_frames += 1;
                        if in_loss_recovery.is_none() {
                            in_loss_recovery = Some(Instant::now());
                        }
                        decoder = Arc::new(Mutex::new(V2VideoDecoder::new(codec)?));
                        last_clean_frame_id = None;
                        if last_idr_req.is_none_or(|t| {
                            t.elapsed() >= Duration::from_millis(IDR_MIN_INTERVAL_MS)
                        }) {
                            let _ = controller
                                .session_mut()
                                .send_control(
                                    CTRL_MSG_REQUEST_IDR,
                                    &assembled.frame_id.to_be_bytes(),
                                )
                                .await;
                            idr_requests_sent += 1;
                            last_idr_req = Some(Instant::now());
                        }
                        continue;
                    }

                    match decode_on_blocking(&decoder, assembled).await {
                        Ok((decoded_frame, sha256, i420)) => {
                            let reference = generate_animated_i420(WIDTH, HEIGHT, meta.idx as u32);
                            let psnr = compute_y_psnr(&reference, &i420)?;
                            let ssim = compute_y_ssim(&reference, &i420)?;
                            if psnr < min_psnr {
                                min_psnr = psnr;
                            }
                            if ssim < min_ssim {
                                min_ssim = ssim;
                            }
                            sum_psnr += psnr;
                            sum_ssim += ssim;
                            delivered_frames += 1;
                            if sha256 == meta.sha256 {
                                sha256_matched_frames += 1;
                            }
                            last_clean_frame_id = Some(decoded_frame.frame_id);
                            if let Some(loss_started) = in_loss_recovery.take() {
                                recovery_ms_samples
                                    .push(loss_started.elapsed().as_secs_f64() * 1000.0);
                            }
                        }
                        Err(SessionError::Video(_)) => {
                            decode_errors += 1;
                            dropped_or_corrupt_frames += 1;
                            if in_loss_recovery.is_none() {
                                in_loss_recovery = Some(Instant::now());
                            }
                            decoder = Arc::new(Mutex::new(V2VideoDecoder::new(codec)?));
                            last_clean_frame_id = None;
                            if last_idr_req.is_none_or(|t| {
                                t.elapsed() >= Duration::from_millis(IDR_MIN_INTERVAL_MS)
                            }) {
                                let _ = controller
                                    .session_mut()
                                    .send_control(
                                        CTRL_MSG_REQUEST_IDR,
                                        &meta.frame_id.to_be_bytes(),
                                    )
                                    .await;
                                idr_requests_sent += 1;
                                last_idr_req = Some(Instant::now());
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }
                Ok(TransportEvent::Control(ctrl)) => {
                    if let Some(error_code) = parse_session_close(&ctrl) {
                        return Err(SessionError::SessionClosed { error_code });
                    }
                    if ctrl.msg_type == CTRL_MSG_WAN_VIDEO_EOS {
                        eos_received = true;
                        last_video_at = Instant::now();
                    }
                }
                Ok(_) | Err(ClientError::Timeout(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }

        recv_done.store(true, Ordering::Release);
        Ok::<_, SessionError>((
            delivered_frames,
            sha256_matched_frames,
            dropped_or_corrupt_frames,
            decode_errors,
            idr_requests_sent,
            idr_frames_received,
            min_psnr,
            sum_psnr,
            min_ssim,
            sum_ssim,
            recovery_ms_samples,
            in_loss_recovery.is_some(),
        ))
    };

    let (
        (
            encode_samples_us,
            total_raw_bytes,
            total_wire_bytes,
            total_slices_sent,
            idr_frames_sent,
            forced_idr_frame_ids,
            sent_frame_ids_strictly_monotonic,
            wire_mbps,
        ),
        (
            delivered_frames,
            sha256_matched_frames,
            dropped_or_corrupt_frames,
            decode_errors,
            idr_requests_sent,
            idr_frames_received,
            min_psnr,
            sum_psnr,
            min_ssim,
            sum_ssim,
            recovery_ms_samples,
            unrecovered_loss_at_eof,
        ),
    ) = tokio::try_join!(send_task, recv_task)?;

    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    let missing_frames = frames.saturating_sub(delivered_frames + dropped_or_corrupt_frames);
    let (decoded_min_psnr_db, decoded_avg_psnr_db, decoded_min_ssim, decoded_avg_ssim) =
        if delivered_frames > 0 {
            let denom = delivered_frames as f64;
            (min_psnr, sum_psnr / denom, min_ssim, sum_ssim / denom)
        } else {
            (0.0, 0.0, 0.0, 0.0)
        };
    let encode_ms_p50 = percentile_ms(&encode_samples_us, 0.50);
    let encode_ms_p95 = percentile_ms(&encode_samples_us, 0.95);
    let encode_ms_max = percentile_ms(&encode_samples_us, 1.0);
    let loss_recovery_count = recovery_ms_samples.len();
    let recovery_ms = recovery_ms_samples.iter().copied().fold(0.0f64, f64::max);

    let delivery_ratio = (delivered_frames as f64) / (frames.max(1) as f64);
    let pass = delivered_frames > 0
        && delivery_ratio >= MIN_VIDEO_DELIVERY_RATIO
        && sha256_matched_frames == delivered_frames
        && decoded_min_psnr_db >= MIN_PSNR_DB
        && decoded_min_ssim >= MIN_SSIM;

    Ok(WanVideoTelemetry {
        codec: codec.name().to_string(),
        width: WIDTH,
        height: HEIGHT,
        target_frames: frames,
        delivered_frames,
        sha256_matched_frames,
        dropped_or_corrupt_frames,
        missing_frames,
        decode_errors,
        idr_requests_sent,
        idr_frames_sent,
        idr_frames_received,
        forced_idr_frame_ids,
        sent_frame_ids_strictly_monotonic,
        encode_ms_p50,
        encode_ms_p95,
        encode_ms_max,
        decoded_min_psnr_db,
        decoded_avg_psnr_db,
        decoded_min_ssim,
        decoded_avg_ssim,
        loss_recovery_count,
        recovery_ms,
        recovery_ms_samples,
        unrecovered_loss_at_eof,
        total_raw_bytes,
        total_wire_bytes,
        total_slices_sent,
        wire_mbps,
        elapsed_ms,
        pass,
    })
}

pub async fn run_wan_bench(args: &WanBenchArgs) -> Result<WanBenchReport, SessionError> {
    let cfg = ClusterConfig::from_file(&args.config)?;
    let bootstrap_mbps = (args.bg_mbps.max(args.max_wire_mbps).ceil() as u32).max(1);
    let BootstrappedSessions {
        controller: pair_ctrl,
        host: pair_host,
        edge_a_ping_us,
        edge_b_ping_us,
        signaling_rtt_us,
        renew_guard,
    } = bootstrap_live_pair(&cfg, args.ca_der.as_deref(), bootstrap_mbps).await?;

    let is_ipv6 = pair_host
        .udp_link()
        .is_some_and(|u| u.edge_addr().is_ipv6());
    let init_enc = V2VideoEncoder::new(
        args.codec,
        WIDTH as u32,
        HEIGHT as u32,
        ENCODER_QUALITY,
        Some(WAN_KEYFRAME_INTERVAL),
    )?;
    let init_dec = V2VideoDecoder::new(args.codec)?;
    let mut host = DesktopHostSession::new(pair_host, init_enc);
    let mut controller = DesktopControllerSession::new(pair_ctrl, init_dec);

    let hid_preemption = run_wan_hid_preemption(
        &mut host,
        &mut controller,
        args.rounds,
        args.probes_per_round,
        args.bg_mbps,
        args.max_wire_mbps,
    )
    .await?;

    let video_telemetry = run_wan_video_telemetry(
        &mut host,
        &mut controller,
        args.codec,
        args.frames,
        args.max_wire_mbps,
    )
    .await?;

    let (lease_renewals_ok, lease_renewals_err) = renew_guard.shutdown().await;
    eprintln!(
        "[wan-bench] lease_renewals_ok={lease_renewals_ok} lease_renewals_err={lease_renewals_err}"
    );

    let (verdict, pass, error) = if hid_preemption.verdict == "INCONCLUSIVE" {
        (
            "INCONCLUSIVE".to_string(),
            false,
            Some(format!(
                "wan-bench INCONCLUSIVE: only {}/{} rounds had stable baseline (unloaded_p95 - unloaded_p50 <= {BASELINE_JITTER_INCONCLUSIVE_MS:.1} ms)",
                hid_preemption.valid_rounds, hid_preemption.rounds_total
            )),
        )
    } else if hid_preemption.pass && video_telemetry.pass && lease_renewals_err == 0 {
        ("PASS".to_string(), true, None)
    } else {
        let mut reasons = Vec::new();
        if !hid_preemption.pass {
            reasons.push(format!(
                "HID incremental gate failed (delta_p50={:.2}ms <= {:.1}ms, delta_p95={:.2}ms <= {:.1}ms, wire_mbps=[{:.2}, {:.2}] target={:.2})",
                hid_preemption.delta_p50_ms,
                DELTA_P50_GATE_MS,
                hid_preemption.delta_p95_ms,
                DELTA_P95_GATE_MS,
                hid_preemption.min_round_wire_mbps,
                hid_preemption.max_round_wire_mbps,
                hid_preemption.effective_target_wire_mbps,
            ));
        }
        if !video_telemetry.pass {
            reasons.push(format!(
                "video telemetry gate failed (delivered={}/{}, sha256={}, min_psnr={:.2}dB, min_ssim={:.4})",
                video_telemetry.delivered_frames,
                video_telemetry.target_frames,
                video_telemetry.sha256_matched_frames,
                video_telemetry.decoded_min_psnr_db,
                video_telemetry.decoded_min_ssim,
            ));
        }
        if lease_renewals_err > 0 {
            reasons.push(format!(
                "background lease renewal failed ({lease_renewals_err} errors, {lease_renewals_ok} ok)"
            ));
        }
        ("FAIL".to_string(), false, Some(reasons.join("; ")))
    };

    Ok(WanBenchReport {
        pass,
        verdict,
        width: WIDTH,
        height: HEIGHT,
        ip_udp_overhead_bytes: ip_udp_overhead_bytes(is_ipv6),
        edge_a_ping_rtt_ms: (edge_a_ping_us as f64) / 1000.0,
        edge_b_ping_rtt_ms: (edge_b_ping_us as f64) / 1000.0,
        signaling_tcp_rtt_ms: (signaling_rtt_us as f64) / 1000.0,
        lease_renewals_ok,
        lease_renewals_err,
        hid_preemption,
        video_telemetry,
        error,
    })
}

pub async fn cmd_wan_bench(args: &[String]) -> ExitCode {
    let parsed = match parse_wan_bench_args(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[wan-bench] {e}");
            print_usage();
            return ExitCode::from(2);
        }
    };

    match run_wan_bench(&parsed).await {
        Ok(report) => {
            if let Ok(json) = serde_json::to_string_pretty(&report) {
                println!("{json}");
            }
            if report.pass {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            let err_json = serde_json::json!({
                "pass": false,
                "verdict": "FAIL",
                "error": e.to_string(),
            });
            if let Ok(s) = serde_json::to_string_pretty(&err_json) {
                println!("{s}");
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::{net::UdpSocket, task::JoinHandle};
    use v2_client::{AccessKeys, UdpAccessLink, UdpE2eeSession};
    use v2_transport::{
        seal_udp_v11, AccessEpochState, AccessFlags, AccessHeaderV11, VerifiedTenantPolicy,
        DIR_CLIENT_TO_EDGE, DIR_EDGE_TO_CLIENT, TRANSPORT_DATAGRAM, UDP_MAX_LEN,
    };

    #[derive(Clone, Default)]
    struct FaultSpec {
        /// Drop the Nth (1-based) P0 packet from controller -> host.
        drop_ctrl_to_host_p0_nth: Option<usize>,
        /// Drop the Nth (1-based) P2 video packet from host -> controller.
        drop_host_to_ctrl_p2_nth: Option<usize>,
    }

    struct LoopbackPair {
        host: DesktopHostSession,
        controller: DesktopControllerSession,
        _relay: JoinHandle<()>,
    }

    async fn spawn_loopback_pair_with_faults(faults: FaultSpec) -> LoopbackPair {
        let edge_a_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let edge_b_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let edge_a_addr = edge_a_sock.local_addr().unwrap();
        let edge_b_addr = edge_b_sock.local_addr().unwrap();

        let cid_a = [0xA1; 8];
        let cid_b = [0xB2; 8];
        let hs_a = [0x33; 32];
        let hs_b = [0x44; 32];
        let keys_a = AccessKeys::derive(cid_a, hs_a, 1).unwrap();
        let keys_b = AccessKeys::derive(cid_b, hs_b, 1).unwrap();

        let mut link_ctrl = UdpAccessLink::connect(&edge_a_addr.to_string(), &keys_a, 50_000)
            .await
            .unwrap();
        let mut link_host = UdpAccessLink::connect(&edge_b_addr.to_string(), &keys_b, 50_000)
            .await
            .unwrap();
        // Disable auto LegNack in fault-injection tests so a dropped P2 packet actually
        // exercises end-to-end decoder drop & IDR recovery rather than L2 retransmission.
        if faults.drop_host_to_ctrl_p2_nth.is_some() || faults.drop_ctrl_to_host_p0_nth.is_some() {
            link_ctrl.auto_leg_nack = false;
            link_host.auto_leg_nack = false;
        }
        let ctrl_local = link_ctrl.local_addr().unwrap();
        let host_local = link_host.local_addr().unwrap();

        let mut rx_a =
            AccessEpochState::new(cid_a, hs_a, TRANSPORT_DATAGRAM, DIR_CLIENT_TO_EDGE, 1, 20)
                .unwrap();
        let tx_a =
            AccessEpochState::new(cid_a, hs_a, TRANSPORT_DATAGRAM, DIR_EDGE_TO_CLIENT, 1, 20)
                .unwrap();
        let mut rx_b =
            AccessEpochState::new(cid_b, hs_b, TRANSPORT_DATAGRAM, DIR_CLIENT_TO_EDGE, 1, 20)
                .unwrap();
        let tx_b =
            AccessEpochState::new(cid_b, hs_b, TRANSPORT_DATAGRAM, DIR_EDGE_TO_CLIENT, 1, 20)
                .unwrap();

        let p0_a2b_seen = Arc::new(AtomicUsize::new(0));
        let p2_b2a_seen = Arc::new(AtomicUsize::new(0));

        let relay = tokio::spawn(async move {
            let mut buf_a = [0u8; UDP_MAX_LEN + 64];
            let mut buf_b = [0u8; UDP_MAX_LEN + 64];
            let mut seq_to_host = 1u32;
            let mut seq_to_ctrl = 1u32;
            loop {
                tokio::select! {
                    res = edge_a_sock.recv(&mut buf_a) => {
                        let Ok(n) = res else { break; };
                        let Ok((hdr, payload)) = rx_a.verify_udp_packet(&buf_a[..n], 0) else { continue; };
                        if hdr.flags.pp == 0 && !hdr.flags.is_ctrl_edge {
                            let idx = p0_a2b_seen.fetch_add(1, Ordering::SeqCst) + 1;
                            if faults.drop_ctrl_to_host_p0_nth == Some(idx) {
                                continue;
                            }
                        }
                        let fwd_hdr = AccessHeaderV11 {
                            flags: AccessFlags {
                                pp: hdr.flags.pp,
                                discardable: hdr.flags.discardable,
                                frame_end: hdr.flags.frame_end,
                                is_ctrl_edge: false,
                                dir_edge_to_client: true,
                                rtx: false,
                            },
                            route_cid: cid_b,
                            access_epoch: tx_b.cur_epoch(),
                            leg_seq: seq_to_host,
                            mac_64: [0; 8],
                        };
                        seq_to_host = seq_to_host.wrapping_add(1);
                        if let Ok(wire) = seal_udp_v11(tx_b.cur_key(), fwd_hdr, payload) {
                            let _ = edge_b_sock.send_to(&wire, host_local).await;
                        }
                    }
                    res = edge_b_sock.recv(&mut buf_b) => {
                        let Ok(n) = res else { break; };
                        let Ok((hdr, payload)) = rx_b.verify_udp_packet(&buf_b[..n], 0) else { continue; };
                        if hdr.flags.pp == 2 && !hdr.flags.is_ctrl_edge {
                            let idx = p2_b2a_seen.fetch_add(1, Ordering::SeqCst) + 1;
                            if faults.drop_host_to_ctrl_p2_nth == Some(idx) {
                                continue;
                            }
                        }
                        let fwd_hdr = AccessHeaderV11 {
                            flags: AccessFlags {
                                pp: hdr.flags.pp,
                                discardable: hdr.flags.discardable,
                                frame_end: hdr.flags.frame_end,
                                is_ctrl_edge: false,
                                dir_edge_to_client: true,
                                rtx: false,
                            },
                            route_cid: cid_a,
                            access_epoch: tx_a.cur_epoch(),
                            leg_seq: seq_to_ctrl,
                            mac_64: [0; 8],
                        };
                        seq_to_ctrl = seq_to_ctrl.wrapping_add(1);
                        if let Ok(wire) = seal_udp_v11(tx_a.cur_key(), fwd_hdr, payload) {
                            let _ = edge_a_sock.send_to(&wire, ctrl_local).await;
                        }
                    }
                }
            }
        });

        let policy = VerifiedTenantPolicy::free_tier([0x11; 16]);
        let key_c2h = [0x55; 32];
        let key_h2c = [0x66; 32];
        let ctrl_sess =
            UdpE2eeSession::from_keys(link_ctrl, key_c2h, key_h2c, policy.clone(), [0x01; 16]);
        let host_sess =
            UdpE2eeSession::from_keys(link_host, key_h2c, key_c2h, policy, [0x02; 16]);

        let enc =
            V2VideoEncoder::new(VideoCodec::Vp9, WIDTH as u32, HEIGHT as u32, 2.0, Some(30))
                .unwrap();
        let dec = V2VideoDecoder::new(VideoCodec::Vp9).unwrap();

        LoopbackPair {
            host: DesktopHostSession::new(host_sess, enc),
            controller: DesktopControllerSession::new(ctrl_sess, dec),
            _relay: relay,
        }
    }

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn wan_bench_cli_parser_defaults_and_validation() {
        let ok = parse_wan_bench_args(&argv(&[
            "zerodesk-desktop-e2e",
            "wan-bench",
            "--config",
            "/tmp/cluster.json",
        ]))
        .unwrap();
        assert_eq!(ok.frames, 120);
        assert_eq!(ok.codec, VideoCodec::Vp9);
        assert_eq!(ok.bg_mbps, 8.0);
        assert_eq!(ok.rounds, 3);
        assert_eq!(ok.probes_per_round, 200);
        assert_eq!(ok.max_wire_mbps, 8.0);

        let custom = parse_wan_bench_args(&argv(&[
            "zerodesk-desktop-e2e",
            "wan-bench",
            "--config",
            "/tmp/cluster.json",
            "--ca-der",
            "/tmp/ca.der",
            "--frames",
            "90",
            "--codec",
            "av1",
            "--bg-mbps",
            "10",
            "--rounds",
            "5",
            "--probes-per-round",
            "250",
            "--max-wire-mbps",
            "8",
        ]))
        .unwrap();
        assert_eq!(custom.frames, 90);
        assert_eq!(custom.codec, VideoCodec::Av1);
        assert_eq!(custom.bg_mbps, 10.0);
        assert_eq!(custom.rounds, 5);
        assert_eq!(custom.probes_per_round, 250);
        assert_eq!(custom.max_wire_mbps, 8.0);
        assert_eq!(custom.ca_der, Some(PathBuf::from("/tmp/ca.der")));

        for bad in [
            argv(&["bin", "wan-bench"]),
            argv(&["bin", "wan-bench", "--config", "c.json", "--rounds", "2"]),
            argv(&[
                "bin",
                "wan-bench",
                "--config",
                "c.json",
                "--probes-per-round",
                "199",
            ]),
            argv(&["bin", "wan-bench", "--config", "c.json", "--frames", "0"]),
            argv(&["bin", "wan-bench", "--config", "c.json", "--bg-mbps", "0"]),
            argv(&[
                "bin",
                "wan-bench",
                "--config",
                "c.json",
                "--max-wire-mbps",
                "-1",
            ]),
            argv(&[
                "bin",
                "wan-bench",
                "--config",
                "c.json",
                "--codec",
                "h264",
            ]),
        ] {
            assert!(
                parse_wan_bench_args(&bad).is_err(),
                "expected invalid CLI args to fail: {bad:?}"
            );
        }
    }

    #[test]
    fn noisy_baseline_marks_inconclusive_and_never_silently_passes() {
        // Round with unloaded_p95 - unloaded_p50 = 60 ms > 50 ms must be marked INCONCLUSIVE.
        let mut unloaded = vec![20_000u64; 185];
        unloaded.extend(vec![80_000u64; 15]); // p50=20ms, p95=80ms -> jitter=60ms > 50ms
        let loaded = vec![25_000u64; 200];

        let noisy_round = evaluate_round(RoundEvalInput {
            round: 1,
            probes_sent: 200,
            unloaded_rtts_us: unloaded,
            unloaded_field_exact_match: true,
            loaded_rtts_us: loaded,
            loaded_field_exact_match: true,
            bg_raw_video_bytes_sent: 100_000,
            bg_wire_bytes_sent: 111_400,
            bg_udp_packets_sent: 100,
            bg_recv_video_frames: 30,
            wire_mbps: 7.9,
        });
        assert!(noisy_round.inconclusive);
        assert_eq!(noisy_round.status, "INCONCLUSIVE");
        assert!(noisy_round.unloaded_jitter_ms > 50.0);

        // If 2 of 3 rounds are INCONCLUSIVE, aggregate verdict MUST be INCONCLUSIVE (pass=false).
        let clean_round = evaluate_round(RoundEvalInput {
            round: 2,
            probes_sent: 200,
            unloaded_rtts_us: vec![120_000u64; 200],
            unloaded_field_exact_match: true,
            loaded_rtts_us: vec![130_000u64; 200],
            loaded_field_exact_match: true,
            bg_raw_video_bytes_sent: 100_000,
            bg_wire_bytes_sent: 111_400,
            bg_udp_packets_sent: 100,
            bg_recv_video_frames: 30,
            wire_mbps: 7.9,
        });
        assert!(!clean_round.inconclusive);

        let mut noisy2 = noisy_round.clone();
        noisy2.round = 3;
        let agg_inconclusive = aggregate_rounds(
            vec![noisy_round.clone(), clean_round.clone(), noisy2],
            200,
            8.0,
            8.0,
        );
        assert_eq!(agg_inconclusive.verdict, "INCONCLUSIVE");
        assert!(!agg_inconclusive.pass);
        assert_eq!(agg_inconclusive.valid_rounds, 1);
        assert_eq!(agg_inconclusive.inconclusive_rounds, 2);

        // With 2 of 3 valid rounds and clean incremental deltas, median across valid rounds passes.
        let mut clean2 = clean_round.clone();
        clean2.round = 3;
        let agg_pass = aggregate_rounds(vec![noisy_round, clean_round, clean2], 200, 8.0, 8.0);
        assert_eq!(agg_pass.verdict, "PASS");
        assert!(agg_pass.pass);
        assert_eq!(agg_pass.valid_rounds, 2);
        assert_eq!(agg_pass.inconclusive_rounds, 1);
        assert!((agg_pass.delta_p50_ms - 10.0).abs() < 1e-6);
        assert!((agg_pass.delta_p95_ms - 10.0).abs() < 1e-6);
    }

    #[test]
    fn incremental_gate_rejects_excess_delta_even_when_below_3x_wan_rtt() {
        // High-RTT WAN: unloaded p50=150ms, p95=160ms (3x unloaded_p50 would be 450ms!).
        // Loaded p50=170ms (+20ms <= 25ms), p95=215ms (+55ms > 50ms) => MUST FAIL incremental gate!
        let mut unloaded = vec![150_000u64; 180];
        unloaded.extend(vec![160_000u64; 20]);
        let mut loaded = vec![170_000u64; 180];
        loaded.extend(vec![215_000u64; 20]);

        let make_round = |round| {
            evaluate_round(RoundEvalInput {
                round,
                probes_sent: 200,
                unloaded_rtts_us: unloaded.clone(),
                unloaded_field_exact_match: true,
                loaded_rtts_us: loaded.clone(),
                loaded_field_exact_match: true,
                bg_raw_video_bytes_sent: 100_000,
                bg_wire_bytes_sent: 111_400,
                bg_udp_packets_sent: 100,
                bg_recv_video_frames: 30,
                wire_mbps: 7.8,
            })
        };
        let agg = aggregate_rounds(vec![make_round(1), make_round(2), make_round(3)], 200, 8.0, 8.0);
        assert_eq!(agg.verdict, "FAIL");
        assert!(!agg.pass);
        assert!((agg.delta_p50_ms - 20.0).abs() < 1e-6);
        assert!((agg.delta_p95_ms - 55.0).abs() < 1e-6);

        // Loaded p50=+30ms (> 25ms) with p95=+35ms (<= 50ms) => MUST ALSO FAIL incremental gate.
        let mut loaded_p50_fail = vec![180_000u64; 180];
        loaded_p50_fail.extend(vec![195_000u64; 20]);
        let r_p50_fail = |round| {
            evaluate_round(RoundEvalInput {
                round,
                probes_sent: 200,
                unloaded_rtts_us: unloaded.clone(),
                unloaded_field_exact_match: true,
                loaded_rtts_us: loaded_p50_fail.clone(),
                loaded_field_exact_match: true,
                bg_raw_video_bytes_sent: 100_000,
                bg_wire_bytes_sent: 111_400,
                bg_udp_packets_sent: 100,
                bg_recv_video_frames: 30,
                wire_mbps: 7.8,
            })
        };
        let agg2 = aggregate_rounds(
            vec![r_p50_fail(1), r_p50_fail(2), r_p50_fail(3)],
            200,
            8.0,
            8.0,
        );
        assert_eq!(agg2.verdict, "FAIL");
        assert!(!agg2.pass);
        assert!((agg2.delta_p50_ms - 30.0).abs() < 1e-6);
        assert!((agg2.delta_p95_ms - 35.0).abs() < 1e-6);
    }

    #[test]
    fn wire_rate_pacer_enforces_exact_wire_cap_including_ip_udp_overhead() {
        // 3000B payload -> 3 slices * (18+8+16+16+28+28=114B) + 3000B = 3342B wire.
        assert_eq!(estimate_video_frame_wire_bytes(3_000, L3_MTU_DEFAULT, false), 3_342);
        assert_eq!(estimate_video_frame_wire_bytes(3_000, L3_MTU_DEFAULT, true), 3_402);

        let t0 = Instant::now();
        let mut pacer = WireRatePacer::with_start(8.0, 3_342, t0);
        let mut now = t0;
        for _ in 0..300 {
            if pacer.next_send_at() > now {
                now = pacer.next_send_at();
            }
            pacer.record_sent(3_342, 3_342, now);
        }
        let measured = pacer.measured_wire_mbps(now);
        assert!(
            (7.9..=8.0 + 1e-6).contains(&measured),
            "expected measured wire_mbps in [7.9, 8.0], got {measured:.4}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_loopback_wire_bytes_match_estimate_and_survive_p0_drop() {
        // Inject 1 dropped P0 packet from controller -> host to verify loss_pct reporting
        // and clean recovery without sequence desynchronization or hanging.
        let mut pair = spawn_loopback_pair_with_faults(FaultSpec {
            drop_ctrl_to_host_p0_nth: Some(3),
            drop_host_to_ctrl_p2_nth: None,
        })
        .await;

        // First verify our wire-byte estimator matches UdpAccessLink::stats byte-for-byte.
        let payload = vec![0x5Au8; 3_000];
        let meta = VideoFrameMeta {
            display_idx: 0,
            codec_id: VideoCodec::Vp9.codec_id(),
            frame_id: 1,
            ref_frame_id: 1,
            ltr_slot: 0,
            is_idr: false,
            is_ref: false,
            max_age_ms: 200,
        };
        let s0 = pair.host.session().data_plane().stats();
        let b0 = s0.tx_bytes;
        let p0 = s0.tx_packets;
        pair.host.publish_raw_video(&meta, &payload).await.unwrap();
        let s1 = pair.host.session().data_plane().stats();
        let db = s1.tx_bytes - b0;
        let dp = s1.tx_packets - p0;
        assert_eq!(
            actual_wire_bytes(db, dp, false),
            estimate_video_frame_wire_bytes(payload.len(), L3_MTU_DEFAULT, false)
        );
        drain_quiet_window(
            &mut pair.host,
            &mut pair.controller,
            Duration::from_millis(30),
            Duration::from_millis(150),
        )
        .await
        .unwrap();

        let base_ts = now_ms();
        let mut seq = 1u32;
        let round = run_wan_hid_round(
            &mut pair.host,
            &mut pair.controller,
            1,
            20,
            base_ts,
            &mut seq,
            6.0,
            &payload,
            Duration::from_millis(120),
        )
        .await
        .unwrap();
        assert_eq!(round.unloaded_lost, 1);
        assert_eq!(round.unloaded_received, 19);
        assert!((round.unloaded_loss_pct - 5.0).abs() < 1e-6);
        assert!(round.unloaded_field_exact_match);
        assert_eq!(round.loaded_received, 20);
        assert!(round.loaded_field_exact_match);
        assert!(round.bg_recv_video_frames > 0);
        assert!(
            round.wire_mbps > 0.0 && round.wire_mbps <= 6.0 + 1e-6,
            "wire_mbps {} exceeded cap 6.0",
            round.wire_mbps
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_loopback_real_codec_video_telemetry_and_loss_recovery() {
        // Drop a P2 slice mid-stream (10th P2 packet) to force a real dropped frame on the wire,
        // verifying clean drop without crash/hang, IDR recovery, recovery_ms > 0, and PSNR/SSIM.
        let mut pair = spawn_loopback_pair_with_faults(FaultSpec {
            drop_ctrl_to_host_p0_nth: None,
            drop_host_to_ctrl_p2_nth: Some(10),
        })
        .await;

        let telemetry = run_wan_video_telemetry(
            &mut pair.host,
            &mut pair.controller,
            VideoCodec::Vp9,
            40,
            8.0,
        )
        .await
        .unwrap();

        assert_eq!(telemetry.codec, "vp9");
        assert_eq!(telemetry.target_frames, 40);
        assert!(
            telemetry.delivered_frames >= 20,
            "expected recovery to deliver clean frames after drop, got {}",
            telemetry.delivered_frames
        );
        assert_eq!(telemetry.sha256_matched_frames, telemetry.delivered_frames);
        assert!(telemetry.encode_ms_p50 > 0.0);
        assert!(telemetry.encode_ms_p95 >= telemetry.encode_ms_p50);
        assert!(
            telemetry.decoded_min_psnr_db >= MIN_PSNR_DB,
            "min PSNR too low: {:.2}",
            telemetry.decoded_min_psnr_db
        );
        assert!(
            telemetry.decoded_min_ssim >= MIN_SSIM,
            "min SSIM too low: {:.4}",
            telemetry.decoded_min_ssim
        );
        assert!(
            telemetry.loss_recovery_count >= 1 && telemetry.recovery_ms > 0.0,
            "expected recorded loss recovery after dropped P2 packet, got count={}, recovery_ms={}",
            telemetry.loss_recovery_count,
            telemetry.recovery_ms
        );
        assert!(telemetry.idr_frames_sent >= 2);
        assert!(
            telemetry.sent_frame_ids_strictly_monotonic,
            "every emitted frame_id (including forced IDRs after replace_encoder) must be strictly monotonic"
        );
        assert!(
            !telemetry.forced_idr_frame_ids.is_empty(),
            "expected at least one forced IDR emitted via replace_encoder on CTRL_MSG_REQUEST_IDR"
        );
        assert!(!telemetry.unrecovered_loss_at_eof);
    }

    #[test]
    fn loaded_blackout_and_high_loaded_loss_fail_never_inconclusive() {
        let clean = |round| {
            evaluate_round(RoundEvalInput {
                round,
                probes_sent: 200,
                unloaded_rtts_us: vec![100_000u64; 200],
                unloaded_field_exact_match: true,
                loaded_rtts_us: vec![105_000u64; 200],
                loaded_field_exact_match: true,
                bg_raw_video_bytes_sent: 100_000,
                bg_wire_bytes_sent: 111_400,
                bg_udp_packets_sent: 100,
                bg_recv_video_frames: 30,
                wire_mbps: 7.9,
            })
        };

        // Round with loaded_received == 0 must NOT be marked INCONCLUSIVE and MUST FAIL aggregate
        // even when the other 2 rounds pass.
        let blackout = evaluate_round(RoundEvalInput {
            round: 1,
            probes_sent: 200,
            unloaded_rtts_us: vec![100_000u64; 200],
            unloaded_field_exact_match: true,
            loaded_rtts_us: vec![],
            loaded_field_exact_match: true,
            bg_raw_video_bytes_sent: 100_000,
            bg_wire_bytes_sent: 111_400,
            bg_udp_packets_sent: 100,
            bg_recv_video_frames: 30,
            wire_mbps: 7.9,
        });
        assert!(!blackout.inconclusive);
        assert_eq!(blackout.status, "VALID");

        let agg_blackout = aggregate_rounds(vec![blackout.clone(), clean(2), clean(3)], 200, 8.0, 8.0);
        assert_eq!(agg_blackout.verdict, "FAIL");
        assert!(!agg_blackout.pass);

        // Even if the other 2 rounds have noisy baselines, loaded blackout MUST still be FAIL
        // (never masked as INCONCLUSIVE).
        let mut noisy_unloaded = vec![20_000u64; 185];
        noisy_unloaded.extend(vec![80_000u64; 15]);
        let noisy = |round| {
            evaluate_round(RoundEvalInput {
                round,
                probes_sent: 200,
                unloaded_rtts_us: noisy_unloaded.clone(),
                unloaded_field_exact_match: true,
                loaded_rtts_us: vec![25_000u64; 200],
                loaded_field_exact_match: true,
                bg_raw_video_bytes_sent: 100_000,
                bg_wire_bytes_sent: 111_400,
                bg_udp_packets_sent: 100,
                bg_recv_video_frames: 30,
                wire_mbps: 7.9,
            })
        };
        let agg_blackout_noisy =
            aggregate_rounds(vec![blackout, noisy(2), noisy(3)], 200, 8.0, 8.0);
        assert_eq!(agg_blackout_noisy.verdict, "FAIL");
        assert!(!agg_blackout_noisy.pass);

        // High loaded loss (70% lost, surviving RTTs unchanged so delta=0ms) MUST FAIL LOADED_LOSS_GATE_PCT.
        let high_loss = |round| {
            evaluate_round(RoundEvalInput {
                round,
                probes_sent: 200,
                unloaded_rtts_us: vec![100_000u64; 200],
                unloaded_field_exact_match: true,
                loaded_rtts_us: vec![100_000u64; 60],
                loaded_field_exact_match: true,
                bg_raw_video_bytes_sent: 100_000,
                bg_wire_bytes_sent: 111_400,
                bg_udp_packets_sent: 100,
                bg_recv_video_frames: 30,
                wire_mbps: 7.9,
            })
        };
        let agg_loss = aggregate_rounds(
            vec![high_loss(1), high_loss(2), high_loss(3)],
            200,
            8.0,
            8.0,
        );
        assert_eq!(agg_loss.verdict, "FAIL");
        assert!(!agg_loss.pass);
        assert!((agg_loss.loaded_loss_pct - 70.0).abs() < 1e-6);
    }

    #[test]
    fn wire_rate_band_rejects_underdriven_or_non_finite_load() {
        let make_round = |round, wire_mbps| {
            evaluate_round(RoundEvalInput {
                round,
                probes_sent: 200,
                unloaded_rtts_us: vec![100_000u64; 200],
                unloaded_field_exact_match: true,
                loaded_rtts_us: vec![105_000u64; 200],
                loaded_field_exact_match: true,
                bg_raw_video_bytes_sent: 100_000,
                bg_wire_bytes_sent: 111_400,
                bg_udp_packets_sent: 100,
                bg_recv_video_frames: 30,
                wire_mbps,
            })
        };

        // Under-driven load: 7.0 Mbps < 0.90 * 8.0 Mbps (7.2 Mbps) => FAIL.
        let agg_under = aggregate_rounds(
            vec![make_round(1, 7.0), make_round(2, 7.9), make_round(3, 7.9)],
            200,
            8.0,
            8.0,
        );
        assert_eq!(agg_under.verdict, "FAIL");
        assert!(!agg_under.pass);
        assert!((agg_under.min_round_wire_mbps - 7.0).abs() < 1e-6);

        // Over-driven load: 8.2 Mbps > 1.01 * 8.0 Mbps (8.08 Mbps) => FAIL.
        let agg_over = aggregate_rounds(
            vec![make_round(1, 8.2), make_round(2, 7.9), make_round(3, 7.9)],
            200,
            8.0,
            8.0,
        );
        assert_eq!(agg_over.verdict, "FAIL");
        assert!(!agg_over.pass);

        // Non-finite wire_mbps (NaN / Inf) => FAIL.
        for bad_rate in [f64::NAN, f64::INFINITY] {
            let agg_bad = aggregate_rounds(
                vec![
                    make_round(1, bad_rate),
                    make_round(2, 7.9),
                    make_round(3, 7.9),
                ],
                200,
                8.0,
                8.0,
            );
            assert_eq!(agg_bad.verdict, "FAIL");
            assert!(!agg_bad.pass);
        }

        // In-band load [7.2, 8.08] => PASS.
        let agg_ok = aggregate_rounds(
            vec![make_round(1, 7.5), make_round(2, 7.9), make_round(3, 8.05)],
            200,
            8.0,
            8.0,
        );
        assert_eq!(agg_ok.verdict, "PASS");
        assert!(agg_ok.pass);
        assert!((agg_ok.min_round_wire_mbps - 7.5).abs() < 1e-6);
        assert!((agg_ok.max_round_wire_mbps - 8.05).abs() < 1e-6);
    }
}
