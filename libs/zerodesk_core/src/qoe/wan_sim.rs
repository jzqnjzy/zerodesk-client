// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Deterministic discrete-event WAN network simulator for ZeroDesk Phase 9A QoE benchmarking.
//!
//! Guarantees 100% deterministic execution across macOS, Windows, and Linux:
//! - Zero `std::time::Instant` calls (pure monotonic virtual microsecond clock).
//! - Zero system randomness (fixed-seed SplitMix64 PRNG).
//! - Exercises real `QoeEngine`, real `RsCodec` GF(2^8) encoding/decoding,
//!   real `FecReorderBuffer` hard timeouts, real `ParameterSetInliner`, and real `ZeroBufferPacer`.

use super::{
    congestion::{CcState, FeedbackSample},
    fast_start::{PacerDecision, ParameterSetInliner, ZeroBufferPacer},
    fec::{
        choose_fec_slice_size, compute_fec_wait_ms, FecGroupOutcome, FecReorderBuffer, RsCodec,
        FEC_MAX_DATA_SHARDS,
    },
    QoeConfig, QoeEngine,
};
use crate::session::video::VideoCodec;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BinaryHeap, VecDeque},
};

const MTU_PAYLOAD_BYTES: usize = 1_200;
const ENCODE_DELAY_MS: u64 = 8;
const DECODE_DELAY_MS: u64 = 6;
const FREEZE_GAP_THRESHOLD_MS: u64 = 500;
const FNV1A_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV1A_PRIME: u64 = 0x100000001b3;

/// Deterministic fixed-seed SplitMix64 PRNG (zero OS entropy dependence).
#[derive(Debug, Clone)]
struct DetRng {
    state: u64,
}

impl DetRng {
    fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_f64(&mut self) -> f64 {
        // Use top 53 bits for uniform [0.0, 1.0) IEEE-754 double.
        let bits = self.next_u64() >> 11;
        (bits as f64) * (1.0 / ((1u64 << 53) as f64))
    }
}

/// Packet loss channel model.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum LossModel {
    None,
    Random {
        loss_rate: f64,
    },
    /// Two-state Markov Gilbert-Elliott burst loss channel.
    GilbertElliott {
        p_good_to_bad: f64,
        p_bad_to_good: f64,
        loss_in_good: f64,
        loss_in_bad: f64,
    },
}

#[derive(Debug, Clone)]
struct LossChannelState {
    model: LossModel,
    in_bad_state: bool,
}

impl LossChannelState {
    fn new(model: LossModel) -> Self {
        Self {
            model,
            in_bad_state: false,
        }
    }

    fn should_drop(&mut self, rng: &mut DetRng) -> bool {
        match self.model {
            LossModel::None => false,
            LossModel::Random { loss_rate } => rng.next_f64() < loss_rate.clamp(0.0, 1.0),
            LossModel::GilbertElliott {
                p_good_to_bad,
                p_bad_to_good,
                loss_in_good,
                loss_in_bad,
            } => {
                let u = rng.next_f64();
                if self.in_bad_state {
                    if u < p_bad_to_good.clamp(0.0, 1.0) {
                        self.in_bad_state = false;
                    }
                } else if u < p_good_to_bad.clamp(0.0, 1.0) {
                    self.in_bad_state = true;
                }
                let p = if self.in_bad_state {
                    loss_in_bad
                } else {
                    loss_in_good
                };
                rng.next_f64() < p.clamp(0.0, 1.0)
            }
        }
    }
}

/// Piecewise-constant bottleneck bandwidth change point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BandwidthStep {
    pub at_ms: u64,
    pub bandwidth_kbps: u32,
}

/// Full deterministic WAN simulation scenario definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WanScenario {
    pub name: String,
    pub seed: u64,
    pub duration_ms: u64,
    /// Measurement steady-state window start (ms), allowing FastStart & FEC debounce warmup.
    pub steady_measure_start_ms: u64,
    pub base_rtt_ms: f64,
    pub jitter_ms: f64,
    pub max_queue_delay_ms: f64,
    pub loss_model: LossModel,
    pub bandwidth_schedule: Vec<BandwidthStep>,
    /// Optional bandwidth step-down timestamp & target kbps for convergence gate tracking.
    pub step_down_check: Option<(u64, u32)>,
    pub qoe_config: QoeConfig,
}

impl WanScenario {
    /// Returns bottleneck capacity (kbps) active at `now_ms`.
    pub fn bandwidth_at(&self, now_ms: u64) -> u32 {
        let mut active = self
            .bandwidth_schedule
            .first()
            .map_or(10_000, |s| s.bandwidth_kbps);
        for step in &self.bandwidth_schedule {
            if step.at_ms <= now_ms {
                active = step.bandwidth_kbps;
            }
        }
        active.max(300)
    }
}

/// Quantified benchmark report returned by `WanSimulator::run`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WanBenchMetrics {
    pub scenario_name: String,
    pub seed: u64,
    pub ttff_ms: u64,
    pub glass_to_glass_p50_ms: f64,
    pub glass_to_glass_p95_ms: f64,
    pub frames_sent_steady: u64,
    pub frames_completed_steady: u64,
    pub frame_recovery_rate: f64,
    pub fec_recovered_packets: u64,
    pub fec_extra_delay_p50_ms: f64,
    pub fec_extra_delay_p95_ms: f64,
    pub fec_extra_delay_max_ms: u64,
    pub max_queue_delay_ms: f64,
    pub p95_queue_delay_ms: f64,
    /// Ground-truth steady-state per-packet bottleneck queue wait P95 (ms).
    pub steady_gt_queue_p95_ms: f64,
    /// Ground-truth steady-state per-packet bottleneck queue wait max (ms).
    pub steady_gt_queue_max_ms: f64,
    /// Ground-truth overall per-packet bottleneck queue wait max (ms).
    pub overall_gt_queue_max_ms: f64,
    pub step_down_converge_ms: Option<u64>,
    pub post_step_down_bitrate_kbps: Option<u32>,
    pub freeze_events: u64,
    pub decoder_errors: u64,
    pub steady_duration_ms: u64,
    pub steady_bitrate_changes: u64,
    pub steady_changes_per_sec: f64,
    pub max_consecutive_flips: u32,
    pub cc_transitions: usize,
    pub final_bitrate_kbps: u32,
    pub trajectory_hash: u64,
}

#[derive(Debug, Clone)]
enum SimEventKind {
    /// Sender generates and transmits the next video frame.
    SendFrame,
    /// A media or FEC parity packet arrives at the receiver.
    PacketArrive {
        frame_id: u64,
        capture_ms: u64,
        is_idr: bool,
        frame_group_count: usize,
        frame_group_idx: usize,
        group_id: u64,
        k: usize,
        m: usize,
        is_parity: bool,
        shard_index: usize,
        send_ms: f64,
        queue_wait_ms: f64,
        seq_no: u64,
        payload: Vec<u8>,
    },
    /// Receiver polls expired FEC groups and emits periodic feedback to sender.
    ReceiverTick,
    /// Receiver feedback arrives at sender.
    FeedbackArrive { sample: FeedbackSample },
}

#[derive(Debug, Clone)]
struct SimEvent {
    at_us: u64,
    order: u64,
    kind: SimEventKind,
}

impl PartialEq for SimEvent {
    fn eq(&self, other: &Self) -> bool {
        self.at_us == other.at_us && self.order == other.order
    }
}

impl Eq for SimEvent {}

impl PartialOrd for SimEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SimEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        // Min-heap: smallest `at_us`, then smallest `order` pops first.
        other
            .at_us
            .cmp(&self.at_us)
            .then_with(|| other.order.cmp(&self.order))
    }
}

#[derive(Debug, Clone)]
struct SentFrameTruth {
    original_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct RxFrameAssembly {
    capture_ms: u64,
    is_idr: bool,
    group_count: usize,
    completed_groups: BTreeMap<usize, Vec<Vec<u8>>>,
    failed: bool,
}

#[derive(Debug, Clone, Copy)]
struct BottleneckTx {
    arrival_us: Option<u64>,
    queue_wait_ms: f64,
}

fn clamp_prob(v: f64) -> f64 {
    if v.is_finite() {
        v.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

fn validate_and_normalize_scenario(raw: &WanScenario) -> WanScenario {
    let mut sc = raw.clone();
    sc.duration_ms = sc.duration_ms.max(1);
    sc.base_rtt_ms = if sc.base_rtt_ms.is_finite() && sc.base_rtt_ms >= 0.0 {
        sc.base_rtt_ms.min(10_000.0)
    } else {
        40.0
    };
    sc.jitter_ms = if sc.jitter_ms.is_finite() && sc.jitter_ms >= 0.0 {
        sc.jitter_ms.min(5_000.0)
    } else {
        0.0
    };
    sc.max_queue_delay_ms = if sc.max_queue_delay_ms.is_finite() && sc.max_queue_delay_ms > 0.0 {
        sc.max_queue_delay_ms.min(60_000.0)
    } else {
        400.0
    };
    sc.loss_model = match sc.loss_model {
        LossModel::None => LossModel::None,
        LossModel::Random { loss_rate } => LossModel::Random {
            loss_rate: clamp_prob(loss_rate),
        },
        LossModel::GilbertElliott {
            p_good_to_bad,
            p_bad_to_good,
            loss_in_good,
            loss_in_bad,
        } => LossModel::GilbertElliott {
            p_good_to_bad: clamp_prob(p_good_to_bad),
            p_bad_to_good: clamp_prob(p_bad_to_good),
            loss_in_good: clamp_prob(loss_in_good),
            loss_in_bad: clamp_prob(loss_in_bad),
        },
    };
    if sc.bandwidth_schedule.is_empty() {
        sc.bandwidth_schedule.push(BandwidthStep {
            at_ms: 0,
            bandwidth_kbps: 10_000,
        });
    } else {
        sc.bandwidth_schedule.sort_by_key(|s| s.at_ms);
        for step in &mut sc.bandwidth_schedule {
            step.bandwidth_kbps = step.bandwidth_kbps.max(300);
        }
    }
    sc
}

/// Deterministic discrete-event WAN simulator.
pub struct WanSimulator;

impl WanSimulator {
    /// Executes a complete deterministic simulation for `scenario` and returns exact metrics.
    pub fn run(raw_scenario: &WanScenario) -> WanBenchMetrics {
        let scenario = &validate_and_normalize_scenario(raw_scenario);
        let mut rng = DetRng::new(scenario.seed);
        let mut loss_channel = LossChannelState::new(scenario.loss_model);
        let mut qoe = QoeEngine::new(scenario.qoe_config);
        let mut reorder = FecReorderBuffer::new();
        let mut pacer = ZeroBufferPacer::new();

        // Session connects at t = 0ms; FastStart pre-triggers immediate IDR at 1500 kbps.
        pacer.on_session_connected(0);
        let mut current_target = qoe.on_session_connected(0);
        let mut pending_force_idr = current_target.force_idr;

        // First frame begins capture after a compact connection setup (~1 RTT handshake + zero-wait IDR).
        let base_rtt_u64 = scenario.base_rtt_ms.round().clamp(0.0, 10_000.0) as u64;
        let connect_setup_ms = base_rtt_u64.min(scenario.duration_ms);
        let one_way_prop_ms_u64 = (scenario.base_rtt_ms * 0.5).round().clamp(0.0, 10_000.0) as u64;
        let max_jitter_u64 = scenario.jitter_ms.ceil().clamp(0.0, 5_000.0) as u64;

        let mut heap: BinaryHeap<SimEvent> = BinaryHeap::new();
        let mut next_event_order = 0u64;
        let mut push_event = |heap: &mut BinaryHeap<SimEvent>, at_us: u64, kind: SimEventKind| {
            next_event_order = next_event_order.saturating_add(1);
            heap.push(SimEvent {
                at_us,
                order: next_event_order,
                kind,
            });
        };

        let feedback_interval_ms = ((scenario.base_rtt_ms * 0.5).round() as u64).clamp(40, 80);
        push_event(
            &mut heap,
            connect_setup_ms.saturating_mul(1_000),
            SimEventKind::SendFrame,
        );
        push_event(
            &mut heap,
            connect_setup_ms
                .saturating_add(feedback_interval_ms)
                .saturating_mul(1_000),
            SimEventKind::ReceiverTick,
        );

        // Bottleneck FIFO serialization clock (in virtual milliseconds).
        let mut queue_drain_until_ms = 0.0f64;

        // Sender state
        let mut next_frame_id = 0u64;
        let mut next_group_id = 1u64;
        let mut next_pkt_seq = 1u64;
        let mut sent_frames: BTreeMap<u64, SentFrameTruth> = BTreeMap::new();
        let mut sent_pkts_due: VecDeque<(u64, u64)> = VecDeque::new();
        let mut overdue_max_seq = 0u64;
        let mut frames_sent_steady = 0u64;

        // Ground-truth bottleneck queue delay tracking (independent of CC self-estimate)
        let mut steady_gt_queue_samples: Vec<f64> = Vec::new();
        let mut steady_gt_queue_max_ms = 0.0f64;
        let mut overall_gt_queue_max_ms = 0.0f64;

        // Receiver assembly & telemetry state (BTreeMap for deterministic oldest-first pruning)
        let mut rx_frames: BTreeMap<u64, RxFrameAssembly> = BTreeMap::new();
        let mut group_to_frame: BTreeMap<u64, (u64, usize)> = BTreeMap::new();
        let mut frames_completed_steady = 0u64;
        let mut glass_to_glass_samples: Vec<f64> = Vec::new();
        let mut last_display_ms: Option<u64> = None;
        let mut freeze_events = 0u64;
        let mut decoder_errors = 0u64;

        // Receiver feedback window accumulators
        let mut win_start_ms: Option<f64> = None;
        let mut win_last_recv_ms: Option<f64> = None;
        let mut win_first_send_ms: Option<f64> = None;
        let mut win_last_send_ms: Option<f64> = None;
        let mut win_pkts_recv = 0u32;
        let mut win_bytes_recv = 0u64;
        let mut win_queue_sum = 0.0f64;
        let mut win_queue_count = 0u32;
        let mut highest_seq_seen = 0u64;
        let mut prev_highest_seq = 0u64;
        let mut rx_jitter_ewma = 0.0f64;
        let mut last_transit_ms: Option<f64> = None;

        // Sender-side audit metrics
        let mut queue_delay_samples: Vec<f64> = Vec::new();
        let mut max_queue_delay_ms = 0.0f64;
        let mut trajectory_hash = FNV1A_OFFSET_BASIS;

        // Steady-state oscillation & rate-change tracking
        let mut steady_enter_ms: Option<u64> = None;
        let mut steady_duration_ms = 0u64;
        let mut steady_bitrate_changes = 0u64;
        let mut last_steady_bitrate = current_target.total_bitrate_kbps;
        let mut last_steady_dir: Option<i8> = None;
        let mut cur_consecutive_flips = 0u32;
        let mut max_consecutive_flips = 0u32;

        // Bandwidth step-down convergence tracking
        let mut step_down_converge_ms: Option<u64> = None;
        let mut post_step_down_bitrate_kbps: Option<u32> = None;
        let mut in_band_since_ms: Option<u64> = None;

        let duration_us = scenario.duration_ms.saturating_mul(1_000);

        while let Some(ev) = heap.pop() {
            if ev.at_us > duration_us {
                break;
            }
            let now_ms = ev.at_us / 1_000;

            match ev.kind {
                SimEventKind::SendFrame => {
                    let frame_id = next_frame_id;
                    next_frame_id = next_frame_id.saturating_add(1);

                    // Advance FastStart watchdog in case feedback is delayed/blacked out.
                    let tick_dir = qoe.on_fast_start_tick(now_ms);
                    pending_force_idr |= tick_dir.force_idr;

                    let fps = current_target.fps_cap.max(5);
                    let frame_interval_ms = (1_000u64 / u64::from(fps)).max(16);
                    let is_idr = frame_id == 0 || pending_force_idr || frame_id.is_multiple_of(120);
                    pending_force_idr = false;

                    // Compute realistic frame payload size from current media bitrate target
                    // (200-byte floor is physically consistent with 300 kbps minimum protection).
                    let avg_p_bytes = ((u64::from(current_target.media_bitrate_kbps)
                        .saturating_mul(1_000))
                        / 8
                        / u64::from(fps))
                    .max(200) as usize;
                    let jitter_scale = 0.94 + 0.12 * rng.next_f64();
                    let raw_target_bytes = if is_idr {
                        if frame_id == 0 {
                            // FastStart initial IDR stays compact (~1.3x P-frame at 1500 kbps).
                            ((avg_p_bytes as f64) * 1.3).round() as usize
                        } else {
                            ((avg_p_bytes as f64) * 1.8).round() as usize
                        }
                    } else {
                        ((avg_p_bytes as f64) * jitter_scale).round() as usize
                    };

                    // Construct synthetic Annex-B H.264 bitstream and run real ParameterSetInliner.
                    let raw_annex_b = synthesize_annex_b_h264(frame_id, is_idr, raw_target_bytes);
                    let (inlined, fs_dir) =
                        qoe.on_frame_encoded(VideoCodec::H264, &raw_annex_b, is_idr);
                    pending_force_idr |= fs_dir.force_idr;
                    let frame_bytes = inlined.data;

                    // Split frame into FEC-aware MTU slices (only splits to 9 slices when
                    // effective redundancy >= 12%, so low-loss bands never over-split).
                    let slice_size = choose_fec_slice_size(
                        frame_bytes.len(),
                        qoe.fec().effective_redundancy_ratio(),
                        MTU_PAYLOAD_BYTES,
                    );
                    let slices: Vec<&[u8]> = frame_bytes.chunks(slice_size).collect();
                    let num_groups = slices.len().div_ceil(FEC_MAX_DATA_SHARDS).max(1);
                    let balanced_chunk_size = slices.len().div_ceil(num_groups).max(1);
                    let group_chunks: Vec<&[&[u8]]> = slices.chunks(balanced_chunk_size).collect();
                    let group_count = group_chunks.len();

                    if now_ms >= scenario.steady_measure_start_ms
                        && now_ms
                            .saturating_add(base_rtt_u64.saturating_add(150))
                            <= scenario.duration_ms
                    {
                        frames_sent_steady = frames_sent_steady.saturating_add(1);
                    }

                    sent_frames.insert(
                        frame_id,
                        SentFrameTruth {
                            original_bytes: frame_bytes.clone(),
                        },
                    );
                    // Prune very old ground-truth records.
                    while sent_frames.len() > 256 {
                        if let Some((&oldest_fid, _)) = sent_frames.iter().next() {
                            sent_frames.remove(&oldest_fid);
                        } else {
                            break;
                        }
                    }

                    // Atomically plan RS parity counts for each group before pacing/sending so
                    // wire-byte <= 25% accounting (including 2*k length tables) is exact.
                    let mut planned_groups = Vec::with_capacity(group_chunks.len());
                    let mut total_packets_planned = 0usize;
                    for data_chunk in &group_chunks {
                        let k = data_chunk.len();
                        let media_bytes: u64 = data_chunk.iter().map(|s| s.len() as u64).sum();
                        let max_shard_len: usize =
                            data_chunk.iter().map(|s| s.len()).max().unwrap_or(0);
                        let m = qoe.plan_fec_group(k, media_bytes, max_shard_len);
                        let parities = if m > 0 {
                            RsCodec::encode(data_chunk, m).unwrap_or_default()
                        } else {
                            Vec::new()
                        };
                        total_packets_planned =
                            total_packets_planned.saturating_add(k.saturating_add(parities.len()));
                        planned_groups.push((data_chunk, parities));
                    }

                    let pace_span_ms = (frame_interval_ms as f64 * 0.25).clamp(2.0, 8.0);
                    let pkt_spacing_ms = if total_packets_planned > 1 {
                        pace_span_ms / ((total_packets_planned - 1) as f64)
                    } else {
                        0.0
                    };
                    let encode_done_ms = now_ms.saturating_add(ENCODE_DELAY_MS) as f64;
                    let mut pkt_cursor = 0usize;

                    for (g_idx, (data_chunk, parities)) in planned_groups.into_iter().enumerate() {
                        let k = data_chunk.len();
                        let actual_m = parities.len();
                        let group_id = next_group_id;
                        next_group_id = next_group_id.saturating_add(1);

                        // Transmit k data shards followed immediately by m parity shards.
                        for (shard_idx, slice) in data_chunk.iter().enumerate() {
                            let send_ms = encode_done_ms + (pkt_cursor as f64) * pkt_spacing_ms;
                            pkt_cursor += 1;
                            let seq_no = next_pkt_seq;
                            next_pkt_seq = next_pkt_seq.saturating_add(1);
                            let tx = transmit_over_bottleneck(
                                scenario,
                                send_ms,
                                slice.len(),
                                &mut queue_drain_until_ms,
                                &mut loss_channel,
                                &mut rng,
                            );
                            let due_ms = (send_ms.ceil().max(0.0) as u64)
                                .saturating_add(one_way_prop_ms_u64)
                                .saturating_add(max_jitter_u64)
                                .saturating_add(5);
                            sent_pkts_due.push_back((due_ms, seq_no));
                            if tx.queue_wait_ms > overall_gt_queue_max_ms {
                                overall_gt_queue_max_ms = tx.queue_wait_ms;
                            }
                            if (send_ms as u64) >= scenario.steady_measure_start_ms {
                                steady_gt_queue_samples.push(tx.queue_wait_ms);
                                if tx.queue_wait_ms > steady_gt_queue_max_ms {
                                    steady_gt_queue_max_ms = tx.queue_wait_ms;
                                }
                            }
                            if let Some(arr_us) = tx.arrival_us {
                                push_event(
                                    &mut heap,
                                    arr_us,
                                    SimEventKind::PacketArrive {
                                        frame_id,
                                        capture_ms: now_ms,
                                        is_idr,
                                        frame_group_count: group_count,
                                        frame_group_idx: g_idx,
                                        group_id,
                                        k,
                                        m: actual_m,
                                        is_parity: false,
                                        shard_index: shard_idx,
                                        send_ms,
                                        queue_wait_ms: tx.queue_wait_ms,
                                        seq_no,
                                        payload: (*slice).to_vec(),
                                    },
                                );
                            }
                        }

                        for (p_idx, parity) in parities.into_iter().enumerate() {
                            let send_ms = encode_done_ms + (pkt_cursor as f64) * pkt_spacing_ms;
                            pkt_cursor += 1;
                            let seq_no = next_pkt_seq;
                            next_pkt_seq = next_pkt_seq.saturating_add(1);
                            let tx = transmit_over_bottleneck(
                                scenario,
                                send_ms,
                                parity.len(),
                                &mut queue_drain_until_ms,
                                &mut loss_channel,
                                &mut rng,
                            );
                            let due_ms = (send_ms.ceil().max(0.0) as u64)
                                .saturating_add(one_way_prop_ms_u64)
                                .saturating_add(max_jitter_u64)
                                .saturating_add(5);
                            sent_pkts_due.push_back((due_ms, seq_no));
                            if tx.queue_wait_ms > overall_gt_queue_max_ms {
                                overall_gt_queue_max_ms = tx.queue_wait_ms;
                            }
                            if (send_ms as u64) >= scenario.steady_measure_start_ms {
                                steady_gt_queue_samples.push(tx.queue_wait_ms);
                                if tx.queue_wait_ms > steady_gt_queue_max_ms {
                                    steady_gt_queue_max_ms = tx.queue_wait_ms;
                                }
                            }
                            if let Some(arr_us) = tx.arrival_us {
                                push_event(
                                    &mut heap,
                                    arr_us,
                                    SimEventKind::PacketArrive {
                                        frame_id,
                                        capture_ms: now_ms,
                                        is_idr,
                                        frame_group_count: group_count,
                                        frame_group_idx: g_idx,
                                        group_id,
                                        k,
                                        m: actual_m,
                                        is_parity: true,
                                        shard_index: p_idx,
                                        send_ms,
                                        queue_wait_ms: tx.queue_wait_ms,
                                        seq_no,
                                        payload: parity,
                                    },
                                );
                            }
                        }
                    }

                    // Schedule next frame generation according to current fps_cap.
                    let next_frame_us = ev
                        .at_us
                        .saturating_add(frame_interval_ms.saturating_mul(1_000));
                    if next_frame_us <= duration_us {
                        push_event(&mut heap, next_frame_us, SimEventKind::SendFrame);
                    }
                }

                SimEventKind::PacketArrive {
                    frame_id,
                    capture_ms,
                    is_idr,
                    frame_group_count,
                    frame_group_idx,
                    group_id,
                    k,
                    m,
                    is_parity,
                    shard_index,
                    send_ms,
                    queue_wait_ms,
                    seq_no,
                    payload,
                } => {
                    let arr_ms_f = (ev.at_us as f64) / 1_000.0;

                    // Update receiver feedback window stats.
                    if win_start_ms.is_none() {
                        win_start_ms = Some(arr_ms_f);
                        win_first_send_ms = Some(send_ms);
                    }
                    win_last_recv_ms = Some(arr_ms_f);
                    win_last_send_ms = Some(send_ms);
                    win_pkts_recv = win_pkts_recv.saturating_add(1);
                    win_bytes_recv = win_bytes_recv.saturating_add(payload.len() as u64);
                    win_queue_sum += queue_wait_ms;
                    win_queue_count = win_queue_count.saturating_add(1);
                    if seq_no > highest_seq_seen {
                        highest_seq_seen = seq_no;
                    }
                    let transit = arr_ms_f - send_ms;
                    if let Some(prev_t) = last_transit_ms {
                        let d = (transit - prev_t).abs();
                        // Track peak-aware jitter so fec_wait_ms covers the full jitter spread.
                        rx_jitter_ewma = if d > rx_jitter_ewma {
                            0.5 * rx_jitter_ewma + 0.5 * d
                        } else {
                            0.92 * rx_jitter_ewma + 0.08 * d
                        };
                    }
                    last_transit_ms = Some(transit);

                    // Track frame assembly & push into real FecReorderBuffer.
                    group_to_frame.insert(group_id, (frame_id, frame_group_idx));
                    rx_frames.entry(frame_id).or_insert_with(|| RxFrameAssembly {
                        capture_ms,
                        is_idr,
                        group_count: frame_group_count,
                        completed_groups: BTreeMap::new(),
                        failed: false,
                    });

                    let push_res = reorder.push_shard(
                        group_id,
                        k,
                        m,
                        is_parity,
                        shard_index,
                        payload,
                        now_ms,
                        rx_jitter_ewma,
                        current_target.fps_cap,
                    );

                    match push_res {
                        Ok(Some(
                            FecGroupOutcome::CompleteDirect {
                                group_id: gid,
                                data_shards,
                                ..
                            }
                            | FecGroupOutcome::RecoveredViaFec {
                                group_id: gid,
                                data_shards,
                                ..
                            },
                        )) => {
                            if let Some((fid, g_idx)) = group_to_frame.remove(&gid) {
                                if let Some(asm) = rx_frames.get_mut(&fid) {
                                    asm.completed_groups.insert(g_idx, data_shards);
                                    if !asm.failed && asm.completed_groups.len() == asm.group_count
                                    {
                                        if let Some(done) = rx_frames.remove(&fid) {
                                            finalize_received_frame(
                                                fid,
                                                done,
                                                now_ms,
                                                scenario,
                                                &sent_frames,
                                                &mut pacer,
                                                &mut frames_completed_steady,
                                                &mut glass_to_glass_samples,
                                                &mut last_display_ms,
                                                &mut freeze_events,
                                                &mut decoder_errors,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        Ok(Some(FecGroupOutcome::TimedOutNeedsNack { group_id: gid, .. })) => {
                            if let Some((fid, _)) = group_to_frame.remove(&gid) {
                                if let Some(asm) = rx_frames.get_mut(&fid) {
                                    asm.failed = true;
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(_) => {
                            decoder_errors = decoder_errors.saturating_add(1);
                        }
                    }

                    // Drain any eviction or corrupted-group NACK outcomes queued by push_shard.
                    for pending in reorder.drain_pending_outcomes() {
                        if let FecGroupOutcome::TimedOutNeedsNack { group_id: gid, .. } = pending {
                            if let Some((fid, _)) = group_to_frame.remove(&gid) {
                                if let Some(asm) = rx_frames.get_mut(&fid) {
                                    asm.failed = true;
                                }
                            }
                        }
                    }
                }

                SimEventKind::ReceiverTick => {
                    // 1. Expire any FEC groups past hard fec_wait_ms deadline.
                    for expired in reorder.poll_expired(now_ms) {
                        if let FecGroupOutcome::TimedOutNeedsNack { group_id: gid, .. } = expired {
                            if let Some((fid, _)) = group_to_frame.remove(&gid) {
                                if let Some(asm) = rx_frames.get_mut(&fid) {
                                    asm.failed = true;
                                }
                            }
                        }
                    }

                    // Prune old incomplete frames deterministically (oldest frame_id first via BTreeMap).
                    while rx_frames.len() > 128 {
                        if let Some((&oldest_fid, _)) = rx_frames.iter().next() {
                            rx_frames.remove(&oldest_fid);
                        } else {
                            break;
                        }
                    }

                    // Advance overdue sent-packet frontier for blackout / zero-arrival loss detection.
                    while let Some(&(due_ms, seq)) = sent_pkts_due.front() {
                        if due_ms <= now_ms {
                            overdue_max_seq = overdue_max_seq.max(seq);
                            sent_pkts_due.pop_front();
                        } else {
                            break;
                        }
                    }

                    // 2. Emit feedback sample (including zero-arrival timeout feedback during
                    // total blackout / heavy drop windows so CC is never blind).
                    let jb_ms = compute_fec_wait_ms(rx_jitter_ewma, current_target.fps_cap);
                    let fb_arrive_ms = now_ms.saturating_add(one_way_prop_ms_u64);
                    if win_pkts_recv > 0 {
                        let expected_in_win =
                            highest_seq_seen.saturating_sub(prev_highest_seq) as u32;
                        let lost_in_win = expected_in_win.saturating_sub(win_pkts_recv);
                        prev_highest_seq = prev_highest_seq.max(highest_seq_seen);

                        let avg_q = if win_queue_count > 0 {
                            win_queue_sum / (win_queue_count as f64)
                        } else {
                            0.0
                        };
                        let measured_rtt = scenario.base_rtt_ms + avg_q;
                        let delay_delta_ms = match (
                            win_start_ms,
                            win_last_recv_ms,
                            win_first_send_ms,
                            win_last_send_ms,
                        ) {
                            (Some(r0), Some(r1), Some(s0), Some(s1)) if r1 > r0 => {
                                (r1 - r0) - (s1 - s0)
                            }
                            _ => 0.0,
                        };
                        let delivery_rate_kbps = match (win_start_ms, win_last_recv_ms) {
                            (Some(r0), Some(r1)) if (r1 - r0) >= 8.0 && win_pkts_recv >= 3 => {
                                Some((win_bytes_recv as f64 * 8.0) / (r1 - r0))
                            }
                            _ => None,
                        };

                        let sample = FeedbackSample {
                            now_ms: fb_arrive_ms,
                            rtt_ms: measured_rtt,
                            delay_delta_ms,
                            packets_received: win_pkts_recv,
                            packets_lost: lost_in_win,
                            jitter_ms: rx_jitter_ewma,
                            jitter_buffer_ms: jb_ms as f64,
                            delivery_rate_kbps,
                        };
                        push_event(
                            &mut heap,
                            fb_arrive_ms.saturating_mul(1_000),
                            SimEventKind::FeedbackArrive { sample },
                        );

                        win_start_ms = None;
                        win_last_recv_ms = None;
                        win_first_send_ms = None;
                        win_last_send_ms = None;
                        win_pkts_recv = 0;
                        win_bytes_recv = 0;
                        win_queue_sum = 0.0;
                        win_queue_count = 0;
                    } else if overdue_max_seq > prev_highest_seq {
                        let inferred_lost = overdue_max_seq
                            .saturating_sub(prev_highest_seq)
                            .min(u64::from(u32::MAX)) as u32;
                        prev_highest_seq = overdue_max_seq;
                        // Emit zero-arrival timeout feedback with rtt_ms = 0.0 (never poisons min_rtt)
                        // and inferred packet loss so CC/FEC react promptly during total blackouts.
                        let sample = FeedbackSample {
                            now_ms: fb_arrive_ms,
                            rtt_ms: 0.0,
                            delay_delta_ms: 0.0,
                            packets_received: 0,
                            packets_lost: inferred_lost,
                            jitter_ms: rx_jitter_ewma,
                            jitter_buffer_ms: jb_ms as f64,
                            delivery_rate_kbps: Some(0.0),
                        };
                        push_event(
                            &mut heap,
                            fb_arrive_ms.saturating_mul(1_000),
                            SimEventKind::FeedbackArrive { sample },
                        );
                    }

                    let next_tick_us = ev
                        .at_us
                        .saturating_add(feedback_interval_ms.saturating_mul(1_000));
                    if next_tick_us <= duration_us {
                        push_event(&mut heap, next_tick_us, SimEventKind::ReceiverTick);
                    }
                }

                SimEventKind::FeedbackArrive { sample } => {
                    let prev_state = qoe.congestion().state();
                    let next_target = qoe.on_feedback(sample);
                    let new_state = qoe.congestion().state();

                    // Track queuing delay after initial FastStart warmup.
                    if now_ms >= scenario.steady_measure_start_ms {
                        let qd = qoe.congestion().queue_delay_ms();
                        queue_delay_samples.push(qd);
                        if qd > max_queue_delay_ms {
                            max_queue_delay_ms = qd;
                        }
                    }

                    // Track Steady-state duration, bitrate change frequency, and consecutive flips.
                    if prev_state != CcState::Steady && new_state == CcState::Steady {
                        steady_enter_ms = Some(now_ms);
                        last_steady_bitrate = next_target.total_bitrate_kbps;
                    } else if prev_state == CcState::Steady && new_state != CcState::Steady {
                        if let Some(entered) = steady_enter_ms.take() {
                            steady_duration_ms =
                                steady_duration_ms.saturating_add(now_ms.saturating_sub(entered));
                        }
                    } else if new_state == CcState::Steady
                        && next_target.total_bitrate_kbps != last_steady_bitrate
                    {
                        steady_bitrate_changes = steady_bitrate_changes.saturating_add(1);
                        let dir: i8 = if next_target.total_bitrate_kbps > last_steady_bitrate {
                            1
                        } else {
                            -1
                        };
                        if let Some(prev_d) = last_steady_dir {
                            if prev_d != dir {
                                cur_consecutive_flips = cur_consecutive_flips.saturating_add(1);
                                if cur_consecutive_flips > max_consecutive_flips {
                                    max_consecutive_flips = cur_consecutive_flips;
                                }
                            } else {
                                cur_consecutive_flips = 0;
                            }
                        }
                        last_steady_dir = Some(dir);
                        last_steady_bitrate = next_target.total_bitrate_kbps;
                    }

                    // Track bandwidth step-down convergence to target ± 15%.
                    if let Some((step_at_ms, target_kbps)) = scenario.step_down_check {
                        if now_ms >= step_at_ms {
                            let lo = ((target_kbps as f64) * 0.85).floor() as u32;
                            let hi = ((target_kbps as f64) * 1.15).ceil() as u32;
                            let cur = next_target.total_bitrate_kbps;
                            if cur >= lo && cur <= hi {
                                let since = *in_band_since_ms.get_or_insert(now_ms);
                                if step_down_converge_ms.is_none()
                                    && now_ms.saturating_sub(since) >= 150
                                {
                                    step_down_converge_ms =
                                        Some(since.saturating_sub(step_at_ms));
                                    post_step_down_bitrate_kbps = Some(cur);
                                }
                            } else if step_down_converge_ms.is_none() {
                                in_band_since_ms = None;
                            }
                        }
                    }

                    // Update deterministic FNV-1a trajectory hash.
                    trajectory_hash = fnv1a_step(trajectory_hash, now_ms);
                    trajectory_hash = fnv1a_step(trajectory_hash, new_state as u64);
                    trajectory_hash =
                        fnv1a_step(trajectory_hash, u64::from(next_target.total_bitrate_kbps));
                    trajectory_hash =
                        fnv1a_step(trajectory_hash, u64::from(next_target.media_bitrate_kbps));
                    trajectory_hash =
                        fnv1a_step(trajectory_hash, u64::from(next_target.fec_budget_kbps));
                    trajectory_hash = fnv1a_step(trajectory_hash, u64::from(next_target.width));
                    trajectory_hash = fnv1a_step(trajectory_hash, u64::from(next_target.height));
                    trajectory_hash = fnv1a_step(trajectory_hash, u64::from(next_target.fps_cap));

                    if next_target.force_idr {
                        pending_force_idr = true;
                    }
                    current_target = next_target;
                }
            }
        }

        // Flush remaining Steady-state dwell if simulation ended in Steady.
        if let Some(entered) = steady_enter_ms {
            steady_duration_ms =
                steady_duration_ms.saturating_add(scenario.duration_ms.saturating_sub(entered));
        }

        let fec_stats = reorder.stats();
        let fec_delay_f64: Vec<f64> = fec_stats
            .fec_extra_delay_ms_samples
            .iter()
            .map(|&v| v as f64)
            .collect();
        let fec_extra_delay_max_ms = fec_stats
            .fec_extra_delay_ms_samples
            .iter()
            .copied()
            .max()
            .unwrap_or(0);

        let frame_recovery_rate = if frames_sent_steady > 0 {
            (frames_completed_steady as f64) / (frames_sent_steady as f64)
        } else {
            1.0
        };
        let steady_changes_per_sec = if steady_duration_ms > 0 {
            (steady_bitrate_changes as f64) / ((steady_duration_ms as f64) / 1_000.0)
        } else {
            0.0
        };

        WanBenchMetrics {
            scenario_name: scenario.name.clone(),
            seed: scenario.seed,
            ttff_ms: pacer.ttff_ms().unwrap_or(scenario.duration_ms),
            glass_to_glass_p50_ms: percentile(&glass_to_glass_samples, 0.50),
            glass_to_glass_p95_ms: percentile(&glass_to_glass_samples, 0.95),
            frames_sent_steady,
            frames_completed_steady,
            frame_recovery_rate,
            fec_recovered_packets: fec_stats.fec_recovered_packets,
            fec_extra_delay_p50_ms: percentile(&fec_delay_f64, 0.50),
            fec_extra_delay_p95_ms: percentile(&fec_delay_f64, 0.95),
            fec_extra_delay_max_ms,
            max_queue_delay_ms,
            p95_queue_delay_ms: percentile(&queue_delay_samples, 0.95),
            steady_gt_queue_p95_ms: percentile(&steady_gt_queue_samples, 0.95),
            steady_gt_queue_max_ms,
            overall_gt_queue_max_ms,
            step_down_converge_ms,
            post_step_down_bitrate_kbps,
            freeze_events,
            decoder_errors,
            steady_duration_ms,
            steady_bitrate_changes,
            steady_changes_per_sec,
            max_consecutive_flips,
            cc_transitions: qoe.congestion().transitions().len(),
            final_bitrate_kbps: current_target.total_bitrate_kbps,
            trajectory_hash,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn finalize_received_frame(
    frame_id: u64,
    assembly: RxFrameAssembly,
    now_ms: u64,
    scenario: &WanScenario,
    sent_frames: &BTreeMap<u64, SentFrameTruth>,
    pacer: &mut ZeroBufferPacer,
    frames_completed_steady: &mut u64,
    glass_to_glass_samples: &mut Vec<f64>,
    last_display_ms: &mut Option<u64>,
    freeze_events: &mut u64,
    decoder_errors: &mut u64,
) {
    let mut reassembled = Vec::new();
    for shards in assembly.completed_groups.values() {
        for shard in shards {
            reassembled.extend_from_slice(shard);
        }
    }

    // Verify exact byte-for-byte integrity against sender ground truth (real RS verification).
    if let Some(truth) = sent_frames.get(&frame_id) {
        if reassembled != truth.original_bytes {
            *decoder_errors = decoder_errors.saturating_add(1);
            return;
        }
    }

    let has_ps = if assembly.is_idr {
        let ok = ParameterSetInliner::bitstream_has_complete_param_sets(
            VideoCodec::H264,
            &reassembled,
        );
        if !ok {
            *decoder_errors = decoder_errors.saturating_add(1);
        }
        ok
    } else {
        true
    };

    let display_ms = now_ms.saturating_add(DECODE_DELAY_MS);
    match pacer.on_decoded_frame_ready(display_ms, assembly.is_idr, has_ps) {
        PacerDecision::WaitForIdr => return,
        PacerDecision::RenderImmediately { .. } | PacerDecision::RenderNormal { .. } => {}
    }

    if let Some(prev_disp) = *last_display_ms {
        if display_ms.saturating_sub(prev_disp) > FREEZE_GAP_THRESHOLD_MS {
            *freeze_events = freeze_events.saturating_add(1);
        }
    }
    *last_display_ms = Some(display_ms);

    let base_rtt_u64 = scenario.base_rtt_ms.round().clamp(0.0, 10_000.0) as u64;
    if assembly.capture_ms >= scenario.steady_measure_start_ms
        && assembly
            .capture_ms
            .saturating_add(base_rtt_u64.saturating_add(150))
            <= scenario.duration_ms
    {
        *frames_completed_steady = frames_completed_steady.saturating_add(1);
        let g2g = display_ms.saturating_sub(assembly.capture_ms) as f64;
        glass_to_glass_samples.push(g2g);
    }
}

fn transmit_over_bottleneck(
    scenario: &WanScenario,
    send_ms: f64,
    size_bytes: usize,
    queue_drain_until_ms: &mut f64,
    loss_channel: &mut LossChannelState,
    rng: &mut DetRng,
) -> BottleneckTx {
    let bw_kbps = (scenario.bandwidth_at(send_ms.max(0.0) as u64) as f64).max(1.0);
    let tx_ms = ((size_bytes as f64) * 8.0) / bw_kbps;
    let queue_wait_ms = (*queue_drain_until_ms - send_ms).max(0.0);

    // Finite bottleneck buffer tail-drop (realistic router queue limit).
    if queue_wait_ms + tx_ms > scenario.max_queue_delay_ms {
        return BottleneckTx {
            arrival_us: None,
            queue_wait_ms: queue_wait_ms.min(scenario.max_queue_delay_ms),
        };
    }

    let depart_ms = send_ms.max(*queue_drain_until_ms) + tx_ms;
    *queue_drain_until_ms = depart_ms;

    // Stochastic / Gilbert-Elliott channel loss.
    if loss_channel.should_drop(rng) {
        return BottleneckTx {
            arrival_us: None,
            queue_wait_ms,
        };
    }

    let one_way_prop_ms = scenario.base_rtt_ms * 0.5;
    let jitter = rng.next_f64() * scenario.jitter_ms.max(0.0);
    let arrival_ms = depart_ms + one_way_prop_ms + jitter;
    let arrival_us = (arrival_ms * 1_000.0).round().max(0.0) as u64;
    BottleneckTx {
        arrival_us: Some(arrival_us),
        queue_wait_ms,
    }
}

fn synthesize_annex_b_h264(frame_id: u64, is_idr: bool, target_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(target_len.max(64));
    if frame_id == 0 {
        // First IDR carries SPS (7) + PPS (8) + IDR (5) to seed ParameterSetInliner.
        out.extend_from_slice(&[0, 0, 0, 1, 0x67, 0x42, 0xE0, 0x28, 0x95, 0xA0]);
        out.extend_from_slice(&[0, 0, 0, 1, 0x68, 0xCE, 0x3C, 0x80]);
        out.extend_from_slice(&[0, 0, 0, 1, 0x65, 0x88, 0x84]);
    } else if is_idr {
        // Subsequent IDRs deliberately omit SPS/PPS so ParameterSetInliner proves auto-inlining!
        out.extend_from_slice(&[0, 0, 0, 1, 0x65, 0x88, 0x84]);
    } else {
        // P-frame slice (NAL type 1).
        out.extend_from_slice(&[0, 0, 0, 1, 0x41, 0x9A, 0x02]);
    }
    let seed_byte = ((frame_id.wrapping_mul(37)) & 0xFF) as u8;
    while out.len() < target_len {
        let idx = out.len();
        out.push(seed_byte.wrapping_add((idx as u8).wrapping_mul(13)));
    }
    out
}

fn fnv1a_step(mut hash: u64, value: u64) -> u64 {
    for b in value.to_le_bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(FNV1A_PRIME);
    }
    hash
}

/// Computes an interpolated percentile (`p` in `0.0..=1.0`) over a slice of finite samples.
pub fn percentile(samples: &[f64], p: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut sorted: Vec<f64> = samples.iter().copied().filter(|v| v.is_finite()).collect();
    if sorted.is_empty() {
        return 0.0;
    }
    sorted.sort_by(|a, b| a.total_cmp(b));
    let p_clamped = p.clamp(0.0, 1.0);
    let idx = ((sorted.len() - 1) as f64) * p_clamped;
    let lo = idx.floor() as usize;
    let hi = idx.ceil() as usize;
    if lo == hi {
        sorted[lo]
    } else {
        let w = idx - (lo as f64);
        sorted[lo] * (1.0 - w) + sorted[hi] * w
    }
}
