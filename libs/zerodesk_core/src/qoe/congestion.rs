// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Dual-signal GCC-like adaptive congestion controller and encoder target selector.
//!
//! Signals:
//! 1. Primary 1: Inter-arrival delay gradient (OLS trendline slope + queuing delay delta),
//!    prioritized strictly ahead of packet loss to suppress bufferbloat proactively.
//! 2. Primary 2: Measured packet loss rate (windowed count + EWMA).
//! 3. Auxiliary 1: Smoothed RTT (SRTT) + aging baseline `min_rtt`.
//! 4. Auxiliary 2: Receiver jitter buffer depth estimate.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Hard minimum protection bitrate (kbps).
pub const CC_MIN_BITRATE_KBPS: u32 = 300;
/// Hard minimum frame rate cap once at lowest resolution tier (360p).
pub const CC_MIN_FPS_CAP: u32 = 5;
/// Default initial bitrate (kbps) aligned with FastStart probe launch.
pub const CC_DEFAULT_START_BITRATE_KBPS: u32 = 1_500;
/// Default maximum bitrate ceiling (kbps).
pub const CC_DEFAULT_MAX_BITRATE_KBPS: u32 = 20_000;
/// Default base target FPS.
pub const CC_DEFAULT_MAX_FPS: u32 = 30;

/// Minimum consecutive confirming windows for normal state transitions / upgrades.
pub const CC_CONFIRM_WINDOWS: u32 = 3;
/// Minimum confirming span (ms) for normal state transitions / upgrades.
pub const CC_CONFIRM_SPAN_MS: u64 = 200;
/// Minimum interval (ms) between bitrate adjustments inside `Steady` (`<= 1/sec`).
pub const CC_STEADY_ADJUST_INTERVAL_MS: u64 = 1_100;
/// Minimum interval (ms) between encoder `set_bitrate` invocations (unless urgent).
pub const CC_ENCODER_BITRATE_THROTTLE_MS: u64 = 100;
/// Sustained below-threshold time required to downgrade resolution (`>= 2000ms`).
pub const CC_RES_DOWNGRADE_HOLD_MS: u64 = 2_000;
/// Sustained above-threshold time required to upgrade resolution (`>= 5000ms`).
pub const CC_RES_UPGRADE_HOLD_MS: u64 = 5_000;
/// Rolling baseline `min_rtt` aging window (`10s`) to prevent permanent drift.
pub const CC_MIN_RTT_WINDOW_MS: u64 = 10_000;
/// Maximum stored transition history events.
pub const CC_MAX_TRANSITION_LOG: usize = 512;

/// Fixed resolution ladder ordered from highest to lowest.
pub const RESOLUTION_LADDER: [(u32, u32); 4] = [
    (1920, 1080),
    (1280, 720),
    (960, 540),
    (640, 360),
];

/// Asymmetric downgrade/upgrade bitrate thresholds (kbps, media bitrate) per ladder tier.
/// Tier `i` downgrades to `i + 1` when media bitrate stays `< DOWNGRADE_THRESHOLDS[i]` for >= 2s.
/// Tier `i + 1` upgrades to `i` when media bitrate stays `>= UPGRADE_THRESHOLDS[i]` for >= 5s.
const RES_DOWNGRADE_KBPS: [u32; 3] = [2_500, 1_200, 600];
const RES_UPGRADE_KBPS: [u32; 3] = [3_200, 1_600, 850];

/// Four-state congestion control finite state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CcState {
    Startup,
    Steady,
    Drain,
    Recover,
}

/// Classified delay-gradient signal produced by the OLS trendline estimator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelaySignal {
    Underusing,
    Normal,
    Overusing,
}

/// Structured state transition record for simulation auditing and diagnostics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CcTransitionEvent {
    pub ts_ms: u64,
    pub from: CcState,
    pub to: CcState,
    pub reason: String,
    pub bitrate_kbps: u32,
    pub rtt_ms: f64,
    pub queue_delay_ms: f64,
    pub loss_rate: f64,
}

/// Feedback sample fed into `CongestionController::on_feedback`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct FeedbackSample {
    /// Monotonic caller/simulator timestamp in milliseconds.
    pub now_ms: u64,
    /// Measured RTT sample in milliseconds.
    pub rtt_ms: f64,
    /// Inter-arrival delay delta (`recv_delta_ms - send_delta_ms`) for this window.
    pub delay_delta_ms: f64,
    /// Media/FEC packets received in this feedback window.
    pub packets_received: u32,
    /// Raw network packets lost in this feedback window.
    pub packets_lost: u32,
    /// Receiver-measured packet arrival jitter in milliseconds.
    pub jitter_ms: f64,
    /// Receiver jitter buffer depth in milliseconds.
    pub jitter_buffer_ms: f64,
    /// Optional receiver-measured delivery throughput over this window (kbps).
    pub delivery_rate_kbps: Option<f64>,
}

/// Unified bitrate, FEC budget, resolution, and frame-rate target emitted to the encoder.
///
/// Invariant: `media_bitrate_kbps + fec_budget_kbps <= total_bitrate_kbps` ALWAYS holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncoderTarget {
    pub media_bitrate_kbps: u32,
    pub fec_budget_kbps: u32,
    pub total_bitrate_kbps: u32,
    pub width: u32,
    pub height: u32,
    pub fps_cap: u32,
    pub force_idr: bool,
    pub bitrate_changed: bool,
}

/// Configuration knobs for `CongestionController`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CongestionConfig {
    pub min_bitrate_kbps: u32,
    pub start_bitrate_kbps: u32,
    pub max_bitrate_kbps: u32,
    pub min_fps: u32,
    pub max_fps: u32,
    pub initial_tier_index: usize,
    /// Queuing delay delta (ms) that triggers Startup exit / Drain entry.
    pub queue_overuse_ms: f64,
    /// Queuing delay delta (ms) below which Drain is considered cleared.
    pub queue_drain_exit_ms: f64,
    /// OLS trendline slope (ms/ms) above which delay gradient signals overuse.
    pub trend_overuse_slope: f64,
    /// Burst packet loss threshold triggering `Recover` when delay gradient is not overusing.
    pub burst_loss_threshold: f64,
}

impl Default for CongestionConfig {
    fn default() -> Self {
        Self {
            min_bitrate_kbps: CC_MIN_BITRATE_KBPS,
            start_bitrate_kbps: CC_DEFAULT_START_BITRATE_KBPS,
            max_bitrate_kbps: CC_DEFAULT_MAX_BITRATE_KBPS,
            min_fps: CC_MIN_FPS_CAP,
            max_fps: CC_DEFAULT_MAX_FPS,
            initial_tier_index: 0,
            queue_overuse_ms: 28.0,
            queue_drain_exit_ms: 14.0,
            trend_overuse_slope: 0.045,
            burst_loss_threshold: 0.08,
        }
    }
}

/// GCC-like OLS trendline estimator over inter-arrival delay deltas.
#[derive(Debug, Clone)]
struct TrendlineEstimator {
    window: VecDeque<(f64, f64)>,
    max_window: usize,
    first_ts_ms: Option<u64>,
    accumulated_delay_ms: f64,
    smoothed_delay_ms: f64,
    smoothing_coef: f64,
    last_slope: f64,
}

impl TrendlineEstimator {
    fn new() -> Self {
        Self {
            window: VecDeque::with_capacity(16),
            max_window: 12,
            first_ts_ms: None,
            accumulated_delay_ms: 0.0,
            smoothed_delay_ms: 0.0,
            smoothing_coef: 0.65,
            last_slope: 0.0,
        }
    }

    fn update(&mut self, now_ms: u64, delay_delta_ms: f64, queue_delay_ms: f64) -> f64 {
        let first = *self.first_ts_ms.get_or_insert(now_ms);
        let x = now_ms.saturating_sub(first) as f64;
        let delta = if delay_delta_ms.is_finite() {
            delay_delta_ms.clamp(-200.0, 200.0)
        } else {
            0.0
        };
        // Anchor accumulated delay gently toward measured queue_delay_ms so drift never saturates.
        let raw_acc = (self.accumulated_delay_ms + delta).max(0.0);
        self.accumulated_delay_ms = 0.5 * raw_acc + 0.5 * queue_delay_ms.max(0.0);
        if self.window.is_empty() {
            self.smoothed_delay_ms = self.accumulated_delay_ms;
        } else {
            self.smoothed_delay_ms = self.smoothing_coef * self.smoothed_delay_ms
                + (1.0 - self.smoothing_coef) * self.accumulated_delay_ms;
        }

        self.window.push_back((x, self.smoothed_delay_ms));
        while self.window.len() > self.max_window {
            self.window.pop_front();
        }

        self.last_slope = self.compute_ols_slope();
        self.last_slope
    }

    fn compute_ols_slope(&self) -> f64 {
        let n = self.window.len();
        if n < 3 {
            return 0.0;
        }
        let inv_n = 1.0 / (n as f64);
        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        for &(x, y) in &self.window {
            sum_x += x;
            sum_y += y;
        }
        let mean_x = sum_x * inv_n;
        let mean_y = sum_y * inv_n;

        let mut num = 0.0;
        let mut den = 0.0;
        for &(x, y) in &self.window {
            let dx = x - mean_x;
            let dy = y - mean_y;
            num += dx * dy;
            den += dx * dx;
        }
        if den <= 1e-6 {
            0.0
        } else {
            num / den
        }
    }

    fn slope(&self) -> f64 {
        self.last_slope
    }

    fn reset_after_drain(&mut self, queue_delay_ms: f64) {
        self.accumulated_delay_ms = queue_delay_ms.max(0.0);
        self.smoothed_delay_ms = queue_delay_ms.max(0.0);
        self.window.clear();
        self.first_ts_ms = None;
        self.last_slope = 0.0;
    }
}

/// Rolling minimum RTT tracker with periodic aging to prevent baseline drift.
#[derive(Debug, Clone)]
struct AgingMinRtt {
    samples: VecDeque<(u64, f64)>,
    window_ms: u64,
    current_min: f64,
}

impl AgingMinRtt {
    fn new(window_ms: u64) -> Self {
        Self {
            samples: VecDeque::with_capacity(64),
            window_ms: window_ms.max(1_000),
            current_min: 0.0,
        }
    }

    fn update(&mut self, now_ms: u64, rtt_ms: f64) -> f64 {
        let rtt = if rtt_ms.is_finite() && rtt_ms > 0.0 {
            rtt_ms
        } else {
            return self.current_min;
        };

        // Evict samples older than aging window.
        let cutoff = now_ms.saturating_sub(self.window_ms);
        while let Some(&(ts, _)) = self.samples.front() {
            if ts < cutoff {
                self.samples.pop_front();
            } else {
                break;
            }
        }
        // Maintain monotonic deque for O(1) sliding minimum.
        while let Some(&(_, back_rtt)) = self.samples.back() {
            if back_rtt >= rtt {
                self.samples.pop_back();
            } else {
                break;
            }
        }
        self.samples.push_back((now_ms, rtt));
        self.current_min = self.samples.front().map_or(rtt, |&(_, m)| m);
        self.current_min
    }

    fn value(&self) -> f64 {
        self.current_min
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RateDirection {
    Up,
    Down,
}

/// Dual-signal adaptive congestion controller implementing the 4-state FSM,
/// asymmetric resolution/rate hysteresis, encoder throttling, and FEC budget coupling.
#[derive(Debug, Clone)]
pub struct CongestionController {
    cfg: CongestionConfig,
    state: CcState,
    feedback_received: bool,
    rtt_initialized: bool,

    total_bitrate_kbps: u32,
    media_bitrate_kbps: u32,
    fec_budget_kbps: u32,
    last_steady_bitrate_kbps: u32,

    // Smoothed telemetry
    srtt_ms: f64,
    min_rtt: AgingMinRtt,
    queue_delay_ms: f64,
    queue_overuse_windows: u32,
    jitter_ms: f64,
    jitter_buffer_ms: f64,
    loss_window: VecDeque<(u64, u32, u32)>,
    loss_ewma: f64,
    last_window_loss: f64,
    delivery_rate_ewma_kbps: Option<f64>,
    trendline: TrendlineEstimator,
    last_delay_signal: DelaySignal,

    // FSM timing & anti-oscillation guards
    state_entered_ms: u64,
    last_rate_increase_ms: Option<u64>,
    last_rate_decrease_ms: Option<u64>,
    last_steady_adjust_ms: Option<u64>,
    last_applied_encoder_bitrate_kbps: u32,
    last_applied_encoder_bitrate_ms: Option<u64>,
    confirm_up_windows: u32,
    confirm_up_since_ms: Option<u64>,
    confirm_exit_windows: u32,
    confirm_exit_since_ms: Option<u64>,
    last_rate_dir: Option<RateDirection>,
    consecutive_flips: u32,
    clean_steady_probes: u32,
    post_congestion_cooldown_until_ms: u64,

    // Resolution ladder & FPS cap state
    tier_index: usize,
    fps_cap: u32,
    res_down_since_ms: Option<u64>,
    res_up_since_ms: Option<u64>,

    // Audit trail
    transitions: Vec<CcTransitionEvent>,
}

impl Default for CongestionController {
    fn default() -> Self {
        Self::new(CongestionConfig::default())
    }
}

impl CongestionController {
    pub fn new(mut cfg: CongestionConfig) -> Self {
        let defaults = CongestionConfig::default();
        cfg.min_bitrate_kbps = cfg.min_bitrate_kbps.max(CC_MIN_BITRATE_KBPS);
        cfg.max_bitrate_kbps = cfg.max_bitrate_kbps.max(cfg.min_bitrate_kbps);
        cfg.start_bitrate_kbps = cfg
            .start_bitrate_kbps
            .clamp(cfg.min_bitrate_kbps, cfg.max_bitrate_kbps);
        cfg.min_fps = cfg.min_fps.max(CC_MIN_FPS_CAP);
        cfg.max_fps = cfg.max_fps.max(cfg.min_fps);
        cfg.initial_tier_index = cfg.initial_tier_index.min(RESOLUTION_LADDER.len() - 1);
        cfg.queue_overuse_ms = if cfg.queue_overuse_ms.is_finite() && cfg.queue_overuse_ms > 2.0 {
            cfg.queue_overuse_ms
        } else {
            defaults.queue_overuse_ms
        };
        cfg.queue_drain_exit_ms = if cfg.queue_drain_exit_ms.is_finite()
            && cfg.queue_drain_exit_ms >= 0.0
            && cfg.queue_drain_exit_ms < cfg.queue_overuse_ms
        {
            cfg.queue_drain_exit_ms
        } else {
            defaults
                .queue_drain_exit_ms
                .min((cfg.queue_overuse_ms * 0.5).max(0.0))
        };
        cfg.trend_overuse_slope =
            if cfg.trend_overuse_slope.is_finite() && cfg.trend_overuse_slope > 0.0 {
                cfg.trend_overuse_slope
            } else {
                defaults.trend_overuse_slope
            };
        cfg.burst_loss_threshold = if cfg.burst_loss_threshold.is_finite()
            && (0.01..=1.0).contains(&cfg.burst_loss_threshold)
        {
            cfg.burst_loss_threshold
        } else {
            defaults.burst_loss_threshold
        };
        let tier_index = cfg.initial_tier_index;

        let start = cfg.start_bitrate_kbps;
        Self {
            cfg,
            state: CcState::Startup,
            feedback_received: false,
            rtt_initialized: false,
            total_bitrate_kbps: start,
            media_bitrate_kbps: start,
            fec_budget_kbps: 0,
            last_steady_bitrate_kbps: start,
            srtt_ms: 40.0,
            min_rtt: AgingMinRtt::new(CC_MIN_RTT_WINDOW_MS),
            queue_delay_ms: 0.0,
            queue_overuse_windows: 0,
            jitter_ms: 0.0,
            jitter_buffer_ms: 0.0,
            loss_window: VecDeque::with_capacity(32),
            loss_ewma: 0.0,
            last_window_loss: 0.0,
            delivery_rate_ewma_kbps: None,
            trendline: TrendlineEstimator::new(),
            last_delay_signal: DelaySignal::Normal,
            state_entered_ms: 0,
            last_rate_increase_ms: None,
            last_rate_decrease_ms: None,
            last_steady_adjust_ms: None,
            last_applied_encoder_bitrate_kbps: start,
            last_applied_encoder_bitrate_ms: None,
            confirm_up_windows: 0,
            confirm_up_since_ms: None,
            confirm_exit_windows: 0,
            confirm_exit_since_ms: None,
            last_rate_dir: None,
            consecutive_flips: 0,
            clean_steady_probes: 0,
            post_congestion_cooldown_until_ms: 0,
            tier_index,
            fps_cap: cfg.max_fps,
            res_down_since_ms: None,
            res_up_since_ms: None,
            transitions: Vec::new(),
        }
    }

    pub fn state(&self) -> CcState {
        self.state
    }

    pub fn total_bitrate_kbps(&self) -> u32 {
        self.total_bitrate_kbps
    }

    pub fn media_bitrate_kbps(&self) -> u32 {
        self.media_bitrate_kbps
    }

    pub fn fec_budget_kbps(&self) -> u32 {
        self.fec_budget_kbps
    }

    pub fn srtt_ms(&self) -> f64 {
        self.srtt_ms
    }

    pub fn min_rtt_ms(&self) -> f64 {
        self.min_rtt.value()
    }

    pub fn queue_delay_ms(&self) -> f64 {
        self.queue_delay_ms
    }

    pub fn loss_rate(&self) -> f64 {
        self.loss_ewma
    }

    pub fn delay_slope(&self) -> f64 {
        self.trendline.slope()
    }

    pub fn last_delay_signal(&self) -> DelaySignal {
        self.last_delay_signal
    }

    pub fn jitter_buffer_ms(&self) -> f64 {
        self.jitter_buffer_ms
    }

    pub fn current_resolution(&self) -> (u32, u32) {
        RESOLUTION_LADDER[self.tier_index]
    }

    pub fn fps_cap(&self) -> u32 {
        self.fps_cap
    }

    pub fn transitions(&self) -> &[CcTransitionEvent] {
        &self.transitions
    }

    pub fn current_target(&self, force_idr: bool, bitrate_changed: bool) -> EncoderTarget {
        let (width, height) = RESOLUTION_LADDER[self.tier_index];
        EncoderTarget {
            media_bitrate_kbps: self.media_bitrate_kbps,
            fec_budget_kbps: self.fec_budget_kbps,
            total_bitrate_kbps: self.total_bitrate_kbps,
            width,
            height,
            fps_cap: self.fps_cap,
            force_idr,
            bitrate_changed,
        }
    }

    /// Processes a receiver feedback window and computes the next `EncoderTarget`.
    ///
    /// `fec_redundancy_ratio` (`0.0..=0.25`) is carved directly out of `total_bitrate_kbps`
    /// so `media_bitrate_kbps + fec_budget_kbps <= total_bitrate_kbps` ALWAYS holds.
    pub fn on_feedback(
        &mut self,
        sample: FeedbackSample,
        fec_redundancy_ratio: f64,
    ) -> EncoderTarget {
        let now_ms = sample.now_ms;
        let has_valid_rtt = sample.rtt_ms.is_finite() && sample.rtt_ms > 0.0;

        // 1. Update RTT / min_rtt / queuing delay / jitter / delivery rate / loss.
        // Only genuine measured RTT samples enter AgingMinRtt and SRTT; never poison min_rtt
        // with the synthetic 40ms default SRTT when sample.rtt_ms is <= 0 or non-finite.
        if !self.feedback_received {
            self.feedback_received = true;
            self.state_entered_ms = now_ms;
        }
        let (min_rtt, raw_queue_ms) = if has_valid_rtt {
            let m = self.min_rtt.update(now_ms, sample.rtt_ms);
            let raw_q = (sample.rtt_ms - m).max(0.0);
            if !self.rtt_initialized {
                self.rtt_initialized = true;
                self.srtt_ms = sample.rtt_ms;
                self.queue_delay_ms = raw_q;
            } else {
                self.srtt_ms = 0.75 * self.srtt_ms + 0.25 * sample.rtt_ms;
                // Light EWMA over queuing delay filters single-sample jitter while remaining
                // responsive to genuine queue buildup and clearing during Drain.
                self.queue_delay_ms = 0.45 * self.queue_delay_ms + 0.55 * raw_q;
            }
            (m, raw_q)
        } else {
            let m = self.min_rtt.value();
            if !self.rtt_initialized || m <= 0.0 {
                self.queue_delay_ms = 0.0;
            }
            (m, 0.0)
        };
        let _ = min_rtt;
        self.jitter_ms = if sample.jitter_ms.is_finite() && sample.jitter_ms >= 0.0 {
            0.7 * self.jitter_ms + 0.3 * sample.jitter_ms
        } else {
            self.jitter_ms
        };
        self.jitter_buffer_ms =
            if sample.jitter_buffer_ms.is_finite() && sample.jitter_buffer_ms >= 0.0 {
                sample.jitter_buffer_ms
            } else {
                self.jitter_buffer_ms
            };

        let total_pkts = sample.packets_received.saturating_add(sample.packets_lost);
        let window_loss = if total_pkts > 0 {
            (sample.packets_lost as f64) / (total_pkts as f64)
        } else {
            0.0
        };
        self.last_window_loss = window_loss;

        // Rolling 1-second packet-counted loss rate eliminates small-window sampling noise
        // while keeping EWMA responsive to genuine sustained loss shifts.
        self.loss_window
            .push_back((now_ms, sample.packets_received, sample.packets_lost));
        let loss_cutoff = now_ms.saturating_sub(1_000);
        while let Some(&(ts, _, _)) = self.loss_window.front() {
            if ts < loss_cutoff {
                self.loss_window.pop_front();
            } else {
                break;
            }
        }
        let mut sum_recv = 0u64;
        let mut sum_lost = 0u64;
        for &(_, r, l) in &self.loss_window {
            sum_recv = sum_recv.saturating_add(u64::from(r));
            sum_lost = sum_lost.saturating_add(u64::from(l));
        }
        let sum_total = sum_recv.saturating_add(sum_lost);
        let rolling_loss = if sum_total > 0 {
            (sum_lost as f64) / (sum_total as f64)
        } else {
            0.0
        };
        self.loss_ewma = 0.70 * self.loss_ewma + 0.30 * rolling_loss;

        if let Some(dr) = sample.delivery_rate_kbps {
            if dr.is_finite() && dr > 0.0 {
                self.delivery_rate_ewma_kbps = Some(match self.delivery_rate_ewma_kbps {
                    None => dr,
                    Some(prev) => {
                        // Track sudden drops immediately while smoothing steady noise.
                        if dr < prev * 0.75 {
                            0.35 * prev + 0.65 * dr
                        } else {
                            0.7 * prev + 0.3 * dr
                        }
                    }
                });
            }
        }

        // 2. Primary Signal 1: OLS trendline delay gradient (prioritized strictly over loss).
        let slope = self
            .trendline
            .update(now_ms, sample.delay_delta_ms, self.queue_delay_ms);
        if self.queue_delay_ms >= self.cfg.queue_overuse_ms
            && raw_queue_ms >= self.cfg.queue_overuse_ms
        {
            self.queue_overuse_windows = self.queue_overuse_windows.saturating_add(1);
        } else {
            self.queue_overuse_windows = 0;
        }
        let delay_overusing =
            slope > self.cfg.trend_overuse_slope || self.queue_overuse_windows >= 2;
        let delay_underusing = slope < -0.02 && self.queue_delay_ms <= 8.0;
        self.last_delay_signal = if delay_overusing {
            DelaySignal::Overusing
        } else if delay_underusing {
            DelaySignal::Underusing
        } else {
            DelaySignal::Normal
        };

        // 3. Primary Signal 2: Burst packet loss (evaluated ONLY if delay gradient did not trigger).
        // Require a genuine burst spike (not steady 5% wireless loss absorbed by FEC) before
        // cutting bitrate on the combined loss + moderate queue path.
        let significant_window_burst = total_pkts >= 25
            && sample.packets_lost >= 6
            && window_loss >= self.cfg.burst_loss_threshold.max(0.12);
        let loss_with_queue_burst = self.loss_ewma >= 0.05
            && self.queue_delay_ms >= 18.0
            && (self.last_window_loss >= 2.0 * self.loss_ewma
                || self.last_window_loss >= self.cfg.burst_loss_threshold);
        let burst_loss = significant_window_burst
            || self.loss_ewma >= self.cfg.burst_loss_threshold
            || loss_with_queue_burst;

        let srtt_clamped_ms = self.srtt_ms.clamp(1.0, 60_000.0).ceil() as u64;
        let rtt_interval_ms = srtt_clamped_ms.max(100);
        let drain_rtt_interval_ms = srtt_clamped_ms.max(50);
        let prev_total = self.total_bitrate_kbps;
        let mut urgent_rate_change = false;

        // 4. Drive 4-state FSM.
        match self.state {
            CcState::Startup => {
                if delay_overusing {
                    // Priority 1: Delay gradient triggers Drain before loss!
                    let next = self.compute_drain_target(true);
                    self.apply_total_bitrate(next, now_ms, false);
                    self.transition(now_ms, CcState::Drain, "startup_delay_overuse");
                    urgent_rate_change = true;
                } else if burst_loss {
                    self.last_steady_bitrate_kbps = self.total_bitrate_kbps;
                    let next = self.compute_recover_target();
                    if next < self.total_bitrate_kbps {
                        self.apply_total_bitrate(next, now_ms, false);
                        self.transition(now_ms, CcState::Recover, "startup_burst_loss");
                        urgent_rate_change = true;
                    }
                } else if self.total_bitrate_kbps >= self.cfg.max_bitrate_kbps {
                    if self.confirm_exit_window(now_ms) {
                        self.last_steady_bitrate_kbps = self.total_bitrate_kbps;
                        self.transition(now_ms, CcState::Steady, "startup_reached_max_bitrate");
                    }
                } else if self.queue_overuse_windows == 0
                    && self.queue_delay_ms < 14.0
                    && self.can_increase_rate(now_ms, rtt_interval_ms)
                {
                    // Startup aggressive ramp: up to x1.6 per RTT, bounded by delivery headroom.
                    let mut next = ((self.total_bitrate_kbps as f64) * 1.6).round() as u32;
                    if let Some(dr) = sample.delivery_rate_kbps.filter(|v| v.is_finite() && *v > 0.0)
                    {
                        // Once smoothed queue begins rising (>= 6ms -> ~24ms raw queue), cap ramp
                        // to delivery headroom instead of overshooting blindly into bufferbloat.
                        if self.queue_delay_ms >= 6.0 {
                            next = next.min((dr * 1.15).round() as u32);
                        }
                    }
                    let next = next.clamp(self.cfg.min_bitrate_kbps, self.cfg.max_bitrate_kbps);
                    if next > self.total_bitrate_kbps {
                        self.apply_total_bitrate(next, now_ms, false);
                    }
                }
            }

            CcState::Steady => {
                if delay_overusing {
                    self.last_steady_bitrate_kbps = self.total_bitrate_kbps;
                    let next = self.compute_drain_target(true);
                    self.apply_total_bitrate(next, now_ms, false);
                    self.transition(now_ms, CcState::Drain, "steady_delay_overuse");
                    urgent_rate_change = true;
                } else if burst_loss {
                    self.last_steady_bitrate_kbps = self.total_bitrate_kbps;
                    let next = self.compute_recover_target();
                    if next < self.total_bitrate_kbps {
                        self.apply_total_bitrate(next, now_ms, false);
                        self.transition(now_ms, CcState::Recover, "steady_burst_loss");
                        urgent_rate_change = true;
                    }
                } else {
                    // Check if delivery rate dropped sharply without queue crossing threshold yet
                    // (e.g., sudden bottleneck reduction already reflected in delivery rate).
                    let severe_delivery_drop = sample
                        .delivery_rate_kbps
                        .filter(|v| v.is_finite() && *v > 0.0)
                        .is_some_and(|dr| {
                            dr < (self.total_bitrate_kbps as f64) * 0.65
                                && self.queue_delay_ms >= 10.0
                        });

                    if severe_delivery_drop {
                        self.last_steady_bitrate_kbps = self.total_bitrate_kbps;
                        let next = self.compute_drain_target(true);
                        self.apply_total_bitrate(next, now_ms, false);
                        self.transition(now_ms, CcState::Drain, "steady_delivery_drop");
                        urgent_rate_change = true;
                    } else if self.loss_ewma < 0.03 && self.queue_delay_ms < 14.0 {
                        // Gentle +5% periodic probe in Steady, strictly <= 1 adjustment/sec,
                        // confirmed over >= 3 windows & >= 200ms, and honoring anti-flip cooldown.
                        if self.confirm_up_window(now_ms)
                            && now_ms >= self.post_congestion_cooldown_until_ms
                            && self.can_adjust_in_steady(now_ms, rtt_interval_ms)
                            && self.total_bitrate_kbps < self.cfg.max_bitrate_kbps
                        {
                            // Reset stale flip counter after sustained clean steady dwell.
                            if now_ms.saturating_sub(self.state_entered_ms) >= 2_500 {
                                self.consecutive_flips = 0;
                            }
                            // Single-step Steady increase strictly <= x1.2 (nominal +5%,
                            // stepping up to +18% only after consecutive zero-queue probes
                            // indicate large unutilized headroom, e.g. 2 -> 15 Mbps recovery).
                            let clean_headroom = self.queue_delay_ms < 5.0
                                && self.loss_ewma < 0.01
                                && self.clean_steady_probes >= 2;
                            let factor = if self.consecutive_flips >= 1 {
                                1.03
                            } else if clean_headroom {
                                1.18
                            } else {
                                1.05
                            };
                            let next = ((self.total_bitrate_kbps as f64) * factor)
                                .round()
                                .min((self.total_bitrate_kbps as f64) * 1.2)
                                as u32;
                            let next =
                                next.clamp(self.cfg.min_bitrate_kbps, self.cfg.max_bitrate_kbps);
                            if next > self.total_bitrate_kbps {
                                self.apply_total_bitrate(next, now_ms, true);
                                self.last_steady_bitrate_kbps = self.total_bitrate_kbps;
                                self.clean_steady_probes =
                                    self.clean_steady_probes.saturating_add(1);
                            }
                            self.reset_up_confirmation();
                        }
                    } else {
                        self.reset_up_confirmation();
                    }
                }
            }

            CcState::Drain => {
                let dwell_ms = now_ms.saturating_sub(self.state_entered_ms);
                let min_dwell = drain_rtt_interval_ms;

                // While draining, if queue is still overloaded or delivery rate is still much lower,
                // step down again once per RTT (strictly respecting single-step >= x0.5).
                let still_congested = self.queue_delay_ms > self.cfg.queue_drain_exit_ms
                    || (slope > 0.015 && sample.delay_delta_ms > 0.0)
                    || (self.queue_delay_ms > 6.0
                        && sample
                            .delivery_rate_kbps
                            .filter(|v| v.is_finite() && *v > 0.0)
                            .is_some_and(|dr| (self.total_bitrate_kbps as f64) > dr * 1.12));

                if still_congested {
                    self.reset_exit_confirmation();
                    let since_last_dec = self
                        .last_rate_decrease_ms
                        .map_or(u64::MAX, |t| now_ms.saturating_sub(t));
                    if since_last_dec >= drain_rtt_interval_ms {
                        let next = self.compute_drain_target(false);
                        if next < self.total_bitrate_kbps {
                            self.apply_total_bitrate(next, now_ms, false);
                            urgent_rate_change = true;
                        }
                    }
                } else if dwell_ms >= min_dwell {
                    // Queue drained and min dwell >= 1 * RTT satisfied -> return to Steady.
                    self.last_steady_bitrate_kbps = self.total_bitrate_kbps;
                    self.trendline.reset_after_drain(self.queue_delay_ms);
                    self.post_congestion_cooldown_until_ms = now_ms.saturating_add(
                        if self.consecutive_flips >= 1 {
                            2_400
                        } else {
                            1_400
                        },
                    );
                    self.transition(now_ms, CcState::Steady, "drain_queue_cleared");
                }
            }

            CcState::Recover => {
                let dwell_ms = now_ms.saturating_sub(self.state_entered_ms);
                let min_dwell = rtt_interval_ms;

                if delay_overusing {
                    // Escalate immediately to Drain if queue builds during Recover.
                    let next = self.compute_drain_target(true);
                    self.apply_total_bitrate(next, now_ms, false);
                    self.transition(now_ms, CcState::Drain, "recover_escalated_to_drain");
                    urgent_rate_change = true;
                } else {
                    let rtt_recovered = self.queue_delay_ms <= 20.0;
                    if !rtt_recovered {
                        self.reset_exit_confirmation();
                    } else if dwell_ms >= min_dwell && self.confirm_exit_window(now_ms) {
                        self.last_steady_bitrate_kbps = self.total_bitrate_kbps;
                        self.post_congestion_cooldown_until_ms = now_ms.saturating_add(
                            if self.consecutive_flips >= 1 {
                                2_400
                            } else {
                                1_400
                            },
                        );
                        self.transition(now_ms, CcState::Steady, "recover_rtt_restored");
                    }
                }
            }
        }

        // 5. Couple FEC budget inside total bitrate budget: media + fec <= total ALWAYS.
        let ratio = if fec_redundancy_ratio.is_finite() {
            fec_redundancy_ratio.clamp(0.0, 0.25)
        } else {
            0.0
        };
        self.recompute_budget_split(ratio);

        // 6. Asymmetric resolution ladder (2000ms down, 5000ms up) + FPS cap at 360p.
        let resolution_changed = self.update_resolution_and_fps(now_ms);
        let force_idr = resolution_changed;

        // 7. Throttle encoder `set_bitrate` calls >= 100ms unless urgent or resolution downgrade.
        let since_applied = self
            .last_applied_encoder_bitrate_ms
            .map_or(u64::MAX, |t| now_ms.saturating_sub(t));
        let media_delta = self.media_bitrate_kbps != self.last_applied_encoder_bitrate_kbps;
        let bitrate_changed = if media_delta
            && (since_applied >= CC_ENCODER_BITRATE_THROTTLE_MS
                || urgent_rate_change
                || resolution_changed
                || self.total_bitrate_kbps < prev_total)
        {
            self.last_applied_encoder_bitrate_kbps = self.media_bitrate_kbps;
            self.last_applied_encoder_bitrate_ms = Some(now_ms);
            true
        } else {
            false
        };

        self.current_target(force_idr, bitrate_changed)
    }

    fn compute_drain_target(&self, initial_entry: bool) -> u32 {
        let current = self.total_bitrate_kbps as f64;
        let step_floor = (current * 0.5).ceil();
        let nominal = current * 0.85;
        let guided = match self.delivery_rate_ewma_kbps {
            Some(dr) if dr.is_finite() && dr > 0.0 && dr < current * 0.82 => {
                // Target ~92% of measured delivery rate to drain queued packets quickly,
                // while strictly respecting the single-step floor >= 0.5 * current.
                let drain_rate = if initial_entry { dr * 0.90 } else { dr * 0.88 };
                drain_rate.min(nominal).max(step_floor)
            }
            _ => nominal.max(step_floor),
        };
        (guided.round() as u32).clamp(self.cfg.min_bitrate_kbps, self.cfg.max_bitrate_kbps)
    }

    fn compute_recover_target(&self) -> u32 {
        let current = self.total_bitrate_kbps as f64;
        let step_floor = (current * 0.5).ceil();
        let target = ((self.last_steady_bitrate_kbps as f64) * 0.90)
            .min(current)
            .max(step_floor);
        (target.round() as u32).clamp(self.cfg.min_bitrate_kbps, self.cfg.max_bitrate_kbps)
    }

    fn apply_total_bitrate(&mut self, next_kbps: u32, now_ms: u64, in_steady: bool) {
        let clamped = next_kbps.clamp(self.cfg.min_bitrate_kbps, self.cfg.max_bitrate_kbps);
        if clamped == self.total_bitrate_kbps {
            return;
        }
        let dir = if clamped > self.total_bitrate_kbps {
            self.last_rate_increase_ms = Some(now_ms);
            RateDirection::Up
        } else {
            self.last_rate_decrease_ms = Some(now_ms);
            RateDirection::Down
        };

        if let Some(prev_dir) = self.last_rate_dir {
            if prev_dir != dir {
                self.consecutive_flips = self.consecutive_flips.saturating_add(1);
            } else {
                self.consecutive_flips = 0;
            }
        }
        self.last_rate_dir = Some(dir);

        if in_steady {
            self.last_steady_adjust_ms = Some(now_ms);
        }
        self.total_bitrate_kbps = clamped;
    }

    fn recompute_budget_split(&mut self, fec_ratio: f64) {
        let total = self.total_bitrate_kbps.max(self.cfg.min_bitrate_kbps);
        if fec_ratio <= 0.0 {
            self.media_bitrate_kbps = total;
            self.fec_budget_kbps = 0;
            return;
        }
        let media = ((total as f64) / (1.0 + fec_ratio)).floor() as u32;
        let media = media.max(self.cfg.min_bitrate_kbps).min(total);
        let fec = total.saturating_sub(media);
        self.media_bitrate_kbps = media;
        self.fec_budget_kbps = fec;
    }

    fn can_increase_rate(&self, now_ms: u64, rtt_interval_ms: u64) -> bool {
        let min_gap = rtt_interval_ms.max(100);
        self.last_rate_increase_ms
            .is_none_or(|t| now_ms.saturating_sub(t) >= min_gap)
    }

    fn can_adjust_in_steady(&self, now_ms: u64, rtt_interval_ms: u64) -> bool {
        let min_gap = CC_STEADY_ADJUST_INTERVAL_MS.max(rtt_interval_ms);
        let steady_ok = self
            .last_steady_adjust_ms
            .is_none_or(|t| now_ms.saturating_sub(t) >= min_gap);
        steady_ok && self.can_increase_rate(now_ms, rtt_interval_ms)
    }

    fn confirm_up_window(&mut self, now_ms: u64) -> bool {
        self.confirm_up_windows = self.confirm_up_windows.saturating_add(1);
        let since = *self.confirm_up_since_ms.get_or_insert(now_ms);
        self.confirm_up_windows >= CC_CONFIRM_WINDOWS
            && now_ms.saturating_sub(since) >= CC_CONFIRM_SPAN_MS
    }

    fn reset_up_confirmation(&mut self) {
        self.confirm_up_windows = 0;
        self.confirm_up_since_ms = None;
    }

    fn confirm_exit_window(&mut self, now_ms: u64) -> bool {
        self.confirm_exit_windows = self.confirm_exit_windows.saturating_add(1);
        let since = *self.confirm_exit_since_ms.get_or_insert(now_ms);
        self.confirm_exit_windows >= CC_CONFIRM_WINDOWS
            && now_ms.saturating_sub(since) >= CC_CONFIRM_SPAN_MS
    }

    fn reset_exit_confirmation(&mut self) {
        self.confirm_exit_windows = 0;
        self.confirm_exit_since_ms = None;
    }

    fn transition(&mut self, now_ms: u64, to: CcState, reason: &str) {
        let from = self.state;
        if from == to {
            return;
        }
        self.state = to;
        self.state_entered_ms = now_ms;
        self.clean_steady_probes = 0;
        self.queue_overuse_windows = 0;
        self.reset_up_confirmation();
        self.reset_exit_confirmation();

        if self.transitions.len() >= CC_MAX_TRANSITION_LOG {
            self.transitions.remove(0);
        }
        self.transitions.push(CcTransitionEvent {
            ts_ms: now_ms,
            from,
            to,
            reason: reason.to_string(),
            bitrate_kbps: self.total_bitrate_kbps,
            rtt_ms: self.srtt_ms,
            queue_delay_ms: self.queue_delay_ms,
            loss_rate: self.loss_ewma,
        });
    }

    /// Updates resolution ladder with asymmetric hysteresis (2000ms down, 5000ms up)
    /// and scales FPS cap at the lowest tier (`640x360`) without dropping resolution further.
    fn update_resolution_and_fps(&mut self, now_ms: u64) -> bool {
        let media = self.media_bitrate_kbps;
        let max_tier = RESOLUTION_LADDER.len() - 1;
        let mut changed = false;

        // Check downgrade condition (only if not already at 360p).
        if self.tier_index < max_tier && media < RES_DOWNGRADE_KBPS[self.tier_index] {
            self.res_up_since_ms = None;
            let since = *self.res_down_since_ms.get_or_insert(now_ms);
            if now_ms.saturating_sub(since) >= CC_RES_DOWNGRADE_HOLD_MS {
                self.tier_index += 1;
                self.res_down_since_ms = None;
                changed = true;
            }
        } else {
            self.res_down_since_ms = None;
        }

        // Check upgrade condition (only if not already at 1080p and not just downgraded).
        if !changed && self.tier_index > 0 && media >= RES_UPGRADE_KBPS[self.tier_index - 1] {
            let since = *self.res_up_since_ms.get_or_insert(now_ms);
            if now_ms.saturating_sub(since) >= CC_RES_UPGRADE_HOLD_MS {
                self.tier_index -= 1;
                self.res_up_since_ms = None;
                changed = true;
            }
        } else if !changed {
            self.res_up_since_ms = None;
        }

        // At lowest resolution (640x360), never drop resolution further; scale fps_cap down to min_fps.
        if self.tier_index == max_tier {
            if media >= RES_DOWNGRADE_KBPS[max_tier - 1] {
                self.fps_cap = self.cfg.max_fps;
            } else {
                let low = self.cfg.min_bitrate_kbps as f64;
                let high = RES_DOWNGRADE_KBPS[max_tier - 1] as f64;
                let frac = ((media as f64 - low) / (high - low).max(1.0)).clamp(0.0, 1.0);
                let fps = (self.cfg.min_fps as f64
                    + frac * (self.cfg.max_fps.saturating_sub(self.cfg.min_fps) as f64))
                    .round() as u32;
                self.fps_cap = fps.clamp(self.cfg.min_fps, self.cfg.max_fps);
            }
        } else {
            self.fps_cap = self.cfg.max_fps;
        }

        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(
        now_ms: u64,
        rtt_ms: f64,
        delay_delta_ms: f64,
        recv: u32,
        lost: u32,
        delivery_rate_kbps: Option<f64>,
    ) -> FeedbackSample {
        FeedbackSample {
            now_ms,
            rtt_ms,
            delay_delta_ms,
            packets_received: recv,
            packets_lost: lost,
            jitter_ms: 2.0,
            jitter_buffer_ms: 5.0,
            delivery_rate_kbps,
        }
    }

    #[test]
    fn delay_gradient_prioritized_over_loss_and_records_transition_event() {
        let mut cc = CongestionController::default();
        // Establish baseline RTT = 30ms during Startup.
        cc.on_feedback(sample(0, 30.0, 0.0, 50, 0, Some(10_000.0)), 0.0);
        cc.on_feedback(sample(100, 30.0, 0.0, 50, 0, Some(10_000.0)), 0.0);
        assert_eq!(cc.state(), CcState::Startup);

        // Simultaneous delay gradient overuse (rising slope + queue) AND 12% burst loss -> MUST enter Drain, NOT Recover!
        let before = cc.total_bitrate_kbps();
        cc.on_feedback(sample(200, 120.0, 45.0, 44, 6, Some(4_000.0)), 0.15);
        assert_eq!(cc.state(), CcState::Drain);
        assert!(cc.total_bitrate_kbps() < before);
        assert!(cc.total_bitrate_kbps() >= (before as f64 * 0.5).floor() as u32);
        let ev = cc.transitions().last().unwrap();
        assert_eq!(ev.from, CcState::Startup);
        assert_eq!(ev.to, CcState::Drain);
        assert_eq!(ev.ts_ms, 200);
    }

    #[test]
    fn recover_state_backs_off_to_90pct_of_last_steady_and_restores_on_baseline_rtt() {
        let mut cc = CongestionController::new(CongestionConfig {
            start_bitrate_kbps: 8_000,
            max_bitrate_kbps: 8_000,
            ..Default::default()
        });
        // Transition Startup -> Steady at max bitrate (requires >= 3 windows & >= 200ms).
        for i in 0..5 {
            cc.on_feedback(sample(i * 100, 40.0, 0.0, 60, 0, Some(8_000.0)), 0.0);
        }
        assert_eq!(cc.state(), CcState::Steady);
        assert_eq!(cc.total_bitrate_kbps(), 8_000);

        // Sudden 12% burst loss with flat RTT (no delay gradient overuse) -> Recover at 90% = 7200 kbps!
        let t = cc.on_feedback(sample(600, 42.0, 0.0, 44, 6, Some(7_500.0)), 0.15);
        assert_eq!(cc.state(), CcState::Recover);
        assert_eq!(t.total_bitrate_kbps, 7_200);
        assert!(t.media_bitrate_kbps + t.fec_budget_kbps <= t.total_bitrate_kbps);

        // RTT stays near baseline across >= 3 windows & >= 200ms -> back to Steady.
        for i in 1..=4 {
            cc.on_feedback(sample(600 + i * 100, 40.0, 0.0, 60, 0, Some(7_500.0)), 0.0);
        }
        assert_eq!(cc.state(), CcState::Steady);
    }

    #[test]
    fn fec_budget_strictly_coupled_inside_total_bitrate_and_min_floor_protected() {
        let mut cc = CongestionController::new(CongestionConfig {
            start_bitrate_kbps: 350,
            max_bitrate_kbps: 20_000,
            ..Default::default()
        });
        for fec_ratio in [0.0, 0.05, 0.15, 0.25, 0.50] {
            let target = cc.on_feedback(sample(100, 30.0, 0.0, 40, 0, None), fec_ratio);
            assert!(
                target.media_bitrate_kbps + target.fec_budget_kbps <= target.total_bitrate_kbps,
                "budget overflow: media={} + fec={} > total={}",
                target.media_bitrate_kbps,
                target.fec_budget_kbps,
                target.total_bitrate_kbps
            );
            assert!(target.media_bitrate_kbps >= CC_MIN_BITRATE_KBPS);
        }
    }

    #[test]
    fn asymmetric_resolution_ladder_2s_down_5s_up_and_360p_fps_cap() {
        let mut cc = CongestionController::new(CongestionConfig {
            start_bitrate_kbps: 1_000,
            max_bitrate_kbps: 1_000,
            ..Default::default()
        });
        // Starts at 1080p; media=1000 < 2500 threshold. Must NOT downgrade before 2000ms.
        let t0 = cc.on_feedback(sample(0, 30.0, 0.0, 50, 0, Some(1_000.0)), 0.0);
        assert_eq!((t0.width, t0.height), (1920, 1080));
        let t1 = cc.on_feedback(sample(1_900, 30.0, 0.0, 50, 0, Some(1_000.0)), 0.0);
        assert_eq!((t1.width, t1.height), (1920, 1080));
        assert!(!t1.force_idr);

        // At 2000ms -> downgrades to 720p and MUST set force_idr = true!
        let t2 = cc.on_feedback(sample(2_000, 30.0, 0.0, 50, 0, Some(1_000.0)), 0.0);
        assert_eq!((t2.width, t2.height), (1280, 720));
        assert!(t2.force_idr);

        // Downgrade through 540p -> 360p at 300 kbps.
        let mut low_cc = CongestionController::new(CongestionConfig {
            start_bitrate_kbps: 300,
            max_bitrate_kbps: 300,
            initial_tier_index: 2, // 540p
            ..Default::default()
        });
        low_cc.on_feedback(sample(0, 30.0, 0.0, 30, 0, Some(300.0)), 0.0);
        let t_360 = low_cc.on_feedback(sample(2_100, 30.0, 0.0, 30, 0, Some(300.0)), 0.0);
        assert_eq!((t_360.width, t_360.height), (640, 360));
        assert!(t_360.force_idr);
        assert_eq!(t_360.fps_cap, CC_MIN_FPS_CAP);

        // Stay at 360p even after 10 more seconds at 300 kbps (never drops below 360p).
        let t_still = low_cc.on_feedback(sample(12_000, 30.0, 0.0, 30, 0, Some(300.0)), 0.0);
        assert_eq!((t_still.width, t_still.height), (640, 360));
        assert_eq!(t_still.fps_cap, CC_MIN_FPS_CAP);

        // Test 5000ms asymmetric upgrade from 720p -> 1080p at 4000 kbps.
        let mut up_cc = CongestionController::new(CongestionConfig {
            start_bitrate_kbps: 4_000,
            max_bitrate_kbps: 4_000,
            initial_tier_index: 1, // 720p
            ..Default::default()
        });
        up_cc.on_feedback(sample(0, 30.0, 0.0, 50, 0, Some(4_000.0)), 0.0);
        let u4 = up_cc.on_feedback(sample(4_900, 30.0, 0.0, 50, 0, Some(4_000.0)), 0.0);
        assert_eq!((u4.width, u4.height), (1280, 720));
        assert!(!u4.force_idr);
        let u5 = up_cc.on_feedback(sample(5_000, 30.0, 0.0, 50, 0, Some(4_000.0)), 0.0);
        assert_eq!((u5.width, u5.height), (1920, 1080));
        assert!(u5.force_idr);
    }

    #[test]
    fn steady_rate_adjustments_strictly_bounded_to_at_most_once_per_second() {
        let mut cc = CongestionController::new(CongestionConfig {
            start_bitrate_kbps: 3_000,
            max_bitrate_kbps: 15_000,
            ..Default::default()
        });
        // Push into Drain briefly (sustained queue/trend) then settle into Steady.
        cc.on_feedback(sample(0, 30.0, 0.0, 50, 0, Some(3_000.0)), 0.0);
        cc.on_feedback(sample(100, 30.0, 0.0, 50, 0, Some(3_000.0)), 0.0);
        cc.on_feedback(sample(200, 120.0, 45.0, 50, 0, Some(3_000.0)), 0.0);
        assert_eq!(cc.state(), CcState::Drain);
        for t in [300, 400, 500, 600] {
            cc.on_feedback(sample(t, 30.0, -10.0, 50, 0, Some(3_000.0)), 0.0);
        }
        assert_eq!(cc.state(), CcState::Steady);

        // Run 10 seconds in clean Steady at 100ms feedback ticks.
        let mut prev_br = cc.total_bitrate_kbps();
        let mut steady_changes = 0u32;
        for step in 1..=100u64 {
            let now = 600 + step * 100;
            let t = cc.on_feedback(sample(now, 30.0, 0.0, 50, 0, Some(15_000.0)), 0.0);
            assert_eq!(cc.state(), CcState::Steady);
            if t.total_bitrate_kbps != prev_br {
                steady_changes += 1;
                // Every single-step Steady increase must be <= x1.2.
                assert!(t.total_bitrate_kbps <= ((prev_br as f64) * 1.2).ceil() as u32);
                prev_br = t.total_bitrate_kbps;
            }
        }
        let changes_per_sec = (steady_changes as f64) / 10.0;
        assert!(
            changes_per_sec <= 1.0,
            "Steady changes/sec {changes_per_sec} exceeded 1.0"
        );
        assert!(steady_changes >= 3, "expected gentle periodic probing");
    }

    #[test]
    fn zero_or_non_finite_rtt_never_poisons_min_rtt_or_triggers_false_drain() {
        let mut cc = CongestionController::default();
        // First feedback carries invalid rtt_ms = 0.0 (and NaN) -> must NEVER seed min_rtt with 40ms!
        cc.on_feedback(sample(0, 0.0, 0.0, 10, 0, Some(5_000.0)), 0.0);
        cc.on_feedback(sample(50, f64::NAN, 0.0, 10, 0, Some(5_000.0)), 0.0);
        assert_eq!(cc.min_rtt_ms(), 0.0);
        assert_eq!(cc.queue_delay_ms(), 0.0);
        assert_eq!(cc.state(), CcState::Startup);

        // Genuine steady 200ms WAN RTT follows for 5 seconds -> must NOT enter false Drain!
        for step in 1..=50u64 {
            let now = 100 + step * 100;
            cc.on_feedback(sample(now, 200.0, 0.0, 40, 0, Some(10_000.0)), 0.0);
            assert_ne!(
                cc.state(),
                CcState::Drain,
                "false Drain at t={now}ms (min_rtt={}, srtt={}, q={})",
                cc.min_rtt_ms(),
                cc.srtt_ms(),
                cc.queue_delay_ms()
            );
        }
        assert!((cc.min_rtt_ms() - 200.0).abs() < 1e-6);
        assert!(cc.queue_delay_ms() < 1.0);
    }

    #[test]
    fn single_delayed_ack_spike_does_not_false_trigger_drain_requires_two_windows() {
        let mut cc = CongestionController::new(CongestionConfig {
            start_bitrate_kbps: 6_000,
            max_bitrate_kbps: 6_000,
            ..Default::default()
        });
        // Establish steady baseline at 30ms RTT over 12 samples so OLS window is populated.
        for i in 0..12u64 {
            cc.on_feedback(sample(i * 100, 30.0, 0.0, 50, 0, Some(6_000.0)), 0.0);
        }
        assert_eq!(cc.state(), CcState::Steady);

        // Single delayed-ACK RTT spike (160ms, raw queue +130ms -> srtt = 62.5ms, queue = 32.5ms >= 28ms)
        // for ONE window only, then immediately returns to 30ms -> MUST stay in Steady!
        cc.on_feedback(sample(1_200, 160.0, 0.0, 50, 0, Some(6_000.0)), 0.0);
        assert_eq!(cc.state(), CcState::Steady);
        cc.on_feedback(sample(1_300, 30.0, 0.0, 50, 0, Some(6_000.0)), 0.0);
        assert_eq!(cc.state(), CcState::Steady);

        // Settle back to baseline, then apply sustained high RTT across >= 2 consecutive queue-overuse windows -> MUST Drain!
        for i in 14..22u64 {
            cc.on_feedback(sample(i * 100, 30.0, 0.0, 50, 0, Some(6_000.0)), 0.0);
        }
        assert_eq!(cc.state(), CcState::Steady);
        cc.on_feedback(sample(2_200, 160.0, 0.0, 50, 0, Some(6_000.0)), 0.0);
        assert_eq!(cc.state(), CcState::Steady);
        cc.on_feedback(sample(2_300, 160.0, 0.0, 50, 0, Some(6_000.0)), 0.0);
        assert_eq!(cc.state(), CcState::Drain);
    }

    #[test]
    fn steady_five_percent_wireless_loss_with_moderate_queue_does_not_trigger_recover() {
        let mut cc = CongestionController::new(CongestionConfig {
            start_bitrate_kbps: 6_000,
            max_bitrate_kbps: 6_000,
            ..Default::default()
        });
        for i in 0..12u64 {
            cc.on_feedback(sample(i * 100, 40.0, 0.0, 60, 0, Some(6_000.0)), 0.0);
        }
        assert_eq!(cc.state(), CcState::Steady);
        let initial_br = cc.total_bitrate_kbps();

        // Feed steady 5% wireless loss (3 lost out of 60) with moderate ~20ms queue (60ms RTT, < 28ms overuse).
        // Must NOT repeatedly enter Recover or slash bitrate.
        for i in 12..35u64 {
            cc.on_feedback(sample(i * 100, 60.0, 0.0, 57, 3, Some(6_000.0)), 0.15);
            assert_eq!(
                cc.state(),
                CcState::Steady,
                "steady 5% wireless loss falsely triggered {:?} at step {i}",
                cc.state()
            );
        }
        assert_eq!(cc.total_bitrate_kbps(), initial_br);

        // Genuine sudden burst spike (12% window loss, >= 2x EWMA) DOES trigger Recover!
        cc.on_feedback(sample(3_600, 60.0, 0.0, 44, 6, Some(6_000.0)), 0.15);
        assert_eq!(cc.state(), CcState::Recover);
        assert!(cc.total_bitrate_kbps() < initial_br);
    }

    #[test]
    fn config_normalization_and_recover_at_floor_and_exit_reset_hygiene() {
        // Adversarial NaN / inverted config must normalize safely without panicking.
        let mut cc = CongestionController::new(CongestionConfig {
            min_bitrate_kbps: 50,
            start_bitrate_kbps: 50_000,
            max_bitrate_kbps: 100,
            min_fps: 2,
            max_fps: 1,
            initial_tier_index: 99,
            queue_overuse_ms: f64::NAN,
            queue_drain_exit_ms: 999.0,
            trend_overuse_slope: -1.0,
            burst_loss_threshold: f64::INFINITY,
        });
        assert_eq!(cc.total_bitrate_kbps(), CC_MIN_BITRATE_KBPS);
        assert_eq!(cc.current_resolution(), RESOLUTION_LADDER[RESOLUTION_LADDER.len() - 1]);
        assert_eq!(cc.fps_cap(), CC_MIN_FPS_CAP);

        // Move to Steady at floor (300 kbps).
        for i in 0..5u64 {
            cc.on_feedback(sample(i * 100, 40.0, 0.0, 50, 0, Some(300.0)), 0.0);
        }
        assert_eq!(cc.state(), CcState::Steady);
        let transitions_before = cc.transitions().len();

        // Repeated burst loss while already pinned at min_bitrate_kbps must NOT spam Steady->Recover.
        for i in 5..12u64 {
            cc.on_feedback(sample(i * 100, 40.0, 0.0, 40, 10, Some(300.0)), 0.25);
            assert_eq!(cc.state(), CcState::Steady);
        }
        assert_eq!(cc.transitions().len(), transitions_before);

        // Verify Recover exit resets confirm_exit_windows when rtt_recovered drops false.
        let mut rcc = CongestionController::new(CongestionConfig {
            start_bitrate_kbps: 6_000,
            max_bitrate_kbps: 6_000,
            ..Default::default()
        });
        for i in 0..5u64 {
            rcc.on_feedback(sample(i * 100, 40.0, 0.0, 60, 0, Some(6_000.0)), 0.0);
        }
        assert_eq!(rcc.state(), CcState::Steady);
        rcc.on_feedback(sample(500, 40.0, 0.0, 44, 6, Some(6_000.0)), 0.15);
        assert_eq!(rcc.state(), CcState::Recover);
        // Two good windows (confirm_exit_windows = 2), then one elevated RTT window (> 20ms queue) resets it.
        rcc.on_feedback(sample(600, 40.0, 0.0, 60, 0, Some(6_000.0)), 0.0);
        rcc.on_feedback(sample(700, 40.0, 0.0, 60, 0, Some(6_000.0)), 0.0);
        assert_eq!(rcc.state(), CcState::Recover);
        rcc.on_feedback(sample(800, 130.0, 0.0, 60, 0, Some(6_000.0)), 0.0);
        // srtt = 62.5 -> queue_delay_ms = 22.5 > 20.0 -> confirmation counter must reset!
        assert_eq!(rcc.state(), CcState::Recover);
        // One good window at 900ms is NOT enough because confirmation was reset (needs 3 windows / 200ms).
        rcc.on_feedback(sample(900, 40.0, 0.0, 60, 0, Some(6_000.0)), 0.0);
        assert_eq!(rcc.state(), CcState::Recover);
    }
}
