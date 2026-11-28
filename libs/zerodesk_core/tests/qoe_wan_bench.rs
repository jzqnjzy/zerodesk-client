// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Phase 9A deterministic weak-network WAN simulation benchmark gates.
//! Every hard threshold from the Phase 9A QoE specification is asserted directly.

use zerodesk_core::qoe::{
    wan_sim::percentile, BandwidthStep, CongestionConfig, LossModel, QoeConfig, WanScenario,
    WanSimulator,
};

fn base_scenario(name: &str, seed: u64, rtt_ms: f64, bw_kbps: u32) -> WanScenario {
    WanScenario {
        name: name.to_string(),
        seed,
        duration_ms: 14_000,
        steady_measure_start_ms: 2_500,
        base_rtt_ms: rtt_ms,
        jitter_ms: 4.0,
        max_queue_delay_ms: 400.0,
        loss_model: LossModel::None,
        bandwidth_schedule: vec![BandwidthStep {
            at_ms: 0,
            bandwidth_kbps: bw_kbps,
        }],
        step_down_check: None,
        qoe_config: QoeConfig::default(),
    }
}

#[test]
fn gate_1_ttff_20ms_120ms_220ms_p50_and_p95_ratio() {
    let cases = [
        ("ttff_rtt_20ms", 20.0, 300.0),
        ("ttff_rtt_120ms", 120.0, 600.0),
        ("ttff_rtt_220ms", 220.0, 900.0),
    ];

    for (label, rtt_ms, p50_limit_ms) in cases {
        let mut ttff_samples = Vec::with_capacity(20);
        for trial in 0..20u64 {
            let mut sc = base_scenario(label, 0x9A00 + trial, rtt_ms, 8_000);
            sc.duration_ms = 2_500;
            sc.steady_measure_start_ms = 500;
            sc.jitter_ms = (rtt_ms * 0.08).clamp(2.0, 12.0);
            let m = WanSimulator::run(&sc);
            assert_eq!(m.decoder_errors, 0, "{label} trial {trial} had decode errors");
            ttff_samples.push(m.ttff_ms as f64);
        }
        let p50 = percentile(&ttff_samples, 0.50);
        let p95 = percentile(&ttff_samples, 0.95);
        println!(
            "[GATE 1] {label}: TTFF P50={p50:.1}ms (limit <= {p50_limit_ms:.0}ms), P95={p95:.1}ms (limit <= {:.1}ms)",
            1.5 * p50
        );
        assert!(
            p50 <= p50_limit_ms,
            "{label}: TTFF P50 {p50:.1}ms exceeded {p50_limit_ms:.1}ms"
        );
        assert!(
            p95 <= 1.5 * p50,
            "{label}: TTFF P95 {p95:.1}ms exceeded 1.5 * P50 ({:.1}ms)",
            1.5 * p50
        );
    }
}

#[test]
fn gate_2_steady_glass_to_glass_latency_across_rtts() {
    for rtt_ms in [20.0, 120.0, 220.0] {
        let sc = base_scenario(&format!("g2g_rtt_{}ms", rtt_ms as u32), 0x9A20, rtt_ms, 8_000);
        let m = WanSimulator::run(&sc);
        let p50_limit = rtt_ms + 150.0;
        let p95_limit = rtt_ms + 250.0;
        println!(
            "[GATE 2] RTT={rtt_ms:.0}ms: G2G P50={:.1}ms (<= {p50_limit:.0}ms), P95={:.1}ms (<= {p95_limit:.0}ms), queue_p95={:.1}ms",
            m.glass_to_glass_p50_ms, m.glass_to_glass_p95_ms, m.p95_queue_delay_ms
        );
        assert_eq!(m.decoder_errors, 0);
        assert!(m.frames_completed_steady >= 100);
        assert!(
            m.glass_to_glass_p50_ms <= p50_limit,
            "RTT={rtt_ms}ms: G2G P50 {:.1}ms > {p50_limit:.1}ms",
            m.glass_to_glass_p50_ms
        );
        assert!(
            m.glass_to_glass_p95_ms <= p95_limit,
            "RTT={rtt_ms}ms: G2G P95 {:.1}ms > {p95_limit:.1}ms",
            m.glass_to_glass_p95_ms
        );
    }
}

#[test]
fn gate_3_five_percent_random_loss_fec_recovery_and_gilbert_elliott_burst() {
    // 3A: 5% random packet loss -> frame recovery >= 95%, FEC extra delay <= 30ms.
    let mut sc_rand = base_scenario("random_loss_5pct_fec", 0x9A30, 60.0, 4_500);
    sc_rand.duration_ms = 18_000;
    sc_rand.steady_measure_start_ms = 3_000;
    sc_rand.jitter_ms = 5.0;
    sc_rand.loss_model = LossModel::Random { loss_rate: 0.05 };
    let m_rand = WanSimulator::run(&sc_rand);

    let mut sc_rand_nofec = sc_rand.clone();
    sc_rand_nofec.name = "random_loss_5pct_no_fec".to_string();
    sc_rand_nofec.qoe_config.fec_enabled_by_policy = false;
    let m_rand_nofec = WanSimulator::run(&sc_rand_nofec);

    println!(
        "[GATE 3A] 5% Random Loss: FEC recovery={:.2}% ({}/{}) vs No-FEC={:.2}%, recovered_pkts={}, fec_delay P50={:.1}ms P95={:.1}ms max={}ms",
        m_rand.frame_recovery_rate * 100.0,
        m_rand.frames_completed_steady,
        m_rand.frames_sent_steady,
        m_rand_nofec.frame_recovery_rate * 100.0,
        m_rand.fec_recovered_packets,
        m_rand.fec_extra_delay_p50_ms,
        m_rand.fec_extra_delay_p95_ms,
        m_rand.fec_extra_delay_max_ms,
    );

    assert_eq!(m_rand.decoder_errors, 0);
    assert!(m_rand.frames_sent_steady >= 300);
    assert!(m_rand.fec_recovered_packets > 0);
    assert!(
        m_rand.frame_recovery_rate >= 0.95,
        "5% random loss frame recovery {:.2}% < 95%",
        m_rand.frame_recovery_rate * 100.0
    );
    assert!(
        m_rand.fec_extra_delay_p95_ms <= 30.0,
        "FEC extra wait delay P95 {:.1}ms > 30ms",
        m_rand.fec_extra_delay_p95_ms
    );

    // 3B: Gilbert-Elliott two-state burst loss -> FEC must substantially outperform no-FEC.
    let mut sc_ge = base_scenario("gilbert_elliott_burst_fec", 0x9A31, 60.0, 4_500);
    sc_ge.duration_ms = 18_000;
    sc_ge.steady_measure_start_ms = 3_000;
    sc_ge.jitter_ms = 5.0;
    sc_ge.loss_model = LossModel::GilbertElliott {
        p_good_to_bad: 0.018,
        p_bad_to_good: 0.48,
        loss_in_good: 0.005,
        loss_in_bad: 0.45,
    };
    let m_ge_fec = WanSimulator::run(&sc_ge);

    let mut sc_ge_nofec = sc_ge.clone();
    sc_ge_nofec.name = "gilbert_elliott_burst_no_fec".to_string();
    sc_ge_nofec.qoe_config.fec_enabled_by_policy = false;
    let m_ge_nofec = WanSimulator::run(&sc_ge_nofec);

    println!(
        "[GATE 3B] Gilbert-Elliott Burst: FEC recovery={:.2}% vs No-FEC={:.2}%, fec_delay P95={:.1}ms",
        m_ge_fec.frame_recovery_rate * 100.0,
        m_ge_nofec.frame_recovery_rate * 100.0,
        m_ge_fec.fec_extra_delay_p95_ms,
    );

    assert_eq!(m_ge_fec.decoder_errors, 0);
    assert!(
        m_ge_fec.frame_recovery_rate >= m_ge_nofec.frame_recovery_rate + 0.10,
        "Gilbert-Elliott FEC {:.2}% did not significantly outperform no-FEC {:.2}%",
        m_ge_fec.frame_recovery_rate * 100.0,
        m_ge_nofec.frame_recovery_rate * 100.0
    );
    assert!(
        m_ge_fec.fec_extra_delay_p95_ms <= 30.0,
        "Gilbert-Elliott FEC extra delay P95 {:.1}ms > 30ms",
        m_ge_fec.fec_extra_delay_p95_ms
    );
}

#[test]
fn gate_4_bandwidth_step_20m_to_2m_to_15m_convergence() {
    let sc = WanScenario {
        name: "bw_step_20m_2m_15m".to_string(),
        seed: 0x9A40,
        duration_ms: 22_000,
        steady_measure_start_ms: 2_000,
        base_rtt_ms: 40.0,
        jitter_ms: 4.0,
        max_queue_delay_ms: 400.0,
        loss_model: LossModel::None,
        bandwidth_schedule: vec![
            BandwidthStep {
                at_ms: 0,
                bandwidth_kbps: 20_000,
            },
            BandwidthStep {
                at_ms: 6_000,
                bandwidth_kbps: 2_000,
            },
            BandwidthStep {
                at_ms: 14_000,
                bandwidth_kbps: 15_000,
            },
        ],
        step_down_check: Some((6_000, 2_000)),
        qoe_config: QoeConfig::default(),
    };
    let m = WanSimulator::run(&sc);
    println!(
        "[GATE 4] 20->2->15 Mbps: converge_ms={:?} (<= 2000ms), post_step_br={:?} kbps (1700..2300), final_br={} kbps, freezes={} (<= 2), decode_err={}",
        m.step_down_converge_ms,
        m.post_step_down_bitrate_kbps,
        m.final_bitrate_kbps,
        m.freeze_events,
        m.decoder_errors,
    );

    let conv_ms = m
        .step_down_converge_ms
        .expect("bitrate failed to converge into 2000 +/- 15% band");
    assert!(
        conv_ms <= 2_000,
        "step-down convergence took {conv_ms}ms > 2000ms"
    );
    let post_br = m.post_step_down_bitrate_kbps.unwrap();
    assert!(
        (1_700..=2_300).contains(&post_br),
        "post step-down bitrate {post_br} kbps outside [1700, 2300]"
    );
    assert!(
        m.freeze_events <= 2,
        "freeze_events {} exceeded 2",
        m.freeze_events
    );
    assert_eq!(m.decoder_errors, 0);
    assert!(
        m.final_bitrate_kbps > post_br,
        "expected bitrate to probe upward after 15 Mbps recovery (post={post_br}, final={})",
        m.final_bitrate_kbps
    );
}

#[test]
fn gate_5_bufferbloat_suppression_under_bottleneck_saturation() {
    let sc = WanScenario {
        name: "bufferbloat_4m_bottleneck".to_string(),
        seed: 0x9A50,
        duration_ms: 16_000,
        steady_measure_start_ms: 2_000,
        base_rtt_ms: 40.0,
        jitter_ms: 3.0,
        max_queue_delay_ms: 400.0,
        loss_model: LossModel::None,
        bandwidth_schedule: vec![BandwidthStep {
            at_ms: 0,
            bandwidth_kbps: 4_000,
        }],
        step_down_check: None,
        qoe_config: QoeConfig {
            congestion: CongestionConfig {
                max_bitrate_kbps: 20_000,
                ..Default::default()
            },
            ..Default::default()
        },
    };
    let m = WanSimulator::run(&sc);
    println!(
        "[GATE 5] Bufferbloat (4 Mbps bottleneck, 400ms router queue): gt_steady_p95={:.1}ms, gt_steady_max={:.1}ms, gt_overall_max={:.1}ms, cc_q_p95={:.1}ms (limit <= 100ms), final_br={} kbps",
        m.steady_gt_queue_p95_ms,
        m.steady_gt_queue_max_ms,
        m.overall_gt_queue_max_ms,
        m.p95_queue_delay_ms,
        m.final_bitrate_kbps
    );
    assert_eq!(m.decoder_errors, 0);
    // Assert directly against ground-truth per-packet bottleneck queue wait (NOT just CC's self-estimate).
    assert!(
        m.steady_gt_queue_p95_ms <= 100.0,
        "ground-truth steady queue delay P95 {:.1}ms exceeded 100ms",
        m.steady_gt_queue_p95_ms
    );
    assert!(
        m.steady_gt_queue_max_ms <= 100.0,
        "ground-truth steady queue delay max {:.1}ms exceeded 100ms",
        m.steady_gt_queue_max_ms
    );
    assert!(
        m.p95_queue_delay_ms <= 100.0,
        "CC queue delay P95 {:.1}ms exceeded 100ms",
        m.p95_queue_delay_ms
    );
    assert!(
        m.max_queue_delay_ms <= 100.0,
        "CC queue delay max {:.1}ms exceeded 100ms",
        m.max_queue_delay_ms
    );
}

#[test]
fn gate_6_anti_oscillation_steady_rate_and_flip_bound() {
    let scenarios = [
        base_scenario("anti_osc_clean_6m", 0x9A60, 50.0, 6_000),
        WanScenario {
            loss_model: LossModel::Random { loss_rate: 0.02 },
            ..base_scenario("anti_osc_loss2pct_6m", 0x9A61, 60.0, 6_000)
        },
    ];

    for sc in scenarios {
        let m = WanSimulator::run(&sc);
        let total_span_ms = sc.duration_ms.max(1);
        let steady_dwell_ratio = (m.steady_duration_ms as f64) / (total_span_ms as f64);
        println!(
            "[GATE 6] {}: steady_dur={}ms (dwell_ratio={:.2} >= 0.70), steady_changes={}, changes/s={:.2} (<= 1.0), max_consecutive_flips={} (< 3), cc_transitions={} (<= 12)",
            m.scenario_name,
            m.steady_duration_ms,
            steady_dwell_ratio,
            m.steady_bitrate_changes,
            m.steady_changes_per_sec,
            m.max_consecutive_flips,
            m.cc_transitions,
        );
        assert!(
            m.steady_duration_ms >= 5_000,
            "{}: insufficient steady dwell ({}ms)",
            m.scenario_name,
            m.steady_duration_ms
        );
        assert!(
            steady_dwell_ratio >= 0.70,
            "{}: steady dwell ratio {:.2} < 0.70 (anti-oscillation gate cannot be bypassed via frequent state exits)",
            m.scenario_name,
            steady_dwell_ratio
        );
        assert!(
            m.cc_transitions <= 12,
            "{}: cc_transitions {} > 12 (excessive FSM flapping)",
            m.scenario_name,
            m.cc_transitions
        );
        assert!(
            m.steady_changes_per_sec <= 1.0,
            "{}: steady_changes_per_sec {:.2} > 1.0",
            m.scenario_name,
            m.steady_changes_per_sec
        );
        assert!(
            m.max_consecutive_flips < 3,
            "{}: max_consecutive_flips {} >= 3",
            m.scenario_name,
            m.max_consecutive_flips
        );
    }
}

#[test]
fn wan_sim_zero_arrival_blackout_feedback_and_invalid_scenario_input_safety() {
    // 100% packet loss blackout: ReceiverTick must emit zero-arrival timeout feedback so CC
    // reacts and drops bitrate from 1500 kbps rather than remaining blind.
    let mut blackout = base_scenario("total_blackout_100pct", 0x9A80, 50.0, 5_000);
    blackout.duration_ms = 4_000;
    blackout.loss_model = LossModel::Random { loss_rate: 1.0 };
    let mb = WanSimulator::run(&blackout);
    assert_eq!(mb.decoder_errors, 0);
    assert!(
        mb.cc_transitions >= 1,
        "CC must react via zero-arrival timeout feedback during 100% loss blackout"
    );
    assert!(
        mb.final_bitrate_kbps < 1_500,
        "bitrate {} should back off during total blackout",
        mb.final_bitrate_kbps
    );

    // Adversarial / unsorted / non-finite scenario inputs must normalize safely without NaN or panic.
    let ugly = WanScenario {
        name: "adversarial_inputs".to_string(),
        seed: 42,
        duration_ms: 0,
        steady_measure_start_ms: 0,
        base_rtt_ms: f64::NAN,
        jitter_ms: -10.0,
        max_queue_delay_ms: f64::NEG_INFINITY,
        loss_model: LossModel::Random { loss_rate: 5.0 },
        bandwidth_schedule: vec![
            BandwidthStep {
                at_ms: 500,
                bandwidth_kbps: 0,
            },
            BandwidthStep {
                at_ms: 0,
                bandwidth_kbps: 0,
            },
        ],
        step_down_check: None,
        qoe_config: QoeConfig::default(),
    };
    let mu = WanSimulator::run(&ugly);
    assert!(mu.steady_gt_queue_p95_ms.is_finite());
    assert!(mu.glass_to_glass_p50_ms.is_finite());
}

#[test]
fn gate_7_strict_three_run_determinism_zero_deviation() {
    let sc = WanScenario {
        name: "determinism_3x_mixed".to_string(),
        seed: 0x00C0_FFEE_9A07,
        duration_ms: 16_000,
        steady_measure_start_ms: 2_500,
        base_rtt_ms: 55.0,
        jitter_ms: 6.0,
        max_queue_delay_ms: 400.0,
        loss_model: LossModel::Random { loss_rate: 0.02 },
        bandwidth_schedule: vec![
            BandwidthStep {
                at_ms: 0,
                bandwidth_kbps: 16_000,
            },
            BandwidthStep {
                at_ms: 6_000,
                bandwidth_kbps: 2_000,
            },
            BandwidthStep {
                at_ms: 12_000,
                bandwidth_kbps: 10_000,
            },
        ],
        step_down_check: Some((6_000, 2_000)),
        qoe_config: QoeConfig::default(),
    };

    let r1 = WanSimulator::run(&sc);
    let r2 = WanSimulator::run(&sc);
    let r3 = WanSimulator::run(&sc);

    println!(
        "[GATE 7] Determinism 3x: hash={:#018x}, ttff={}ms, g2g_p50={:.2}ms, g2g_p95={:.2}ms, rec={:.4}, conv={:?}ms",
        r1.trajectory_hash,
        r1.ttff_ms,
        r1.glass_to_glass_p50_ms,
        r1.glass_to_glass_p95_ms,
        r1.frame_recovery_rate,
        r1.step_down_converge_ms,
    );

    assert_eq!(r1, r2, "run 1 vs run 2 diverged");
    assert_eq!(r2, r3, "run 2 vs run 3 diverged");
    assert_ne!(r1.trajectory_hash, 0);
}
