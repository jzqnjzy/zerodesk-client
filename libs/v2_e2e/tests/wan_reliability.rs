// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Deterministic 435 ms cross-Pacific RTT WAN reliability integration tests for Item #29:
//! - `scenario_a` reproducer: 16 KiB × 2 file transfer with trailing chunks reordered behind later packets
//! - `scenario_c1` reproducer: fixed-seed 5% loss + 10% reordering over 435 ms RTT for FileTransfer + multi-chunk Clipboard PNG
//! - Targeted single-frame drop matrix (OFFER, ACCEPT, CHUNK[0], CHUNK[last], ACK, COMPLETE, COMPLETE_ACK)
//! - 0-byte file boundary + partial-deny `send_l4_bypass_local_policy` recovery under WAN drop

use sha2::{Digest, Sha256};
use std::{
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH},
};
use tokio::{net::UdpSocket, sync::mpsc};
use v2_client::{AccessKeys, UdpAccessLink, UdpE2eeSession, V2RecvEvent};
use v2_e2e::{
    decode_clipboard_l4, decode_file_l4, prepare_outbound_clipboard, ChannelFramingErrorCounter,
    ClipMessage, ClipboardReceiver, ClipboardRecvAction, EffectiveTenantPolicy, FileChunk,
    FileMessage, FileOffer, FileRecvAction, FileSenderWindow, FileTransferReceiver, CLIP_ACK_OK,
    CLIP_MIME_IMAGE_PNG, CLIP_MSG_ACK, CLIP_MSG_CHUNK, CLIP_MSG_SYNC, FILE_COMPLETE_ACK_OK,
    FILE_ERR_POLICY_DENIED, FILE_MSG_ABORT, FILE_MSG_ACCEPT, FILE_MSG_ACK, FILE_MSG_CHUNK,
    FILE_MSG_COMPLETE, FILE_MSG_COMPLETE_ACK, FILE_MSG_OFFER,
};
use v2_transport::{
    seal_udp_v11, AccessEpochState, AccessFlags, AccessHeaderV11, EdgeCtrlFrame,
    QuotaExhaustPolicy, VerifiedTenantPolicy, CHAN_CLIPBOARD, CHAN_FILE_TRANSFER,
    DIR_CLIENT_TO_EDGE, TRANSPORT_DATAGRAM,
};
use zerodesk_core::session::policy::{
    TenantPolicyBody, POLICY_FLAG_ALLOW_CLIPBOARD, POLICY_FLAG_ALLOW_FILE_TRANSFER,
};

#[derive(Clone, Copy)]
struct WanRelayProfile {
    one_way_ms: u64,
    drop_pct_a2b: u32,
    drop_pct_b2a: u32,
    reorder_pct: u32,
    reorder_extra_ms: u64,
    /// Optional 1-indexed p3 packet index to drop once on a->b (0 = disabled).
    drop_exact_a2b_p3: usize,
    /// Optional 1-indexed p3 packet index to drop once on b->a (0 = disabled).
    drop_exact_b2a_p3: usize,
    /// Optional 1-indexed inclusive range of a->b p3 packets to delay by +120ms (for reordering).
    delay_a2b_p3_range: Option<(usize, usize)>,
    prng_seed: u64,
}

impl Default for WanRelayProfile {
    fn default() -> Self {
        Self {
            one_way_ms: 217,
            drop_pct_a2b: 0,
            drop_pct_b2a: 0,
            reorder_pct: 0,
            reorder_extra_ms: 90,
            drop_exact_a2b_p3: 0,
            drop_exact_b2a_p3: 0,
            delay_a2b_p3_range: None,
            prng_seed: 0x5EED_C100_2026_0001,
        }
    }
}

fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

struct WanSessionPair {
    sess_a: UdpE2eeSession,
    sess_b: UdpE2eeSession,
    stop_tx: mpsc::Sender<()>,
    relay_task: tokio::task::JoinHandle<()>,
}

fn allow_all_verified_policy() -> VerifiedTenantPolicy {
    VerifiedTenantPolicy {
        tenant_id: [0x11; 16],
        policy_version: 1,
        policy_hash: [0x22; 32],
        allow_file_transfer: true,
        allow_clipboard: true,
        allow_file_clipboard: true,
        allow_tcp_tunnel: false,
        allow_terminal: false,
        allow_realtime_actuator: false,
        bw_cap_kbps: 20_000,
        exhaust_policy: QuotaExhaustPolicy::Throttle256Kbps,
    }
}

fn effective_policy(allow_clip: bool, allow_file: bool) -> EffectiveTenantPolicy {
    let mut flags = 0u32;
    if allow_clip {
        flags |= POLICY_FLAG_ALLOW_CLIPBOARD;
    }
    if allow_file {
        flags |= POLICY_FLAG_ALLOW_FILE_TRANSFER;
    }
    EffectiveTenantPolicy {
        tenant_id: [0x11; 16],
        version: 1,
        exp_unix: u64::MAX,
        policy_hash: [0x22; 32],
        body: TenantPolicyBody {
            schema_ver: 1,
            flags,
            max_bw_kbps: 20_000,
            max_file_mb: 16,
            max_clipboard_kb: 256,
        },
        degraded: false,
        degraded_reason: None,
    }
}

fn unique_temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("zd-wan-{tag}-{}-{nanos}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

async fn spawn_wan_session_pair(
    profile: WanRelayProfile,
    policy_a: VerifiedTenantPolicy,
    policy_b: VerifiedTenantPolicy,
) -> WanSessionPair {
    let relay_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr_a = relay_a.local_addr().unwrap();
    let addr_b = relay_b.local_addr().unwrap();

    let cid_a = [0x81; 8];
    let cid_b = [0x82; 8];
    let hs_a = [0x83; 32];
    let hs_b = [0x84; 32];
    let keys_a = AccessKeys::derive(cid_a, hs_a, 0).unwrap();
    let keys_b = AccessKeys::derive(cid_b, hs_b, 0).unwrap();

    let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
    let ka = keys_a.clone();
    let kb = keys_b.clone();
    let ra = Arc::clone(&relay_a);
    let rb = Arc::clone(&relay_b);

    let relay_task = tokio::spawn(async move {
        let mut rx_a =
            AccessEpochState::new(cid_a, hs_a, TRANSPORT_DATAGRAM, DIR_CLIENT_TO_EDGE, 0, 10)
                .unwrap();
        let mut rx_b =
            AccessEpochState::new(cid_b, hs_b, TRANSPORT_DATAGRAM, DIR_CLIENT_TO_EDGE, 0, 10)
                .unwrap();
        let mut peer_a: Option<SocketAddr> = None;
        let mut peer_b: Option<SocketAddr> = None;
        let mut seq_to_a = 1u32;
        let mut seq_to_b = 1u32;
        let mut a2b_p3_seen = 0usize;
        let mut b2a_p3_seen = 0usize;
        // Separate per-direction fixed-seed PRNGs so drop/reorder decisions are 100% deterministic
        // independent of tokio::select! polling order.
        let mut prng_a2b = profile.prng_seed;
        let mut prng_b2a = profile.prng_seed ^ 0x9E37_79B9_7F4A_7C15;
        let mut ba = [0u8; 4096];
        let mut bb = [0u8; 4096];

        loop {
            tokio::select! {
                _ = stop_rx.recv() => break,
                Ok((n, src)) = ra.recv_from(&mut ba) => {
                    peer_a = Some(src);
                    if let Ok((hdr, body)) = rx_a.verify_udp_packet(&ba[..n], 100) {
                        if hdr.flags.is_ctrl_edge {
                            if let Ok(EdgeCtrlFrame::Ping { ts_us }) = EdgeCtrlFrame::decode(body) {
                                let ph = AccessHeaderV11 {
                                    flags: AccessFlags {
                                        pp: 0, discardable: false, frame_end: false,
                                        is_ctrl_edge: true, dir_edge_to_client: true, rtx: false,
                                    },
                                    route_cid: cid_a, access_epoch: 0, leg_seq: 0, mac_64: [0; 8],
                                };
                                let w = seal_udp_v11(
                                    &ka.udp_key_e2c,
                                    ph,
                                    &EdgeCtrlFrame::Pong { ts_us }.encode(),
                                ).unwrap();
                                let sock_out = Arc::clone(&ra);
                                let ping_delay_ms = profile.one_way_ms;
                                tokio::spawn(async move {
                                    if ping_delay_ms > 0 {
                                        tokio::time::sleep(Duration::from_millis(ping_delay_ms)).await;
                                    }
                                    let _ = sock_out.send_to(&w, src).await;
                                });
                            }
                        } else if let Some(dst) = peer_b {
                            let is_p3 = hdr.flags.pp == 3;
                            if is_p3 {
                                a2b_p3_seen += 1;
                                if profile.drop_exact_a2b_p3 != 0 && a2b_p3_seen == profile.drop_exact_a2b_p3 {
                                    continue;
                                }
                            }
                            if profile.drop_pct_a2b > 0 && (xorshift64(&mut prng_a2b) % 100) < u64::from(profile.drop_pct_a2b) {
                                continue;
                            }
                            let mut delay_ms = profile.one_way_ms;
                            if is_p3 {
                                if let Some((lo, hi)) = profile.delay_a2b_p3_range {
                                    if a2b_p3_seen >= lo && a2b_p3_seen <= hi {
                                        delay_ms = delay_ms.saturating_add(120);
                                    }
                                }
                            }
                            if profile.reorder_pct > 0 && (xorshift64(&mut prng_a2b) % 100) < u64::from(profile.reorder_pct) {
                                delay_ms = delay_ms.saturating_add(profile.reorder_extra_ms);
                            }
                            // Assign leg_seq at ingress BEFORE spawning delayed delivery so
                            // reordered packets arrive with genuine out-of-order leg_seq.
                            let leg_seq = seq_to_b;
                            seq_to_b = seq_to_b.wrapping_add(1);
                            let payload = body.to_vec();
                            let flags = hdr.flags;
                            let sock_out = Arc::clone(&rb);
                            let key_out = *kb.udp_key_e2c;
                            tokio::spawn(async move {
                                if delay_ms > 0 {
                                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                }
                                let fh = AccessHeaderV11 {
                                    flags: AccessFlags {
                                        pp: flags.pp,
                                        discardable: flags.discardable,
                                        frame_end: false,
                                        is_ctrl_edge: false,
                                        dir_edge_to_client: true,
                                        rtx: false,
                                    },
                                    route_cid: cid_b,
                                    access_epoch: 0,
                                    leg_seq,
                                    mac_64: [0; 8],
                                };
                                let w = seal_udp_v11(&key_out, fh, &payload).unwrap();
                                let _ = sock_out.send_to(&w, dst).await;
                            });
                        }
                    }
                }
                Ok((n, src)) = rb.recv_from(&mut bb) => {
                    peer_b = Some(src);
                    if let Ok((hdr, body)) = rx_b.verify_udp_packet(&bb[..n], 100) {
                        if hdr.flags.is_ctrl_edge {
                            if let Ok(EdgeCtrlFrame::Ping { ts_us }) = EdgeCtrlFrame::decode(body) {
                                let ph = AccessHeaderV11 {
                                    flags: AccessFlags {
                                        pp: 0, discardable: false, frame_end: false,
                                        is_ctrl_edge: true, dir_edge_to_client: true, rtx: false,
                                    },
                                    route_cid: cid_b, access_epoch: 0, leg_seq: 0, mac_64: [0; 8],
                                };
                                let w = seal_udp_v11(
                                    &kb.udp_key_e2c,
                                    ph,
                                    &EdgeCtrlFrame::Pong { ts_us }.encode(),
                                ).unwrap();
                                let sock_out = Arc::clone(&rb);
                                let ping_delay_ms = profile.one_way_ms;
                                tokio::spawn(async move {
                                    if ping_delay_ms > 0 {
                                        tokio::time::sleep(Duration::from_millis(ping_delay_ms)).await;
                                    }
                                    let _ = sock_out.send_to(&w, src).await;
                                });
                            }
                        } else if let Some(dst) = peer_a {
                            let is_p3 = hdr.flags.pp == 3;
                            if is_p3 {
                                b2a_p3_seen += 1;
                                if profile.drop_exact_b2a_p3 != 0 && b2a_p3_seen == profile.drop_exact_b2a_p3 {
                                    continue;
                                }
                            }
                            if profile.drop_pct_b2a > 0 && (xorshift64(&mut prng_b2a) % 100) < u64::from(profile.drop_pct_b2a) {
                                continue;
                            }
                            let mut delay_ms = profile.one_way_ms;
                            if profile.reorder_pct > 0 && (xorshift64(&mut prng_b2a) % 100) < u64::from(profile.reorder_pct) {
                                delay_ms = delay_ms.saturating_add(profile.reorder_extra_ms);
                            }
                            let leg_seq = seq_to_a;
                            seq_to_a = seq_to_a.wrapping_add(1);
                            let payload = body.to_vec();
                            let flags = hdr.flags;
                            let sock_out = Arc::clone(&ra);
                            let key_out = *ka.udp_key_e2c;
                            tokio::spawn(async move {
                                if delay_ms > 0 {
                                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                }
                                let fh = AccessHeaderV11 {
                                    flags: AccessFlags {
                                        pp: flags.pp,
                                        discardable: flags.discardable,
                                        frame_end: false,
                                        is_ctrl_edge: false,
                                        dir_edge_to_client: true,
                                        rtx: false,
                                    },
                                    route_cid: cid_a,
                                    access_epoch: 0,
                                    leg_seq,
                                    mac_64: [0; 8],
                                };
                                let w = seal_udp_v11(&key_out, fh, &payload).unwrap();
                                let _ = sock_out.send_to(&w, dst).await;
                            });
                        }
                    }
                }
            }
        }
    });

    let mut link_a = UdpAccessLink::connect(&addr_a.to_string(), &keys_a, 20_000)
        .await
        .unwrap();
    let mut link_b = UdpAccessLink::connect(&addr_b.to_string(), &keys_b, 20_000)
        .await
        .unwrap();
    link_a.auto_leg_nack = false;
    link_b.auto_leg_nack = false;
    link_a
        .ping_with_retry(1, Duration::from_secs(2))
        .await
        .unwrap();
    link_b
        .ping_with_retry(1, Duration::from_secs(2))
        .await
        .unwrap();

    let sess_a = UdpE2eeSession::from_keys(link_a, [0xA1; 32], [0xB2; 32], policy_a, [0x01; 16]);
    let sess_b = UdpE2eeSession::from_keys(link_b, [0xB2; 32], [0xA1; 32], policy_b, [0x02; 16]);
    WanSessionPair {
        sess_a,
        sess_b,
        stop_tx,
        relay_task,
    }
}

async fn run_file_transfer_sender_window(
    sess: &mut UdpE2eeSession,
    policy: &EffectiveTenantPolicy,
    transfer_id: u64,
    rel_name: &str,
    data: &[u8],
) -> Result<[u8; 32], String> {
    let sha256: [u8; 32] = Sha256::digest(data).into();
    let (mut win, offer) = FileSenderWindow::new(
        policy,
        transfer_id,
        rel_name,
        data.len() as u64,
        1024,
        sha256,
        StdInstant::now(),
    )
    .map_err(|e| e.to_string())?;

    let offer_bytes = offer.encode().map_err(|e| e.to_string())?;
    let mut offer_sent = match sess
        .send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_OFFER, 0, false, &offer_bytes)
        .await
    {
        Ok(_) => true,
        Err(v2_client::ClientError::P3Backpressure { .. }) => false,
        Err(e) => return Err(e.to_string()),
    };

    let mut complete_sent = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if !offer_sent {
            match sess
                .send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_OFFER, 0, false, &offer_bytes)
                .await
            {
                Ok(_) => offer_sent = true,
                Err(v2_client::ClientError::P3Backpressure { .. }) => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        while let Some((off, len)) = win.next_chunk_range(false) {
            let chunk = FileChunk {
                transfer_id,
                offset: off,
                data: data[off as usize..(off as usize + len)].to_vec(),
            };
            let wire = chunk.encode().map_err(|e| e.to_string())?;
            match sess
                .send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_CHUNK, 0, false, &wire)
                .await
            {
                Ok(_) => win.mark_chunk_sent(off, len, StdInstant::now()),
                Err(v2_client::ClientError::P3Backpressure { .. }) => break,
                Err(e) => return Err(e.to_string()),
            }
        }
        if !complete_sent && win.ready_for_complete() {
            let comp = win.peek_complete();
            match sess
                .send_l4_raw(
                    CHAN_FILE_TRANSFER,
                    FILE_MSG_COMPLETE,
                    0,
                    false,
                    &comp.encode(),
                )
                .await
            {
                Ok(_) => {
                    win.commit_complete(StdInstant::now());
                    complete_sent = true;
                }
                Err(v2_client::ClientError::P3Backpressure { .. }) => {}
                Err(e) => return Err(e.to_string()),
            }
        }

        if tokio::time::Instant::now() >= deadline {
            return Err("file sender timed out".into());
        }
        match sess.recv_v124_event(Duration::from_millis(50)).await {
            Ok(V2RecvEvent::FileTransferRaw(raw)) => {
                match decode_file_l4(&raw.header, &raw.body).map_err(|e| e.to_string())? {
                    FileMessage::Accept(acc) if acc.transfer_id == transfer_id => {
                        win.on_accept(&acc, StdInstant::now())
                            .map_err(|e| e.to_string())?;
                    }
                    FileMessage::Ack(ack) if ack.transfer_id == transfer_id => {
                        win.on_ack(&ack, StdInstant::now())
                            .map_err(|e| e.to_string())?;
                    }
                    FileMessage::CompleteAck(cack) if cack.transfer_id == transfer_id => {
                        if cack.status != FILE_COMPLETE_ACK_OK {
                            return Err(format!("FILE_COMPLETE_ACK status={}", cack.status));
                        }
                        return Ok(sha256);
                    }
                    FileMessage::Abort(ab) if ab.transfer_id == transfer_id => {
                        return Err(format!("FILE_ABORT error_code=0x{:04x}", ab.error_code));
                    }
                    _ => {}
                }
            }
            Ok(_) | Err(v2_client::ClientError::Timeout(_)) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
}

async fn run_host_receiver_loop(
    mut sess: UdpE2eeSession,
    policy: EffectiveTenantPolicy,
    dl_dir: PathBuf,
    expected_files: usize,
    expected_clips: usize,
) -> Result<(Vec<PathBuf>, Vec<[u8; 32]>), String> {
    let mut file_rx = FileTransferReceiver::new(policy.clone(), dl_dir);
    let mut clip_rx = ClipboardReceiver::new(policy);
    let mut err_cnt = ChannelFramingErrorCounter::new();
    let mut saved_files = Vec::new();
    let mut delivered_clips = Vec::new();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while (saved_files.len() < expected_files || delivered_clips.len() < expected_clips)
        && tokio::time::Instant::now() < deadline
    {
        match sess.recv_v124_event(Duration::from_millis(50)).await {
            Ok(V2RecvEvent::FileTransferRaw(raw)) => {
                match file_rx.on_l4_frame(&raw.header, &raw.body, StdInstant::now(), &mut err_cnt) {
                    FileRecvAction::SendAccept(acc) => {
                        let w = acc.encode().map_err(|e| e.to_string())?;
                        sess.send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_ACCEPT, 0, false, &w)
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                    FileRecvAction::SendAck(ack) => {
                        let w = ack.encode().map_err(|e| e.to_string())?;
                        sess.send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_ACK, 0, false, &w)
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                    FileRecvAction::SendCompleteAck {
                        ack,
                        saved_path,
                        ..
                    } => {
                        let w = ack.encode().map_err(|e| e.to_string())?;
                        sess.send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_COMPLETE_ACK, 0, false, &w)
                            .await
                            .map_err(|e| e.to_string())?;
                        if ack.status == FILE_COMPLETE_ACK_OK {
                            if let Some(p) = saved_path {
                                saved_files.push(p);
                            }
                        }
                    }
                    FileRecvAction::SendAbort(ab) => {
                        sess.send_l4_raw(
                            CHAN_FILE_TRANSFER,
                            FILE_MSG_ABORT,
                            0,
                            false,
                            &ab.encode(),
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                    }
                    FileRecvAction::SessionFatal(r) => return Err(format!("host file fatal: {r}")),
                    FileRecvAction::None => {}
                }
            }
            Ok(V2RecvEvent::ClipboardRaw(raw)) => {
                match clip_rx.on_l4_frame(&raw.header, &raw.body, StdInstant::now(), &mut err_cnt) {
                    ClipboardRecvAction::SendAck(ack) => {
                        let w = ack.encode().map_err(|e| e.to_string())?;
                        sess.send_l4_raw(CHAN_CLIPBOARD, CLIP_MSG_ACK, 0, false, &w)
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                    ClipboardRecvAction::DeliverAndAck { delivered, ack } => {
                        let w = ack.encode().map_err(|e| e.to_string())?;
                        sess.send_l4_raw(CHAN_CLIPBOARD, CLIP_MSG_ACK, 0, false, &w)
                            .await
                            .map_err(|e| e.to_string())?;
                        delivered_clips.push(delivered.sha256);
                    }
                    ClipboardRecvAction::SessionFatal(r) => {
                        return Err(format!("host clip fatal: {r}"));
                    }
                    ClipboardRecvAction::None => {}
                }
            }
            Ok(_) | Err(v2_client::ClientError::Timeout(_)) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    // Keep driving ARQ briefly so final COMPLETE_ACK / CLIP_ACK retransmits if lost on return leg.
    let settle = tokio::time::Instant::now() + Duration::from_secs(2);
    while (sess.p3_arq_inflight_pkts(CHAN_FILE_TRANSFER) > 0
        || sess.p3_arq_inflight_pkts(CHAN_CLIPBOARD) > 0)
        && tokio::time::Instant::now() < settle
    {
        let _ = sess.recv_v124_event(Duration::from_millis(50)).await;
    }
    if err_cnt.consecutive() != 0 {
        return Err(format!("non-zero framing errors: {}", err_cnt.consecutive()));
    }
    Ok((saved_files, delivered_clips))
}

#[tokio::test]
async fn wan_435ms_scenario_a_file_complete_reordered_ahead_of_trailing_chunks() {
    let dl_dir = unique_temp_dir("scenario_a");
    let pol_v = allow_all_verified_policy();
    let pol_e = effective_policy(true, true);

    // Delay the trailing 3 chunks of the first 16 KiB burst (p3 pkts 15..=17) by +120ms so
    // any premature FILE_COMPLETE would overtake them over 435ms RTT.
    let profile = WanRelayProfile {
        one_way_ms: 217,
        delay_a2b_p3_range: Some((15, 17)),
        ..WanRelayProfile::default()
    };
    let mut pair = spawn_wan_session_pair(profile, pol_v.clone(), pol_v).await;
    let payload: Vec<u8> = (0..(16 * 1024))
        .map(|i| ((i * 37 + 13) & 0xFF) as u8)
        .collect();
    let expected_sha: [u8; 32] = Sha256::digest(&payload).into();

    let host_dl = dl_dir.clone();
    let host_pol = pol_e.clone();
    let host_task = tokio::spawn(async move {
        run_host_receiver_loop(pair.sess_b, host_pol, host_dl, 2, 0).await
    });

    for idx in 1..=2u64 {
        let sha = run_file_transfer_sender_window(
            &mut pair.sess_a,
            &pol_e,
            100 + idx,
            "phase4b_sample.bin",
            &payload,
        )
        .await
        .unwrap();
        assert_eq!(sha, expected_sha);
    }

    let (saved, _) = host_task.await.unwrap().unwrap();
    assert_eq!(saved.len(), 2);
    assert_eq!(fs::read(&saved[0]).unwrap(), payload);
    assert_eq!(fs::read(&saved[1]).unwrap(), payload);
    assert!(
        saved[1]
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.contains("(1)")),
        "second transfer should collision-rename with (1): {:?}",
        saved[1]
    );

    let _ = pair.stop_tx.send(()).await;
    pair.relay_task.abort();
    let _ = fs::remove_dir_all(&dl_dir);
}

#[tokio::test]
async fn wan_435ms_scenario_c1_asymmetric_loss_and_reorder_file_and_clipboard() {
    let dl_dir = unique_temp_dir("scenario_c1");
    let pol_v = allow_all_verified_policy();
    let pol_e = effective_policy(true, true);

    // 435 ms RTT with fixed-seed 5% loss + 10% reordering on the UDP leg (both directions).
    let profile = WanRelayProfile {
        one_way_ms: 217,
        drop_pct_a2b: 5,
        drop_pct_b2a: 5,
        reorder_pct: 10,
        reorder_extra_ms: 95,
        prng_seed: 0x5EED_C100_2026_0001,
        ..WanRelayProfile::default()
    };
    let mut pair = spawn_wan_session_pair(profile, pol_v.clone(), pol_v).await;

    let file_payload: Vec<u8> = (0..(16 * 1024))
        .map(|i| ((i * 53 + 19) & 0xFF) as u8)
        .collect();
    let file_sha: [u8; 32] = Sha256::digest(&file_payload).into();

    // 16 KiB valid PNG-signature + IHDR clipboard payload (16 chunks of 1024B).
    let mut png_payload = vec![
        0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
        0x00, 0x00, 0x00, 0x0D, b'I', b'H', b'D', b'R', // IHDR length=13
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1
        0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE, // 8-bit RGB + CRC
    ];
    png_payload.resize(16 * 1024, 0x5A);
    let png_sha: [u8; 32] = Sha256::digest(&png_payload).into();

    let host_dl = dl_dir.clone();
    let host_pol = pol_e.clone();
    let host_task = tokio::spawn(async move {
        run_host_receiver_loop(pair.sess_b, host_pol, host_dl, 1, 1).await
    });

    // 1. Multi-chunk 16 KiB Clipboard PNG transfer over lossy + reordered 435 ms RTT link
    let clip_tx = prepare_outbound_clipboard(
        &pol_e,
        CLIP_MIME_IMAGE_PNG,
        &png_payload,
        42,
        0xCAFE_0042,
        false,
    )
    .unwrap();
    let mut clip_frames: Vec<(u8, Vec<u8>)> = Vec::with_capacity(1 + clip_tx.chunks.len());
    clip_frames.push((CLIP_MSG_SYNC, clip_tx.sync.encode().unwrap().to_vec()));
    for ch in &clip_tx.chunks {
        clip_frames.push((CLIP_MSG_CHUNK, ch.encode().unwrap()));
    }
    let mut clip_idx = 0usize;
    let mut got_clip_ack = false;
    let clip_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !got_clip_ack && tokio::time::Instant::now() < clip_deadline {
        while clip_idx < clip_frames.len() {
            let (mt, ref body) = clip_frames[clip_idx];
            match pair
                .sess_a
                .send_l4_raw(CHAN_CLIPBOARD, mt, 0, false, body)
                .await
            {
                Ok(_) => clip_idx += 1,
                Err(v2_client::ClientError::P3Backpressure { .. }) => break,
                Err(e) => panic!("clip send failed: {e}"),
            }
        }
        match pair.sess_a.recv_v124_event(Duration::from_millis(50)).await {
            Ok(V2RecvEvent::ClipboardRaw(raw)) => {
                if let Ok(ClipMessage::Ack(ack)) = decode_clipboard_l4(&raw.header, &raw.body) {
                    assert_eq!(ack.clip_id, 42);
                    assert_eq!(ack.status, CLIP_ACK_OK);
                    got_clip_ack = true;
                }
            }
            Ok(_) | Err(v2_client::ClientError::Timeout(_)) => {}
            Err(e) => panic!("clip recv failed: {e}"),
        }
    }
    assert!(got_clip_ack, "multi-chunk clipboard PNG must complete under 5% loss + 10% reorder");

    // 2. 16 KiB File transfer over the same lossy + reordered 435 ms RTT link
    let got_sha = run_file_transfer_sender_window(
        &mut pair.sess_a,
        &pol_e,
        201,
        "scenario_c1_file.bin",
        &file_payload,
    )
    .await
    .unwrap();
    assert_eq!(got_sha, file_sha);
    assert!(
        pair.sess_a.p3_arq_rtx_sent(CHAN_FILE_TRANSFER)
            + pair.sess_a.p3_arq_rtx_sent(CHAN_CLIPBOARD)
            > 0,
        "expected P3 ARQ retransmits under 5% loss"
    );

    let (saved, clips) = host_task.await.unwrap().unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(fs::read(&saved[0]).unwrap(), file_payload);
    assert_eq!(clips, vec![png_sha]);

    let _ = pair.stop_tx.send(()).await;
    pair.relay_task.abort();
    let _ = fs::remove_dir_all(&dl_dir);
}

#[tokio::test]
async fn wan_435ms_targeted_single_frame_drop_matrix() {
    // 4 KiB file => 4 chunks (1024B each):
    // a->b p3 pkts: #1 OFFER, #2 CHUNK[0], #3 CHUNK[1], #4 CHUNK[2], #5 CHUNK[3], #6 COMPLETE
    // b->a p3 pkts: #1 ACCEPT, #2 ACK[0], #3 ACK[1], #4 ACK[2], #5 ACK[3], #6 COMPLETE_ACK
    let cases: &[(&str, usize, usize)] = &[
        ("drop_FILE_OFFER", 1, 0),
        ("drop_FILE_ACCEPT", 0, 1),
        ("drop_FILE_CHUNK_0", 2, 0),
        ("drop_FILE_CHUNK_last", 5, 0),
        ("drop_FILE_ACK", 0, 2),
        ("drop_FILE_COMPLETE", 6, 0),
        ("drop_FILE_COMPLETE_ACK", 0, 6),
    ];

    let payload: Vec<u8> = (0..4096).map(|i| ((i * 17 + 3) & 0xFF) as u8).collect();
    let expected_sha: [u8; 32] = Sha256::digest(&payload).into();
    let pol_v = allow_all_verified_policy();
    let pol_e = effective_policy(true, true);

    let mut handles = Vec::with_capacity(cases.len());
    for &(label, drop_a2b, drop_b2a) in cases {
        let payload = payload.clone();
        let pol_v = pol_v.clone();
        let pol_e = pol_e.clone();
        handles.push(tokio::spawn(async move {
            let dl_dir = unique_temp_dir(label);
            let profile = WanRelayProfile {
                one_way_ms: 217,
                drop_exact_a2b_p3: drop_a2b,
                drop_exact_b2a_p3: drop_b2a,
                ..WanRelayProfile::default()
            };
            let mut pair = spawn_wan_session_pair(profile, pol_v.clone(), pol_v).await;
            let host_dl = dl_dir.clone();
            let host_pol = pol_e.clone();
            let host_task = tokio::spawn(async move {
                run_host_receiver_loop(pair.sess_b, host_pol, host_dl, 1, 0).await
            });

            let sha = run_file_transfer_sender_window(
                &mut pair.sess_a,
                &pol_e,
                301,
                "matrix.bin",
                &payload,
            )
            .await
            .unwrap_or_else(|e| panic!("case {label} failed: {e}"));
            assert_eq!(sha, expected_sha, "case {label} sha mismatch");

            let (saved, _) = host_task
                .await
                .unwrap()
                .unwrap_or_else(|e| panic!("case {label} host failed: {e}"));
            assert_eq!(saved.len(), 1, "case {label} saved count");
            assert_eq!(fs::read(&saved[0]).unwrap(), payload, "case {label} bytes");

            let _ = pair.stop_tx.send(()).await;
            pair.relay_task.abort();
            let _ = fs::remove_dir_all(&dl_dir);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn wan_435ms_zero_byte_file_and_partial_deny_bypass_local_policy() {
    // 1. 0-byte file transfer with dropped FILE_OFFER over 435 ms RTT
    let dl_dir = unique_temp_dir("zero_byte");
    let pol_v = allow_all_verified_policy();
    let pol_e = effective_policy(true, true);
    let profile = WanRelayProfile {
        one_way_ms: 217,
        drop_exact_a2b_p3: 1,
        ..WanRelayProfile::default()
    };
    let mut pair = spawn_wan_session_pair(profile, pol_v.clone(), pol_v).await;
    let host_dl = dl_dir.clone();
    let host_pol = pol_e.clone();
    let host_task = tokio::spawn(async move {
        run_host_receiver_loop(pair.sess_b, host_pol, host_dl, 1, 0).await
    });

    let empty_sha: [u8; 32] = Sha256::digest(b"").into();
    let got_sha =
        run_file_transfer_sender_window(&mut pair.sess_a, &pol_e, 401, "empty.bin", b"")
            .await
            .unwrap();
    assert_eq!(got_sha, empty_sha);
    let (saved, _) = host_task.await.unwrap().unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(fs::read(&saved[0]).unwrap().len(), 0);
    let _ = pair.stop_tx.send(()).await;
    pair.relay_task.abort();
    let _ = fs::remove_dir_all(&dl_dir);

    // 2. Partial-deny (clipboard allowed, file denied) with dropped FILE_OFFER:
    //    `send_l4_bypass_local_policy` uses P3 ARQ so Host reliably receives FILE_OFFER
    //    and replies FILE_ABORT(0x0401) even when first attempt is lost!
    let dl_dir2 = unique_temp_dir("partial_deny");
    let mut partial_pol_v = allow_all_verified_policy();
    partial_pol_v.allow_file_transfer = false;
    let partial_pol_e = effective_policy(true, false);
    let mut pair2 = spawn_wan_session_pair(profile, partial_pol_v.clone(), partial_pol_v).await;

    let host_dl2 = dl_dir2.clone();
    let host_task2 = tokio::spawn(async move {
        let mut file_rx = FileTransferReceiver::new(partial_pol_e, host_dl2);
        let mut err_cnt = ChannelFramingErrorCounter::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline {
            match pair2.sess_b.recv_v124_event(Duration::from_millis(50)).await {
                Ok(V2RecvEvent::FileTransferRaw(raw)) => {
                    if let FileRecvAction::SendAbort(ab) = file_rx.on_l4_frame(
                        &raw.header,
                        &raw.body,
                        StdInstant::now(),
                        &mut err_cnt,
                    ) {
                        pair2
                            .sess_b
                            .send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_ABORT, 0, false, &ab.encode())
                            .await
                            .unwrap();
                        // Drive ARQ briefly until abort is ACKed
                        let settle = tokio::time::Instant::now() + Duration::from_secs(2);
                        while pair2.sess_b.p3_arq_inflight_pkts(CHAN_FILE_TRANSFER) > 0
                            && tokio::time::Instant::now() < settle
                        {
                            let _ = pair2.sess_b.recv_v124_event(Duration::from_millis(50)).await;
                        }
                        return ab.error_code;
                    }
                }
                Ok(_) | Err(v2_client::ClientError::Timeout(_)) => {}
                Err(e) => panic!("host partial deny err: {e}"),
            }
        }
        panic!("host never received partial-deny FILE_OFFER");
    });

    let offer = FileOffer {
        transfer_id: 902,
        file_size: 16,
        chunk_size: 1024,
        sha256: Sha256::digest(b"0123456789abcdef").into(),
        rel_name: "denied.txt".into(),
    };
    pair2
        .sess_a
        .send_l4_bypass_local_policy(CHAN_FILE_TRANSFER, FILE_MSG_OFFER, &offer.encode().unwrap())
        .await
        .unwrap();

    let mut got_abort_code = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while got_abort_code.is_none() && tokio::time::Instant::now() < deadline {
        match pair2.sess_a.recv_v124_event(Duration::from_millis(50)).await {
            Ok(V2RecvEvent::FileTransferRaw(raw)) => {
                if let Ok(FileMessage::Abort(ab)) = decode_file_l4(&raw.header, &raw.body) {
                    got_abort_code = Some(ab.error_code);
                }
            }
            Ok(_) | Err(v2_client::ClientError::Timeout(_)) => {}
            Err(e) => panic!("ctl partial deny err: {e}"),
        }
    }
    assert_eq!(got_abort_code, Some(FILE_ERR_POLICY_DENIED));
    assert_eq!(host_task2.await.unwrap(), FILE_ERR_POLICY_DENIED);

    let _ = pair2.stop_tx.send(()).await;
    pair2.relay_task.abort();
    let _ = fs::remove_dir_all(&dl_dir2);
}
