// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::{
    controller::{
        load_config_json, normalize_codec_setting, BridgePersistedConfig, BridgeSnapshot,
        BridgeState, PolicySummary, RedactedConfigView, V2BridgeController, VerifiedCallerDisplay,
        BRIDGE_JSON_ABI_V2, BRIDGE_V2_CAPABILITIES,
    },
    events::BridgeEventHub,
    json_abi::{
        parse_and_validate_command, CodecAckPayload, HandshakeCapabilitiesData, HudStatsPayload,
        RuntimeCommandEnvelope, RuntimeReplyEnvelope, MAX_BITRATE_KBPS, MAX_FPS_CAP,
        MIN_BITRATE_KBPS, MIN_FPS_CAP,
    },
};
use crate::{
    frame::{FrameError, FrameInfo, FrameMailbox, PixelFormat},
    os::{
        audio::{open_os_audio_capture, open_os_audio_playback, AudioStatusChanged},
        capture::{
            convert_captured_stride_to_i420, create_os_screen_capture_with_policy,
            preflight_screen_capture_permission,
        },
        clipboard::{
            create_os_clipboard_backend, validate_clipboard_png_bytes, ClipboardPoller,
        },
        dryrun::{
            raw_captured_to_i420, DryRunHidJournal, DryRunHidSink, MemoryClipboardBackend,
            SilentAudioCapture, SilentAudioPlayback, SyntheticScreenSource,
        },
        input::{
            create_real_os_hid_sink, GatedOsHidSink, OsInputGateError, PermissionProbe,
            PermissionStatusReport, RealInputPermit, SystemPermissionProbe,
        },
        watchdog_supervisor::{
            HidWatchdogConfig, HidWatchdogSupervisor, WatchdogSupervisedHidSink,
        },
        EmergencyKeyReleaser, OsAudioCapture, OsAudioPlayback, OsError, OsHidSink, OsPermission,
        OsScreenCapture,
    },
    session::{
        audio::{
            AudioChannelGate, AudioJitterBuffer, AudioSource, OpusWireFrame,
            SyntheticMultiToneSource, V2AudioDecoder, V2AudioEncoder, AUDIO_DEFAULT_BITRATE_BPS,
            AUDIO_FRAME_SAMPLES_PER_CH, AUDIO_JITTER_MAX_FRAMES, AUDIO_JITTER_MIN_FRAMES,
        },
        clipboard::{
            check_clipboard_policy_for_sync, decode_clipboard_l4, prepare_outbound_clipboard,
            ChannelFramingErrorCounter, ClipMessage, ClipboardReceiver, ClipboardRecvAction,
            CLIP_ACK_OK, CLIP_HARD_MAX_BYTES, CLIP_MIME_IMAGE_PNG, CLIP_MIME_TEXT_UTF8,
            CLIP_MSG_ACK, CLIP_MSG_CHUNK, CLIP_MSG_SYNC,
        },
        config::{TransportMode, V2ClientConfig},
        file_transfer::{
            check_file_policy, decode_file_l4, validate_safe_filename, FileAbort, FileAccept,
            FileAck, FileChunk, FileComplete, FileMessage, FileOffer, FileRecvAction,
            FileTransferReceiver, FILE_COMPLETE_ACK_OK, FILE_ERR_POLICY_DENIED, FILE_MSG_ABORT,
            FILE_MSG_ACCEPT, FILE_MSG_ACK, FILE_MSG_CHUNK, FILE_MSG_COMPLETE,
            FILE_MSG_COMPLETE_ACK, FILE_MSG_OFFER, FILE_RECOMMENDED_CHUNK_SIZE,
        },
        hid::{
            decode_hid_frame, encode_hid_frame, required_modifier_bit_for_usage, HidPayload,
            KeyEvent, MouseEvent, MouseKind, MOUSE_BUTTONS_VALID_MASK,
        },
        identity::PersistentV2Identity,
        manager::{
            CallDecision, DesktopControllerClient, DesktopHostDaemon, IncomingCall, SecurityEvent,
            UiCallbackDispatcher, V2SessionState, V2UiCallback,
        },
        policy::{verify_tenant_policy_blob, EffectiveTenantPolicy, PolicyVerifyOutcome},
        runtime::send_redundant_session_close_3x,
        session::{
            parse_codec_switch_ack, parse_codec_switch_req, parse_request_idr, parse_session_close,
            DesktopHostSession, SessionError, CTRL_MSG_CODEC_SWITCH_ACK, CTRL_MSG_CODEC_SWITCH_REQ,
            CTRL_MSG_REQUEST_IDR, CTRL_MSG_SESSION_CLOSE,
        },
        video::{
            local_v2_cap_bits, negotiate_video_codec, DecodedVideoFrame, V2VideoDecoder,
            V2VideoEncoder, VideoCodec, VideoError,
        },
    },
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    panic::{catch_unwind, AssertUnwindSafe},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc as std_mpsc, Arc, Condvar, Mutex, RwLock,
    },
    thread::{self, JoinHandle, ThreadId},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use v2_client::{
    now_unix_secs, ActiveTransportMode, ControlPlaneClient, SignalingDeviceCert, UdpE2eeSession,
    V2RecvEvent,
};
use v2_transport::{
    AudioPacket, TransportEvent, VerifiedTenantPolicy, CHAN_CLIPBOARD, CHAN_FILE_TRANSFER,
    IDR_MIN_INTERVAL_MS,
};

pub const SYNC_CMD_TIMEOUT: Duration = Duration::from_millis(500);
pub const RELEASE_ALL_FLUSH_TIMEOUT: Duration = Duration::from_millis(150);
pub const UNIFIED_SHUTDOWN_BUDGET: Duration = Duration::from_secs(3);
pub const DEFAULT_RING_TIMEOUT: Duration = Duration::from_secs(15);
const POLICY_REFRESH_TIMEOUT: Duration = Duration::from_secs(5);
const FILE_COMPLETE_ACK_TIMEOUT: Duration = Duration::from_secs(15);
const FILE_NO_PROGRESS_TIMEOUT: Duration = Duration::from_secs(30);
const FILE_PROGRESS_THROTTLE_INTERVAL: Duration = Duration::from_millis(200);
const PENDING_CLIP_FRAMES_CAP: usize = 256;
const PENDING_CLIP_BYTES_CAP: usize = 4 * 1024 * 1024;
const PENDING_FILE_CTRL_CAP: usize = 128;
const FILE_ERR_LOCAL_ABORT: u16 = 0x0500;
const ACTOR_CHANNEL_CAP: usize = 256;
const SESSION_ACTION_CAP: usize = 128;

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Configuration knobs for `V2BridgeRuntime` adapters.
/// Defaults are strictly zero-OS-side-effect (DryRun HID, Synthetic capture, Silent audio, MemoryClipboard).
pub struct V2BridgeRuntimeOptions {
    pub use_os_capture: bool,
    pub legacy_capture_fallback: bool,
    pub use_os_audio: bool,
    pub use_os_clipboard: bool,
    pub enable_hid_watchdog_subprocess: bool,
    pub watchdog_report_path: Option<PathBuf>,
    pub watchdog_bin_path: Option<PathBuf>,
    pub real_input_permit: Option<Arc<RealInputPermit>>,
    pub permission_probe: Option<Arc<dyn PermissionProbe>>,
    pub dryrun_journal: DryRunHidJournal,
    pub memory_clipboard: MemoryClipboardBackend,
    pub download_dir: Option<PathBuf>,
    pub ring_timeout: Duration,
    #[cfg(feature = "e2e-fault-injection")]
    pub drop_udp_override: bool,
    #[cfg(feature = "e2e-fault-injection")]
    pub silent_peer_blackhole: Option<Arc<AtomicBool>>,
    pub synthetic_width: u32,
    pub synthetic_height: u32,
}

impl Default for V2BridgeRuntimeOptions {
    fn default() -> Self {
        Self {
            use_os_capture: false,
            legacy_capture_fallback: false,
            use_os_audio: false,
            use_os_clipboard: false,
            enable_hid_watchdog_subprocess: false,
            watchdog_report_path: None,
            watchdog_bin_path: None,
            real_input_permit: None,
            permission_probe: None,
            dryrun_journal: DryRunHidJournal::new(),
            memory_clipboard: MemoryClipboardBackend::new(),
            download_dir: None,
            ring_timeout: DEFAULT_RING_TIMEOUT,
            #[cfg(feature = "e2e-fault-injection")]
            drop_udp_override: false,
            #[cfg(feature = "e2e-fault-injection")]
            silent_peer_blackhole: None,
            synthetic_width: 640,
            synthetic_height: 360,
        }
    }
}

/// RAII guard tracking every spawned session background task so `active_task_count()` is
/// guaranteed to return to `0` even on early return, cancel, or panic.
struct TaskCountGuard {
    active: Arc<AtomicUsize>,
}

impl TaskCountGuard {
    fn enter(active: &Arc<AtomicUsize>, total: &Arc<AtomicU64>) -> Self {
        active.fetch_add(1, Ordering::AcqRel);
        total.fetch_add(1, Ordering::Relaxed);
        Self {
            active: Arc::clone(active),
        }
    }
}

impl Drop for TaskCountGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveRole {
    None,
    Host,
    Controller,
}

#[derive(Debug, Default)]
struct ControllerHidState {
    pressed_keys: BTreeSet<u32>,
    pressed_buttons: u8,
    last_mouse_pos: (i32, i32),
}

impl ControllerHidState {
    fn record_outbound(&mut self, payload: &HidPayload) {
        match payload {
            HidPayload::Key(ev) => {
                if ev.down {
                    self.pressed_keys.insert(ev.usb_hid_usage);
                } else {
                    self.pressed_keys.remove(&ev.usb_hid_usage);
                }
            }
            HidPayload::Mouse(ev) => {
                match ev.kind {
                    MouseKind::MoveAbs | MouseKind::Down | MouseKind::Up => {
                        self.last_mouse_pos = (ev.x_or_dx, ev.y_or_dy);
                    }
                    MouseKind::MoveRel | MouseKind::Wheel => {}
                }
                self.pressed_buttons = ev.buttons & MOUSE_BUTTONS_VALID_MASK;
            }
            HidPayload::EchoAck(_) => {}
        }
    }

    fn has_pressed(&self) -> bool {
        !self.pressed_keys.is_empty() || self.pressed_buttons != 0
    }

    /// Atomically clears tracked controller HID state and builds `spec/04` §6 release frames
    /// (non-modifier keys first, then modifier keys, then mouse button release if any held).
    fn take_release_all_payloads(
        &mut self,
        extra_keys: &[u16],
        extra_buttons: u8,
        now_ms: u64,
    ) -> (Vec<HidPayload>, usize, usize) {
        let mut keys = std::mem::take(&mut self.pressed_keys);
        for &k in extra_keys {
            if k != 0 {
                keys.insert(u32::from(k));
            }
        }
        let buttons_to_release =
            self.pressed_buttons | (extra_buttons & MOUSE_BUTTONS_VALID_MASK);
        self.pressed_buttons = 0;

        let mut regular = Vec::new();
        let mut modifiers = Vec::new();
        for usage in keys {
            if required_modifier_bit_for_usage(usage).is_some() {
                modifiers.push(usage);
            } else {
                regular.push(usage);
            }
        }

        let released_keys = regular.len() + modifiers.len();
        let released_buttons = buttons_to_release.count_ones() as usize;
        let mut payloads = Vec::with_capacity(released_keys + usize::from(buttons_to_release != 0));
        for usage in regular.into_iter().chain(modifiers.into_iter()) {
            payloads.push(HidPayload::Key(KeyEvent {
                down: false,
                modifiers: 0,
                usb_hid_usage: usage,
                unicode_scalar: 0,
                client_ts_ms: now_ms,
            }));
        }
        if buttons_to_release != 0 {
            payloads.push(HidPayload::Mouse(MouseEvent {
                kind: MouseKind::Up,
                buttons: 0,
                x_or_dx: self.last_mouse_pos.0,
                y_or_dy: self.last_mouse_pos.1,
                wheel_dx: 0,
                wheel_dy: 0,
                client_ts_ms: now_ms,
            }));
        }
        (payloads, released_keys, released_buttons)
    }
}

enum SessionAction {
    SendHid(HidPayload),
    ReleaseAll {
        keys: Vec<u16>,
        buttons: u8,
        ack: Option<oneshot::Sender<(usize, usize)>>,
    },
    SendClipboard {
        mime_kind: u8,
        bytes: Vec<u8>,
    },
    SendFile {
        cmd_id: u64,
        path: PathBuf,
        rel_name: String,
    },
    CancelFile {
        transfer_id: u64,
    },
    SetAudioMute(bool),
    SetClipboardSync(bool),
    SetVideoQuality {
        bitrate_kbps: u32,
        fps_cap: u32,
    },
    RequestCodec(String),
    RefreshPolicy {
        cmd_id: u64,
    },
}

enum ActorEvent {
    HostBootstrapped {
        cmd_id: u64,
        local_cert: SignalingDeviceCert,
        policy: EffectiveTenantPolicy,
    },
    HostBootstrapFailed {
        cmd_id: u64,
        error: String,
    },
    IncomingCall {
        call: IncomingCall,
        reply: oneshot::Sender<CallDecision>,
    },
    IncomingTimedOut {
        incoming_id: String,
    },
    StreamingStarted {
        cmd_id: Option<u64>,
        session_id: [u8; 16],
        local_cert: Box<SignalingDeviceCert>,
        peer_cert: Box<SignalingDeviceCert>,
        policy: EffectiveTenantPolicy,
        active_mode: ActiveTransportMode,
        attach_ms: u64,
        action_tx: mpsc::Sender<SessionAction>,
    },
    DialFailed {
        cmd_id: u64,
        error: String,
    },
    PolicyUpdated {
        cmd_id: Option<u64>,
        policy: EffectiveTenantPolicy,
        is_degraded: bool,
    },
    AudioStatus(AudioStatusChanged),
    HostCapabilityDegraded {
        capability: String,
        reason: String,
    },
    CodecAck {
        active_codec: String,
        requested_codec: Option<String>,
        accepted: bool,
    },
    PermissionStatusChanged(PermissionStatusReport),
    WatchdogTriggered {
        released_keys: usize,
        released_buttons: usize,
    },
    ClipboardReceived {
        mime_kind: u8,
        byte_count: usize,
        sha256_hex: String,
    },
    FileProgress {
        transfer_id: u64,
        bytes_transferred: u64,
        total_bytes: u64,
    },
    FileComplete {
        transfer_id: u64,
        rel_name: String,
        bytes: u64,
        sha256_hex: String,
        saved_path: Option<String>,
    },
    FileAborted {
        transfer_id: u64,
        error_code: u16,
        reason: String,
    },
    CommandResult {
        cmd_id: u64,
        ok: bool,
        data: Option<serde_json::Value>,
        error_code: Option<String>,
        error: Option<String>,
    },
    SessionEnded {
        return_to_listening: bool,
        reason: String,
    },
    SecurityEvent(SecurityEvent),
}

#[allow(clippy::large_enum_variant)]
enum ActorMessage {
    ExecCommand {
        env: Box<RuntimeCommandEnvelope>,
        queued_at: Instant,
        reply: std_mpsc::SyncSender<RuntimeReplyEnvelope>,
    },
    SendClipboardPng {
        bytes: Vec<u8>,
        queued_at: Instant,
        reply: std_mpsc::SyncSender<RuntimeReplyEnvelope>,
    },
    SendFilePath {
        path: String,
        queued_at: Instant,
        reply: std_mpsc::SyncSender<RuntimeReplyEnvelope>,
    },
    InternalEvent {
        session_gen: u64,
        event: ActorEvent,
    },
    #[cfg(test)]
    InjectTestIncoming {
        session_id: [u8; 16],
        caller_cert: SignalingDeviceCert,
        reply_tx: oneshot::Sender<CallDecision>,
        ack: std_mpsc::SyncSender<String>,
    },
    #[cfg(test)]
    SimulateStaleEvent {
        session_gen: u64,
        cmd_id: Option<u64>,
        ack: std_mpsc::SyncSender<()>,
    },
    #[cfg(test)]
    SimulateStaleSecurityEvent {
        session_gen: u64,
        ack: std_mpsc::SyncSender<()>,
    },
    #[cfg(test)]
    SimulateStreamingForTest {
        session_id: [u8; 16],
        cert: SignalingDeviceCert,
        ack: std_mpsc::SyncSender<()>,
    },
    Shutdown {
        ack: std_mpsc::SyncSender<()>,
    },
}

struct PendingIncoming {
    incoming_id: String,
    session_id_hex: String,
    reply_tx: Option<oneshot::Sender<CallDecision>>,
    timer_cancel: CancellationToken,
}

impl Drop for PendingIncoming {
    fn drop(&mut self) {
        self.timer_cancel.cancel();
        // Dropping `reply_tx` without sending equals rejection on the host wait side.
        let _ = self.reply_tx.take();
    }
}

struct BridgeUiCallback {
    session_gen: u64,
    actor_tx: mpsc::Sender<ActorMessage>,
    events: Arc<BridgeEventHub>,
    dropped_events: Arc<AtomicU64>,
}

impl V2UiCallback for BridgeUiCallback {
    fn on_frame(&self, _frame: Arc<crate::session::video::I420Frame>) {}
    fn on_state(&self, _state: V2SessionState) {}
    fn on_qoe(&self, snapshot: crate::session::runtime::QoeSnapshot) {
        // High-frequency QoE telemetry bypasses the actor control channel completely.
        if let Ok(val) = serde_json::to_value(snapshot) {
            self.events.set_telemetry("QoeTelemetry", val);
        }
    }
    fn on_capabilities(&self, _caps: VerifiedTenantPolicy) {}
    fn on_incoming_call(&self, call: IncomingCall, reply: oneshot::Sender<CallDecision>) {
        if let Err(err) = self.actor_tx.try_send(ActorMessage::InternalEvent {
            session_gen: self.session_gen,
            event: ActorEvent::IncomingCall { call, reply },
        }) {
            self.dropped_events.fetch_add(1, Ordering::Relaxed);
            if let ActorMessage::InternalEvent {
                event: ActorEvent::IncomingCall { reply, .. },
                ..
            } = match err {
                mpsc::error::TrySendError::Full(m) | mpsc::error::TrySendError::Closed(m) => m,
            } {
                let _ = reply.send(CallDecision::Reject {
                    error_code: 0x0503,
                    reason: "actor_control_channel_busy".into(),
                });
            }
        }
    }
    fn on_security_event(&self, event: SecurityEvent) {
        if self
            .actor_tx
            .try_send(ActorMessage::InternalEvent {
                session_gen: self.session_gen,
                event: ActorEvent::SecurityEvent(event),
            })
            .is_err()
        {
            self.dropped_events.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Async single-writer actor runtime driving `V2BridgeController`, `FrameMailbox`, OS adapters,
/// and live Host/Controller V2 sessions on a dedicated OS thread (`"zerodesk-v2-rt"`).
///
/// Safe to construct, call, and `destroy()` / `Drop` from ANY thread (including inside another
/// Tokio runtime) with zero deadlocks and bounded <= 3s shutdown.
pub struct V2BridgeRuntime {
    actor_tx: mpsc::Sender<ActorMessage>,
    shutdown_token: CancellationToken,
    snapshot_cache: Arc<RwLock<BridgeSnapshot>>,
    mailbox: Arc<FrameMailbox>,
    events: Arc<BridgeEventHub>,
    active_tasks: Arc<AtomicUsize>,
    spawned_tasks_total: Arc<AtomicU64>,
    dropped_events: Arc<AtomicU64>,
    emergency_releaser: Arc<Mutex<Option<Arc<dyn EmergencyKeyReleaser>>>>,
    dryrun_journal: DryRunHidJournal,
    memory_clipboard: MemoryClipboardBackend,
    actor_thread_id: ThreadId,
    thread_handle: Mutex<Option<JoinHandle<()>>>,
    shutdown_done: Arc<(Mutex<bool>, Condvar)>,
    destroyed: AtomicBool,
}

impl V2BridgeRuntime {
    pub fn new() -> Result<Self, String> {
        Self::with_options(V2BridgeRuntimeOptions::default())
    }

    pub fn with_options(options: V2BridgeRuntimeOptions) -> Result<Self, String> {
        if let Some(report_path) = &options.watchdog_report_path {
            if report_path.as_os_str().is_empty() {
                return Err("InvalidArgument: watchdog_report_path must be non-empty".into());
            }
            if options.real_input_permit.is_some() {
                return Err(
                    "InvalidArgument: watchdog_report_path (dry-run watchdog) cannot be combined with real_input_permit"
                        .into(),
                );
            }
        }
        let mailbox = Arc::new(FrameMailbox::new());
        let events = Arc::new(BridgeEventHub::new(Arc::clone(&mailbox)));
        let controller = V2BridgeController::new();
        let mut initial_snap = controller.snapshot();
        initial_snap.real_input_enabled = Some(options.real_input_permit.is_some());
        let snapshot_cache = Arc::new(RwLock::new(initial_snap));
        let shutdown_token = CancellationToken::new();
        let active_tasks = Arc::new(AtomicUsize::new(0));
        let spawned_tasks_total = Arc::new(AtomicU64::new(0));
        let dropped_events = Arc::new(AtomicU64::new(0));
        let emergency_releaser: Arc<Mutex<Option<Arc<dyn EmergencyKeyReleaser>>>> =
            Arc::new(Mutex::new(None));
        let dryrun_journal = options.dryrun_journal.clone();
        let memory_clipboard = options.memory_clipboard.clone();

        let (actor_tx, actor_rx) = mpsc::channel::<ActorMessage>(ACTOR_CHANNEL_CAP);
        let (ready_tx, ready_rx) = std_mpsc::sync_channel::<Result<(), String>>(1);

        let actor_tx_bg = actor_tx.clone();
        let shutdown_bg = shutdown_token.clone();
        let snapshot_bg = Arc::clone(&snapshot_cache);
        let mailbox_bg = Arc::clone(&mailbox);
        let events_bg = Arc::clone(&events);
        let active_bg = Arc::clone(&active_tasks);
        let total_bg = Arc::clone(&spawned_tasks_total);
        let dropped_bg = Arc::clone(&dropped_events);
        let releaser_bg = Arc::clone(&emergency_releaser);

        let handle = thread::Builder::new()
            .name("zerodesk-v2-rt".to_string())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => {
                        let _ = ready_tx.send(Ok(()));
                        rt
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(format!("build tokio current_thread rt: {e}")));
                        return;
                    }
                };
                let shutdown_panic = shutdown_bg.clone();
                let snapshot_panic = Arc::clone(&snapshot_bg);
                let events_panic = Arc::clone(&events_bg);
                let releaser_panic = Arc::clone(&releaser_bg);

                let run_res = catch_unwind(AssertUnwindSafe(move || {
                    rt.block_on(async move {
                        let mut actor = BridgeActor {
                            controller,
                            options,
                            actor_tx: actor_tx_bg,
                            snapshot_cache: snapshot_bg,
                            mailbox: mailbox_bg,
                            events: events_bg,
                            active_tasks: active_bg,
                            spawned_tasks_total: total_bg,
                            dropped_events: dropped_bg,
                            emergency_releaser: releaser_bg,
                            session_gen: 0,
                            next_cmd_id: 1,
                            next_incoming_seq: 1,
                            role: ActiveRole::None,
                            loaded_config: None,
                            effective_policy: None,
                            session_cancel: None,
                            session_handles: Vec::new(),
                            pending_incoming: None,
                            active_session_tx: None,
                            shutting_down: false,
                            enable_os_input: Arc::new(AtomicBool::new(false)),
                            active_watchdog_ax_probe: Arc::new(Mutex::new(None)),
                            clipboard_sync_enabled: Arc::new(AtomicBool::new(true)),
                            bitrate_kbps: None,
                            fps_cap: None,
                            active_codec: None,
                            last_emitted_permission_status: None,
                            cached_perm_probe: Mutex::new(None),
                        };
                        actor.run(actor_rx, shutdown_bg).await;
                    });
                    // Bounded runtime shutdown so lingering blocking tasks can never hang teardown.
                    rt.shutdown_timeout(Duration::from_millis(500));
                }));
                if run_res.is_err() {
                    shutdown_panic.cancel();
                    if let Some(releaser) = releaser_panic
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone()
                    {
                        let _ = releaser.release_all_keys();
                    }
                    {
                        let mut snap = snapshot_panic
                            .write()
                            .unwrap_or_else(|e| e.into_inner());
                        snap.state = BridgeState::Faulted;
                        snap.fault_reason = Some("bridge actor panicked".into());
                    }
                    events_panic.push_critical(
                        "SessionTaskCrashed",
                        serde_json::json!({ "task": "bridge_actor" }),
                    );
                    events_panic.close();
                }
            })
            .map_err(|e| format!("spawn zerodesk-v2-rt thread: {e}"))?;

        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| "timed out starting zerodesk-v2-rt thread".to_string())??;

        let actor_thread_id = handle.thread().id();

        Ok(Self {
            actor_tx,
            shutdown_token,
            snapshot_cache,
            mailbox,
            events,
            active_tasks,
            spawned_tasks_total,
            dropped_events,
            emergency_releaser,
            dryrun_journal,
            memory_clipboard,
            actor_thread_id,
            thread_handle: Mutex::new(Some(handle)),
            shutdown_done: Arc::new((Mutex::new(false), Condvar::new())),
            destroyed: AtomicBool::new(false),
        })
    }

    pub fn mailbox(&self) -> &Arc<FrameMailbox> {
        &self.mailbox
    }

    pub fn dryrun_hid_journal(&self) -> &DryRunHidJournal {
        &self.dryrun_journal
    }

    pub fn memory_clipboard(&self) -> &MemoryClipboardBackend {
        &self.memory_clipboard
    }

    pub fn active_task_count(&self) -> usize {
        self.active_tasks.load(Ordering::Acquire)
    }

    pub fn spawned_tasks_total(&self) -> u64 {
        self.spawned_tasks_total.load(Ordering::Relaxed)
    }

    pub fn dropped_event_count(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    /// Reads the latest redacted snapshot under a short non-async lock (ZERO `.await`, ZERO I/O).
    pub fn snapshot(&self) -> BridgeSnapshot {
        self.snapshot_cache
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn snapshot_json(&self) -> String {
        let snap = self.snapshot();
        serde_json::to_string(&snap).unwrap_or_else(|_| {
            r#"{"v":1,"state":"faulted","fault_reason":"snapshot serialize error"}"#.to_string()
        })
    }

    fn send_to_actor(&self, mut msg: ActorMessage, timeout: Duration) -> Result<(), ()> {
        let deadline = Instant::now().checked_add(timeout);
        loop {
            if self.destroyed.load(Ordering::Acquire) {
                return Err(());
            }
            match self.actor_tx.try_send(msg) {
                Ok(()) => return Ok(()),
                Err(mpsc::error::TrySendError::Closed(_)) => return Err(()),
                Err(mpsc::error::TrySendError::Full(returned)) => {
                    msg = returned;
                    if deadline.is_some_and(|dl| Instant::now() >= dl) {
                        return Err(());
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }

    /// Validates and executes a versioned JSON command (`"v": 1`).
    /// Never panics on malformed JSON, invalid UTF-8, oversized inputs, or when called from
    /// inside an outer Tokio runtime thread.
    pub fn exec_json(&self, cmd_json: &str) -> String {
        if self.destroyed.load(Ordering::Acquire) {
            return RuntimeReplyEnvelope::err("Destroyed", "bridge runtime has been destroyed")
                .to_json_string();
        }
        let env = match parse_and_validate_command(cmd_json) {
            Ok(e) => e,
            Err(err_reply) => return err_reply.to_json_string(),
        };
        // Fast lock-only path for `snapshot` without even hopping to the actor thread.
        if env.cmd == "snapshot" {
            let snap = self.snapshot();
            return match serde_json::to_value(&snap) {
                Ok(v) => RuntimeReplyEnvelope::ok(v).to_json_string(),
                Err(e) => RuntimeReplyEnvelope::err("Internal", e.to_string()).to_json_string(),
            };
        }
        let (tx, rx) = std_mpsc::sync_channel(1);
        if self
            .send_to_actor(
                ActorMessage::ExecCommand {
                    env: Box::new(env),
                    queued_at: Instant::now(),
                    reply: tx,
                },
                SYNC_CMD_TIMEOUT,
            )
            .is_err()
        {
            return RuntimeReplyEnvelope::err("Destroyed", "bridge actor channel closed or full")
                .to_json_string();
        }
        match rx.recv_timeout(SYNC_CMD_TIMEOUT) {
            Ok(reply) => reply.to_json_string(),
            Err(_) => RuntimeReplyEnvelope::err(
                "Timeout",
                "bridge command exceeded 500ms synchronous wait budget",
            )
            .to_json_string(),
        }
    }

    /// Binary PNG clipboard entrypoint (zero JSON base64).
    pub fn send_clipboard_png(&self, png_bytes: &[u8]) -> String {
        if self.destroyed.load(Ordering::Acquire) {
            return RuntimeReplyEnvelope::err("Destroyed", "bridge runtime has been destroyed")
                .to_json_string();
        }
        if let Err(e) = validate_clipboard_png_bytes(png_bytes) {
            return RuntimeReplyEnvelope::err("InvalidArgument", e.to_string()).to_json_string();
        }
        let (tx, rx) = std_mpsc::sync_channel(1);
        if self
            .send_to_actor(
                ActorMessage::SendClipboardPng {
                    bytes: png_bytes.to_vec(),
                    queued_at: Instant::now(),
                    reply: tx,
                },
                SYNC_CMD_TIMEOUT,
            )
            .is_err()
        {
            return RuntimeReplyEnvelope::err("Destroyed", "bridge actor channel closed")
                .to_json_string();
        }
        match rx.recv_timeout(SYNC_CMD_TIMEOUT) {
            Ok(r) => r.to_json_string(),
            Err(_) => RuntimeReplyEnvelope::err("Timeout", "send_clipboard_png timed out")
                .to_json_string(),
        }
    }

    /// Binary/path file transfer entrypoint (zero JSON base64).
    pub fn send_file_path(&self, path: &str) -> String {
        if self.destroyed.load(Ordering::Acquire) {
            return RuntimeReplyEnvelope::err("Destroyed", "bridge runtime has been destroyed")
                .to_json_string();
        }
        if path.is_empty() || path.contains('\0') {
            return RuntimeReplyEnvelope::err("InvalidArgument", "invalid file path")
                .to_json_string();
        }
        let (tx, rx) = std_mpsc::sync_channel(1);
        if self
            .send_to_actor(
                ActorMessage::SendFilePath {
                    path: path.to_string(),
                    queued_at: Instant::now(),
                    reply: tx,
                },
                SYNC_CMD_TIMEOUT,
            )
            .is_err()
        {
            return RuntimeReplyEnvelope::err("Destroyed", "bridge actor channel closed")
                .to_json_string();
        }
        match rx.recv_timeout(SYNC_CMD_TIMEOUT) {
            Ok(r) => r.to_json_string(),
            Err(_) => {
                RuntimeReplyEnvelope::err("Timeout", "send_file_path timed out").to_json_string()
            }
        }
    }

    pub fn poll_event_json(&self) -> Option<String> {
        let ev = self.events.poll_event()?;
        serde_json::to_string(&ev).ok()
    }

    pub fn poll_event_json_timeout(&self, timeout: Duration) -> Option<String> {
        let ev = self.events.poll_event_timeout(timeout)?;
        serde_json::to_string(&ev).ok()
    }

    pub fn frame_info(&self) -> Result<FrameInfo, FrameError> {
        self.mailbox.frame_info()
    }

    pub fn take_latest_frame(
        &self,
        out_buf: &mut [u8],
    ) -> Result<FrameInfo, (FrameError, Option<FrameInfo>)> {
        self.mailbox.take_latest_into_with_info(out_buf)
    }

    /// Unified, idempotent, bounded (<= 3s) shutdown safe from ANY thread.
    /// Synchronously invokes the independent `EmergencyKeyReleaser` without depending on Tokio!
    /// Concurrent callers wait on `shutdown_done` until shutdown completes (except same-thread calls,
    /// which check thread ID first so they never self-deadlock).
    pub fn destroy(&self) {
        let is_actor_thread = thread::current().id() == self.actor_thread_id;
        if is_actor_thread {
            self.destroyed.store(true, Ordering::Release);
            if let Some(releaser) = self
                .emergency_releaser
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
            {
                let _ = releaser.release_all_keys();
            }
            self.shutdown_token.cancel();
            self.events.close();
            self.mailbox.clear();
            self.memory_clipboard.clear();
            return;
        }

        if self.destroyed.swap(true, Ordering::AcqRel) {
            // Another caller owns teardown; wait boundedly until it finishes.
            let (lock, cvar) = &*self.shutdown_done;
            let mut done = lock.lock().unwrap_or_else(|e| e.into_inner());
            let deadline = Instant::now().checked_add(UNIFIED_SHUTDOWN_BUDGET);
            while !*done {
                let rem = match deadline {
                    Some(dl) => match dl.checked_duration_since(Instant::now()) {
                        Some(r) if !r.is_zero() => r,
                        _ => break,
                    },
                    None => UNIFIED_SHUTDOWN_BUDGET,
                };
                let (guard, wait_res) = cvar
                    .wait_timeout(done, rem)
                    .unwrap_or_else(|e| e.into_inner());
                done = guard;
                if wait_res.timed_out() {
                    break;
                }
            }
            return;
        }

        // 1. Trigger independent emergency key release synchronously (cloned outside lock).
        let releaser_opt = self
            .emergency_releaser
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(releaser) = releaser_opt {
            let _ = releaser.release_all_keys();
        }
        // 2. Cancel all runtime tasks and wake blocked pollers.
        self.shutdown_token.cancel();
        self.events.close();
        let (ack_tx, ack_rx) = std_mpsc::sync_channel(1);
        let _ = self.actor_tx.try_send(ActorMessage::Shutdown { ack: ack_tx });
        let _ = ack_rx.recv_timeout(UNIFIED_SHUTDOWN_BUDGET);

        // 3. Join the dedicated OS thread.
        let handle = self
            .thread_handle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(h) = handle {
            let _ = h.join();
        }
        // 4. Final defensive emergency key release pass after actor thread exited (outside lock).
        let final_releaser = self
            .emergency_releaser
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(releaser) = final_releaser {
            let _ = releaser.release_all_keys();
        }
        // 5. Clear & zeroize buffered pixels and in-memory clipboard secrets at shutdown end.
        self.mailbox.clear();
        self.memory_clipboard.clear();

        let (lock, cvar) = &*self.shutdown_done;
        *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
        cvar.notify_all();
    }

    #[cfg(test)]
    fn inject_test_incoming(
        &self,
        session_id: [u8; 16],
        caller_cert: SignalingDeviceCert,
    ) -> (String, oneshot::Receiver<CallDecision>) {
        let (dec_tx, dec_rx) = oneshot::channel();
        let (ack_tx, ack_rx) = std_mpsc::sync_channel(1);
        self.actor_tx
            .blocking_send(ActorMessage::InjectTestIncoming {
                session_id,
                caller_cert,
                reply_tx: dec_tx,
                ack: ack_tx,
            })
            .unwrap();
        let id = ack_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        (id, dec_rx)
    }

    #[cfg(test)]
    fn simulate_stale_event(&self, stale_gen: u64, cmd_id: Option<u64>) {
        let (ack_tx, ack_rx) = std_mpsc::sync_channel(1);
        self.actor_tx
            .blocking_send(ActorMessage::SimulateStaleEvent {
                session_gen: stale_gen,
                cmd_id,
                ack: ack_tx,
            })
            .unwrap();
        let _ = ack_rx.recv_timeout(Duration::from_secs(2));
    }

    #[cfg(test)]
    fn simulate_stale_security_event(&self, stale_gen: u64) {
        let (ack_tx, ack_rx) = std_mpsc::sync_channel(1);
        self.actor_tx
            .blocking_send(ActorMessage::SimulateStaleSecurityEvent {
                session_gen: stale_gen,
                ack: ack_tx,
            })
            .unwrap();
        let _ = ack_rx.recv_timeout(Duration::from_secs(2));
    }

    #[cfg(test)]
    fn simulate_streaming_for_test(&self, session_id: [u8; 16], cert: SignalingDeviceCert) {
        let (ack_tx, ack_rx) = std_mpsc::sync_channel(1);
        self.actor_tx
            .blocking_send(ActorMessage::SimulateStreamingForTest {
                session_id,
                cert,
                ack: ack_tx,
            })
            .unwrap();
        let _ = ack_rx.recv_timeout(Duration::from_secs(2));
    }
}

impl Drop for V2BridgeRuntime {
    fn drop(&mut self) {
        self.destroy();
    }
}

type WatchdogAxProbeSlot = Arc<Mutex<Option<(u64, Arc<AtomicBool>)>>>;

struct BridgeActor {
    controller: V2BridgeController,
    options: V2BridgeRuntimeOptions,
    actor_tx: mpsc::Sender<ActorMessage>,
    snapshot_cache: Arc<RwLock<BridgeSnapshot>>,
    mailbox: Arc<FrameMailbox>,
    events: Arc<BridgeEventHub>,
    active_tasks: Arc<AtomicUsize>,
    spawned_tasks_total: Arc<AtomicU64>,
    dropped_events: Arc<AtomicU64>,
    emergency_releaser: Arc<Mutex<Option<Arc<dyn EmergencyKeyReleaser>>>>,
    session_gen: u64,
    next_cmd_id: u64,
    next_incoming_seq: u64,
    role: ActiveRole,
    loaded_config: Option<BridgePersistedConfig>,
    effective_policy: Option<EffectiveTenantPolicy>,
    session_cancel: Option<CancellationToken>,
    session_handles: Vec<tokio::task::JoinHandle<()>>,
    pending_incoming: Option<PendingIncoming>,
    active_session_tx: Option<mpsc::Sender<SessionAction>>,
    shutting_down: bool,
    enable_os_input: Arc<AtomicBool>,
    active_watchdog_ax_probe: WatchdogAxProbeSlot,
    clipboard_sync_enabled: Arc<AtomicBool>,
    bitrate_kbps: Option<u32>,
    fps_cap: Option<u32>,
    active_codec: Option<String>,
    last_emitted_permission_status: Option<PermissionStatusReport>,
    cached_perm_probe: Mutex<Option<(PermissionStatusReport, Instant)>>,
}

fn validate_download_dir(path: &Path) -> Result<PathBuf, RuntimeReplyEnvelope> {
    if !path.is_absolute() {
        return Err(RuntimeReplyEnvelope::err(
            "InvalidArgument",
            "download_dir must be an absolute path",
        ));
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(RuntimeReplyEnvelope::err(
                    "InvalidArgument",
                    "download_dir must be a real directory (not a symlink or file)",
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Walk up to the nearest existing ancestor and ensure it is not a symlink.
            let mut cur = path.parent();
            while let Some(p) = cur {
                match std::fs::symlink_metadata(p) {
                    Ok(meta) => {
                        if meta.file_type().is_symlink() || !meta.is_dir() {
                            return Err(RuntimeReplyEnvelope::err(
                                "InvalidArgument",
                                "download_dir parent must be a real directory (not a symlink)",
                            ));
                        }
                        break;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        cur = p.parent();
                    }
                    Err(err) => {
                        return Err(RuntimeReplyEnvelope::err(
                            "InvalidArgument",
                            format!("inspect download_dir parent failed: {err}"),
                        ));
                    }
                }
            }
        }
        Err(e) => {
            return Err(RuntimeReplyEnvelope::err(
                "InvalidArgument",
                format!("inspect download_dir failed: {e}"),
            ));
        }
    }
    Ok(path.to_path_buf())
}

fn should_accept_policy_update(
    current: Option<&EffectiveTenantPolicy>,
    candidate: &EffectiveTenantPolicy,
    now_unix: u64,
) -> Result<(), String> {
    if let Some(cur) = current {
        if !cur.degraded && cur.exp_unix > now_unix {
            if candidate.degraded {
                return Err(
                    "refusing to overwrite unexpired verified policy with degraded policy".into(),
                );
            }
            if candidate.version < cur.version {
                return Err(format!(
                    "refusing policy version downgrade ({} < {})",
                    candidate.version, cur.version
                ));
            }
        }
    }
    Ok(())
}

fn security_event_to_json(se: &SecurityEvent) -> serde_json::Value {
    match se {
        SecurityEvent::CertVerified { peer_device_id } => serde_json::json!({
            "event": "CertVerified",
            "peer_device_id_hex": hex::encode(peer_device_id),
        }),
        SecurityEvent::CertRejected { reason } => serde_json::json!({
            "event": "CertRejected",
            "reason": reason,
        }),
        SecurityEvent::TenantMismatch { expected, actual } => serde_json::json!({
            "event": "TenantMismatch",
            "expected_tenant_hex": hex::encode(expected),
            "actual_tenant_hex": hex::encode(actual),
        }),
        SecurityEvent::ReplaySessionRejected { session_id } => serde_json::json!({
            "event": "ReplaySessionRejected",
            "session_id_hex": hex::encode(session_id),
        }),
        SecurityEvent::InvalidHidFraming { reason } => serde_json::json!({
            "event": "InvalidHidFraming",
            "reason": reason,
        }),
        SecurityEvent::InputFaulted {
            residual_buttons,
            residual_keys,
        } => serde_json::json!({
            "event": "InputFaulted",
            "residual_buttons": residual_buttons,
            "residual_key_count": residual_keys.len(),
        }),
        SecurityEvent::WatchdogTriggered => serde_json::json!({
            "event": "WatchdogTriggered",
        }),
        SecurityEvent::LeaseRenewalFailed {
            consecutive,
            reason,
        } => serde_json::json!({
            "event": "LeaseRenewalFailed",
            "consecutive": consecutive,
            "reason": reason,
        }),
        SecurityEvent::SignalingDisconnected { reason } => serde_json::json!({
            "event": "SignalingDisconnected",
            "reason": reason,
        }),
        SecurityEvent::PolicyDegraded { reason } => serde_json::json!({
            "event": "PolicyDegraded",
            "reason": reason,
        }),
    }
}

impl BridgeActor {
    fn alloc_cmd_id(&mut self) -> u64 {
        let id = self.next_cmd_id;
        self.next_cmd_id = self.next_cmd_id.saturating_add(1);
        id
    }

    fn probe_permissions(&self) -> PermissionStatusReport {
        let wd_ax = self
            .active_watchdog_ax_probe
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|(_, flag)| flag.load(Ordering::Acquire));
        let enabled = self.enable_os_input.load(Ordering::Acquire);
        let rep = if let Some(probe) = &self.options.permission_probe {
            probe.probe(wd_ax, enabled)
        } else {
            SystemPermissionProbe.probe(wd_ax, enabled)
        };
        if self.options.permission_probe.is_none() {
            *self
                .cached_perm_probe
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some((rep.clone(), Instant::now()));
        }
        rep
    }

    fn probe_permissions_cached(&self) -> PermissionStatusReport {
        if self.options.permission_probe.is_some() {
            return self.probe_permissions();
        }
        const PERM_CACHE_TTL: Duration = Duration::from_millis(200);
        let now = Instant::now();
        {
            let g = self
                .cached_perm_probe
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some((rep, ts)) = g.as_ref() {
                if now.saturating_duration_since(*ts) <= PERM_CACHE_TTL {
                    let mut cached = rep.clone();
                    cached.enable_os_input = self.enable_os_input.load(Ordering::Acquire);
                    return cached;
                }
            }
        }
        self.probe_permissions()
    }

    fn invalidate_perm_cache(&self) {
        *self
            .cached_perm_probe
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
    }

    fn sync_snapshot(&self) {
        self.controller
            .set_enable_os_input(self.enable_os_input.load(Ordering::Acquire));
        self.controller
            .set_clipboard_sync_enabled(self.clipboard_sync_enabled.load(Ordering::Acquire));
        self.controller.set_active_codec(self.active_codec.clone());
        self.controller
            .set_video_quality(self.bitrate_kbps, self.fps_cap);
        let mut snap = self.controller.snapshot();
        snap.real_input_enabled = Some(self.options.real_input_permit.is_some());
        snap.abi_version = Some(BRIDGE_JSON_ABI_V2);
        snap.caps = Some(
            BRIDGE_V2_CAPABILITIES
                .iter()
                .map(|c| (*c).to_string())
                .collect(),
        );
        if snap.bitrate_kbps.is_none() {
            snap.bitrate_kbps = Some(0);
        }
        if snap.fps_cap.is_none() {
            snap.fps_cap = Some(30);
        }
        *self
            .snapshot_cache
            .write()
            .unwrap_or_else(|e| e.into_inner()) = snap;
    }

    fn drain_controller_events_to_hub(&self) {
        for ev in self.controller.drain_events() {
            self.events.push_critical(&ev.kind, ev.payload);
        }
    }

    fn clear_pending_incoming(&mut self, reason: &str) {
        if let Some(mut p) = self.pending_incoming.take() {
            p.timer_cancel.cancel();
            if let Some(tx) = p.reply_tx.take() {
                let _ = tx.send(CallDecision::Reject {
                    error_code: 0x0409,
                    reason: reason.to_string(),
                });
            }
            self.events.push_critical(
                "IncomingEnded",
                serde_json::json!({
                    "incoming_id": p.incoming_id,
                    "session_id_hex": p.session_id_hex,
                    "reason": reason,
                }),
            );
        }
    }

    async fn unified_shutdown_session(&mut self, return_to_listening: bool) {
        // Every session teardown unconditionally resets per-session `enable_os_input = false`
        // and clears live negotiated `active_codec`.
        self.enable_os_input.store(false, Ordering::Release);
        self.controller.set_enable_os_input(false);
        self.active_codec = None;
        self.controller.set_active_codec(None);
        self.invalidate_perm_cache();
        {
            let mut slot = self
                .active_watchdog_ax_probe
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if slot.as_ref().is_some_and(|(id, _)| *id == self.session_gen) {
                *slot = None;
            }
        }
        self.clear_pending_incoming("session_shutdown");
        let active_tx = self.active_session_tx.take();
        let mut release_failures: Vec<String> = Vec::new();

        // Flush controller remote release_all BEFORE cancelling the session or tearing down data-plane.
        if self.role == ActiveRole::Controller {
            if let Some(tx) = active_tx {
                let (ack_tx, ack_rx) = oneshot::channel();
                match tokio::time::timeout(
                    RELEASE_ALL_FLUSH_TIMEOUT,
                    tx.send(SessionAction::ReleaseAll {
                        keys: Vec::new(),
                        buttons: 0,
                        ack: Some(ack_tx),
                    }),
                )
                .await
                {
                    Ok(Ok(())) => {
                        if !matches!(
                            tokio::time::timeout(RELEASE_ALL_FLUSH_TIMEOUT, ack_rx).await,
                            Ok(Ok(_))
                        ) {
                            release_failures.push("controller_release_all_ack_timeout".into());
                        }
                    }
                    Ok(Err(_)) => {
                        release_failures.push("controller_release_all_channel_closed".into());
                    }
                    Err(_) => {
                        release_failures.push("controller_release_all_send_timeout".into());
                    }
                }
            }
        }

        if let Some(tok) = self.session_cancel.take() {
            tok.cancel();
        }
        // Synchronously release any held HID keys before waiting for async joins (cloned outside lock).
        let releaser_opt = self
            .emergency_releaser
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(releaser) = releaser_opt {
            let rep = releaser.release_all_keys();
            if rep.residual_keys > 0 || rep.residual_buttons > 0 {
                release_failures.push(format!(
                    "local_release_residual(keys={},buttons={})",
                    rep.residual_keys, rep.residual_buttons
                ));
            }
        }
        if !release_failures.is_empty() {
            self.events.push_critical(
                "release_failed",
                serde_json::json!({
                    "reason": "session_shutdown",
                    "errors": release_failures,
                }),
            );
        }

        let handles = std::mem::take(&mut self.session_handles);
        let deadline = tokio::time::Instant::now() + UNIFIED_SHUTDOWN_BUDGET;
        for mut h in handles {
            let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
            if rem.is_zero() {
                h.abort();
                if let Err(e) = h.await {
                    if e.is_panic() {
                        self.events.push_critical(
                            "SessionTaskCrashed",
                            serde_json::json!({ "reason": "task panicked during shutdown" }),
                        );
                    }
                }
            } else {
                match tokio::time::timeout(rem, &mut h).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        if e.is_panic() {
                            self.events.push_critical(
                                "SessionTaskCrashed",
                                serde_json::json!({ "reason": "task panicked" }),
                            );
                        }
                    }
                    Err(_) => {
                        h.abort();
                        if let Err(e) = h.await {
                            if e.is_panic() {
                                self.events.push_critical(
                                    "SessionTaskCrashed",
                                    serde_json::json!({ "reason": "task panicked after abort" }),
                                );
                            }
                        }
                    }
                }
            }
        }
        // Zeroize any buffered frame pixels from the ended session.
        self.mailbox.clear();

        if !return_to_listening {
            self.role = ActiveRole::None;
        }
        if !matches!(
            self.controller.state(),
            BridgeState::Idle | BridgeState::Bootstrapping
        ) {
            let _ = self.controller.on_closed(return_to_listening);
            self.drain_controller_events_to_hub();
        }
        self.sync_snapshot();
    }

    async fn run(
        &mut self,
        mut rx: mpsc::Receiver<ActorMessage>,
        shutdown_token: CancellationToken,
    ) {
        loop {
            tokio::select! {
                _ = shutdown_token.cancelled() => {
                    self.shutting_down = true;
                    self.unified_shutdown_session(false).await;
                    break;
                }
                msg = rx.recv() => {
                    let Some(msg) = msg else {
                        self.shutting_down = true;
                        self.unified_shutdown_session(false).await;
                        break;
                    };
                    match msg {
                        ActorMessage::ExecCommand { env, queued_at, reply } => {
                            if self.shutting_down || shutdown_token.is_cancelled() {
                                let _ = reply.send(RuntimeReplyEnvelope::err(
                                    "Destroyed",
                                    "bridge runtime is shutting down",
                                ));
                                continue;
                            }
                            if queued_at.elapsed() > SYNC_CMD_TIMEOUT {
                                let _ = reply.send(RuntimeReplyEnvelope::err(
                                    "Timeout",
                                    "command expired in actor queue before execution",
                                ));
                                continue;
                            }
                            let resp = self.handle_command(*env).await;
                            let _ = reply.send(resp);
                        }
                        ActorMessage::SendClipboardPng { bytes, queued_at, reply } => {
                            if self.shutting_down || shutdown_token.is_cancelled() {
                                let _ = reply.send(RuntimeReplyEnvelope::err(
                                    "Destroyed",
                                    "bridge runtime is shutting down",
                                ));
                                continue;
                            }
                            if queued_at.elapsed() > SYNC_CMD_TIMEOUT {
                                let _ = reply.send(RuntimeReplyEnvelope::err(
                                    "Timeout",
                                    "send_clipboard_png expired in actor queue",
                                ));
                                continue;
                            }
                            let resp = self.handle_send_clipboard_binary(CLIP_MIME_IMAGE_PNG, bytes);
                            let _ = reply.send(resp);
                        }
                        ActorMessage::SendFilePath { path, queued_at, reply } => {
                            if self.shutting_down || shutdown_token.is_cancelled() {
                                let _ = reply.send(RuntimeReplyEnvelope::err(
                                    "Destroyed",
                                    "bridge runtime is shutting down",
                                ));
                                continue;
                            }
                            if queued_at.elapsed() > SYNC_CMD_TIMEOUT {
                                let _ = reply.send(RuntimeReplyEnvelope::err(
                                    "Timeout",
                                    "send_file_path expired in actor queue",
                                ));
                                continue;
                            }
                            let resp = self.handle_send_file_path(&path);
                            let _ = reply.send(resp);
                        }
                        ActorMessage::InternalEvent { session_gen, event } => {
                            self.apply_event(session_gen, event).await;
                        }
                        #[cfg(test)]
                        ActorMessage::InjectTestIncoming { session_id, caller_cert, reply_tx, ack } => {
                            // Prepare controller into Listening if not already, for isolated unit tests.
                            if self.controller.state() == BridgeState::Idle {
                                let cfg = BridgePersistedConfig {
                                    v: 1,
                                    control_plane_endpoint: "http://127.0.0.1:8080".into(),
                                    signaling_addr: "127.0.0.1:9001".into(),
                                    signaling_tls: Some(false),
                                    edge_a: None,
                                    edge_b: None,
                                    enrollment_token: None,
                                    ca_der_path: None,
                                    identity_dir: "/tmp".into(),
                                    home_region: "local".into(),
                                    codec: "vp9".into(),
                                    fps: 30,
                                    watchdog_timeout_ms: 3000,
                                    keepalive_interval_ms: 500,
                                    lease_renew_interval_sec: 15,
                                    bw_cap_kbps: 20_000,
                                    transport_mode: TransportMode::Auto,
                                    udp_probe_timeout_ms: 1500,
                                };
                                self.loaded_config = Some(cfg);
                            }
                            self.session_gen = self.session_gen.saturating_add(1);
                            let gen = self.session_gen;
                            self.role = ActiveRole::Host;
                            let incoming_id = format!("inc-{gen}-{}", self.next_incoming_seq);
                            self.next_incoming_seq += 1;
                            let sid_hex = hex::encode(session_id);
                            let caller = VerifiedCallerDisplay::from_verified_cert(&caller_cert);
                            let timer_cancel = CancellationToken::new();
                            self.pending_incoming = Some(PendingIncoming {
                                incoming_id: incoming_id.clone(),
                                session_id_hex: sid_hex.clone(),
                                reply_tx: Some(reply_tx),
                                timer_cancel,
                            });
                            self.events.push_critical(
                                "IncomingCall",
                                serde_json::json!({
                                    "incoming_id": incoming_id,
                                    "session_id_hex": sid_hex,
                                    "caller_device_id_hex": caller.device_id_hex,
                                    "caller_tenant_id_hex": caller.tenant_id_hex,
                                    "verified_by_ca": caller.verified_by_ca,
                                    "verified_caller": caller,
                                    "session_gen": gen,
                                }),
                            );
                            let _ = ack.send(incoming_id);
                        }
                        #[cfg(test)]
                        ActorMessage::SimulateStaleEvent { session_gen, cmd_id, ack } => {
                            let ev = if let Some(cid) = cmd_id {
                                ActorEvent::CommandResult {
                                    cmd_id: cid,
                                    ok: true,
                                    data: None,
                                    error_code: None,
                                    error: None,
                                }
                            } else {
                                ActorEvent::AudioStatus(AudioStatusChanged {
                                    available: false,
                                    reason: Some("stale_gen_marker".into()),
                                })
                            };
                            self.apply_event(session_gen, ev).await;
                            let _ = ack.send(());
                        }
                        #[cfg(test)]
                        ActorMessage::SimulateStaleSecurityEvent { session_gen, ack } => {
                            self.apply_event(
                                session_gen,
                                ActorEvent::SecurityEvent(SecurityEvent::ReplaySessionRejected {
                                    session_id: [0xEE; 16],
                                }),
                            )
                            .await;
                            let _ = ack.send(());
                        }
                        #[cfg(test)]
                        ActorMessage::SimulateStreamingForTest {
                            session_id,
                            cert,
                            ack,
                        } => {
                            let pol = EffectiveTenantPolicy::degraded(
                                cert.tenant_id,
                                cert.policy_hash,
                                "test_streaming",
                            );
                            if self.controller.state() == BridgeState::Idle {
                                let cfg = BridgePersistedConfig {
                                    v: 1,
                                    control_plane_endpoint: "http://127.0.0.1:8080".into(),
                                    signaling_addr: "127.0.0.1:9001".into(),
                                    signaling_tls: Some(false),
                                    edge_a: None,
                                    edge_b: None,
                                    enrollment_token: None,
                                    ca_der_path: None,
                                    identity_dir: "/tmp".into(),
                                    home_region: "local".into(),
                                    codec: "vp9".into(),
                                    fps: 30,
                                    watchdog_timeout_ms: 3000,
                                    keepalive_interval_ms: 500,
                                    lease_renew_interval_sec: 15,
                                    bw_cap_kbps: 20_000,
                                    transport_mode: TransportMode::Auto,
                                    udp_probe_timeout_ms: 1500,
                                };
                                self.loaded_config = Some(cfg);
                                self.controller.on_faulted("test_init");
                                self.controller
                                    .on_bootstrap_complete(&cert, pol.clone(), true)
                                    .expect("test bootstrap complete");
                            }
                            self.controller
                                .on_incoming_verified_call(session_id, &cert)
                                .expect("test incoming verified call");
                            self.controller
                                .on_streaming_started(
                                    session_id,
                                    &cert,
                                    ActiveTransportMode::Udp,
                                )
                                .expect("test streaming started");
                            self.enable_os_input.store(false, Ordering::Release);
                            self.effective_policy = Some(pol);
                            self.drain_controller_events_to_hub();
                            self.sync_snapshot();
                            let _ = ack.send(());
                        }
                        ActorMessage::Shutdown { ack } => {
                            self.shutting_down = true;
                            self.unified_shutdown_session(false).await;
                            let _ = ack.send(());
                            break;
                        }
                    }
                }
            }
        }
    }

    async fn handle_command(&mut self, env: RuntimeCommandEnvelope) -> RuntimeReplyEnvelope {
        match env.cmd.as_str() {
            "load_config" => {
                let Some(path) = env.path.as_deref().filter(|s| !s.is_empty()) else {
                    return RuntimeReplyEnvelope::err(
                        "InvalidArgument",
                        "load_config requires 'path'",
                    );
                };
                if !self.controller.allows_config_mutation() {
                    return RuntimeReplyEnvelope::err(
                        "IllegalStateTransition",
                        format!(
                            "load_config forbidden in state {:?}",
                            self.controller.state()
                        ),
                    );
                }
                match load_config_json(Path::new(path)) {
                    Ok(cfg) => {
                        let cmd = serde_json::json!({
                            "v": 1,
                            "cmd": "load_config",
                            "path": path,
                        });
                        let resp_raw = self.controller.execute_command_json(&cmd.to_string());
                        let parsed: serde_json::Value =
                            serde_json::from_str(&resp_raw).unwrap_or_default();
                        if parsed["ok"].as_bool() == Some(true) {
                            let redacted = RedactedConfigView::from(&cfg);
                            self.loaded_config = Some(cfg);
                            self.drain_controller_events_to_hub();
                            self.sync_snapshot();
                            RuntimeReplyEnvelope::ok(serde_json::json!({
                                "config": redacted,
                                "state": self.controller.state(),
                            }))
                        } else {
                            RuntimeReplyEnvelope::err(
                                parsed["error_code"].as_str().unwrap_or("IllegalStateTransition"),
                                parsed["error"].as_str().unwrap_or("load_config failed"),
                            )
                        }
                    }
                    Err(e) => RuntimeReplyEnvelope::err("ConfigError", e.to_string()),
                }
            }
            "save_config" => {
                let Some(path) = env.path.as_deref().filter(|s| !s.is_empty()) else {
                    return RuntimeReplyEnvelope::err(
                        "InvalidArgument",
                        "save_config requires 'path'",
                    );
                };
                let Some(cfg) = env.config else {
                    return RuntimeReplyEnvelope::err(
                        "InvalidArgument",
                        "save_config requires 'config'",
                    );
                };
                // Validate controller state AND config BEFORE writing anything to disk!
                if !self.controller.allows_config_mutation() {
                    return RuntimeReplyEnvelope::err(
                        "IllegalStateTransition",
                        format!(
                            "save_config forbidden in state {:?}",
                            self.controller.state()
                        ),
                    );
                }
                if let Err(e) = cfg.validate() {
                    return RuntimeReplyEnvelope::err("ConfigError", e.to_string());
                }
                let cmd = serde_json::json!({
                    "v": 1,
                    "cmd": "save_config",
                    "path": path,
                    "config": cfg,
                });
                let resp_raw = self.controller.execute_command_json(&cmd.to_string());
                let parsed: serde_json::Value = serde_json::from_str(&resp_raw).unwrap_or_default();
                if parsed["ok"].as_bool() == Some(true) {
                    let redacted = RedactedConfigView::from(&cfg);
                    self.loaded_config = Some(cfg);
                    self.drain_controller_events_to_hub();
                    self.sync_snapshot();
                    RuntimeReplyEnvelope::ok(serde_json::json!({ "config": redacted }))
                } else {
                    RuntimeReplyEnvelope::err(
                        parsed["error_code"].as_str().unwrap_or("IllegalStateTransition"),
                        parsed["error"].as_str().unwrap_or("save_config failed"),
                    )
                }
            }
            "set_transport_mode" => {
                let Some(mode_str) = env.mode.as_deref() else {
                    return RuntimeReplyEnvelope::err(
                        "InvalidArgument",
                        "set_transport_mode requires 'mode'",
                    );
                };
                let cmd = serde_json::json!({
                    "v": 1,
                    "cmd": "set_transport_mode",
                    "mode": mode_str,
                });
                let resp_raw = self.controller.execute_command_json(&cmd.to_string());
                let parsed: serde_json::Value = serde_json::from_str(&resp_raw).unwrap_or_default();
                if parsed["ok"].as_bool() == Some(true) {
                    if let (Some(cfg), Ok(m)) =
                        (self.loaded_config.as_mut(), TransportMode::parse_name(mode_str))
                    {
                        cfg.transport_mode = m;
                    }
                    self.drain_controller_events_to_hub();
                    self.sync_snapshot();
                    RuntimeReplyEnvelope::ok(parsed["data"].clone())
                } else {
                    RuntimeReplyEnvelope::err(
                        parsed["error_code"].as_str().unwrap_or("InvalidArgument"),
                        parsed["error"].as_str().unwrap_or("set_transport_mode failed"),
                    )
                }
            }
            "handshake" | "get_capabilities" => {
                let base_cmd = serde_json::json!({ "v": 1, "cmd": env.cmd });
                let base_raw = self.controller.execute_command_json(&base_cmd.to_string());
                let base_parsed: serde_json::Value =
                    serde_json::from_str(&base_raw).unwrap_or_default();
                let mut merged = if base_parsed["ok"].as_bool() == Some(true) {
                    match base_parsed.get("data") {
                        Some(serde_json::Value::Object(map)) => map.clone(),
                        _ => serde_json::Map::new(),
                    }
                } else {
                    serde_json::Map::new()
                };
                let caps_data = HandshakeCapabilitiesData {
                    abi_version: BRIDGE_JSON_ABI_V2,
                    caps: BRIDGE_V2_CAPABILITIES
                        .iter()
                        .map(|c| (*c).to_string())
                        .collect(),
                };
                merged.insert(
                    "abi_version".to_string(),
                    serde_json::json!(caps_data.abi_version),
                );
                merged.insert("caps".to_string(), serde_json::json!(caps_data.caps));
                RuntimeReplyEnvelope::ok(serde_json::Value::Object(merged))
            }
            "get_permissions" => {
                self.invalidate_perm_cache();
                let perms = self.probe_permissions();
                match serde_json::to_value(&perms) {
                    Ok(val) => {
                        if self.last_emitted_permission_status.as_ref() != Some(&perms) {
                            self.last_emitted_permission_status = Some(perms);
                            self.events.push_critical("permission_status", val.clone());
                        }
                        RuntimeReplyEnvelope::ok(val)
                    }
                    Err(e) => RuntimeReplyEnvelope::err("Internal", e.to_string()),
                }
            }
            "set_input_enabled" | "enable_os_input" => self.handle_set_input_enabled(env).await,
            "set_video_quality" => self.handle_set_video_quality(env),
            "set_clipboard_sync" => self.handle_set_clipboard_sync(env),
            "set_codec" => {
                let Some(codec_str) = env.codec.as_deref() else {
                    return RuntimeReplyEnvelope::err(
                        "InvalidArgument",
                        "set_codec requires 'codec' (auto|hevc|h264|vp9|av1)",
                    );
                };
                let norm = match normalize_codec_setting(codec_str) {
                    Ok(c) => c,
                    Err(e) => {
                        return RuntimeReplyEnvelope::err("InvalidArgument", e.to_string());
                    }
                };
                if self.controller.state() == BridgeState::Streaming {
                    let Some(tx) = &self.active_session_tx else {
                        return RuntimeReplyEnvelope::err(
                            "Unavailable",
                            "no active session channel available for codec switch",
                        );
                    };
                    match tx.try_send(SessionAction::RequestCodec(norm.clone())) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            return RuntimeReplyEnvelope::err("Busy", "session action queue full");
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            return RuntimeReplyEnvelope::err(
                                "Unavailable",
                                "active session channel closed",
                            );
                        }
                    }
                    return RuntimeReplyEnvelope::ok(serde_json::json!({
                        "requested_codec": norm,
                        "active_codec": self.active_codec,
                    }));
                }
                let cmd = serde_json::json!({
                    "v": 1,
                    "cmd": "set_codec",
                    "codec": norm,
                });
                let resp_raw = self.controller.execute_command_json(&cmd.to_string());
                let parsed: serde_json::Value = serde_json::from_str(&resp_raw).unwrap_or_default();
                if parsed["ok"].as_bool() == Some(true) {
                    if let Some(cfg) = self.loaded_config.as_mut() {
                        cfg.codec = norm.clone();
                    }
                    self.active_codec = Some(norm);
                    self.drain_controller_events_to_hub();
                    self.sync_snapshot();
                    RuntimeReplyEnvelope::ok(parsed["data"].clone())
                } else {
                    RuntimeReplyEnvelope::err(
                        parsed["error_code"]
                            .as_str()
                            .unwrap_or("IllegalStateTransition"),
                        parsed["error"].as_str().unwrap_or("set_codec failed"),
                    )
                }
            }
            "set_audio_mute" => {
                let Some(muted) = env.muted else {
                    return RuntimeReplyEnvelope::err(
                        "InvalidArgument",
                        "set_audio_mute requires boolean 'muted'",
                    );
                };
                if let Some(tx) = &self.active_session_tx {
                    if tx.try_send(SessionAction::SetAudioMute(muted)).is_err() {
                        return RuntimeReplyEnvelope::err(
                            "Busy",
                            "session action queue full or closed",
                        );
                    }
                }
                let cmd = serde_json::json!({
                    "v": 1,
                    "cmd": "set_audio_mute",
                    "muted": muted,
                });
                let resp_raw = self.controller.execute_command_json(&cmd.to_string());
                let parsed: serde_json::Value = serde_json::from_str(&resp_raw).unwrap_or_default();
                self.drain_controller_events_to_hub();
                self.sync_snapshot();
                if parsed["ok"].as_bool() == Some(true) {
                    RuntimeReplyEnvelope::ok(parsed["data"].clone())
                } else {
                    RuntimeReplyEnvelope::err(
                        parsed["error_code"].as_str().unwrap_or("IllegalStateTransition"),
                        parsed["error"].as_str().unwrap_or("set_audio_mute failed"),
                    )
                }
            }
            "get_snapshot" | "snapshot" => {
                self.sync_snapshot();
                let snap = self
                    .snapshot_cache
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                match serde_json::to_value(snap) {
                    Ok(val) => RuntimeReplyEnvelope::ok(val),
                    Err(e) => RuntimeReplyEnvelope::err("Internal", e.to_string()),
                }
            }
            "start_host" => self.handle_start_host(env),
            "stop_host" => self.handle_stop_host().await,
            "dial" => self.handle_dial(env),
            "disconnect" => self.handle_disconnect().await,
            "accept_incoming" => self.handle_incoming_decision(true, env),
            "reject_incoming" => self.handle_incoming_decision(false, env),
            "send_hid_key" => self.handle_send_hid_key(env, None),
            "key_down" => self.handle_send_hid_key(env, Some(true)),
            "key_up" => self.handle_send_hid_key(env, Some(false)),
            "send_hid_mouse" => self.handle_send_hid_mouse(env),
            "release_all" => self.handle_release_all(env).await,
            "send_clipboard" => self.handle_send_clipboard_cmd(env),
            "send_file" => {
                if let Some(path) = env.path.as_deref() {
                    self.handle_send_file_path(path)
                } else {
                    RuntimeReplyEnvelope::err(
                        "InvalidArgument",
                        "send_file requires 'path' to an existing file",
                    )
                }
            }
            "refresh_policy" => self.handle_refresh_policy(),
            "cancel_file" => {
                let Some(tid) = env.transfer_id else {
                    return RuntimeReplyEnvelope::err(
                        "InvalidArgument",
                        "cancel_file requires 'transfer_id'",
                    );
                };
                if let Some(tx) = &self.active_session_tx {
                    let _ = tx.try_send(SessionAction::CancelFile { transfer_id: tid });
                }
                let cmd = serde_json::json!({
                    "v": 1,
                    "cmd": "cancel_file",
                    "transfer_id": tid,
                });
                let resp_raw = self.controller.execute_command_json(&cmd.to_string());
                let parsed: serde_json::Value = serde_json::from_str(&resp_raw).unwrap_or_default();
                self.drain_controller_events_to_hub();
                self.sync_snapshot();
                if parsed["ok"].as_bool() == Some(true) {
                    RuntimeReplyEnvelope::ok(parsed["data"].clone())
                } else {
                    RuntimeReplyEnvelope::err(
                        parsed["error_code"].as_str().unwrap_or("NotFound"),
                        parsed["error"].as_str().unwrap_or("cancel_file failed"),
                    )
                }
            }
            other => {
                RuntimeReplyEnvelope::err("UnknownCommand", format!("unknown command '{other}'"))
            }
        }
    }

    fn build_client_config(
        &self,
        codec_override: Option<&str>,
    ) -> Result<(V2ClientConfig, bool), RuntimeReplyEnvelope> {
        let Some(cfg) = &self.loaded_config else {
            return Err(RuntimeReplyEnvelope::err(
                "MissingConfig",
                "load_config or save_config must succeed first",
            ));
        };
        let Some(edge_a) = cfg.edge_a.clone() else {
            return Err(RuntimeReplyEnvelope::err(
                "InvalidConfig",
                "config missing 'edge_a'",
            ));
        };
        let Some(edge_b) = cfg.edge_b.clone() else {
            return Err(RuntimeReplyEnvelope::err(
                "InvalidConfig",
                "config missing 'edge_b'",
            ));
        };
        let raw_codec = codec_override.unwrap_or(cfg.codec.as_str()).trim();
        let (codec, codec_auto) = if raw_codec.is_empty() {
            (VideoCodec::Vp9, false)
        } else if raw_codec.eq_ignore_ascii_case("auto") {
            let local_caps = local_v2_cap_bits();
            let auto_codec =
                negotiate_video_codec(local_caps, local_caps, None).unwrap_or(VideoCodec::Vp9);
            (auto_codec, true)
        } else {
            let parsed = VideoCodec::parse_name(raw_codec)
                .map_err(|e| RuntimeReplyEnvelope::err("InvalidConfig", e.to_string()))?;
            (parsed, false)
        };
        let v2_cfg = V2ClientConfig {
            control_plane_endpoint: cfg.control_plane_endpoint.clone(),
            signaling_addr: cfg.signaling_addr.clone(),
            signaling_tls: cfg.signaling_tls,
            edge_a,
            edge_b,
            enrollment_token: cfg.enrollment_token.clone(),
            ca_der_path: cfg.ca_der_path.as_deref().map(PathBuf::from),
            identity_dir: PathBuf::from(&cfg.identity_dir),
            home_region: cfg.home_region.clone(),
            codec,
            fps: cfg.fps,
            watchdog_timeout_ms: cfg.watchdog_timeout_ms,
            keepalive_interval_ms: cfg.keepalive_interval_ms,
            lease_renew_interval_sec: cfg.lease_renew_interval_sec,
            bw_cap_kbps: cfg.bw_cap_kbps,
            transport_mode: cfg.transport_mode,
            udp_probe_timeout_ms: cfg.udp_probe_timeout_ms,
            #[cfg(feature = "e2e-fault-injection")]
            drop_udp_for_test: self.options.drop_udp_override,
        };
        v2_cfg
            .validate()
            .map_err(|e| RuntimeReplyEnvelope::err("InvalidConfig", e.to_string()))?;
        Ok((v2_cfg, codec_auto))
    }

    fn handle_start_host(&mut self, env: RuntimeCommandEnvelope) -> RuntimeReplyEnvelope {
        // Idempotent when host is already running!
        if self.role == ActiveRole::Host
            && matches!(
                self.controller.state(),
                BridgeState::Bootstrapping
                    | BridgeState::Listening
                    | BridgeState::Incoming
                    | BridgeState::Streaming
            )
        {
            return RuntimeReplyEnvelope::already_running(self.session_gen);
        }
        // Reject when controller is active.
        if self.role == ActiveRole::Controller
            || matches!(
                self.controller.state(),
                BridgeState::Dialing | BridgeState::Streaming | BridgeState::Closing
            )
        {
            return RuntimeReplyEnvelope::err(
                "Busy",
                format!("cannot start_host in state {:?}", self.controller.state()),
            );
        }

        let (client_cfg, codec_auto) = match self.build_client_config(env.codec.as_deref()) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let raw_dl = env
            .download_dir
            .map(PathBuf::from)
            .or_else(|| self.options.download_dir.clone())
            .unwrap_or_else(|| client_cfg.identity_dir.join("downloads"));
        let download_dir = match validate_download_dir(&raw_dl) {
            Ok(d) => d,
            Err(e) => return e,
        };

        let resp_raw = self
            .controller
            .execute_command_json(r#"{"v":1,"cmd":"start_host"}"#);
        let parsed: serde_json::Value = serde_json::from_str(&resp_raw).unwrap_or_default();
        if parsed["ok"].as_bool() != Some(true) {
            return RuntimeReplyEnvelope::err(
                parsed["error_code"].as_str().unwrap_or("IllegalStateTransition"),
                parsed["error"].as_str().unwrap_or("start_host rejected"),
            );
        }

        self.session_gen = self.session_gen.saturating_add(1);
        let gen = self.session_gen;
        let cmd_id = self.alloc_cmd_id();
        self.role = ActiveRole::Host;
        let cancel = CancellationToken::new();
        self.session_cancel = Some(cancel.clone());
        self.drain_controller_events_to_hub();
        self.sync_snapshot();

        let actor_tx = self.actor_tx.clone();
        let events = Arc::clone(&self.events);
        let dropped_events = Arc::clone(&self.dropped_events);
        let active_tasks = Arc::clone(&self.active_tasks);
        let total_tasks = Arc::clone(&self.spawned_tasks_total);
        let releaser_slot = Arc::clone(&self.emergency_releaser);
        let use_os_capture = self.options.use_os_capture;
        let legacy_capture_fallback = self.options.legacy_capture_fallback;
        let use_os_audio = self.options.use_os_audio;
        let use_os_clipboard = self.options.use_os_clipboard;
        let enable_hid_watchdog_subprocess = self.options.enable_hid_watchdog_subprocess;
        let watchdog_report_path = self.options.watchdog_report_path.clone();
        let watchdog_bin_path = self.options.watchdog_bin_path.clone();
        let dryrun_journal = self.options.dryrun_journal.clone();
        let mem_clip = self.options.memory_clipboard.clone();
        let synth_w = self.options.synthetic_width;
        let synth_h = self.options.synthetic_height;
        let real_input_permit = self.options.real_input_permit.clone();
        let permission_probe = self.options.permission_probe.clone();
        let enable_os_input = Arc::clone(&self.enable_os_input);
        let active_watchdog_ax_probe = Arc::clone(&self.active_watchdog_ax_probe);
        let clipboard_sync_enabled = Arc::clone(&self.clipboard_sync_enabled);

        let h = tokio::spawn(async move {
            let _guard = TaskCountGuard::enter(&active_tasks, &total_tasks);
            run_host_lifecycle_task(
                gen,
                cmd_id,
                client_cfg,
                codec_auto,
                cancel,
                actor_tx,
                events,
                dropped_events,
                releaser_slot,
                HostTaskAdapters {
                    use_os_capture,
                    legacy_capture_fallback,
                    use_os_audio,
                    use_os_clipboard,
                    enable_hid_watchdog_subprocess,
                    watchdog_report_path,
                    watchdog_bin_path,
                    real_input_permit,
                    permission_probe,
                    enable_os_input,
                    active_watchdog_ax_probe,
                    clipboard_sync_enabled,
                    dryrun_journal,
                    mem_clip,
                    download_dir,
                    synth_w,
                    synth_h,
                },
            )
            .await;
        });
        self.session_handles.push(h);
        RuntimeReplyEnvelope::accepted(cmd_id, gen)
    }

    async fn handle_stop_host(&mut self) -> RuntimeReplyEnvelope {
        if self.role != ActiveRole::Host
            && matches!(
                self.controller.state(),
                BridgeState::Idle | BridgeState::Ready
            )
        {
            return RuntimeReplyEnvelope::already_stopped();
        }
        let cmd_id = self.alloc_cmd_id();
        let gen = self.session_gen;
        let _ = self
            .controller
            .execute_command_json(r#"{"v":1,"cmd":"stop_host"}"#);
        self.drain_controller_events_to_hub();
        self.sync_snapshot();

        self.unified_shutdown_session(false).await;
        self.events.push_critical(
            "CommandResult",
            serde_json::json!({
                "cmd_id": cmd_id,
                "cmd": "stop_host",
                "ok": true,
                "session_gen": gen,
            }),
        );
        RuntimeReplyEnvelope::accepted(cmd_id, gen)
    }

    fn handle_dial(&mut self, env: RuntimeCommandEnvelope) -> RuntimeReplyEnvelope {
        // Strict Busy rejection when NOT Idle/Ready (never mutates active session!).
        if self.role != ActiveRole::None
            || !matches!(self.controller.state(), BridgeState::Ready)
        {
            return RuntimeReplyEnvelope::err(
                "Busy",
                format!(
                    "dial requires idle/ready state, current state={:?}",
                    self.controller.state()
                ),
            );
        }
        let Some(target_hex) = env.target_device_id_hex.as_deref() else {
            return RuntimeReplyEnvelope::err(
                "InvalidArgument",
                "dial requires 'target_device_id_hex'",
            );
        };
        let target_bytes = match hex::decode(target_hex) {
            Ok(b) if b.len() == 16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&b);
                arr
            }
            _ => {
                return RuntimeReplyEnvelope::err(
                    "InvalidArgument",
                    "target_device_id_hex must be 32 hex chars (16 bytes)",
                );
            }
        };
        let (client_cfg, codec_auto) = match self.build_client_config(env.codec.as_deref()) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let raw_dl = env
            .download_dir
            .map(PathBuf::from)
            .or_else(|| self.options.download_dir.clone())
            .unwrap_or_else(|| client_cfg.identity_dir.join("downloads"));
        let download_dir = match validate_download_dir(&raw_dl) {
            Ok(d) => d,
            Err(e) => return e,
        };

        let dial_cmd = serde_json::json!({
            "v": 1,
            "cmd": "dial",
            "target_device_id_hex": target_hex,
        });
        let resp_raw = self.controller.execute_command_json(&dial_cmd.to_string());
        let parsed: serde_json::Value = serde_json::from_str(&resp_raw).unwrap_or_default();
        if parsed["ok"].as_bool() != Some(true) {
            return RuntimeReplyEnvelope::err(
                "Busy",
                parsed["error"].as_str().unwrap_or("dial rejected"),
            );
        }

        self.session_gen = self.session_gen.saturating_add(1);
        let gen = self.session_gen;
        let cmd_id = self.alloc_cmd_id();
        self.role = ActiveRole::Controller;
        let cancel = CancellationToken::new();
        self.session_cancel = Some(cancel.clone());
        self.drain_controller_events_to_hub();
        self.sync_snapshot();

        let actor_tx = self.actor_tx.clone();
        let mailbox = Arc::clone(&self.mailbox);
        let events = Arc::clone(&self.events);
        let dropped_events = Arc::clone(&self.dropped_events);
        let active_tasks = Arc::clone(&self.active_tasks);
        let total_tasks = Arc::clone(&self.spawned_tasks_total);
        let use_os_audio = self.options.use_os_audio;
        let use_os_clipboard = self.options.use_os_clipboard;
        let mem_clip = self.options.memory_clipboard.clone();
        let clipboard_sync_enabled = Arc::clone(&self.clipboard_sync_enabled);
        #[cfg(feature = "e2e-fault-injection")]
        let silent_blackhole = self.options.silent_peer_blackhole.clone();

        let h = tokio::spawn(async move {
            let _guard = TaskCountGuard::enter(&active_tasks, &total_tasks);
            run_controller_lifecycle_task(
                gen,
                cmd_id,
                client_cfg,
                codec_auto,
                target_bytes,
                cancel,
                actor_tx,
                mailbox,
                events,
                dropped_events,
                use_os_audio,
                use_os_clipboard,
                mem_clip,
                clipboard_sync_enabled,
                download_dir,
                #[cfg(feature = "e2e-fault-injection")]
                silent_blackhole,
            )
            .await;
        });
        self.session_handles.push(h);
        RuntimeReplyEnvelope::accepted(cmd_id, gen)
    }

    async fn handle_disconnect(&mut self) -> RuntimeReplyEnvelope {
        if !matches!(
            self.controller.state(),
            BridgeState::Dialing | BridgeState::Incoming | BridgeState::Streaming
        ) {
            return RuntimeReplyEnvelope::already_stopped();
        }
        let cmd_id = self.alloc_cmd_id();
        let gen = self.session_gen;
        let return_to_listening = self.role == ActiveRole::Host;
        let _ = self
            .controller
            .execute_command_json(r#"{"v":1,"cmd":"disconnect"}"#);
        self.drain_controller_events_to_hub();
        self.sync_snapshot();

        self.unified_shutdown_session(return_to_listening).await;
        self.events.push_critical(
            "CommandResult",
            serde_json::json!({
                "cmd_id": cmd_id,
                "cmd": "disconnect",
                "ok": true,
                "session_gen": gen,
            }),
        );
        RuntimeReplyEnvelope::accepted(cmd_id, gen)
    }

    fn handle_incoming_decision(
        &mut self,
        accept: bool,
        env: RuntimeCommandEnvelope,
    ) -> RuntimeReplyEnvelope {
        let Some(req_id) = env
            .incoming_id
            .as_deref()
            .filter(|s| !s.is_empty())
        else {
            return RuntimeReplyEnvelope::err(
                "StaleIncoming",
                "accept_incoming/reject_incoming requires matching 'incoming_id'",
            );
        };
        let Some(pending) = &self.pending_incoming else {
            return RuntimeReplyEnvelope::err("StaleIncoming", "no pending incoming call");
        };
        if pending.incoming_id != req_id {
            return RuntimeReplyEnvelope::err(
                "StaleIncoming",
                format!(
                    "incoming_id '{req_id}' does not match current pending incoming call"
                ),
            );
        }
        let Some(mut pending) = self.pending_incoming.take() else {
            return RuntimeReplyEnvelope::err("StaleIncoming", "no pending incoming call");
        };
        pending.timer_cancel.cancel();

        let cmd_name = if accept {
            "accept_incoming"
        } else {
            "reject_incoming"
        };
        if self.controller.state() == BridgeState::Incoming {
            let ctrl_cmd = serde_json::json!({
                "v": 1,
                "cmd": cmd_name,
                "session_id_hex": pending.session_id_hex,
                "reason": env.reason,
            });
            let _ = self.controller.execute_command_json(&ctrl_cmd.to_string());
            self.drain_controller_events_to_hub();
            self.sync_snapshot();
        }
        let decision = if accept {
            CallDecision::Accept
        } else {
            CallDecision::Reject {
                error_code: 0x0402,
                reason: env.reason.unwrap_or_else(|| "user_rejected".into()),
            }
        };
        if let Some(tx) = pending.reply_tx.take() {
            let _ = tx.send(decision);
        }
        RuntimeReplyEnvelope::ok(serde_json::json!({
            "incoming_id": pending.incoming_id,
            "decision": if accept { "accept" } else { "reject" },
        }))
    }

    async fn handle_set_input_enabled(
        &mut self,
        env: RuntimeCommandEnvelope,
    ) -> RuntimeReplyEnvelope {
        let Some(requested_enabled) = env.enabled else {
            return RuntimeReplyEnvelope::err(
                "InvalidArgument",
                "set_input_enabled requires explicit boolean 'enabled'",
            );
        };
        self.invalidate_perm_cache();
        let perms = self.probe_permissions();
        if requested_enabled {
            let authoritative = perms.probe_source.is_authoritative();
            if !perms.screen_capture_granted || !perms.accessibility_granted || !authoritative {
                self.enable_os_input.store(false, Ordering::Release);
                self.controller.set_enable_os_input(false);
                self.sync_snapshot();
                self.events.push_critical(
                    "input_enabled_ack",
                    serde_json::json!({
                        "enabled": false,
                        "status": "not_permitted",
                        "screen_capture_granted": perms.screen_capture_granted,
                        "accessibility_granted": perms.accessibility_granted,
                        "probe_source": perms.probe_source.as_str(),
                    }),
                );
                let msg = if !authoritative {
                    "enabling OS input requires an authoritative watchdog/injector Accessibility probe (ui_process_hint cannot authorize OS input)"
                } else {
                    "enabling OS input requires both Screen Recording and Accessibility permissions"
                };
                return RuntimeReplyEnvelope::err("not_permitted", msg);
            }
            if self.controller.state() != BridgeState::Streaming {
                self.enable_os_input.store(false, Ordering::Release);
                self.controller.set_enable_os_input(false);
                self.sync_snapshot();
                self.events.push_critical(
                    "input_enabled_ack",
                    serde_json::json!({
                        "enabled": false,
                        "status": "not_permitted",
                        "screen_capture_granted": perms.screen_capture_granted,
                        "accessibility_granted": perms.accessibility_granted,
                        "probe_source": perms.probe_source.as_str(),
                        "reason": "session_not_streaming",
                    }),
                );
                return RuntimeReplyEnvelope::err(
                    "IllegalStateTransition",
                    "set_input_enabled(true) requires active Streaming session",
                );
            }
            self.enable_os_input.store(true, Ordering::Release);
            self.controller.set_enable_os_input(true);
            self.sync_snapshot();
            self.events.push_critical(
                "input_enabled_ack",
                serde_json::json!({
                    "enabled": true,
                    "status": "ok",
                    "screen_capture_granted": true,
                    "accessibility_granted": true,
                    "probe_source": perms.probe_source.as_str(),
                }),
            );
            return RuntimeReplyEnvelope::ok(serde_json::json!({
                "enabled": true,
                "status": "ok",
            }));
        }

        // Turning OFF input: release all held inputs synchronously and disable gate.
        let reason_str = env.reason.clone().unwrap_or_else(|| "user_disabled".into());
        let rel_env = RuntimeCommandEnvelope {
            v: 1,
            cmd: "release_all".into(),
            path: None,
            config: None,
            target_device_id_hex: None,
            incoming_id: None,
            session_id_hex: None,
            reason: Some(reason_str.clone()),
            muted: None,
            mode: None,
            codec: None,
            mime_kind: None,
            payload_b64: None,
            text: None,
            rel_name: None,
            file_size: None,
            transfer_id: None,
            down: None,
            modifiers: None,
            usb_hid_usage: None,
            unicode_scalar: None,
            keys: None,
            mouse_kind: None,
            x: None,
            y: None,
            dx: None,
            dy: None,
            buttons: None,
            wheel_x: None,
            wheel_y: None,
            download_dir: None,
            ring_timeout_ms: None,
            enabled: None,
            emergency_escape: None,
            bitrate_kbps: None,
            fps_cap: None,
        };
        let rel_reply = self.handle_release_all_inner(rel_env, false).await;
        self.enable_os_input.store(false, Ordering::Release);
        self.controller.set_enable_os_input(false);
        self.sync_snapshot();
        let release_failed = !rel_reply.ok
            || rel_reply
                .data
                .as_ref()
                .and_then(|d| d.get("timed_out"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            || rel_reply
                .data
                .as_ref()
                .and_then(|d| d.get("residual"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
        if release_failed {
            self.events.push_critical(
                "release_failed",
                serde_json::json!({
                    "reason": reason_str,
                    "error": rel_reply.error.as_deref().unwrap_or("release_all_failed"),
                }),
            );
        }
        let mut ack_payload = serde_json::json!({
            "enabled": false,
            "status": "disabled",
            "screen_capture_granted": perms.screen_capture_granted,
            "accessibility_granted": perms.accessibility_granted,
            "probe_source": perms.probe_source.as_str(),
            "reason": reason_str,
        });
        if release_failed {
            ack_payload["release_all"] = serde_json::json!("failed");
        }
        self.events.push_critical("input_enabled_ack", ack_payload);
        let mut ok_data = serde_json::json!({
            "enabled": false,
            "status": "disabled",
        });
        if release_failed {
            ok_data["release_all"] = serde_json::json!("failed");
        }
        RuntimeReplyEnvelope::ok(ok_data)
    }

    fn handle_set_video_quality(&mut self, env: RuntimeCommandEnvelope) -> RuntimeReplyEnvelope {
        if env.bitrate_kbps.is_none() && env.fps_cap.is_none() {
            return RuntimeReplyEnvelope::err(
                "InvalidArgument",
                "set_video_quality requires 'bitrate_kbps' and/or 'fps_cap'",
            );
        }
        if let Some(bps) = env.bitrate_kbps {
            if bps != 0 && !(MIN_BITRATE_KBPS..=MAX_BITRATE_KBPS).contains(&bps) {
                return RuntimeReplyEnvelope::err(
                    "InvalidArgument",
                    format!(
                        "bitrate_kbps {bps} must be 0 (auto) or within [{MIN_BITRATE_KBPS}, {MAX_BITRATE_KBPS}]"
                    ),
                );
            }
        }
        if let Some(fps) = env.fps_cap {
            if !(MIN_FPS_CAP..=MAX_FPS_CAP).contains(&fps) {
                return RuntimeReplyEnvelope::err(
                    "InvalidArgument",
                    format!("fps_cap {fps} outside [{MIN_FPS_CAP}, {MAX_FPS_CAP}]"),
                );
            }
        }
        let default_bitrate = self
            .bitrate_kbps
            .or_else(|| self.loaded_config.as_ref().map(|c| c.bw_cap_kbps))
            .unwrap_or(0);
        let default_fps = self
            .fps_cap
            .or_else(|| self.loaded_config.as_ref().map(|c| c.fps))
            .unwrap_or(30);
        let mut next_bitrate = env.bitrate_kbps.unwrap_or(default_bitrate);
        let next_fps = env.fps_cap.unwrap_or(default_fps);
        if let Some(pol) = &self.effective_policy {
            let max_bw = pol.max_bw_kbps();
            if max_bw > 0 && next_bitrate > max_bw {
                next_bitrate = max_bw;
            }
        }
        if let Some(tx) = &self.active_session_tx {
            match tx.try_send(SessionAction::SetVideoQuality {
                bitrate_kbps: next_bitrate,
                fps_cap: next_fps,
            }) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    return RuntimeReplyEnvelope::err("Busy", "session action queue full");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return RuntimeReplyEnvelope::err(
                        "Unavailable",
                        "active session channel closed",
                    );
                }
            }
        }
        self.bitrate_kbps = Some(next_bitrate);
        self.fps_cap = Some(next_fps);
        if let Some(cfg) = self.loaded_config.as_mut() {
            if next_bitrate > 0 {
                cfg.bw_cap_kbps = next_bitrate;
            }
            cfg.fps = next_fps;
        }
        self.controller
            .set_video_quality(Some(next_bitrate), Some(next_fps));
        self.sync_snapshot();
        let payload = serde_json::json!({
            "bitrate_kbps": next_bitrate,
            "fps_cap": next_fps,
        });
        self.events.push_critical("video_quality_ack", payload.clone());
        RuntimeReplyEnvelope::ok(payload)
    }

    fn handle_set_clipboard_sync(&mut self, env: RuntimeCommandEnvelope) -> RuntimeReplyEnvelope {
        let Some(enabled) = env.enabled else {
            return RuntimeReplyEnvelope::err(
                "InvalidArgument",
                "set_clipboard_sync requires boolean 'enabled'",
            );
        };
        if enabled {
            if let Some(pol) = &self.effective_policy {
                if !pol.allow_clipboard() {
                    self.controller.set_clipboard_sync_enabled(false);
                    self.sync_snapshot();
                    self.events.push_critical(
                        "clipboard_sync_status",
                        serde_json::json!({
                            "enabled": false,
                            "status": "policy_denied",
                            "code": "policy_denied",
                        }),
                    );
                    return RuntimeReplyEnvelope::err(
                        "policy_denied",
                        "clipboard denied by policy",
                    );
                }
            }
        }
        self.clipboard_sync_enabled.store(enabled, Ordering::Release);
        self.controller.set_clipboard_sync_enabled(enabled);
        if let Some(tx) = &self.active_session_tx {
            let _ = tx.try_send(SessionAction::SetClipboardSync(enabled));
        }
        self.sync_snapshot();
        let status = if enabled { "enabled" } else { "disabled" };
        let payload = serde_json::json!({
            "enabled": enabled,
            "status": status,
        });
        self.events
            .push_critical("clipboard_sync_status", payload.clone());
        RuntimeReplyEnvelope::ok(payload)
    }

    fn handle_send_hid_key(
        &self,
        env: RuntimeCommandEnvelope,
        down_override: Option<bool>,
    ) -> RuntimeReplyEnvelope {
        if self.controller.state() != BridgeState::Streaming {
            return RuntimeReplyEnvelope::err(
                "IllegalStateTransition",
                "send_hid_key requires active Streaming session",
            );
        }
        // Fast-path View-Only check FIRST (avoid per-event XPC/TCC calls when input is disabled).
        if !self.enable_os_input.load(Ordering::Acquire) {
            return RuntimeReplyEnvelope::err(
                "not_permitted",
                "remote input dropped: enable_os_input is off",
            );
        }
        let perms = self.probe_permissions_cached();
        if !perms.screen_capture_granted
            || !perms.accessibility_granted
            || !perms.probe_source.is_authoritative()
        {
            return RuntimeReplyEnvelope::err(
                "not_permitted",
                "remote input dropped: permissions missing or non-authoritative probe",
            );
        }
        if self.effective_policy.is_none() {
            return RuntimeReplyEnvelope::err(
                "PolicyDenied",
                "verified tenant policy unavailable",
            );
        }
        let Some(tx) = &self.active_session_tx else {
            return RuntimeReplyEnvelope::err(
                "IllegalStateTransition",
                "send_hid_key requires active Streaming session",
            );
        };
        let Some(usage) = env.usb_hid_usage else {
            return RuntimeReplyEnvelope::err(
                "InvalidArgument",
                "send_hid_key requires 'usb_hid_usage'",
            );
        };
        let Some(down) = down_override.or(env.down) else {
            return RuntimeReplyEnvelope::err("InvalidArgument", "send_hid_key requires 'down'");
        };
        let scalar = env.unicode_scalar.unwrap_or(0);
        if scalar != 0 && char::from_u32(scalar).is_none() {
            return RuntimeReplyEnvelope::err(
                "InvalidArgument",
                "unicode_scalar is not a valid Unicode scalar",
            );
        }
        let ev = KeyEvent {
            down,
            modifiers: env.modifiers.unwrap_or(0),
            usb_hid_usage: u32::from(usage),
            unicode_scalar: scalar,
            client_ts_ms: now_epoch_ms(),
        };
        if let Err(e) = ev.validate() {
            return RuntimeReplyEnvelope::err("InvalidArgument", e.to_string());
        }
        if tx.try_send(SessionAction::SendHid(HidPayload::Key(ev))).is_err() {
            return RuntimeReplyEnvelope::err("Busy", "session action queue full");
        }
        RuntimeReplyEnvelope::ok(serde_json::json!({ "sent": true }))
    }

    fn handle_send_hid_mouse(&self, env: RuntimeCommandEnvelope) -> RuntimeReplyEnvelope {
        if self.controller.state() != BridgeState::Streaming {
            return RuntimeReplyEnvelope::err(
                "IllegalStateTransition",
                "send_hid_mouse requires active Streaming session",
            );
        }
        // Fast-path View-Only check FIRST (avoid per-event XPC/TCC calls when input is disabled).
        if !self.enable_os_input.load(Ordering::Acquire) {
            return RuntimeReplyEnvelope::err(
                "not_permitted",
                "remote input dropped: enable_os_input is off",
            );
        }
        let perms = self.probe_permissions_cached();
        if !perms.screen_capture_granted
            || !perms.accessibility_granted
            || !perms.probe_source.is_authoritative()
        {
            return RuntimeReplyEnvelope::err(
                "not_permitted",
                "remote input dropped: permissions missing or non-authoritative probe",
            );
        }
        if self.effective_policy.is_none() {
            return RuntimeReplyEnvelope::err(
                "PolicyDenied",
                "verified tenant policy unavailable",
            );
        }
        let Some(tx) = &self.active_session_tx else {
            return RuntimeReplyEnvelope::err(
                "IllegalStateTransition",
                "send_hid_mouse requires active Streaming session",
            );
        };
        let kind = match env
            .mouse_kind
            .as_deref()
            .unwrap_or("move_abs")
            .to_ascii_lowercase()
            .as_str()
        {
            "move_abs" => MouseKind::MoveAbs,
            "move_rel" => MouseKind::MoveRel,
            "down" | "button_down" => MouseKind::Down,
            "up" | "button_up" => MouseKind::Up,
            "wheel" => MouseKind::Wheel,
            other => {
                return RuntimeReplyEnvelope::err(
                    "InvalidArgument",
                    format!("invalid mouse_kind '{other}'"),
                );
            }
        };
        let buttons = env.buttons.unwrap_or(0);
        if buttons & !MOUSE_BUTTONS_VALID_MASK != 0 {
            return RuntimeReplyEnvelope::err(
                "InvalidArgument",
                "mouse buttons bitmask must fit within 0x1F",
            );
        }
        let (x_or_dx, y_or_dy) = match kind {
            MouseKind::MoveRel => (
                i32::from(env.dx.unwrap_or(0)),
                i32::from(env.dy.unwrap_or(0)),
            ),
            _ => (
                i32::from(env.x.unwrap_or(0)),
                i32::from(env.y.unwrap_or(0)),
            ),
        };
        let ev = MouseEvent {
            kind,
            buttons,
            x_or_dx,
            y_or_dy,
            wheel_dx: env.wheel_x.unwrap_or(0),
            wheel_dy: env.wheel_y.unwrap_or(0),
            client_ts_ms: now_epoch_ms(),
        };
        if let Err(e) = ev.validate() {
            return RuntimeReplyEnvelope::err("InvalidArgument", e.to_string());
        }
        if tx
            .try_send(SessionAction::SendHid(HidPayload::Mouse(ev)))
            .is_err()
        {
            return RuntimeReplyEnvelope::err("Busy", "session action queue full");
        }
        RuntimeReplyEnvelope::ok(serde_json::json!({ "sent": true }))
    }

    async fn handle_release_all(&self, env: RuntimeCommandEnvelope) -> RuntimeReplyEnvelope {
        self.handle_release_all_inner(env, true).await
    }

    async fn handle_release_all_inner(
        &self,
        env: RuntimeCommandEnvelope,
        emit_escape_ack: bool,
    ) -> RuntimeReplyEnvelope {
        // Emergency Escape runs UNCONDITIONALLY at the very top BEFORE buttons bitmask
        // validation, policy check, or permission check, and releases via the ungated
        // `emergency_releaser()` BEFORE/alongside disabling `enable_os_input`.
        let is_emergency_escape = env.emergency_escape == Some(true)
            || matches!(
                env.reason.as_deref(),
                Some("emergencyEscapeHotkey" | "emergency_escape")
            );
        if is_emergency_escape {
            let mut local_released_keys = 0usize;
            let mut local_released_buttons = 0usize;
            let mut release_failed = false;
            let releaser_opt = self
                .emergency_releaser
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            if let Some(releaser) = releaser_opt {
                let rep = releaser.release_all_keys();
                local_released_keys = rep.released_keys;
                local_released_buttons = rep.released_buttons;
                if rep.residual_keys > 0 || rep.residual_buttons > 0 {
                    release_failed = true;
                }
            }
            self.enable_os_input.store(false, Ordering::Release);
            self.controller.set_enable_os_input(false);
            self.sync_snapshot();

            let mut remote_released_keys = 0usize;
            let mut remote_released_buttons = 0usize;
            let mut active_session = false;
            let mut timed_out = false;
            if let Some(tx) = &self.active_session_tx {
                if self.controller.state() == BridgeState::Streaming {
                    active_session = true;
                    let keys = env.keys.unwrap_or_default();
                    let masked_buttons = env.buttons.unwrap_or(0) & MOUSE_BUTTONS_VALID_MASK;
                    let (ack_tx, ack_rx) = oneshot::channel();
                    match tokio::time::timeout(
                        RELEASE_ALL_FLUSH_TIMEOUT,
                        tx.send(SessionAction::ReleaseAll {
                            keys,
                            buttons: masked_buttons,
                            ack: Some(ack_tx),
                        }),
                    )
                    .await
                    {
                        Ok(Ok(())) => match tokio::time::timeout(RELEASE_ALL_FLUSH_TIMEOUT, ack_rx).await {
                            Ok(Ok((rk, rb))) => {
                                remote_released_keys = rk;
                                remote_released_buttons = rb;
                            }
                            _ => {
                                timed_out = true;
                                release_failed = true;
                            }
                        },
                        _ => {
                            timed_out = true;
                            release_failed = true;
                        }
                    }
                }
            }

            if release_failed {
                self.events.push_critical(
                    "release_failed",
                    serde_json::json!({
                        "reason": "emergency_escape",
                        "timed_out": timed_out,
                    }),
                );
            }
            if emit_escape_ack {
                let mut ack = serde_json::json!({
                    "enabled": false,
                    "status": "disabled",
                    "reason": "emergency_escape",
                });
                if release_failed {
                    ack["release_all"] = serde_json::json!("failed");
                }
                self.events.push_critical("input_enabled_ack", ack);
            }
            let mut out = serde_json::json!({
                "released_keys": local_released_keys.saturating_add(remote_released_keys),
                "released_buttons": local_released_buttons.saturating_add(remote_released_buttons),
                "active_session": active_session,
                "emergency_escape": true,
            });
            if timed_out {
                out["timed_out"] = serde_json::json!(true);
            }
            if release_failed {
                out["residual"] = serde_json::json!(true);
            }
            return RuntimeReplyEnvelope::ok(out);
        }

        let buttons = env.buttons.unwrap_or(0);
        if buttons & !MOUSE_BUTTONS_VALID_MASK != 0 {
            return RuntimeReplyEnvelope::err(
                "InvalidArgument",
                "mouse buttons bitmask must fit within 0x1F",
            );
        }
        let mut local_residual = false;
        let releaser_opt = self
            .emergency_releaser
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(releaser) = releaser_opt {
            let rep = releaser.release_all_keys();
            if rep.residual_keys > 0 || rep.residual_buttons > 0 {
                local_residual = true;
            }
        }
        let Some(tx) = &self.active_session_tx else {
            return RuntimeReplyEnvelope::ok(serde_json::json!({
                "released_keys": 0,
                "released_buttons": 0,
                "active_session": false,
                "residual": local_residual,
            }));
        };
        if self.controller.state() != BridgeState::Streaming {
            return RuntimeReplyEnvelope::ok(serde_json::json!({
                "released_keys": 0,
                "released_buttons": 0,
                "active_session": false,
                "residual": local_residual,
            }));
        }
        let keys = env.keys.unwrap_or_default();
        let (ack_tx, ack_rx) = oneshot::channel();
        if tokio::time::timeout(
            RELEASE_ALL_FLUSH_TIMEOUT,
            tx.send(SessionAction::ReleaseAll {
                keys,
                buttons,
                ack: Some(ack_tx),
            }),
        )
        .await
        .is_err()
        {
            return RuntimeReplyEnvelope::err("Busy", "release_all flush timed out");
        }
        match tokio::time::timeout(RELEASE_ALL_FLUSH_TIMEOUT, ack_rx).await {
            Ok(Ok((released_keys, released_buttons))) => RuntimeReplyEnvelope::ok(serde_json::json!({
                "released_keys": released_keys,
                "released_buttons": released_buttons,
                "active_session": true,
                "residual": local_residual,
            })),
            _ => RuntimeReplyEnvelope::ok(serde_json::json!({
                "released_keys": 0,
                "released_buttons": 0,
                "active_session": true,
                "timed_out": true,
                "residual": local_residual,
            })),
        }
    }

    fn handle_send_clipboard_cmd(&self, env: RuntimeCommandEnvelope) -> RuntimeReplyEnvelope {
        if self.controller.state() != BridgeState::Streaming {
            return RuntimeReplyEnvelope::err(
                "IllegalStateTransition",
                "clipboard requires Streaming state",
            );
        }
        let Some(pol) = &self.effective_policy else {
            return RuntimeReplyEnvelope::err(
                "PolicyDenied",
                "verified tenant policy unavailable",
            );
        };
        let max_allowed = pol
            .max_clipboard_bytes()
            .min(u64::from(CLIP_HARD_MAX_BYTES)) as usize;
        let mime_kind = env.mime_kind.unwrap_or(CLIP_MIME_TEXT_UTF8);
        let bytes = if let Some(text) = env.text {
            if !pol.allow_clipboard() {
                self.events.push_critical(
                    "PolicyDenied",
                    serde_json::json!({
                        "channel": "clipboard",
                        "code": "policy_denied",
                        "reason": "clipboard_disabled",
                    }),
                );
                return RuntimeReplyEnvelope::err(
                    "PolicyDenied",
                    "clipboard disabled by tenant policy",
                );
            }
            if text.len() > max_allowed {
                self.events.push_critical(
                    "PolicyDenied",
                    serde_json::json!({
                        "channel": "clipboard",
                        "code": "policy_denied",
                        "reason": "size_limit_exceeded",
                    }),
                );
                return RuntimeReplyEnvelope::err(
                    "PolicyDenied",
                    format!("clipboard text size {}B exceeds policy cap {max_allowed}B", text.len()),
                );
            }
            text.into_bytes()
        } else if let Some(b64) = env.payload_b64 {
            if !pol.allow_clipboard() {
                self.events.push_critical(
                    "PolicyDenied",
                    serde_json::json!({
                        "channel": "clipboard",
                        "code": "policy_denied",
                        "reason": "clipboard_disabled",
                    }),
                );
                return RuntimeReplyEnvelope::err(
                    "PolicyDenied",
                    "clipboard disabled by tenant policy",
                );
            }
            let est_decoded = (b64.len() / 4).saturating_mul(3);
            if est_decoded > max_allowed {
                self.events.push_critical(
                    "PolicyDenied",
                    serde_json::json!({
                        "channel": "clipboard",
                        "code": "policy_denied",
                        "reason": "size_limit_exceeded",
                    }),
                );
                return RuntimeReplyEnvelope::err(
                    "PolicyDenied",
                    format!(
                        "clipboard base64 estimated size {est_decoded}B exceeds policy cap {max_allowed}B"
                    ),
                );
            }
            match B64.decode(&b64) {
                Ok(b) => b,
                Err(e) => {
                    return RuntimeReplyEnvelope::err(
                        "InvalidArgument",
                        format!("invalid payload_b64: {e}"),
                    );
                }
            }
        } else {
            return RuntimeReplyEnvelope::err(
                "InvalidArgument",
                "send_clipboard requires 'text' or 'payload_b64'",
            );
        };
        self.handle_send_clipboard_binary(mime_kind, bytes)
    }

    fn handle_send_clipboard_binary(&self, mime_kind: u8, bytes: Vec<u8>) -> RuntimeReplyEnvelope {
        if self.controller.state() != BridgeState::Streaming {
            return RuntimeReplyEnvelope::err(
                "IllegalStateTransition",
                "clipboard requires Streaming state",
            );
        }
        if !self.clipboard_sync_enabled.load(Ordering::Acquire) {
            return RuntimeReplyEnvelope::err(
                "ClipboardDisabled",
                "clipboard sync is currently disabled",
            );
        }
        let Some(pol) = &self.effective_policy else {
            return RuntimeReplyEnvelope::err(
                "PolicyDenied",
                "verified tenant policy unavailable",
            );
        };
        let len_u32 = match u32::try_from(bytes.len()) {
            Ok(n) if n > 0 => n,
            _ => {
                return RuntimeReplyEnvelope::err(
                    "InvalidArgument",
                    "clipboard payload must be non-empty",
                );
            }
        };
        if let Err(status) = check_clipboard_policy_for_sync(pol, mime_kind, len_u32) {
            self.events.push_critical(
                "PolicyDenied",
                serde_json::json!({
                    "channel": "clipboard",
                    "code": "policy_denied",
                    "status": status,
                }),
            );
            return RuntimeReplyEnvelope::err(
                "PolicyDenied",
                format!("clipboard denied by tenant policy (status={status})"),
            );
        }
        let Some(tx) = &self.active_session_tx else {
            return RuntimeReplyEnvelope::err(
                "IllegalStateTransition",
                "no active session data channel",
            );
        };
        let byte_count = bytes.len();
        if tx
            .try_send(SessionAction::SendClipboard { mime_kind, bytes })
            .is_err()
        {
            return RuntimeReplyEnvelope::err("Busy", "session action queue full");
        }
        // Note: NEVER include raw clipboard bytes or text in replies/events!
        RuntimeReplyEnvelope::ok(serde_json::json!({
            "queued": true,
            "mime_kind": mime_kind,
            "bytes": byte_count,
        }))
    }

    fn handle_send_file_path(&mut self, path_str: &str) -> RuntimeReplyEnvelope {
        if self.controller.state() != BridgeState::Streaming {
            return RuntimeReplyEnvelope::err(
                "IllegalStateTransition",
                "send_file requires Streaming state",
            );
        }
        let path = PathBuf::from(path_str);
        let file = match open_regular_file_nofollow(&path) {
            Ok(f) => f,
            Err((code, msg)) => return RuntimeReplyEnvelope::err(&code, msg),
        };
        let meta = match file.metadata() {
            Ok(m) if m.is_file() => m,
            Ok(_) => {
                return RuntimeReplyEnvelope::err(
                    "InvalidArgument",
                    "send_file path must be a regular file",
                );
            }
            Err(e) => {
                return RuntimeReplyEnvelope::err("IoError", format!("fstat file failed: {e}"));
            }
        };
        let rel_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => {
                return RuntimeReplyEnvelope::err(
                    "InvalidArgument",
                    "send_file path has invalid UTF-8 filename",
                );
            }
        };
        if let Err(e) = validate_safe_filename(rel_name.as_bytes()) {
            return RuntimeReplyEnvelope::err("InvalidArgument", e.to_string());
        }
        let Some(pol) = &self.effective_policy else {
            return RuntimeReplyEnvelope::err(
                "PolicyDenied",
                "verified tenant policy unavailable",
            );
        };
        if let Err(e) = check_file_policy(pol, meta.len()) {
            self.events.push_critical(
                "PolicyDenied",
                serde_json::json!({
                    "channel": "file_transfer",
                    "code": "policy_denied",
                    "reason": e.to_string(),
                }),
            );
            return RuntimeReplyEnvelope::err("PolicyDenied", e.to_string());
        }
        let cmd_id = self.alloc_cmd_id();
        let gen = self.session_gen;
        let Some(tx) = &self.active_session_tx else {
            return RuntimeReplyEnvelope::err(
                "IllegalStateTransition",
                "no active session data channel",
            );
        };
        if tx
            .try_send(SessionAction::SendFile {
                cmd_id,
                path,
                rel_name,
            })
            .is_err()
        {
            return RuntimeReplyEnvelope::err("Busy", "session action queue full");
        }
        RuntimeReplyEnvelope::accepted(cmd_id, gen)
    }

    fn handle_refresh_policy(&mut self) -> RuntimeReplyEnvelope {
        let cmd_id = self.alloc_cmd_id();
        let gen = self.session_gen;
        if let Some(tx) = &self.active_session_tx {
            if tx.try_send(SessionAction::RefreshPolicy { cmd_id }).is_ok() {
                return RuntimeReplyEnvelope::accepted(cmd_id, gen);
            }
        }
        // Fallback: refresh directly via Control Plane using loaded config even while Ready/Listening.
        let (client_cfg, _) = match self.build_client_config(None) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let actor_tx = self.actor_tx.clone();
        let active_tasks = Arc::clone(&self.active_tasks);
        let total_tasks = Arc::clone(&self.spawned_tasks_total);
        let cancel = self.session_cancel.clone().unwrap_or_default();
        let h = tokio::spawn(async move {
            let _guard = TaskCountGuard::enter(&active_tasks, &total_tasks);
            match refresh_policy_from_cp(&client_cfg, &cancel).await {
                Ok((policy, is_degraded)) => {
                    let _ = actor_tx
                        .send(ActorMessage::InternalEvent {
                            session_gen: gen,
                            event: ActorEvent::PolicyUpdated {
                                cmd_id: Some(cmd_id),
                                policy,
                                is_degraded,
                            },
                        })
                        .await;
                }
                Err(e) => {
                    let _ = actor_tx
                        .send(ActorMessage::InternalEvent {
                            session_gen: gen,
                            event: ActorEvent::CommandResult {
                                cmd_id,
                                ok: false,
                                data: None,
                                error_code: Some("PolicyRefreshFailed".into()),
                                error: Some(e),
                            },
                        })
                        .await;
                }
            }
        });
        self.session_handles.push(h);
        RuntimeReplyEnvelope::accepted(cmd_id, gen)
    }

    async fn apply_event(&mut self, ev_gen: u64, event: ActorEvent) {
        // Handle events from a superseded session generation:
        // - NEVER drop `SecurityEvent` (always audit with structured redacted fields).
        // - Explicitly reject stale `IncomingCall` replies.
        // - Emit `CommandResult { ok: false, error_code: "StaleGeneration" }` for any event carrying a `cmd_id`.
        if ev_gen != self.session_gen {
            match event {
                ActorEvent::SecurityEvent(se) => {
                    self.events.push_critical(
                        "SecurityEvent",
                        serde_json::json!({
                            "session_gen": ev_gen,
                            "stale_generation": true,
                            "detail": security_event_to_json(&se),
                        }),
                    );
                }
                ActorEvent::IncomingCall { reply, .. } => {
                    let _ = reply.send(CallDecision::Reject {
                        error_code: 0x0409,
                        reason: "stale_generation".into(),
                    });
                }
                ActorEvent::HostBootstrapped { cmd_id, .. }
                | ActorEvent::HostBootstrapFailed { cmd_id, .. }
                | ActorEvent::DialFailed { cmd_id, .. }
                | ActorEvent::CommandResult { cmd_id, .. }
                | ActorEvent::StreamingStarted {
                    cmd_id: Some(cmd_id),
                    ..
                }
                | ActorEvent::PolicyUpdated {
                    cmd_id: Some(cmd_id),
                    ..
                } => {
                    self.events.push_critical(
                        "CommandResult",
                        serde_json::json!({
                            "cmd_id": cmd_id,
                            "ok": false,
                            "session_gen": ev_gen,
                            "error_code": "StaleGeneration",
                            "error": "event arrived for superseded session generation",
                        }),
                    );
                }
                _ => {}
            }
            return;
        }
        match event {
            ActorEvent::HostBootstrapped {
                cmd_id,
                local_cert,
                policy,
            } => {
                if let Err(err) = self
                    .controller
                    .on_bootstrap_complete(&local_cert, policy.clone(), true)
                {
                    self.drain_controller_events_to_hub();
                    self.sync_snapshot();
                    self.events.push_critical(
                        "CommandResult",
                        serde_json::json!({
                            "cmd_id": cmd_id,
                            "cmd": "start_host",
                            "ok": false,
                            "session_gen": ev_gen,
                            "error_code": "IllegalStateTransition",
                            "error": err,
                        }),
                    );
                    return;
                }
                self.effective_policy = Some(policy.clone());
                self.drain_controller_events_to_hub();
                self.sync_snapshot();
                self.emit_policy_event(&policy);
                self.events.push_critical(
                    "CommandResult",
                    serde_json::json!({
                        "cmd_id": cmd_id,
                        "cmd": "start_host",
                        "ok": true,
                        "session_gen": ev_gen,
                        "device_id_hex": hex::encode(local_cert.device_id),
                        "tenant_id_hex": hex::encode(local_cert.tenant_id),
                    }),
                );
            }
            ActorEvent::HostBootstrapFailed { cmd_id, error } => {
                self.controller.on_faulted(&error);
                self.role = ActiveRole::None;
                self.drain_controller_events_to_hub();
                self.sync_snapshot();
                self.events.push_critical(
                    "CommandResult",
                    serde_json::json!({
                        "cmd_id": cmd_id,
                        "cmd": "start_host",
                        "ok": false,
                        "session_gen": ev_gen,
                        "error_code": "BootstrapFailed",
                        "error": error,
                    }),
                );
            }
            ActorEvent::IncomingCall { call, reply } => {
                // If an older pending incoming exists, reject it and cancel its timer first.
                self.clear_pending_incoming("superseded");

                // Use the REAL CA-verified caller DeviceCert from DesktopHostDaemon (zero forged certs).
                if let Err(e) = self
                    .controller
                    .on_incoming_verified_call(call.session_id, &call.caller_cert)
                {
                    let _ = reply.send(CallDecision::Reject {
                        error_code: 0x0409,
                        reason: e,
                    });
                    return;
                }
                let incoming_id = format!("inc-{ev_gen}-{}", self.next_incoming_seq);
                self.next_incoming_seq = self.next_incoming_seq.saturating_add(1);
                let sid_hex = hex::encode(call.session_id);
                self.drain_controller_events_to_hub();
                self.sync_snapshot();

                let timer_cancel = CancellationToken::new();
                let ring_timeout = self.options.ring_timeout;
                let tx_clone = self.actor_tx.clone();
                let inc_id_clone = incoming_id.clone();
                let session_cancel_clone = self
                    .session_cancel
                    .clone()
                    .unwrap_or_default();
                let t_cancel = timer_cancel.clone();
                let active_tasks = Arc::clone(&self.active_tasks);
                let total_tasks = Arc::clone(&self.spawned_tasks_total);
                let timer_handle = tokio::spawn(async move {
                    let _guard = TaskCountGuard::enter(&active_tasks, &total_tasks);
                    tokio::select! {
                        _ = t_cancel.cancelled() => {}
                        _ = session_cancel_clone.cancelled() => {}
                        _ = tokio::time::sleep(ring_timeout) => {
                            let _ = tx_clone.send(ActorMessage::InternalEvent {
                                session_gen: ev_gen,
                                event: ActorEvent::IncomingTimedOut { incoming_id: inc_id_clone },
                            }).await;
                        }
                    }
                });
                self.session_handles.push(timer_handle);

                let caller = VerifiedCallerDisplay::from_verified_cert(&call.caller_cert);
                self.pending_incoming = Some(PendingIncoming {
                    incoming_id: incoming_id.clone(),
                    session_id_hex: sid_hex.clone(),
                    reply_tx: Some(reply),
                    timer_cancel,
                });
                self.events.push_critical(
                    "IncomingCall",
                    serde_json::json!({
                        "incoming_id": incoming_id,
                        "session_id_hex": sid_hex,
                        "caller_device_id_hex": caller.device_id_hex,
                        "caller_tenant_id_hex": caller.tenant_id_hex,
                        "verified_by_ca": caller.verified_by_ca,
                        "verified_caller": caller,
                        "session_gen": ev_gen,
                    }),
                );
            }
            ActorEvent::IncomingTimedOut { incoming_id } => {
                if self
                    .pending_incoming
                    .as_ref()
                    .is_some_and(|p| p.incoming_id == incoming_id)
                {
                    if let Some(mut p) = self.pending_incoming.take() {
                        p.timer_cancel.cancel();
                        if let Some(tx) = p.reply_tx.take() {
                            let _ = tx.send(CallDecision::Reject {
                                error_code: 0x0408,
                                reason: "ring_timeout".into(),
                            });
                        }
                        self.events.push_critical(
                            "IncomingEnded",
                            serde_json::json!({
                                "incoming_id": p.incoming_id,
                                "session_id_hex": p.session_id_hex,
                                "reason": "ring_timeout",
                            }),
                        );
                    }
                    let _ = self
                        .controller
                        .execute_command_json(r#"{"v":1,"cmd":"reject_incoming","reason":"ring_timeout"}"#);
                    self.drain_controller_events_to_hub();
                    self.sync_snapshot();
                }
            }
            ActorEvent::StreamingStarted {
                cmd_id,
                session_id,
                local_cert,
                peer_cert,
                policy,
                active_mode,
                attach_ms,
                action_tx,
            } => {
                // Check BOTH controller state transitions fail-closed!
                // When Host is already past bootstrap (Listening/Incoming), update policy in-place
                // via `on_policy_updated` instead of calling `on_bootstrap_complete` a second time.
                let prep_res = if self.role == ActiveRole::Host
                    && matches!(
                        self.controller.state(),
                        BridgeState::Listening | BridgeState::Incoming
                    ) {
                    self.controller.on_policy_updated(policy.clone())
                } else {
                    self.controller.on_bootstrap_complete(
                        &local_cert,
                        policy.clone(),
                        self.role == ActiveRole::Host,
                    )
                };
                let stream_res = prep_res.and_then(|()| {
                    self.controller
                        .on_streaming_started(session_id, &peer_cert, active_mode)
                });
                if let Err(err) = stream_res {
                    let return_to_listening = self.role == ActiveRole::Host;
                    self.unified_shutdown_session(return_to_listening).await;
                    if let Some(cid) = cmd_id {
                        self.events.push_critical(
                            "CommandResult",
                            serde_json::json!({
                                "cmd_id": cid,
                                "cmd": "dial",
                                "ok": false,
                                "session_gen": ev_gen,
                                "error_code": "IllegalStateTransition",
                                "error": err,
                            }),
                        );
                    }
                    return;
                }
                // Defense in depth: double-reset per-session `enable_os_input = false` on every session start.
                self.enable_os_input.store(false, Ordering::Release);
                self.controller.set_enable_os_input(false);
                self.invalidate_perm_cache();
                self.mailbox.reset_for_session(ev_gen);
                self.effective_policy = Some(policy.clone());
                self.active_session_tx = Some(action_tx);
                self.drain_controller_events_to_hub();
                self.sync_snapshot();
                self.events.push_critical(
                    "input_enabled_ack",
                    serde_json::json!({
                        "enabled": false,
                        "status": "disabled",
                        "reason": "new_session_view_only",
                    }),
                );
                self.emit_policy_event(&policy);
                self.events.push_critical(
                    "TransportModeChanged",
                    serde_json::json!({
                        "active_transport_mode": active_mode.label(),
                        "attach_ms": attach_ms,
                        "session_gen": ev_gen,
                    }),
                );
                if let Some(cid) = cmd_id {
                    self.events.push_critical(
                        "CommandResult",
                        serde_json::json!({
                            "cmd_id": cid,
                            "cmd": "dial",
                            "ok": true,
                            "session_gen": ev_gen,
                            "session_id_hex": hex::encode(session_id),
                            "active_transport_mode": active_mode.label(),
                        }),
                    );
                }
            }
            ActorEvent::DialFailed { cmd_id, error } => {
                self.role = ActiveRole::None;
                let _ = self.controller.on_closed(false);
                self.drain_controller_events_to_hub();
                self.sync_snapshot();
                self.events.push_critical(
                    "CommandResult",
                    serde_json::json!({
                        "cmd_id": cmd_id,
                        "cmd": "dial",
                        "ok": false,
                        "session_gen": ev_gen,
                        "error_code": "DialFailed",
                        "error": error,
                    }),
                );
            }
            ActorEvent::PolicyUpdated {
                cmd_id,
                policy,
                is_degraded,
            } => {
                let now = now_unix_secs();
                if let Err(reason) =
                    should_accept_policy_update(self.effective_policy.as_ref(), &policy, now)
                {
                    self.events.push_critical(
                        "PolicyDegraded",
                        serde_json::json!({
                            "reason": reason,
                            "kept_existing_policy": true,
                        }),
                    );
                    if let Some(cid) = cmd_id {
                        self.events.push_critical(
                            "CommandResult",
                            serde_json::json!({
                                "cmd_id": cid,
                                "cmd": "refresh_policy",
                                "ok": false,
                                "error_code": "PolicyDegraded",
                                "error": reason,
                            }),
                        );
                    }
                    return;
                }
                if self.controller.state() != BridgeState::Idle {
                    if let Err(err) = self.controller.on_policy_updated(policy.clone()) {
                        self.events.push_critical(
                            "SecurityEvent",
                            serde_json::json!({
                                "session_gen": ev_gen,
                                "detail": security_event_to_json(&SecurityEvent::PolicyDegraded {
                                    reason: err.clone(),
                                }),
                            }),
                        );
                        if let Some(cid) = cmd_id {
                            self.events.push_critical(
                                "CommandResult",
                                serde_json::json!({
                                    "cmd_id": cid,
                                    "cmd": "refresh_policy",
                                    "ok": false,
                                    "error_code": "PolicyApplyFailed",
                                    "error": err,
                                }),
                            );
                        }
                        return;
                    }
                    self.controller.set_clipboard_sync_enabled(
                        self.clipboard_sync_enabled.load(Ordering::Acquire)
                            && policy.allow_clipboard(),
                    );
                    self.drain_controller_events_to_hub();
                    self.sync_snapshot();
                }
                self.effective_policy = Some(policy.clone());
                if is_degraded || policy.degraded {
                    self.events.push_critical(
                        "PolicyDegraded",
                        serde_json::json!({
                            "reason": policy.degraded_reason,
                            "policy": PolicySummary::from(&policy),
                        }),
                    );
                } else {
                    self.events.push_critical(
                        "PolicyUpdated",
                        serde_json::json!({ "policy": PolicySummary::from(&policy) }),
                    );
                }
                if let Some(cid) = cmd_id {
                    self.events.push_critical(
                        "CommandResult",
                        serde_json::json!({
                            "cmd_id": cid,
                            "cmd": "refresh_policy",
                            "ok": !(is_degraded || policy.degraded),
                            "policy": PolicySummary::from(&policy),
                        }),
                    );
                }
            }
            ActorEvent::AudioStatus(st) => {
                self.events.push_critical(
                    "AudioStatusChanged",
                    serde_json::json!({
                        "available": st.available,
                        "reason": st.reason,
                    }),
                );
            }
            ActorEvent::HostCapabilityDegraded { capability, reason } => {
                self.events.push_critical(
                    "HostCapabilityDegraded",
                    serde_json::json!({
                        "capability": capability,
                        "reason": reason,
                    }),
                );
            }
            ActorEvent::CodecAck {
                active_codec,
                requested_codec,
                accepted,
            } => {
                // Keep previous active_codec untouched when rejected (accepted == false).
                if accepted || self.active_codec.is_none() {
                    self.active_codec = Some(active_codec.clone());
                    self.controller.set_active_codec(Some(active_codec.clone()));
                    self.sync_snapshot();
                }
                let payload = CodecAckPayload {
                    active_codec,
                    requested_codec,
                    accepted,
                };
                if let Ok(val) = serde_json::to_value(&payload) {
                    self.events.push_critical("codec_ack", val);
                }
            }
            ActorEvent::PermissionStatusChanged(mut report) => {
                self.invalidate_perm_cache();
                let permission_lost = !report.screen_capture_granted
                    || !report.accessibility_granted
                    || !report.probe_source.is_authoritative();
                if permission_lost {
                    self.enable_os_input.store(false, Ordering::Release);
                    self.controller.set_enable_os_input(false);
                    report.enable_os_input = false;
                    let mut release_failed = false;
                    let releaser_opt = self
                        .emergency_releaser
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();
                    if let Some(releaser) = releaser_opt {
                        let rep = releaser.release_all_keys();
                        if rep.residual_keys > 0 || rep.residual_buttons > 0 {
                            release_failed = true;
                        }
                    }
                    self.sync_snapshot();
                    if release_failed {
                        self.events.push_critical(
                            "release_failed",
                            serde_json::json!({ "reason": "permission_lost" }),
                        );
                    }
                    let mut ack = serde_json::json!({
                        "enabled": false,
                        "status": "disabled",
                        "screen_capture_granted": report.screen_capture_granted,
                        "accessibility_granted": report.accessibility_granted,
                        "probe_source": report.probe_source.as_str(),
                        "reason": "permission_lost",
                    });
                    if release_failed {
                        ack["release_all"] = serde_json::json!("failed");
                    }
                    self.events.push_critical("input_enabled_ack", ack);
                }
                self.last_emitted_permission_status = Some(report.clone());
                if let Ok(val) = serde_json::to_value(&report) {
                    self.events.push_critical("permission_status", val);
                }
            }
            ActorEvent::WatchdogTriggered {
                released_keys,
                released_buttons,
            } => {
                self.events.push_critical(
                    "WatchdogTriggered",
                    serde_json::json!({
                        "released_keys": released_keys,
                        "released_buttons": released_buttons,
                    }),
                );
            }
            ActorEvent::ClipboardReceived {
                mime_kind,
                byte_count,
                sha256_hex,
            } => {
                // Redacted: NEVER include raw clipboard text or bytes!
                self.events.push_critical(
                    "ClipboardReceived",
                    serde_json::json!({
                        "mime_kind": mime_kind,
                        "bytes": byte_count,
                        "sha256_hex": sha256_hex,
                    }),
                );
            }
            ActorEvent::FileProgress {
                transfer_id,
                bytes_transferred,
                total_bytes,
            } => {
                self.events.push_critical(
                    "FileTransferProgress",
                    serde_json::json!({
                        "transfer_id": transfer_id,
                        "bytes_transferred": bytes_transferred,
                        "total_bytes": total_bytes,
                    }),
                );
            }
            ActorEvent::FileComplete {
                transfer_id,
                rel_name,
                bytes,
                sha256_hex,
                saved_path,
            } => {
                self.events.push_critical(
                    "FileTransferComplete",
                    serde_json::json!({
                        "transfer_id": transfer_id,
                        "rel_name": rel_name,
                        "bytes": bytes,
                        "sha256_hex": sha256_hex,
                        "checksum_algo": "sha256",
                        "saved_path": saved_path,
                    }),
                );
            }
            ActorEvent::FileAborted {
                transfer_id,
                error_code,
                reason,
            } => {
                self.events.push_critical(
                    "FileTransferAborted",
                    serde_json::json!({
                        "transfer_id": transfer_id,
                        "error_code": error_code,
                        "reason": reason,
                    }),
                );
            }
            ActorEvent::CommandResult {
                cmd_id,
                ok,
                data,
                error_code,
                error,
            } => {
                self.events.push_critical(
                    "CommandResult",
                    serde_json::json!({
                        "cmd_id": cmd_id,
                        "ok": ok,
                        "data": data,
                        "error_code": error_code,
                        "error": error,
                    }),
                );
            }
            ActorEvent::SessionEnded {
                return_to_listening,
                reason,
            } => {
                self.enable_os_input.store(false, Ordering::Release);
                self.controller.set_enable_os_input(false);
                self.active_codec = None;
                self.controller.set_active_codec(None);
                self.invalidate_perm_cache();
                {
                    let mut slot = self
                        .active_watchdog_ax_probe
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    if slot.as_ref().is_some_and(|(id, _)| *id == ev_gen) {
                        *slot = None;
                    }
                }
                self.active_session_tx = None;
                self.clear_pending_incoming(&reason);
                self.mailbox.clear();
                if !return_to_listening {
                    self.role = ActiveRole::None;
                }
                if !matches!(
                    self.controller.state(),
                    BridgeState::Idle | BridgeState::Bootstrapping
                ) {
                    let _ = self.controller.on_closed(return_to_listening);
                    self.drain_controller_events_to_hub();
                    self.sync_snapshot();
                }
                self.events.push_critical(
                    "SessionEnded",
                    serde_json::json!({
                        "reason": reason,
                        "return_to_listening": return_to_listening,
                        "session_gen": ev_gen,
                    }),
                );
            }
            ActorEvent::SecurityEvent(se) => {
                self.events.push_critical(
                    "SecurityEvent",
                    serde_json::json!({
                        "session_gen": ev_gen,
                        "detail": security_event_to_json(&se),
                    }),
                );
            }
        }
    }

    fn emit_policy_event(&self, policy: &EffectiveTenantPolicy) {
        let summary = PolicySummary::from(policy);
        if policy.degraded {
            self.events.push_critical(
                "PolicyDegraded",
                serde_json::json!({
                    "reason": policy.degraded_reason,
                    "policy": summary,
                }),
            );
        } else {
            self.events.push_critical(
                "PolicyUpdated",
                serde_json::json!({ "policy": summary }),
            );
        }
    }
}

async fn refresh_policy_from_cp(
    cfg: &V2ClientConfig,
    cancel: &CancellationToken,
) -> Result<(EffectiveTenantPolicy, bool), String> {
    let fut = async {
        let cp = ControlPlaneClient::new(&cfg.control_plane_endpoint, cfg.ca_der_path.as_deref())
            .map_err(|e| e.to_string())?;
        let ca_spki_der = cp
            .get_ca_pubkey()
            .await
            .map_err(|e| e.to_string())?
            .spki_der()
            .map_err(|e| e.to_string())?;
        let mut identity =
            PersistentV2Identity::load_or_create(&cfg.identity_dir).map_err(|e| e.to_string())?;
        let (cert, _inline_blob) = identity
            .ensure_registered_with_policy(
                &cp,
                &ca_spki_der,
                cfg.enrollment_token.as_deref(),
                local_v2_cap_bits(),
                &cfg.home_region,
            )
            .await
            .map_err(|e| e.to_string())?;
        let now = now_unix_secs();
        let fetched = cp
            .fetch_tenant_policy(&cert.device_id, identity.keystore(), now)
            .await
            .map_err(|e| format!("fetch_tenant_policy failed: {e}"))?;
        let last_ver = identity.last_policy_version();
        let outcome = verify_tenant_policy_blob(
            Some(&fetched),
            &ca_spki_der,
            &cert.tenant_id,
            &cert.policy_hash,
            last_ver,
            now,
        );
        match outcome {
            PolicyVerifyOutcome::Verified(p) => {
                let _ = identity.advance_policy_version(p.version);
                Ok((p, false))
            }
            PolicyVerifyOutcome::Degraded { policy, .. } => Ok((policy, true)),
        }
    };
    tokio::select! {
        _ = cancel.cancelled() => Err("policy refresh cancelled".into()),
        res = tokio::time::timeout(POLICY_REFRESH_TIMEOUT, fut) => match res {
            Ok(inner) => inner,
            Err(_) => Err("policy refresh timed out after 5s".into()),
        },
    }
}

/// Opens `path` with `O_NOFOLLOW | O_NONBLOCK` on Unix and verifies `fstat` is a regular file.
fn open_regular_file_nofollow(path: &Path) -> Result<File, (String, String)> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = opts
        .open(path)
        .map_err(|e| ("IoError".to_string(), format!("open file failed: {e}")))?;
    let meta = file
        .metadata()
        .map_err(|e| ("IoError".to_string(), format!("fstat file failed: {e}")))?;
    if !meta.is_file() {
        return Err((
            "InvalidArgument".to_string(),
            "send_file path must be a regular file".to_string(),
        ));
    }
    Ok(file)
}

/// Computes SHA-256 over an already-opened `File` using a bounded 64 KiB streaming buffer
/// (ZERO full-file allocation in RAM, ZERO TOCTOU) and rewinds the descriptor back to byte 0.
fn compute_file_sha256_streaming(mut file: File) -> Result<(File, u64, [u8; 32]), (String, String)> {
    let meta = file
        .metadata()
        .map_err(|e| ("IoError".to_string(), format!("fstat file failed: {e}")))?;
    if !meta.is_file() {
        return Err((
            "InvalidArgument".to_string(),
            "send_file path must be a regular file".to_string(),
        ));
    }
    let total = meta.len();
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut hashed: u64 = 0;
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| ("IoError".to_string(), format!("read file for sha256 failed: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        hashed = hashed.saturating_add(n as u64);
        if hashed > total {
            return Err((
                "IoError".to_string(),
                "file grew concurrently while hashing".to_string(),
            ));
        }
    }
    if hashed != total {
        return Err((
            "IoError".to_string(),
            "file size changed concurrently while hashing".to_string(),
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|e| ("IoError".to_string(), format!("rewind file failed: {e}")))?;
    let sha256: [u8; 32] = hasher.finalize().into();
    Ok((file, total, sha256))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FileSendError {
    Backpressure,
    Transport(String),
}

trait FileL4Sender {
    fn send_file_l4<'a>(
        &'a mut self,
        msg_type: u8,
        body: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), FileSendError>> + Send + 'a>>;

    fn is_bulk_paused(&self) -> bool {
        false
    }
}

impl FileL4Sender for UdpE2eeSession {
    fn send_file_l4<'a>(
        &'a mut self,
        msg_type: u8,
        body: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), FileSendError>> + Send + 'a>>
    {
        Box::pin(async move {
            match self
                .send_l4_raw(CHAN_FILE_TRANSFER, msg_type, 0, false, body)
                .await
            {
                Ok(_) => Ok(()),
                Err(v2_client::ClientError::P3Backpressure { .. }) => {
                    Err(FileSendError::Backpressure)
                }
                Err(e) => Err(FileSendError::Transport(e.to_string())),
            }
        })
    }

    fn is_bulk_paused(&self) -> bool {
        UdpE2eeSession::is_bulk_paused(self)
    }
}

struct OutboundTransferState {
    transfer_id: u64,
    cmd_id: u64,
    rel_name: String,
    file: File,
    total_bytes: u64,
    sha256: [u8; 32],
    pending_offer: Option<Vec<u8>>,
    accepted: bool,
    window_end_offset: u64,
    offset: u64,
    acked_offset: u64,
    complete_sent_at: Option<Instant>,
    last_activity_at: Instant,
    last_progress_at: Instant,
    last_progress_pct: u8,
}

struct OutboundFileManager {
    active: HashMap<u64, OutboundTransferState>,
    pending_ctrl_frames: VecDeque<(u8, Vec<u8>)>,
    unknown_peer_msgs_dropped: u64,
}

impl OutboundFileManager {
    fn new() -> Self {
        Self {
            active: HashMap::new(),
            pending_ctrl_frames: VecDeque::new(),
            unknown_peer_msgs_dropped: 0,
        }
    }

    fn has_active(&self) -> bool {
        !self.active.is_empty() || !self.pending_ctrl_frames.is_empty()
    }

    fn enqueue_ctrl_retry(&mut self, msg_type: u8, body: &[u8]) {
        if self.pending_ctrl_frames.len() >= PENDING_FILE_CTRL_CAP {
            if let Some(pos) = self
                .pending_ctrl_frames
                .iter()
                .position(|(mt, _)| *mt == FILE_MSG_ACK)
            {
                self.pending_ctrl_frames.remove(pos);
            } else {
                // Queue is full of critical frames (ACCEPT / COMPLETE_ACK / ABORT); never drop
                // them in favor of a FILE_MSG_ACK (or overflow the cap).
                return;
            }
        }
        self.pending_ctrl_frames.push_back((msg_type, body.to_vec()));
    }

    /// Processes an inbound `FILE_MSG_ACCEPT` from the peer. Returns `true` if it matched an
    /// active outbound transfer (consumed), or `false` if unknown.
    async fn handle_accept<S: FileL4Sender>(
        &mut self,
        sess: &mut S,
        acc: &FileAccept,
        gen: u64,
        actor_tx: &mpsc::Sender<ActorMessage>,
    ) -> bool {
        let Some(st) = self.active.get_mut(&acc.transfer_id) else {
            self.unknown_peer_msgs_dropped = self.unknown_peer_msgs_dropped.saturating_add(1);
            return false;
        };
        if st.accepted {
            return true;
        }
        if acc.resume_offset > st.total_bytes || acc.initial_window_end_offset < acc.resume_offset {
            if let Some(st) = self.active.remove(&acc.transfer_id) {
                let abort = FileAbort {
                    transfer_id: st.transfer_id,
                    error_code: FILE_ERR_LOCAL_ABORT,
                };
                let ab_wire = abort.encode();
                if matches!(
                    sess.send_file_l4(FILE_MSG_ABORT, &ab_wire).await,
                    Err(FileSendError::Backpressure)
                ) {
                    self.enqueue_ctrl_retry(FILE_MSG_ABORT, &ab_wire);
                }
                let reason = format!(
                    "invalid FILE_ACCEPT resume_offset={} window_end={} for total_bytes={}",
                    acc.resume_offset, acc.initial_window_end_offset, st.total_bytes
                );
                let _ = actor_tx
                    .send(ActorMessage::InternalEvent {
                        session_gen: gen,
                        event: ActorEvent::FileAborted {
                            transfer_id: st.transfer_id,
                            error_code: FILE_ERR_LOCAL_ABORT,
                            reason: reason.clone(),
                        },
                    })
                    .await;
                emit_file_cmd_result(gen, st.cmd_id, actor_tx, Err(("ProtocolError".into(), reason)))
                    .await;
            }
            return true;
        }
        if acc.resume_offset > 0 {
            if let Err(e) = st.file.seek(SeekFrom::Start(acc.resume_offset)) {
                if let Some(st) = self.active.remove(&acc.transfer_id) {
                    let abort = FileAbort {
                        transfer_id: st.transfer_id,
                        error_code: FILE_ERR_LOCAL_ABORT,
                    };
                    let ab_wire = abort.encode();
                    if matches!(
                        sess.send_file_l4(FILE_MSG_ABORT, &ab_wire).await,
                        Err(FileSendError::Backpressure)
                    ) {
                        self.enqueue_ctrl_retry(FILE_MSG_ABORT, &ab_wire);
                    }
                    let reason = format!("seek to resume_offset {} failed: {e}", acc.resume_offset);
                    let _ = actor_tx
                        .send(ActorMessage::InternalEvent {
                            session_gen: gen,
                            event: ActorEvent::FileAborted {
                                transfer_id: st.transfer_id,
                                error_code: FILE_ERR_LOCAL_ABORT,
                                reason: reason.clone(),
                            },
                        })
                        .await;
                    emit_file_cmd_result(gen, st.cmd_id, actor_tx, Err(("IoError".into(), reason)))
                        .await;
                }
                return true;
            }
        }
        let clamped_win = acc.initial_window_end_offset.min(st.total_bytes);
        st.accepted = true;
        st.offset = acc.resume_offset;
        st.acked_offset = acc.resume_offset;
        st.window_end_offset = clamped_win;
        st.last_activity_at = Instant::now();
        true
    }

    /// Processes an inbound `FILE_MSG_ACK` from the peer, monotonically advancing `acked_offset`
    /// and the send credit window. Returns `true` if it matched an active outbound transfer
    /// (consumed), or `false` if unknown.
    fn handle_ack(&mut self, ack: &FileAck) -> bool {
        let Some(st) = self.active.get_mut(&ack.transfer_id) else {
            self.unknown_peer_msgs_dropped = self.unknown_peer_msgs_dropped.saturating_add(1);
            return false;
        };
        if !st.accepted {
            return true;
        }
        if ack.next_expected_offset > st.offset
            || ack.next_expected_offset > st.total_bytes
            || ack.window_end_offset < ack.next_expected_offset
        {
            return true;
        }
        let mut progressed = false;
        if ack.next_expected_offset > st.acked_offset {
            st.acked_offset = ack.next_expected_offset;
            progressed = true;
        }
        let new_win = ack.window_end_offset.min(st.total_bytes);
        if new_win > st.window_end_offset {
            st.window_end_offset = new_win;
            progressed = true;
        }
        if progressed {
            st.last_activity_at = Instant::now();
        }
        true
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_transfer<S: FileL4Sender>(
        &mut self,
        sess: &mut S,
        transfer_id: u64,
        cmd_id: u64,
        path: PathBuf,
        rel_name: String,
        policy: &EffectiveTenantPolicy,
        gen: u64,
        actor_tx: &mpsc::Sender<ActorMessage>,
    ) {
        let policy_c = policy.clone();
        let open_res = tokio::task::spawn_blocking(move || {
            let file = open_regular_file_nofollow(&path)?;
            let meta = file
                .metadata()
                .map_err(|e| ("IoError".to_string(), format!("fstat file failed: {e}")))?;
            if !meta.is_file() {
                return Err((
                    "InvalidArgument".to_string(),
                    "send_file path must be a regular file".to_string(),
                ));
            }
            // Check file policy BEFORE running the 64 KiB streaming SHA-256 loop!
            if let Err(e) = check_file_policy(&policy_c, meta.len()) {
                return Err(("PolicyDenied".to_string(), e.to_string()));
            }
            compute_file_sha256_streaming(file)
        })
        .await;
        let (file, total, sha256) = match open_res {
            Ok(Ok(tuple)) => tuple,
            Ok(Err((code, msg))) => {
                // Policy or I/O failure BEFORE FILE_MSG_OFFER: never send a spurious FILE_MSG_ABORT.
                emit_file_cmd_result(gen, cmd_id, actor_tx, Err((code, msg))).await;
                return;
            }
            Err(e) => {
                emit_file_cmd_result(
                    gen,
                    cmd_id,
                    actor_tx,
                    Err(("IoError".into(), format!("file prepare task failed: {e}"))),
                )
                .await;
                return;
            }
        };

        // Re-verify against latest policy in case file size changed slightly or policy updated.
        if let Err(e) = check_file_policy(policy, total) {
            emit_file_cmd_result(gen, cmd_id, actor_tx, Err(("PolicyDenied".into(), e.to_string())))
                .await;
            return;
        }

        let offer = FileOffer {
            transfer_id,
            file_size: total,
            chunk_size: FILE_RECOMMENDED_CHUNK_SIZE,
            sha256,
            rel_name: rel_name.clone(),
        };
        let offer_wire = match offer.encode() {
            Ok(w) => w,
            Err(e) => {
                emit_file_cmd_result(
                    gen,
                    cmd_id,
                    actor_tx,
                    Err(("InvalidArgument".into(), e.to_string())),
                )
                .await;
                return;
            }
        };
        let pending_offer = match sess.send_file_l4(FILE_MSG_OFFER, &offer_wire).await {
            Ok(()) => None,
            Err(FileSendError::Backpressure) => Some(offer_wire),
            Err(FileSendError::Transport(e)) => {
                emit_file_cmd_result(gen, cmd_id, actor_tx, Err(("TransportError".into(), e)))
                    .await;
                return;
            }
        };

        let now = Instant::now();
        self.active.insert(
            transfer_id,
            OutboundTransferState {
                transfer_id,
                cmd_id,
                rel_name,
                file,
                total_bytes: total,
                sha256,
                pending_offer,
                accepted: false,
                window_end_offset: 0,
                offset: 0,
                acked_offset: 0,
                complete_sent_at: None,
                last_activity_at: now,
                last_progress_at: now,
                last_progress_pct: 0,
            },
        );
    }

    /// Pumps at most one chunk across active outbound transfers, re-checks live file policy,
    /// and enforces bounded stall / `CompleteAck` timeouts.
    async fn pump_one_step<S: FileL4Sender>(
        &mut self,
        sess: &mut S,
        policy: &EffectiveTenantPolicy,
        gen: u64,
        actor_tx: &mpsc::Sender<ActorMessage>,
    ) {
        // 0. Drain any receiver control replies deferred by L4 p3 backpressure first.
        //    When file transfer policy is revoked, drop queued FILE_MSG_ACCEPT rather than
        //    inviting a doomed transfer. When bulk is paused, still allow FILE_MSG_ABORT through.
        if !policy.allow_file_transfer() {
            self.pending_ctrl_frames
                .retain(|(mt, _)| *mt != FILE_MSG_ACCEPT);
        }
        if sess.is_bulk_paused() {
            let mut idx = 0usize;
            while idx < self.pending_ctrl_frames.len() {
                if self.pending_ctrl_frames[idx].0 == FILE_MSG_ABORT {
                    let body = &self.pending_ctrl_frames[idx].1;
                    match sess.send_file_l4(FILE_MSG_ABORT, body).await {
                        Ok(()) | Err(FileSendError::Transport(_)) => {
                            self.pending_ctrl_frames.remove(idx);
                            continue;
                        }
                        Err(FileSendError::Backpressure) => return,
                    }
                }
                idx += 1;
            }
        } else {
            while let Some((msg_type, body)) = self.pending_ctrl_frames.front() {
                match sess.send_file_l4(*msg_type, body).await {
                    Ok(()) | Err(FileSendError::Transport(_)) => {
                        self.pending_ctrl_frames.pop_front();
                    }
                    Err(FileSendError::Backpressure) => return,
                }
            }
        }

        // 1. Re-check live policy on every step: if file transfer was disabled mid-flight, abort all.
        if !policy.allow_file_transfer() {
            let revoked: Vec<OutboundTransferState> =
                self.active.drain().map(|(_, st)| st).collect();
            for st in revoked {
                let abort = FileAbort {
                    transfer_id: st.transfer_id,
                    error_code: FILE_ERR_POLICY_DENIED,
                };
                let _ = sess.send_file_l4(FILE_MSG_ABORT, &abort.encode()).await;
                let _ = actor_tx
                    .send(ActorMessage::InternalEvent {
                        session_gen: gen,
                        event: ActorEvent::FileAborted {
                            transfer_id: st.transfer_id,
                            error_code: FILE_ERR_POLICY_DENIED,
                            reason: "file transfer disabled by policy update".into(),
                        },
                    })
                    .await;
                emit_file_cmd_result(
                    gen,
                    st.cmd_id,
                    actor_tx,
                    Err((
                        "PolicyDenied".into(),
                        "file transfer disabled by tenant policy update".into(),
                    )),
                )
                .await;
            }
            return;
        }

        // 2. Check CompleteAck (15s) and no-progress (30s) timeouts.
        let timed_out_ids: Vec<u64> = self
            .active
            .iter()
            .filter_map(|(&tid, st)| {
                let complete_to = st
                    .complete_sent_at
                    .is_some_and(|t| t.elapsed() >= FILE_COMPLETE_ACK_TIMEOUT);
                let no_progress_to = st.last_activity_at.elapsed() >= FILE_NO_PROGRESS_TIMEOUT;
                if complete_to || no_progress_to {
                    Some(tid)
                } else {
                    None
                }
            })
            .collect();
        for tid in timed_out_ids {
            if let Some(st) = self.active.remove(&tid) {
                let abort = FileAbort {
                    transfer_id: tid,
                    error_code: FILE_ERR_LOCAL_ABORT,
                };
                let _ = sess.send_file_l4(FILE_MSG_ABORT, &abort.encode()).await;
                let _ = actor_tx
                    .send(ActorMessage::InternalEvent {
                        session_gen: gen,
                        event: ActorEvent::FileAborted {
                            transfer_id: tid,
                            error_code: FILE_ERR_LOCAL_ABORT,
                            reason: "file transfer peer timeout".into(),
                        },
                    })
                    .await;
                emit_file_cmd_result(
                    gen,
                    st.cmd_id,
                    actor_tx,
                    Err(("Timeout".into(), "peer did not acknowledge file transfer".into())),
                )
                .await;
            }
        }

        // 3. Respect L2 BwHint bulk pause / Survival Mode before sending offers, chunks, or COMPLETE.
        if sess.is_bulk_paused() {
            return;
        }

        // 4. Retry any FILE_MSG_OFFER deferred by P3 backpressure.
        let pending_offer_tid = self
            .active
            .iter()
            .find(|(_, st)| st.pending_offer.is_some())
            .map(|(&tid, _)| tid);
        if let Some(tid) = pending_offer_tid {
            if let Some(st) = self.active.get_mut(&tid) {
                if let Some(offer_wire) = st.pending_offer.as_ref() {
                    match sess.send_file_l4(FILE_MSG_OFFER, offer_wire).await {
                        Ok(()) => {
                            st.pending_offer = None;
                            st.last_activity_at = Instant::now();
                        }
                        Err(FileSendError::Backpressure) => return,
                        Err(FileSendError::Transport(e)) => {
                            if let Some(st) = self.active.remove(&tid) {
                                emit_file_cmd_result(
                                    gen,
                                    st.cmd_id,
                                    actor_tx,
                                    Err(("TransportError".into(), e)),
                                )
                                .await;
                            }
                        }
                    }
                }
            }
            return;
        }

        // 5. Pick the first accepted transfer that has window credit OR is fully ACKed and ready
        //    for FILE_MSG_COMPLETE (strictly requiring `acked_offset == total_bytes`).
        let next_tid = self
            .active
            .iter()
            .find(|(_, st)| {
                st.accepted
                    && st.complete_sent_at.is_none()
                    && ((st.offset < st.total_bytes && st.offset < st.window_end_offset)
                        || (st.offset == st.total_bytes && st.acked_offset == st.total_bytes))
            })
            .map(|(&tid, _)| tid);
        let Some(tid) = next_tid else {
            return;
        };
        let Some(st) = self.active.get_mut(&tid) else {
            return;
        };

        if st.offset < st.total_bytes {
            let remaining = (st.total_bytes - st.offset) as usize;
            let win_avail = st.window_end_offset.saturating_sub(st.offset) as usize;
            let to_read = remaining
                .min(win_avail)
                .min(FILE_RECOMMENDED_CHUNK_SIZE as usize);
            if to_read == 0 {
                return;
            }
            let mut chunk_buf = vec![0u8; to_read];
            let read_res = st.file.read(&mut chunk_buf);
            match read_res {
                Ok(0) => {
                    let st = self.active.remove(&tid);
                    if let Some(st) = st {
                        let abort = FileAbort {
                            transfer_id: tid,
                            error_code: FILE_ERR_LOCAL_ABORT,
                        };
                        let _ = sess.send_file_l4(FILE_MSG_ABORT, &abort.encode()).await;
                        emit_file_cmd_result(
                            gen,
                            st.cmd_id,
                            actor_tx,
                            Err(("IoError".into(), "unexpected EOF while streaming file".into())),
                        )
                        .await;
                    }
                }
                Ok(n) => {
                    chunk_buf.truncate(n);
                    let ch = FileChunk {
                        transfer_id: tid,
                        offset: st.offset,
                        data: chunk_buf,
                    };
                    let wire = match ch.encode() {
                        Ok(w) => w,
                        Err(e) => {
                            if let Some(st) = self.active.remove(&tid) {
                                let abort = FileAbort {
                                    transfer_id: tid,
                                    error_code: FILE_ERR_LOCAL_ABORT,
                                };
                                let _ = sess.send_file_l4(FILE_MSG_ABORT, &abort.encode()).await;
                                emit_file_cmd_result(
                                    gen,
                                    st.cmd_id,
                                    actor_tx,
                                    Err(("InvalidArgument".into(), e.to_string())),
                                )
                                .await;
                            }
                            return;
                        }
                    };
                    match sess.send_file_l4(FILE_MSG_CHUNK, &wire).await {
                        Ok(()) => {}
                        Err(FileSendError::Backpressure) => {
                            if let Err(seek_err) = st.file.seek(SeekFrom::Start(st.offset)) {
                                if let Some(st) = self.active.remove(&tid) {
                                    let abort = FileAbort {
                                        transfer_id: tid,
                                        error_code: FILE_ERR_LOCAL_ABORT,
                                    };
                                    let ab_wire = abort.encode();
                                    if matches!(
                                        sess.send_file_l4(FILE_MSG_ABORT, &ab_wire).await,
                                        Err(FileSendError::Backpressure)
                                    ) {
                                        self.enqueue_ctrl_retry(FILE_MSG_ABORT, &ab_wire);
                                    }
                                    let reason =
                                        format!("rewind file after backpressure failed: {seek_err}");
                                    let _ = actor_tx
                                        .send(ActorMessage::InternalEvent {
                                            session_gen: gen,
                                            event: ActorEvent::FileAborted {
                                                transfer_id: tid,
                                                error_code: FILE_ERR_LOCAL_ABORT,
                                                reason: reason.clone(),
                                            },
                                        })
                                        .await;
                                    emit_file_cmd_result(
                                        gen,
                                        st.cmd_id,
                                        actor_tx,
                                        Err(("IoError".into(), reason)),
                                    )
                                    .await;
                                }
                            }
                            return;
                        }
                        Err(FileSendError::Transport(e)) => {
                            if let Some(st) = self.active.remove(&tid) {
                                let abort = FileAbort {
                                    transfer_id: tid,
                                    error_code: FILE_ERR_LOCAL_ABORT,
                                };
                                let _ = sess.send_file_l4(FILE_MSG_ABORT, &abort.encode()).await;
                                emit_file_cmd_result(
                                    gen,
                                    st.cmd_id,
                                    actor_tx,
                                    Err(("TransportError".into(), e)),
                                )
                                .await;
                            }
                            return;
                        }
                    }
                    st.offset = st.offset.saturating_add(n as u64);
                    st.last_activity_at = Instant::now();
                    let pct = if st.total_bytes == 0 {
                        100
                    } else {
                        ((st.offset.saturating_mul(100)) / st.total_bytes).min(100) as u8
                    };
                    let should_emit = st.offset == st.total_bytes
                        || pct >= st.last_progress_pct.saturating_add(5)
                        || st.last_progress_at.elapsed() >= FILE_PROGRESS_THROTTLE_INTERVAL;
                    if should_emit {
                        st.last_progress_pct = pct;
                        st.last_progress_at = Instant::now();
                        let _ = actor_tx.try_send(ActorMessage::InternalEvent {
                            session_gen: gen,
                            event: ActorEvent::FileProgress {
                                transfer_id: tid,
                                bytes_transferred: st.offset,
                                total_bytes: st.total_bytes,
                            },
                        });
                    }
                }
                Err(e) => {
                    if let Some(st) = self.active.remove(&tid) {
                        let abort = FileAbort {
                            transfer_id: tid,
                            error_code: FILE_ERR_LOCAL_ABORT,
                        };
                        let _ = sess.send_file_l4(FILE_MSG_ABORT, &abort.encode()).await;
                        emit_file_cmd_result(
                            gen,
                            st.cmd_id,
                            actor_tx,
                            Err(("IoError".into(), format!("read chunk failed: {e}"))),
                        )
                        .await;
                    }
                }
            }
        } else if st.acked_offset == st.total_bytes {
            let complete = FileComplete {
                transfer_id: tid,
                sha256: st.sha256,
            };
            match sess
                .send_file_l4(FILE_MSG_COMPLETE, &complete.encode())
                .await
            {
                Ok(()) => {
                    let now = Instant::now();
                    st.complete_sent_at = Some(now);
                    st.last_activity_at = now;
                }
                Err(FileSendError::Backpressure) => {}
                Err(FileSendError::Transport(e)) => {
                    if let Some(st) = self.active.remove(&tid) {
                        let abort = FileAbort {
                            transfer_id: tid,
                            error_code: FILE_ERR_LOCAL_ABORT,
                        };
                        let _ = sess.send_file_l4(FILE_MSG_ABORT, &abort.encode()).await;
                        emit_file_cmd_result(
                            gen,
                            st.cmd_id,
                            actor_tx,
                            Err(("TransportError".into(), e)),
                        )
                        .await;
                    }
                }
            }
        }
    }

    /// Handles `FILE_MSG_COMPLETE_ACK`. Returns `true` if `transfer_id` matched an active
    /// outbound transfer, or `false` so callers fall through to `FileTransferReceiver`.
    async fn handle_complete_ack(
        &mut self,
        transfer_id: u64,
        status: u8,
        gen: u64,
        actor_tx: &mpsc::Sender<ActorMessage>,
    ) -> bool {
        let Some(st) = self.active.remove(&transfer_id) else {
            self.unknown_peer_msgs_dropped = self.unknown_peer_msgs_dropped.saturating_add(1);
            return false;
        };
        if status == FILE_COMPLETE_ACK_OK {
            let sha_hex = hex::encode(st.sha256);
            let _ = actor_tx
                .send(ActorMessage::InternalEvent {
                    session_gen: gen,
                    event: ActorEvent::FileComplete {
                        transfer_id: st.transfer_id,
                        rel_name: st.rel_name.clone(),
                        bytes: st.total_bytes,
                        sha256_hex: sha_hex.clone(),
                        saved_path: None,
                    },
                })
                .await;
            emit_file_cmd_result(
                gen,
                st.cmd_id,
                actor_tx,
                Ok(serde_json::json!({
                    "transfer_id": st.transfer_id,
                    "rel_name": st.rel_name,
                    "bytes": st.total_bytes,
                    "sha256_hex": sha_hex,
                    "checksum_algo": "sha256",
                })),
            )
            .await;
        } else {
            let reason = format!("remote complete_ack status={status}");
            let _ = actor_tx
                .send(ActorMessage::InternalEvent {
                    session_gen: gen,
                    event: ActorEvent::FileAborted {
                        transfer_id: st.transfer_id,
                        error_code: u16::from(status),
                        reason: reason.clone(),
                    },
                })
                .await;
            emit_file_cmd_result(
                gen,
                st.cmd_id,
                actor_tx,
                Err(("FileAborted".into(), reason)),
            )
            .await;
        }
        true
    }

    /// Handles `FILE_MSG_ABORT`. Returns `true` if `transfer_id` matched an active outbound
    /// transfer, or `false` so callers fall through to `FileTransferReceiver` to clean up
    /// peer-aborted inbound transfers (does NOT count unmatched aborts as unknown drops).
    async fn handle_remote_abort(
        &mut self,
        transfer_id: u64,
        error_code: u16,
        gen: u64,
        actor_tx: &mpsc::Sender<ActorMessage>,
    ) -> bool {
        let Some(st) = self.active.remove(&transfer_id) else {
            return false;
        };
        let reason = format!("remote abort {error_code:#06x}");
        let _ = actor_tx
            .send(ActorMessage::InternalEvent {
                session_gen: gen,
                event: ActorEvent::FileAborted {
                    transfer_id: st.transfer_id,
                    error_code,
                    reason: reason.clone(),
                },
            })
            .await;
        emit_file_cmd_result(
            gen,
            st.cmd_id,
            actor_tx,
            Err(("FileAborted".into(), reason)),
        )
        .await;
        true
    }

    async fn cancel_transfer<S: FileL4Sender>(
        &mut self,
        sess: &mut S,
        transfer_id: u64,
        gen: u64,
        actor_tx: &mpsc::Sender<ActorMessage>,
    ) {
        if let Some(st) = self.active.remove(&transfer_id) {
            let abort = FileAbort {
                transfer_id,
                error_code: FILE_ERR_LOCAL_ABORT,
            };
            let _ = sess.send_file_l4(FILE_MSG_ABORT, &abort.encode()).await;
            let _ = actor_tx
                .send(ActorMessage::InternalEvent {
                    session_gen: gen,
                    event: ActorEvent::FileAborted {
                        transfer_id,
                        error_code: FILE_ERR_LOCAL_ABORT,
                        reason: "cancelled locally".into(),
                    },
                })
                .await;
            emit_file_cmd_result(
                gen,
                st.cmd_id,
                actor_tx,
                Err(("Cancelled".into(), "file transfer cancelled".into())),
            )
            .await;
        }
    }

    /// Best-effort teardown abort using non-blocking `actor_tx.try_send` so teardown can never stall.
    async fn abort_all_on_teardown<S: FileL4Sender>(
        &mut self,
        sess: &mut S,
        gen: u64,
        actor_tx: &mpsc::Sender<ActorMessage>,
    ) {
        let remaining: Vec<OutboundTransferState> =
            self.active.drain().map(|(_, st)| st).collect();
        for st in remaining {
            let abort = FileAbort {
                transfer_id: st.transfer_id,
                error_code: FILE_ERR_LOCAL_ABORT,
            };
            let _ = sess.send_file_l4(FILE_MSG_ABORT, &abort.encode()).await;
            let _ = actor_tx.try_send(ActorMessage::InternalEvent {
                session_gen: gen,
                event: ActorEvent::CommandResult {
                    cmd_id: st.cmd_id,
                    ok: false,
                    data: None,
                    error_code: Some("Aborted".into()),
                    error: Some("session closed during file transfer".into()),
                },
            });
        }
    }
}

/// Shared inbound `0x05 FileTransfer` L4 router used by both Host and Controller.
/// Unconditionally intercepts strictly sender-bound replies (`Accept`, `Ack`, `CompleteAck`) so
/// late/stale/cancelled replies NEVER fall through to `file_receiver` and trigger `0x0103` role
/// violations. Only `Abort` falls through to `file_receiver` when unmatched in `outbound_files`.
#[allow(clippy::too_many_arguments)]
async fn route_inbound_file_l4<S: FileL4Sender>(
    sess: &mut S,
    l4_hdr: &v2_transport::L4Header,
    body: &[u8],
    outbound_files: &mut OutboundFileManager,
    file_receiver: &mut FileTransferReceiver,
    file_err_counter: &mut ChannelFramingErrorCounter,
    gen: u64,
    actor_tx: &mpsc::Sender<ActorMessage>,
) -> Option<String> {
    match decode_file_l4(l4_hdr, body) {
        Ok(FileMessage::Accept(acc)) => {
            let _ = outbound_files
                .handle_accept(sess, &acc, gen, actor_tx)
                .await;
            return None;
        }
        Ok(FileMessage::Ack(ack)) => {
            let _ = outbound_files.handle_ack(&ack);
            return None;
        }
        Ok(FileMessage::CompleteAck(cack)) => {
            let _ = outbound_files
                .handle_complete_ack(cack.transfer_id, cack.status, gen, actor_tx)
                .await;
            return None;
        }
        Ok(FileMessage::Abort(ab))
            if outbound_files
                .handle_remote_abort(ab.transfer_id, ab.error_code, gen, actor_tx)
                .await =>
        {
            return None;
        }
        _ => {}
    }

    match file_receiver.on_l4_frame(l4_hdr, body, Instant::now(), file_err_counter) {
        FileRecvAction::SendAccept(acc) => {
            if let Ok(enc) = acc.encode() {
                if matches!(
                    sess.send_file_l4(FILE_MSG_ACCEPT, &enc).await,
                    Err(FileSendError::Backpressure)
                ) {
                    outbound_files.enqueue_ctrl_retry(FILE_MSG_ACCEPT, &enc);
                }
            }
        }
        FileRecvAction::SendAck(ack) => {
            if let Ok(enc) = ack.encode() {
                if matches!(
                    sess.send_file_l4(FILE_MSG_ACK, &enc).await,
                    Err(FileSendError::Backpressure)
                ) {
                    outbound_files.enqueue_ctrl_retry(FILE_MSG_ACK, &enc);
                }
            }
        }
        FileRecvAction::SendCompleteAck {
            ack,
            saved_path,
            audit,
        } => {
            if let Ok(enc) = ack.encode() {
                if matches!(
                    sess.send_file_l4(FILE_MSG_COMPLETE_ACK, &enc).await,
                    Err(FileSendError::Backpressure)
                ) {
                    outbound_files.enqueue_ctrl_retry(FILE_MSG_COMPLETE_ACK, &enc);
                }
            }
            let _ = actor_tx
                .send(ActorMessage::InternalEvent {
                    session_gen: gen,
                    event: ActorEvent::FileComplete {
                        transfer_id: audit.transfer_id,
                        rel_name: audit.rel_name,
                        bytes: audit.file_size,
                        sha256_hex: audit.sha256_hex,
                        saved_path: saved_path.map(|p| p.display().to_string()),
                    },
                })
                .await;
        }
        FileRecvAction::SendAbort(ab) => {
            let enc = ab.encode();
            if matches!(
                sess.send_file_l4(FILE_MSG_ABORT, &enc).await,
                Err(FileSendError::Backpressure)
            ) {
                outbound_files.enqueue_ctrl_retry(FILE_MSG_ABORT, &enc);
            }
            let _ = actor_tx
                .send(ActorMessage::InternalEvent {
                    session_gen: gen,
                    event: ActorEvent::FileAborted {
                        transfer_id: ab.transfer_id,
                        error_code: ab.error_code,
                        reason: format!("error_code={:#06x}", ab.error_code),
                    },
                })
                .await;
        }
        FileRecvAction::SessionFatal(reason) => {
            return Some(format!("file_fatal: {reason}"));
        }
        FileRecvAction::None => {}
    }
    None
}

trait ClipL4Sender {
    fn send_clip_l4<'a>(
        &'a mut self,
        msg_type: u8,
        body: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), FileSendError>> + Send + 'a>>;
}

impl ClipL4Sender for UdpE2eeSession {
    fn send_clip_l4<'a>(
        &'a mut self,
        msg_type: u8,
        body: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), FileSendError>> + Send + 'a>>
    {
        Box::pin(async move {
            match self
                .send_l4_raw(CHAN_CLIPBOARD, msg_type, 0, false, body)
                .await
            {
                Ok(_) => Ok(()),
                Err(v2_client::ClientError::P3Backpressure { .. }) => {
                    Err(FileSendError::Backpressure)
                }
                Err(e) => Err(FileSendError::Transport(e.to_string())),
            }
        })
    }
}

struct PendingClipQueue {
    frames: VecDeque<(u8, Vec<u8>)>,
    buffered_bytes: usize,
}

impl PendingClipQueue {
    fn new() -> Self {
        Self {
            frames: VecDeque::new(),
            buffered_bytes: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    fn clear(&mut self) {
        self.frames.clear();
        self.buffered_bytes = 0;
    }

    fn push(&mut self, msg_type: u8, body: &[u8]) {
        if msg_type == CLIP_MSG_SYNC {
            // Starting a new clipboard transfer supersedes any stale queued frames from an
            // earlier transfer so orphaned chunks are never sent after a blackout.
            self.clear();
        }
        if self.frames.len() >= PENDING_CLIP_FRAMES_CAP
            || self.buffered_bytes.saturating_add(body.len()) > PENDING_CLIP_BYTES_CAP
        {
            return;
        }
        self.buffered_bytes = self.buffered_bytes.saturating_add(body.len());
        self.frames.push_back((msg_type, body.to_vec()));
    }

    fn front(&self) -> Option<&(u8, Vec<u8>)> {
        self.frames.front()
    }

    fn pop_front(&mut self) -> Option<(u8, Vec<u8>)> {
        let popped = self.frames.pop_front()?;
        self.buffered_bytes = self.buffered_bytes.saturating_sub(popped.1.len());
        Some(popped)
    }
}

async fn send_or_queue_clip_frame<S: ClipL4Sender>(
    sess: &mut S,
    pending: &mut PendingClipQueue,
    msg_type: u8,
    body: &[u8],
) {
    if msg_type == CLIP_MSG_SYNC {
        pending.clear();
    } else if !pending.is_empty() {
        pending.push(msg_type, body);
        return;
    }
    if matches!(
        sess.send_clip_l4(msg_type, body).await,
        Err(FileSendError::Backpressure)
    ) {
        pending.push(msg_type, body);
    }
}

async fn drain_pending_clip_frames<S: ClipL4Sender>(sess: &mut S, pending: &mut PendingClipQueue) {
    while let Some((msg_type, body)) = pending.front() {
        match sess.send_clip_l4(*msg_type, body).await {
            Ok(()) | Err(FileSendError::Transport(_)) => {
                pending.pop_front();
            }
            Err(FileSendError::Backpressure) => break,
        }
    }
}

/// RAII guard ensuring `release_all_keys()` runs and `releaser_slot` is cleared on ANY exit path
/// (normal teardown, early encoder init error, cancellation, or panic unwind).
struct ReleaserDropGuard {
    releaser: Arc<dyn EmergencyKeyReleaser>,
    slot: Arc<Mutex<Option<Arc<dyn EmergencyKeyReleaser>>>>,
}

impl ReleaserDropGuard {
    fn arm(
        releaser: Arc<dyn EmergencyKeyReleaser>,
        slot: Arc<Mutex<Option<Arc<dyn EmergencyKeyReleaser>>>>,
    ) -> Self {
        *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&releaser));
        Self { releaser, slot }
    }
}

impl Drop for ReleaserDropGuard {
    fn drop(&mut self) {
        let _ = self.releaser.release_all_keys();
        *self.slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

struct HostTaskAdapters {
    use_os_capture: bool,
    legacy_capture_fallback: bool,
    use_os_audio: bool,
    use_os_clipboard: bool,
    enable_hid_watchdog_subprocess: bool,
    watchdog_report_path: Option<PathBuf>,
    watchdog_bin_path: Option<PathBuf>,
    real_input_permit: Option<Arc<RealInputPermit>>,
    permission_probe: Option<Arc<dyn PermissionProbe>>,
    enable_os_input: Arc<AtomicBool>,
    active_watchdog_ax_probe: WatchdogAxProbeSlot,
    clipboard_sync_enabled: Arc<AtomicBool>,
    dryrun_journal: DryRunHidJournal,
    mem_clip: MemoryClipboardBackend,
    download_dir: PathBuf,
    synth_w: u32,
    synth_h: u32,
}

#[must_use]
struct WatchdogAxProbeGuard {
    gen: u64,
    slot: WatchdogAxProbeSlot,
}

impl Drop for WatchdogAxProbeGuard {
    fn drop(&mut self) {
        let mut g = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        if g.as_ref().is_some_and(|(id, _)| *id == self.gen) {
            *g = None;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_host_lifecycle_task(
    gen: u64,
    cmd_id: u64,
    cfg: V2ClientConfig,
    codec_auto: bool,
    cancel: CancellationToken,
    actor_tx: mpsc::Sender<ActorMessage>,
    events: Arc<BridgeEventHub>,
    dropped_events: Arc<AtomicU64>,
    releaser_slot: Arc<Mutex<Option<Arc<dyn EmergencyKeyReleaser>>>>,
    adapters: HostTaskAdapters,
) {
    let cb = Arc::new(BridgeUiCallback {
        session_gen: gen,
        actor_tx: actor_tx.clone(),
        events,
        dropped_events,
    });
    let dispatcher = UiCallbackDispatcher::spawn(cb);

    let mut daemon = match DesktopHostDaemon::bootstrap(cfg.clone(), dispatcher).await {
        Ok(d) => d,
        Err(e) => {
            let _ = actor_tx
                .send(ActorMessage::InternalEvent {
                    session_gen: gen,
                    event: ActorEvent::HostBootstrapFailed {
                        cmd_id,
                        error: e.to_string(),
                    },
                })
                .await;
            return;
        }
    };

    let local_cert = match daemon.device_cert().cloned() {
        Some(c) => c,
        None => {
            let _ = actor_tx
                .send(ActorMessage::InternalEvent {
                    session_gen: gen,
                    event: ActorEvent::HostBootstrapFailed {
                        cmd_id,
                        error: "host daemon missing local device cert".into(),
                    },
                })
                .await;
            return;
        }
    };
    let policy = daemon.effective_policy().clone();
    if actor_tx
        .send(ActorMessage::InternalEvent {
            session_gen: gen,
            event: ActorEvent::HostBootstrapped {
                cmd_id,
                local_cert,
                policy,
            },
        })
        .await
        .is_err()
    {
        daemon.disconnect_signaling().await;
        return;
    }

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_flag_c = Arc::clone(&stop_flag);
    let cancel_c = cancel.clone();
    let flag_watcher = tokio::spawn(async move {
        cancel_c.cancelled().await;
        stop_flag_c.store(true, Ordering::Release);
    });

    while !cancel.is_cancelled() {
        let mut accepted = tokio::select! {
            _ = cancel.cancelled() => break,
            res = daemon.accept_next_session(Arc::clone(&stop_flag), None) => match res {
                Ok(sess) => sess,
                Err(_) if cancel.is_cancelled() => break,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            }
        };

        let (action_tx, action_rx) = mpsc::channel::<SessionAction>(SESSION_ACTION_CAP);
        // P0-1: Check StreamingStarted delivery — never enter a headless zombie session loop if actor closed!
        if actor_tx
            .send(ActorMessage::InternalEvent {
                session_gen: gen,
                event: ActorEvent::StreamingStarted {
                    cmd_id: None,
                    session_id: accepted.session_id,
                    local_cert: Box::new(accepted.local_cert.clone()),
                    peer_cert: Box::new(accepted.peer_cert.clone()),
                    policy: accepted.effective_policy.clone(),
                    active_mode: accepted.active_transport_mode,
                    attach_ms: accepted.transport_attach_ms,
                    action_tx,
                },
            })
            .await
            .is_err()
        {
            let _ = send_redundant_session_close_3x(&mut accepted.e2ee_session, 0).await;
            let _ = accepted.lease_renewal.shutdown().await;
            break;
        }

        let end_reason = run_active_host_session(
            gen,
            &cfg,
            codec_auto,
            accepted,
            cancel.clone(),
            actor_tx.clone(),
            Arc::clone(&releaser_slot),
            action_rx,
            &adapters,
        )
        .await;

        let _ = actor_tx
            .send(ActorMessage::InternalEvent {
                session_gen: gen,
                event: ActorEvent::SessionEnded {
                    return_to_listening: !cancel.is_cancelled(),
                    reason: end_reason,
                },
            })
            .await;
    }

    flag_watcher.abort();
    let _ = flag_watcher.await;
    daemon.disconnect_signaling().await;
}

#[allow(clippy::too_many_arguments)]
async fn run_active_host_session(
    gen: u64,
    cfg: &V2ClientConfig,
    codec_auto: bool,
    accepted: crate::session::manager::AcceptedHostSession,
    cancel: CancellationToken,
    actor_tx: mpsc::Sender<ActorMessage>,
    releaser_slot: Arc<Mutex<Option<Arc<dyn EmergencyKeyReleaser>>>>,
    mut action_rx: mpsc::Receiver<SessionAction>,
    adapters: &HostTaskAdapters,
) -> String {
    let mut effective_policy = accepted.effective_policy.clone();
    let poller_allow_clip = Arc::new(AtomicBool::new(
        effective_policy.allow_clipboard() && adapters.clipboard_sync_enabled.load(Ordering::Acquire),
    ));
    let mut audio_gate = AudioChannelGate::from_policy(&effective_policy);
    let mut audio_muted = false;

    // Re-arm the shared dry-run HID journal for this brand-new session after any prior session's release.
    adapters.dryrun_journal.resume_for_new_session();

    // 1. HID sink (DryRun by default; triple-gated RealInput only when Arc<RealInputPermit> provided).
    let mut using_real_input = false;
    let base_hid_sink: Box<dyn OsHidSink> = if let Some(permit) = adapters.real_input_permit.clone()
    {
        match create_real_os_hid_sink(permit) {
            Ok(real) => {
                using_real_input = true;
                real
            }
            Err(e) => {
                let _ = actor_tx
                    .send(ActorMessage::InternalEvent {
                        session_gen: gen,
                        event: ActorEvent::HostCapabilityDegraded {
                            capability: "real_input".into(),
                            reason: e.to_string(),
                        },
                    })
                    .await;
                Box::new(DryRunHidSink::with_journal(adapters.dryrun_journal.clone()))
            }
        }
    } else {
        Box::new(DryRunHidSink::with_journal(adapters.dryrun_journal.clone()))
    };
    let _wd_ax_guard = WatchdogAxProbeGuard {
        gen,
        slot: Arc::clone(&adapters.active_watchdog_ax_probe),
    };
    let mut active_watchdog_sup: Option<Arc<HidWatchdogSupervisor>> = None;
    let inner_hid_sink: Box<dyn OsHidSink> = if adapters.enable_hid_watchdog_subprocess {
        let wd_cfg = HidWatchdogConfig {
            binary_path: adapters.watchdog_bin_path.clone(),
            dry_run_report_path: adapters.watchdog_report_path.clone(),
            real_os_input: using_real_input,
            ..HidWatchdogConfig::default()
        };
        match HidWatchdogSupervisor::spawn(wd_cfg) {
            Ok(sup) => {
                let sup = Arc::new(sup);
                *adapters
                    .active_watchdog_ax_probe
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) =
                    Some((gen, sup.accessibility_trusted_flag()));
                active_watchdog_sup = Some(Arc::clone(&sup));
                let tx_deg = actor_tx.clone();
                let on_degraded = Arc::new(move |reason: String| {
                    let _ = tx_deg.try_send(ActorMessage::InternalEvent {
                        session_gen: gen,
                        event: ActorEvent::HostCapabilityDegraded {
                            capability: "hid_watchdog".into(),
                            reason,
                        },
                    });
                });
                Box::new(WatchdogSupervisedHidSink::new(
                    base_hid_sink,
                    sup,
                    Some(on_degraded),
                ))
            }
            Err(e) => {
                let _ = actor_tx
                    .send(ActorMessage::InternalEvent {
                        session_gen: gen,
                        event: ActorEvent::HostCapabilityDegraded {
                            capability: "hid_watchdog".into(),
                            reason: e.to_string(),
                        },
                    })
                    .await;
                if using_real_input {
                    // Fail closed: terminate session immediately rather than running unsupervised
                    // real OS input or silently degrading to DryRun.
                    let _ = accepted.lease_renewal.shutdown().await;
                    return format!("real_input hid watchdog failed closed: {e}");
                }
                base_hid_sink
            }
        }
    } else {
        base_hid_sink
    };
    let perm_probe_for_sink = adapters.permission_probe.clone();
    let wd_slot_for_sink = Arc::clone(&adapters.active_watchdog_ax_probe);
    let enable_for_sink = Arc::clone(&adapters.enable_os_input);
    let sink_cache_ttl = if adapters.permission_probe.is_some() {
        Duration::ZERO
    } else {
        Duration::from_millis(200)
    };
    let mut hid_sink = GatedOsHidSink::with_probe_cache_ttl(
        inner_hid_sink,
        Arc::clone(&adapters.enable_os_input),
        Arc::new(move || {
            let wd_ax = wd_slot_for_sink
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|(_, flag)| flag.load(Ordering::Acquire));
            let enabled = enable_for_sink.load(Ordering::Acquire);
            let rep = if let Some(p) = &perm_probe_for_sink {
                p.probe(wd_ax, enabled)
            } else {
                SystemPermissionProbe.probe(wd_ax, enabled)
            };
            rep.screen_capture_granted
                && rep.accessibility_granted
                && rep.probe_source.is_authoritative()
        }),
        sink_cache_ttl,
    );
    let releaser = hid_sink.emergency_releaser();
    let _releaser_guard = ReleaserDropGuard::arm(Arc::clone(&releaser), releaser_slot);

    // 2. Capture source (Synthetic by default; OS capture tries ScreenCaptureKit first and fails
    //    closed with HostCapabilityDegraded unless `legacy_capture_fallback` is explicitly true).
    let mut sck_audio_cap: Option<Box<dyn OsAudioCapture>> = None;
    let mut capture: Box<dyn OsScreenCapture> = if adapters.use_os_capture {
        match create_os_screen_capture_with_policy(
            adapters.use_os_audio,
            adapters.legacy_capture_fallback,
        ) {
            Ok((cap, maybe_audio)) => {
                sck_audio_cap = maybe_audio;
                cap
            }
            Err(e) => {
                let _ = actor_tx
                    .send(ActorMessage::InternalEvent {
                        session_gen: gen,
                        event: ActorEvent::HostCapabilityDegraded {
                            capability: "os_capture".into(),
                            reason: e.to_string(),
                        },
                    })
                    .await;
                let _ = accepted.lease_renewal.shutdown().await;
                return format!("os_capture failed closed: {e}");
            }
        }
    } else {
        Box::new(SyntheticScreenSource::new(adapters.synth_w, adapters.synth_h))
    };
    let (cap_w, cap_h) = capture.dimensions();
    let enc_w = (cap_w & !1).clamp(32, 1920);
    let enc_h = (cap_h & !1).clamp(32, 1080);

    let negotiated_codec = if codec_auto {
        negotiate_video_codec(local_v2_cap_bits(), accepted.peer_cert.cap_bits, None)
            .unwrap_or(cfg.codec)
    } else {
        cfg.codec
    };
    let encoder =
        match V2VideoEncoder::new(negotiated_codec, enc_w, enc_h, 2.0, Some(cfg.fps as usize)) {
        Ok(e) => e,
        Err(e) => {
            // `_releaser_guard` automatically releases keys and clears `releaser_slot` on return.
            let _ = accepted.lease_renewal.shutdown().await;
            return format!("encoder init failed: {e}");
        }
    };
    let mut host_sess = DesktopHostSession::new(accepted.e2ee_session, encoder);

    // 3. Audio source & Opus encoder (prefers ScreenCaptureKit system audio loopback when available;
    //    graceful degradation via AudioStatusChanged).
    let mut os_audio_cap: Box<dyn OsAudioCapture> = if let Some(sck_aud) = sck_audio_cap {
        sck_aud
    } else if adapters.use_os_audio {
        match open_os_audio_capture() {
            Ok(cap) => cap,
            Err(status) => {
                let _ = actor_tx
                    .send(ActorMessage::InternalEvent {
                        session_gen: gen,
                        event: ActorEvent::AudioStatus(status),
                    })
                    .await;
                Box::new(SilentAudioCapture)
            }
        }
    } else {
        Box::new(SilentAudioCapture)
    };
    let mut synth_audio = SyntheticMultiToneSource::new(2, 15, 25, 15).ok();
    let mut audio_enc = V2AudioEncoder::new(2, AUDIO_DEFAULT_BITRATE_BPS).ok();
    let mut audio_ts_u32: u32 = 0;

    // 4. Clipboard poller & receiver.
    let clip_backend: Box<dyn crate::os::OsClipboardBackend> = if adapters.use_os_clipboard {
        create_os_clipboard_backend()
            .unwrap_or_else(|_| Box::new(adapters.mem_clip.clone()))
    } else {
        Box::new(adapters.mem_clip.clone())
    };
    let mut clip_poller = ClipboardPoller::new(clip_backend, poller_allow_clip);
    let mut clip_receiver = ClipboardReceiver::new(effective_policy.clone());
    let mut clip_err_counter = ChannelFramingErrorCounter::new();
    let mut next_clip_id: u64 = 1;

    // 5. File transfer receiver + incremental non-blocking outbound manager.
    let _ = std::fs::create_dir_all(&adapters.download_dir);
    let mut file_receiver =
        FileTransferReceiver::new(effective_policy.clone(), adapters.download_dir.clone());
    let mut file_err_counter = ChannelFramingErrorCounter::new();
    let mut outbound_files = OutboundFileManager::new();
    let mut pending_clip_frames = PendingClipQueue::new();
    let mut next_transfer_id: u64 = 1;

    // 6. Non-blocking policy refresh result channel.
    let (pol_tx, mut pol_rx) =
        mpsc::channel::<(u64, Result<(EffectiveTenantPolicy, bool), String>)>(4);

    let initial_fps = cfg.fps.clamp(1, 120);
    let mut frame_period =
        Duration::from_micros(1_000_000 / u64::from(initial_fps)).max(Duration::from_micros(1));
    let mut video_tick = tokio::time::interval(frame_period);
    video_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut audio_tick = tokio::time::interval(Duration::from_millis(20));
    audio_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut clip_tick = tokio::time::interval(Duration::from_millis(100));
    clip_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut file_tick = tokio::time::interval(Duration::from_millis(2));
    file_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut wd_ax_tick = tokio::time::interval(Duration::from_secs(1));
    wd_ax_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let watchdog_timeout = Duration::from_millis(cfg.watchdog_timeout_ms);
    let mut last_peer_activity = Instant::now();
    let mut lease_expired_rx = accepted.lease_renewal.subscribe_expired();
    let mut pts_ms: i64 = 0;
    let mut screen_revoked_reported = false;
    let mut last_revoked_poll = Instant::now();
    let mut capture_fail_count: u32 = 0;
    let mut capture_backoff_until: Option<Instant> = None;
    let mut capture_degraded_reported = false;
    let hid_denied_notified = AtomicBool::new(false);
    let mut last_wd_ax_trusted: Option<bool> = active_watchdog_sup
        .as_ref()
        .map(|s| s.accessibility_trusted());

    // P0-2: Check pre-latched lease expiry BEFORE entering the select loop!
    let end_reason: String = if lease_expired_rx.borrow().is_some() {
        "lease_expired".into()
    } else {
        loop {
            if cancel.is_cancelled() {
                break "local_cancel".into();
            }
            if last_peer_activity.elapsed() >= watchdog_timeout {
                let rep = releaser.release_all_keys();
                let _ = actor_tx
                    .send(ActorMessage::InternalEvent {
                        session_gen: gen,
                        event: ActorEvent::WatchdogTriggered {
                            released_keys: rep.released_keys,
                            released_buttons: rep.released_buttons,
                        },
                    })
                    .await;
                break "watchdog_timeout".into();
            }

            let arq_deadline = host_sess.session().next_arq_deadline();
            tokio::select! {
                _ = async {
                    match arq_deadline {
                        Some(dl) => tokio::time::sleep_until(dl).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    if let Err(e) = host_sess.session_mut().poll_arq().await {
                        break format!("transport_error: {e}");
                    }
                }
                _ = cancel.cancelled() => {
                    break "local_cancel".into();
                }
                // P0-2: Treat both Err(_) (sender dropped) and Some(_) as fail-closed lease_expired!
                res = lease_expired_rx.changed() => {
                    if res.is_err() || lease_expired_rx.borrow().is_some() {
                        break "lease_expired".into();
                    }
                }
                // Non-blocking policy refresh completion
                Some((cmd_id, res)) = pol_rx.recv() => {
                    match res {
                        Ok((new_pol, is_degraded)) => {
                            let now = now_unix_secs();
                            match should_accept_policy_update(Some(&effective_policy), &new_pol, now) {
                                Ok(()) => {
                                    effective_policy = new_pol.clone();
                                    let clip_ok = effective_policy.allow_clipboard()
                                        && adapters.clipboard_sync_enabled.load(Ordering::Acquire);
                                    clip_poller.set_policy_allowed(clip_ok);
                                    audio_gate = AudioChannelGate::from_policy(&effective_policy);
                                    audio_gate.set_muted(audio_muted);
                                    clip_receiver.update_policy(effective_policy.clone());
                                    file_receiver.update_policy(effective_policy.clone());
                                    let _ = actor_tx.send(ActorMessage::InternalEvent {
                                        session_gen: gen,
                                        event: ActorEvent::PolicyUpdated {
                                            cmd_id: Some(cmd_id),
                                            policy: new_pol,
                                            is_degraded,
                                        },
                                    }).await;
                                }
                                Err(reason) => {
                                    let _ = actor_tx.send(ActorMessage::InternalEvent {
                                        session_gen: gen,
                                        event: ActorEvent::SecurityEvent(SecurityEvent::PolicyDegraded {
                                            reason: reason.clone(),
                                        }),
                                    }).await;
                                    let _ = actor_tx.send(ActorMessage::InternalEvent {
                                        session_gen: gen,
                                        event: ActorEvent::CommandResult {
                                            cmd_id,
                                            ok: false,
                                            data: None,
                                            error_code: Some("PolicyUpdateRejected".into()),
                                            error: Some(reason),
                                        },
                                    }).await;
                                }
                            }
                        }
                        Err(e) => {
                            let _ = actor_tx.send(ActorMessage::InternalEvent {
                                session_gen: gen,
                                event: ActorEvent::CommandResult {
                                    cmd_id,
                                    ok: false,
                                    data: None,
                                    error_code: Some("PolicyRefreshFailed".into()),
                                    error: Some(e),
                                },
                            }).await;
                        }
                    }
                }
                // P0-1: Break immediately when action_rx closes (None)!
                act = action_rx.recv() => {
                    let Some(action) = act else {
                        break "action_channel_closed".into();
                    };
                    match action {
                        SessionAction::SetAudioMute(m) => {
                            audio_muted = m;
                            audio_gate.set_muted(m);
                        }
                        SessionAction::SetClipboardSync(enabled) => {
                            adapters.clipboard_sync_enabled.store(enabled, Ordering::Release);
                            clip_poller
                                .set_policy_allowed(enabled && effective_policy.allow_clipboard());
                        }
                        SessionAction::SetVideoQuality {
                            bitrate_kbps,
                            fps_cap,
                        } => {
                            let clamped_fps = fps_cap.clamp(1, cfg.fps.clamp(1, 120));
                            frame_period = Duration::from_micros(
                                1_000_000 / u64::from(clamped_fps),
                            )
                            .max(Duration::from_micros(1));
                            video_tick = tokio::time::interval(frame_period);
                            video_tick
                                .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                            if bitrate_kbps > 0 {
                                let bps = bitrate_kbps.saturating_mul(1000);
                                if let Err(e) = host_sess.set_bitrate(bps) {
                                    eprintln!("[video-quality] host set_bitrate({bitrate_kbps} kbps) degraded: {e}");
                                    let _ = actor_tx.try_send(ActorMessage::InternalEvent {
                                        session_gen: gen,
                                        event: ActorEvent::HostCapabilityDegraded {
                                            capability: "bitrate_control".into(),
                                            reason: format!("encoder set_bitrate failed: {e}"),
                                        },
                                    });
                                }
                            }
                        }
                        SessionAction::RequestCodec(requested) => {
                            let current = host_sess.encoder_codec().name().to_string();
                            let accepted_now = requested == current;
                            let _ = actor_tx.try_send(ActorMessage::InternalEvent {
                                session_gen: gen,
                                event: ActorEvent::CodecAck {
                                    active_codec: current,
                                    requested_codec: Some(requested),
                                    accepted: accepted_now,
                                },
                            });
                        }
                        SessionAction::SendClipboard { mime_kind, bytes } => {
                            if adapters.clipboard_sync_enabled.load(Ordering::Acquire)
                                && effective_policy.allow_clipboard()
                            {
                                let cid = next_clip_id;
                                next_clip_id += 1;
                                let paused = host_sess.session().is_bulk_paused();
                                if let Ok(xfer) = prepare_outbound_clipboard(&effective_policy, mime_kind, &bytes, cid, cid, paused) {
                                    if let Ok(sync_bytes) = xfer.sync.encode() {
                                        send_or_queue_clip_frame(host_sess.session_mut(), &mut pending_clip_frames, CLIP_MSG_SYNC, &sync_bytes).await;
                                    }
                                    for ch in &xfer.chunks {
                                        if let Ok(enc) = ch.encode() {
                                            send_or_queue_clip_frame(host_sess.session_mut(), &mut pending_clip_frames, CLIP_MSG_CHUNK, &enc).await;
                                        }
                                    }
                                }
                            }
                        }
                        SessionAction::SendFile { cmd_id, path, rel_name } => {
                            let tid = next_transfer_id;
                            next_transfer_id += 1;
                            outbound_files.start_transfer(
                                host_sess.session_mut(),
                                tid,
                                cmd_id,
                                path,
                                rel_name,
                                &effective_policy,
                                gen,
                                &actor_tx,
                            ).await;
                        }
                        SessionAction::CancelFile { transfer_id } => {
                            outbound_files.cancel_transfer(host_sess.session_mut(), transfer_id, gen, &actor_tx).await;
                        }
                        SessionAction::RefreshPolicy { cmd_id } => {
                            let cfg_c = cfg.clone();
                            let cancel_c = cancel.clone();
                            let pol_tx_c = pol_tx.clone();
                            tokio::spawn(async move {
                                let res = refresh_policy_from_cp(&cfg_c, &cancel_c).await;
                                let _ = pol_tx_c.send((cmd_id, res)).await;
                            });
                        }
                        SessionAction::SendHid(_) => {}
                        SessionAction::ReleaseAll { ack, .. } => {
                            let _ = releaser.release_all_keys();
                            if let Some(tx) = ack {
                                let _ = tx.send((0, 0));
                            }
                        }
                    }
                }
                _ = file_tick.tick(), if outbound_files.has_active() || !pending_clip_frames.is_empty() => {
                    if !pending_clip_frames.is_empty() {
                        drain_pending_clip_frames(host_sess.session_mut(), &mut pending_clip_frames)
                            .await;
                    }
                    if outbound_files.has_active() {
                        outbound_files
                            .pump_one_step(host_sess.session_mut(), &effective_policy, gen, &actor_tx)
                            .await;
                    }
                }
                _ = wd_ax_tick.tick(), if active_watchdog_sup.is_some() => {
                    if let Some(sup) = &active_watchdog_sup {
                        let ax_now = sup.accessibility_trusted();
                        if last_wd_ax_trusted != Some(ax_now) {
                            last_wd_ax_trusted = Some(ax_now);
                            if !ax_now {
                                let _ = hid_sink.disable_and_release();
                            }
                            let enabled = adapters.enable_os_input.load(Ordering::Acquire);
                            let rep = if let Some(p) = &adapters.permission_probe {
                                p.probe(Some(ax_now), enabled)
                            } else {
                                SystemPermissionProbe.probe(Some(ax_now), enabled)
                            };
                            let _ = actor_tx.try_send(ActorMessage::InternalEvent {
                                session_gen: gen,
                                event: ActorEvent::PermissionStatusChanged(rep),
                            });
                        }
                    }
                }
                _ = video_tick.tick() => {
                    if screen_revoked_reported {
                        // Slow-poll at 1 Hz until Screen Recording is restored or session stops.
                        if last_revoked_poll.elapsed() >= Duration::from_secs(1) {
                            last_revoked_poll = Instant::now();
                            if preflight_screen_capture_permission().unwrap_or(false) {
                                screen_revoked_reported = false;
                                capture_fail_count = 0;
                                capture_backoff_until = None;
                                capture_degraded_reported = false;
                                let wd_ax = adapters
                                    .active_watchdog_ax_probe
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .as_ref()
                                    .map(|(_, f)| f.load(Ordering::Acquire));
                                let rep = if let Some(p) = &adapters.permission_probe {
                                    p.probe(wd_ax, false)
                                } else {
                                    SystemPermissionProbe.probe(wd_ax, false)
                                };
                                let _ = actor_tx.try_send(ActorMessage::InternalEvent {
                                    session_gen: gen,
                                    event: ActorEvent::PermissionStatusChanged(rep),
                                });
                            }
                        }
                    } else if capture_backoff_until.is_none_or(|t| Instant::now() >= t) {
                        match capture.capture_frame() {
                            Ok(raw) => {
                                capture_fail_count = 0;
                                capture_backoff_until = None;
                                capture_degraded_reported = false;
                                let i420_res = if adapters.use_os_capture {
                                    convert_captured_stride_to_i420(&raw)
                                } else {
                                    raw_captured_to_i420(&raw)
                                };
                                if let Ok(i420) = i420_res {
                                    pts_ms += frame_period.as_millis() as i64;
                                    if let Err(SessionError::Video(
                                        e @ (VideoError::CodecFailed { .. }
                                        | VideoError::HardwareUnavailable(_)),
                                    )) = host_sess.publish_i420_frame(Arc::new(i420), pts_ms).await
                                    {
                                        break format!("video_codec_failed: {e}");
                                    }
                                }
                            }
                            Err(OsError::PermissionDenied(OsPermission::ScreenRecording)) => {
                                if !screen_revoked_reported {
                                    screen_revoked_reported = true;
                                    last_revoked_poll = Instant::now();
                                    let _ = hid_sink.disable_and_release();
                                    let wd_ax = adapters
                                        .active_watchdog_ax_probe
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .as_ref()
                                        .map(|(_, f)| f.load(Ordering::Acquire));
                                    let mut rep = if let Some(p) = &adapters.permission_probe {
                                        p.probe(wd_ax, false)
                                    } else {
                                        SystemPermissionProbe.probe(wd_ax, false)
                                    };
                                    rep.screen_capture_granted = false;
                                    let _ = actor_tx
                                        .send(ActorMessage::InternalEvent {
                                            session_gen: gen,
                                            event: ActorEvent::PermissionStatusChanged(rep),
                                        })
                                        .await;
                                    let _ = actor_tx
                                        .send(ActorMessage::InternalEvent {
                                            session_gen: gen,
                                            event: ActorEvent::HostCapabilityDegraded {
                                                capability: "screen_recording_revoked".into(),
                                                reason: "Screen Recording permission revoked mid-session"
                                                    .into(),
                                            },
                                        })
                                        .await;
                                }
                            }
                            Err(OsError::CaptureFailed(msg)) => {
                                if adapters.use_os_capture
                                    && !preflight_screen_capture_permission().unwrap_or(false)
                                {
                                    if !screen_revoked_reported {
                                        screen_revoked_reported = true;
                                        last_revoked_poll = Instant::now();
                                        let _ = hid_sink.disable_and_release();
                                        let wd_ax = adapters
                                            .active_watchdog_ax_probe
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner())
                                            .as_ref()
                                            .map(|(_, f)| f.load(Ordering::Acquire));
                                        let mut rep = if let Some(p) = &adapters.permission_probe {
                                            p.probe(wd_ax, false)
                                        } else {
                                            SystemPermissionProbe.probe(wd_ax, false)
                                        };
                                        rep.screen_capture_granted = false;
                                        let _ = actor_tx
                                            .send(ActorMessage::InternalEvent {
                                                session_gen: gen,
                                                event: ActorEvent::PermissionStatusChanged(rep),
                                            })
                                            .await;
                                        let _ = actor_tx
                                            .send(ActorMessage::InternalEvent {
                                                session_gen: gen,
                                                event: ActorEvent::HostCapabilityDegraded {
                                                    capability: "screen_recording_revoked".into(),
                                                    reason: format!(
                                                        "Screen Recording capture stopped (permission revoked): {msg}"
                                                    ),
                                                },
                                            })
                                            .await;
                                    }
                                } else {
                                    capture_fail_count = capture_fail_count.saturating_add(1);
                                    let backoff_ms =
                                        (50u64 << capture_fail_count.min(5)).min(2_000);
                                    capture_backoff_until =
                                        Some(Instant::now() + Duration::from_millis(backoff_ms));
                                    if capture_fail_count >= 5 && !capture_degraded_reported {
                                        capture_degraded_reported = true;
                                        eprintln!(
                                            "[os-capture] repeated CaptureFailed ({capture_fail_count}x): {msg}"
                                        );
                                        let _ = actor_tx.try_send(ActorMessage::InternalEvent {
                                            session_gen: gen,
                                            event: ActorEvent::HostCapabilityDegraded {
                                                capability: "screen_capture_failed".into(),
                                                reason: format!(
                                                    "repeated screen capture failure ({capture_fail_count}x): {msg}"
                                                ),
                                            },
                                        });
                                    }
                                }
                            }
                            Err(_) => {}
                        }
                    }
                }
                _ = audio_tick.tick() => {
                    if !audio_muted && audio_gate.check_allowed().unwrap_or(false) {
                        if let Some(enc) = audio_enc.as_mut() {
                            let pcm_opt: Option<Vec<f32>> = if adapters.use_os_audio {
                                let mut pcm = vec![0.0f32; AUDIO_FRAME_SAMPLES_PER_CH * 2];
                                if os_audio_cap.read_frame(&mut pcm).unwrap_or(false) {
                                    Some(pcm)
                                } else {
                                    None
                                }
                            } else if let Some(src) = synth_audio.as_mut() {
                                if let Some(frame) = src.next_frame() {
                                    Some(frame)
                                } else {
                                    synth_audio = SyntheticMultiToneSource::new(2, 15, 25, 15).ok();
                                    synth_audio.as_mut().and_then(|s| s.next_frame())
                                }
                            } else {
                                None
                            };
                            if let Some(pcm) = pcm_opt {
                                if let Ok(encoded) = enc.encode_frame(&pcm) {
                                    let ts = audio_ts_u32;
                                    audio_ts_u32 = audio_ts_u32.wrapping_add(AUDIO_FRAME_SAMPLES_PER_CH as u32);
                                    let _ = host_sess.session_mut().send_audio(&AudioPacket {
                                        ts,
                                        dtx: encoded.dtx,
                                        payload: bytes::Bytes::from(encoded.payload),
                                    }).await;
                                }
                            }
                        }
                    }
                }
                _ = clip_tick.tick() => {
                    if let Ok(Some(item)) = clip_poller.poll_once() {
                        let bytes = item.text.into_bytes();
                        let cid = next_clip_id;
                        next_clip_id += 1;
                        let paused = host_sess.session().is_bulk_paused();
                        if let Ok(xfer) = prepare_outbound_clipboard(&effective_policy, CLIP_MIME_TEXT_UTF8, &bytes, cid, cid, paused) {
                            if let Ok(sync_bytes) = xfer.sync.encode() {
                                send_or_queue_clip_frame(host_sess.session_mut(), &mut pending_clip_frames, CLIP_MSG_SYNC, &sync_bytes).await;
                            }
                            for ch in &xfer.chunks {
                                if let Ok(enc) = ch.encode() {
                                    send_or_queue_clip_frame(host_sess.session_mut(), &mut pending_clip_frames, CLIP_MSG_CHUNK, &enc).await;
                                }
                            }
                        }
                    }
                }
                recv_res = host_sess.session_mut().recv_v124_event(Duration::from_millis(25)) => {
                    match recv_res {
                        Ok(ev) => {
                            last_peer_activity = Instant::now();
                            match ev {
                                V2RecvEvent::Transport(TransportEvent::Hid(frame)) => {
                                    if let Ok(payload) = decode_hid_frame(&frame) {
                                        let hid_res = match payload {
                                            HidPayload::Key(k) => Some(hid_sink.dispatch_key(&k)),
                                            HidPayload::Mouse(m) => Some(hid_sink.dispatch_mouse(&m)),
                                            HidPayload::EchoAck(_) => None,
                                        };
                                        match hid_res {
                                            Some(Ok(())) => {
                                                hid_denied_notified.store(false, Ordering::Release);
                                            }
                                            Some(Err(
                                                OsInputGateError::NotPermitted
                                                | OsInputGateError::Os(
                                                    OsError::NotPermitted
                                                    | OsError::PermissionDenied(_),
                                                ),
                                            )) => {
                                                if !hid_denied_notified.swap(true, Ordering::AcqRel)
                                                {
                                                    eprintln!(
                                                        "[hid-gate] host dropped remote HID event (not_permitted / input disabled)"
                                                    );
                                                    let wd_ax = adapters
                                                        .active_watchdog_ax_probe
                                                        .lock()
                                                        .unwrap_or_else(|e| e.into_inner())
                                                        .as_ref()
                                                        .map(|(_, f)| f.load(Ordering::Acquire));
                                                    let enabled = adapters
                                                        .enable_os_input
                                                        .load(Ordering::Acquire);
                                                    let rep = if let Some(p) =
                                                        &adapters.permission_probe
                                                    {
                                                        p.probe(wd_ax, enabled)
                                                    } else {
                                                        SystemPermissionProbe.probe(wd_ax, enabled)
                                                    };
                                                    let _ = actor_tx.try_send(
                                                        ActorMessage::InternalEvent {
                                                            session_gen: gen,
                                                            event:
                                                                ActorEvent::PermissionStatusChanged(
                                                                    rep,
                                                                ),
                                                        },
                                                    );
                                                }
                                            }
                                            Some(Err(e)) => {
                                                if !hid_denied_notified.swap(true, Ordering::AcqRel)
                                                {
                                                    eprintln!(
                                                        "[hid-gate] host remote HID dispatch error: {e}"
                                                    );
                                                }
                                            }
                                            None => {}
                                        }
                                    }
                                }
                                V2RecvEvent::Transport(TransportEvent::Control(ctrl)) => {
                                    if let Some(code) = parse_session_close(&ctrl) {
                                        break format!("peer_closed({code:#06x})");
                                    }
                                    if parse_request_idr(&ctrl).is_some() {
                                        host_sess.force_next_idr();
                                    }
                                    if let Some(req_codec) = parse_codec_switch_req(&ctrl) {
                                        let can_switch = (local_v2_cap_bits() & req_codec.cap_bit())
                                            != 0;
                                        let accepted_switch = if !can_switch {
                                            false
                                        } else if req_codec == host_sess.encoder_codec() {
                                            true
                                        } else {
                                            match V2VideoEncoder::new(
                                                req_codec,
                                                enc_w,
                                                enc_h,
                                                2.0,
                                                Some(cfg.fps as usize),
                                            ) {
                                                Ok(new_enc) => {
                                                    host_sess.replace_encoder(new_enc);
                                                    true
                                                }
                                                Err(e) => {
                                                    eprintln!(
                                                        "[codec-switch] host failed to switch to {}: {e}",
                                                        req_codec.name()
                                                    );
                                                    false
                                                }
                                            }
                                        };
                                        let active_c = host_sess.encoder_codec();
                                        let ack_body = [
                                            u8::from(accepted_switch),
                                            active_c.codec_id(),
                                        ];
                                        let _ = host_sess
                                            .session_mut()
                                            .send_control(CTRL_MSG_CODEC_SWITCH_ACK, &ack_body)
                                            .await;
                                        let _ = actor_tx.try_send(ActorMessage::InternalEvent {
                                            session_gen: gen,
                                            event: ActorEvent::CodecAck {
                                                active_codec: active_c.name().to_string(),
                                                requested_codec: Some(req_codec.name().to_string()),
                                                accepted: accepted_switch,
                                            },
                                        });
                                    }
                                }
                                V2RecvEvent::ClipboardRaw(raw) => {
                                    match clip_receiver.on_l4_frame(&raw.header, &raw.body, Instant::now(), &mut clip_err_counter) {
                                        ClipboardRecvAction::SendAck(ack) => {
                                            if let Ok(enc) = ack.encode() {
                                                let _ = host_sess.session_mut().send_l4_raw(CHAN_CLIPBOARD, CLIP_MSG_ACK, 0, false, &enc).await;
                                            }
                                        }
                                        ClipboardRecvAction::DeliverAndAck { delivered, ack } => {
                                            if let Ok(enc) = ack.encode() {
                                                let _ = host_sess.session_mut().send_l4_raw(CHAN_CLIPBOARD, CLIP_MSG_ACK, 0, false, &enc).await;
                                            }
                                            if delivered.mime_kind == CLIP_MIME_TEXT_UTF8 {
                                                if let Ok(s) = std::str::from_utf8(&delivered.payload) {
                                                    let _ = clip_poller.apply_remote_text(s);
                                                }
                                            }
                                            let _ = actor_tx.send(ActorMessage::InternalEvent {
                                                session_gen: gen,
                                                event: ActorEvent::ClipboardReceived {
                                                    mime_kind: delivered.mime_kind,
                                                    byte_count: delivered.payload.len(),
                                                    sha256_hex: hex::encode(delivered.sha256),
                                                },
                                            }).await;
                                        }
                                        ClipboardRecvAction::SessionFatal(reason) => {
                                            break format!("clipboard_fatal: {reason}");
                                        }
                                        ClipboardRecvAction::None => {}
                                    }
                                }
                                V2RecvEvent::FileTransferRaw(raw) => {
                                    if let Some(fatal) = route_inbound_file_l4(
                                        host_sess.session_mut(),
                                        &raw.header,
                                        &raw.body,
                                        &mut outbound_files,
                                        &mut file_receiver,
                                        &mut file_err_counter,
                                        gen,
                                        &actor_tx,
                                    )
                                    .await
                                    {
                                        break fatal;
                                    }
                                }
                                V2RecvEvent::Transport(_) | V2RecvEvent::AudioRaw(_) => {}
                            }
                        }
                        Err(v2_client::ClientError::Timeout(_)) => {}
                        Err(e) => {
                            break format!("transport_error: {e}");
                        }
                    }
                }
            }
        }
    };

    // Mandatory synchronous key release FIRST before any async network/channel teardown!
    let _ = releaser.release_all_keys();
    let _ = tokio::time::timeout(
        Duration::from_millis(500),
        outbound_files.abort_all_on_teardown(host_sess.session_mut(), gen, &actor_tx),
    )
    .await;
    let _ = send_redundant_session_close_3x(host_sess.session_mut(), 0).await;
    let _ = accepted.lease_renewal.shutdown().await;
    end_reason
}

#[allow(clippy::too_many_arguments)]
async fn run_controller_lifecycle_task(
    gen: u64,
    cmd_id: u64,
    cfg: V2ClientConfig,
    codec_auto: bool,
    target_device_id: [u8; 16],
    cancel: CancellationToken,
    actor_tx: mpsc::Sender<ActorMessage>,
    mailbox: Arc<FrameMailbox>,
    events: Arc<BridgeEventHub>,
    dropped_events: Arc<AtomicU64>,
    use_os_audio: bool,
    use_os_clipboard: bool,
    mem_clip: MemoryClipboardBackend,
    clipboard_sync_enabled: Arc<AtomicBool>,
    download_dir: PathBuf,
    #[cfg(feature = "e2e-fault-injection")] silent_blackhole: Option<Arc<AtomicBool>>,
) {
    let cb = Arc::new(BridgeUiCallback {
        session_gen: gen,
        actor_tx: actor_tx.clone(),
        events: Arc::clone(&events),
        dropped_events,
    });
    let dispatcher = UiCallbackDispatcher::spawn(cb);

    let mut client = match DesktopControllerClient::bootstrap(cfg.clone(), dispatcher).await {
        Ok(c) => c,
        Err(e) => {
            let _ = actor_tx
                .send(ActorMessage::InternalEvent {
                    session_gen: gen,
                    event: ActorEvent::DialFailed {
                        cmd_id,
                        error: e.to_string(),
                    },
                })
                .await;
            return;
        }
    };

    let mut connected = tokio::select! {
        _ = cancel.cancelled() => return,
        res = client.dial(target_device_id, None, Duration::from_secs(20)) => match res {
            Ok(c) => c,
            Err(e) => {
                let _ = actor_tx.send(ActorMessage::InternalEvent {
                    session_gen: gen,
                    event: ActorEvent::DialFailed { cmd_id, error: e.to_string() },
                }).await;
                return;
            }
        }
    };

    let (action_tx, mut action_rx) = mpsc::channel::<SessionAction>(SESSION_ACTION_CAP);
    let mut effective_policy = connected.effective_policy.clone();
    let poller_allow_clip = Arc::new(AtomicBool::new(
        effective_policy.allow_clipboard() && clipboard_sync_enabled.load(Ordering::Acquire),
    ));
    let mut audio_muted = false;

    // P0-1: Check StreamingStarted delivery — never start a headless zombie controller loop!
    if actor_tx
        .send(ActorMessage::InternalEvent {
            session_gen: gen,
            event: ActorEvent::StreamingStarted {
                cmd_id: Some(cmd_id),
                session_id: connected.session_id,
                local_cert: Box::new(connected.local_cert.clone()),
                peer_cert: Box::new(connected.peer_cert.clone()),
                policy: effective_policy.clone(),
                active_mode: connected.active_transport_mode,
                attach_ms: connected.transport_attach_ms,
                action_tx,
            },
        })
        .await
        .is_err()
    {
        let _ = connected
            .e2ee_session
            .send_control(CTRL_MSG_SESSION_CLOSE, &0u16.to_be_bytes())
            .await;
        let _ = connected.lease_renewal.shutdown().await;
        return;
    }

    let negotiated_codec = if codec_auto {
        negotiate_video_codec(local_v2_cap_bits(), connected.peer_cert.cap_bits, None)
            .unwrap_or(cfg.codec)
    } else {
        cfg.codec
    };
    let mut decoder = match V2VideoDecoder::new(negotiated_codec) {
        Ok(d) => d,
        Err(e) => {
            let _ = connected.lease_renewal.shutdown().await;
            let _ = actor_tx
                .send(ActorMessage::InternalEvent {
                    session_gen: gen,
                    event: ActorEvent::SessionEnded {
                        return_to_listening: false,
                        reason: format!("decoder init failed: {e}"),
                    },
                })
                .await;
            return;
        }
    };
    let mut ctrl_sess = connected.e2ee_session;

    let mut os_audio_out: Box<dyn OsAudioPlayback> = if use_os_audio {
        match open_os_audio_playback() {
            Ok(p) => p,
            Err(st) => {
                let _ = actor_tx
                    .send(ActorMessage::InternalEvent {
                        session_gen: gen,
                        event: ActorEvent::AudioStatus(st),
                    })
                    .await;
                Box::new(SilentAudioPlayback::default())
            }
        }
    } else {
        Box::new(SilentAudioPlayback::default())
    };
    let mut audio_dec = V2AudioDecoder::new(2).ok();
    let mut audio_jitter = AudioJitterBuffer::new(AUDIO_JITTER_MIN_FRAMES, AUDIO_JITTER_MAX_FRAMES);
    let mut audio_frames_decoded: u64 = 0;
    let mut audio_dtx_frames: u64 = 0;

    let clip_backend: Box<dyn crate::os::OsClipboardBackend> = if use_os_clipboard {
        create_os_clipboard_backend().unwrap_or_else(|_| Box::new(mem_clip.clone()))
    } else {
        Box::new(mem_clip.clone())
    };
    let mut clip_poller = ClipboardPoller::new(clip_backend, poller_allow_clip);
    let mut clip_receiver = ClipboardReceiver::new(effective_policy.clone());
    let mut clip_err_counter = ChannelFramingErrorCounter::new();
    let mut next_clip_id: u64 = 1;

    let _ = std::fs::create_dir_all(&download_dir);
    let mut file_receiver = FileTransferReceiver::new(effective_policy.clone(), download_dir);
    let mut file_err_counter = ChannelFramingErrorCounter::new();
    let mut outbound_files = OutboundFileManager::new();
    let mut pending_clip_frames = PendingClipQueue::new();
    let mut next_transfer_id: u64 = 1;

    let (pol_tx, mut pol_rx) =
        mpsc::channel::<(u64, Result<(EffectiveTenantPolicy, bool), String>)>(4);

    let mut ka_tick = tokio::time::interval(connected.keepalive_interval);
    ka_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut clip_tick = tokio::time::interval(Duration::from_millis(100));
    clip_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut qoe_tick = tokio::time::interval(Duration::from_millis(500));
    qoe_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut hud_tick = tokio::time::interval(Duration::from_secs(1));
    hud_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut file_tick = tokio::time::interval(Duration::from_millis(2));
    file_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut lease_expired_rx = connected.lease_renewal.subscribe_expired();
    let mut video_frames_decoded: u64 = 0;
    let mut hud_window_frames: u32 = 0;
    let mut hud_window_bytes: u64 = 0;
    let mut hud_window_started = Instant::now();
    let mut hud_decode_ms_sum: f64 = 0.0;
    let mut hud_decode_ms_count: u32 = 0;
    let mut hud_rtt_ms_sum: f64 = 0.0;
    let mut hud_rtt_ms_count: u32 = 0;
    let mut last_rtt_ms: f64 = 0.0;
    let mut last_idr_req_at: Option<Instant> = None;
    let mut pending_codec_req: Option<(String, Instant)> = None;
    let mut hid_state = ControllerHidState::default();

    // Emit initial negotiated active codec ack so UI reflects peer-acknowledged codec.
    let _ = actor_tx
        .send(ActorMessage::InternalEvent {
            session_gen: gen,
            event: ActorEvent::CodecAck {
                active_codec: decoder.codec().name().to_string(),
                requested_codec: None,
                accepted: true,
            },
        })
        .await;

    let is_blackholed = || -> bool {
        #[cfg(feature = "e2e-fault-injection")]
        {
            silent_blackhole
                .as_ref()
                .is_some_and(|f| f.load(Ordering::Acquire))
        }
        #[cfg(not(feature = "e2e-fault-injection"))]
        {
            false
        }
    };

    // P0-2: Check pre-latched lease expiry BEFORE entering the select loop!
    let end_reason: String = if lease_expired_rx.borrow().is_some() {
        "lease_expired".into()
    } else {
        loop {
            let arq_deadline = if is_blackholed() {
                None
            } else {
                ctrl_sess.next_arq_deadline()
            };
            tokio::select! {
                _ = async {
                    match arq_deadline {
                        Some(dl) => tokio::time::sleep_until(dl).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    if !is_blackholed() {
                        if let Err(e) = ctrl_sess.poll_arq().await {
                            break format!("transport_error: {e}");
                        }
                    }
                }
                _ = cancel.cancelled() => {
                    break "local_cancel".into();
                }
                // P0-2: Treat both Err(_) (sender dropped) and Some(_) as fail-closed lease_expired!
                res = lease_expired_rx.changed() => {
                    if res.is_err() || lease_expired_rx.borrow().is_some() {
                        break "lease_expired".into();
                    }
                }
                _ = ka_tick.tick() => {
                    if !is_blackholed() {
                        let ping_started = Instant::now();
                        if ctrl_sess.ping_keepalive(Duration::from_millis(500)).await.is_ok() {
                            let rtt = ping_started.elapsed().as_secs_f64() * 1000.0;
                            if rtt.is_finite() && rtt >= 0.0 {
                                last_rtt_ms = rtt;
                                hud_rtt_ms_sum += rtt;
                                hud_rtt_ms_count = hud_rtt_ms_count.saturating_add(1);
                            }
                        } else {
                            // Reset stale RTT on keepalive ping failure.
                            last_rtt_ms = 0.0;
                            hud_rtt_ms_sum = 0.0;
                            hud_rtt_ms_count = 0;
                        }
                    }
                }
                _ = hud_tick.tick() => {
                    // Enforce 3s timeout for any pending live codec switch request.
                    if let Some((ref req, started)) = pending_codec_req {
                        if started.elapsed() >= Duration::from_secs(3) {
                            let req_owned = req.clone();
                            pending_codec_req = None;
                            let _ = actor_tx.try_send(ActorMessage::InternalEvent {
                                session_gen: gen,
                                event: ActorEvent::CodecAck {
                                    active_codec: decoder.codec().name().to_string(),
                                    requested_codec: Some(req_owned),
                                    accepted: false,
                                },
                            });
                        }
                    }
                    let elapsed_secs = hud_window_started.elapsed().as_secs_f64().max(0.001);
                    let sanitize_f64 = |v: f64| if v.is_finite() && v >= 0.0 { v } else { 0.0 };
                    let fps = sanitize_f64(f64::from(hud_window_frames) / elapsed_secs);
                    let mean_decode_ms = if hud_decode_ms_count > 0 {
                        sanitize_f64(hud_decode_ms_sum / f64::from(hud_decode_ms_count))
                    } else {
                        0.0
                    };
                    let mean_rtt_ms = if hud_rtt_ms_count > 0 {
                        sanitize_f64(hud_rtt_ms_sum / f64::from(hud_rtt_ms_count))
                    } else {
                        sanitize_f64(last_rtt_ms)
                    };
                    let bitrate_kbps = sanitize_f64(
                        (hud_window_bytes as f64 * 8.0) / (elapsed_secs * 1000.0),
                    )
                    .round()
                    .clamp(0.0, u32::MAX as f64) as u32;
                    hud_window_frames = 0;
                    hud_window_bytes = 0;
                    hud_decode_ms_sum = 0.0;
                    hud_decode_ms_count = 0;
                    hud_rtt_ms_sum = 0.0;
                    hud_rtt_ms_count = 0;
                    hud_window_started = Instant::now();
                    let transport_mode = match ctrl_sess.active_transport_mode() {
                        ActiveTransportMode::DualTls443 => "tls443",
                        ActiveTransportMode::Udp => "udp",
                    };
                    let hud = HudStatsPayload {
                        fps: (fps * 10.0).round() / 10.0,
                        decode_ms: (mean_decode_ms * 100.0).round() / 100.0,
                        active_codec: decoder.codec().name().to_string(),
                        transport_mode: transport_mode.to_string(),
                        rtt_ms: (mean_rtt_ms * 10.0).round() / 10.0,
                        bitrate_kbps,
                    }
                    .sanitized();
                    if let Ok(val) = serde_json::to_value(&hud) {
                        events.set_hud_stats(val);
                    }
                }
                _ = qoe_tick.tick() => {
                    // Direct single-slot overwrite telemetry (never enters actor control channel).
                    events.set_telemetry("QoeTelemetry", serde_json::json!({
                        "video_frames_decoded": video_frames_decoded,
                        "dropped_ui_frames": mailbox.dropped_ui_frames(),
                        "audio_frames_decoded": audio_frames_decoded,
                        "audio_dtx_frames": audio_dtx_frames,
                        "active_transport_mode": ctrl_sess.active_transport_mode().label(),
                        "active_codec": decoder.codec().name(),
                    }));
                }
                _ = clip_tick.tick() => {
                    if !is_blackholed() {
                        if let Ok(Some(item)) = clip_poller.poll_once() {
                            let bytes = item.text.into_bytes();
                            let cid = next_clip_id;
                            next_clip_id += 1;
                            let paused = ctrl_sess.is_bulk_paused();
                            if let Ok(xfer) = prepare_outbound_clipboard(&effective_policy, CLIP_MIME_TEXT_UTF8, &bytes, cid, cid, paused) {
                                if let Ok(sync_bytes) = xfer.sync.encode() {
                                    send_or_queue_clip_frame(&mut ctrl_sess, &mut pending_clip_frames, CLIP_MSG_SYNC, &sync_bytes).await;
                                }
                                for ch in &xfer.chunks {
                                    if let Ok(enc) = ch.encode() {
                                        send_or_queue_clip_frame(&mut ctrl_sess, &mut pending_clip_frames, CLIP_MSG_CHUNK, &enc).await;
                                    }
                                }
                            }
                        }
                    }
                }
                Some((cmd_id, res)) = pol_rx.recv() => {
                    match res {
                        Ok((new_pol, is_degraded)) => {
                            let now = now_unix_secs();
                            match should_accept_policy_update(Some(&effective_policy), &new_pol, now) {
                                Ok(()) => {
                                    effective_policy = new_pol.clone();
                                    let clip_ok = effective_policy.allow_clipboard()
                                        && clipboard_sync_enabled.load(Ordering::Acquire);
                                    clip_poller.set_policy_allowed(clip_ok);
                                    clip_receiver.update_policy(effective_policy.clone());
                                    file_receiver.update_policy(effective_policy.clone());
                                    let _ = actor_tx.send(ActorMessage::InternalEvent {
                                        session_gen: gen,
                                        event: ActorEvent::PolicyUpdated {
                                            cmd_id: Some(cmd_id),
                                            policy: new_pol,
                                            is_degraded,
                                        },
                                    }).await;
                                }
                                Err(reason) => {
                                    let _ = actor_tx.send(ActorMessage::InternalEvent {
                                        session_gen: gen,
                                        event: ActorEvent::SecurityEvent(SecurityEvent::PolicyDegraded {
                                            reason: reason.clone(),
                                        }),
                                    }).await;
                                    let _ = actor_tx.send(ActorMessage::InternalEvent {
                                        session_gen: gen,
                                        event: ActorEvent::CommandResult {
                                            cmd_id,
                                            ok: false,
                                            data: None,
                                            error_code: Some("PolicyUpdateRejected".into()),
                                            error: Some(reason),
                                        },
                                    }).await;
                                }
                            }
                        }
                        Err(e) => {
                            let _ = actor_tx.send(ActorMessage::InternalEvent {
                                session_gen: gen,
                                event: ActorEvent::CommandResult {
                                    cmd_id,
                                    ok: false,
                                    data: None,
                                    error_code: Some("PolicyRefreshFailed".into()),
                                    error: Some(e),
                                },
                            }).await;
                        }
                    }
                }
                // P0-1: Break immediately when action_rx closes (None)!
                act = action_rx.recv() => {
                    let Some(action) = act else {
                        break "action_channel_closed".into();
                    };
                    match action {
                        SessionAction::SetAudioMute(m) => { audio_muted = m; }
                        SessionAction::SetClipboardSync(enabled) => {
                            clipboard_sync_enabled.store(enabled, Ordering::Release);
                            clip_poller
                                .set_policy_allowed(enabled && effective_policy.allow_clipboard());
                        }
                        SessionAction::SetVideoQuality {
                            bitrate_kbps,
                            fps_cap,
                        } => {
                            let clamped_fps = fps_cap.clamp(1, cfg.fps.clamp(1, 120));
                            eprintln!(
                                "[video-quality] controller recorded target bitrate_kbps={bitrate_kbps} fps_cap={clamped_fps} (applied on host encoder)"
                            );
                        }
                        SessionAction::RequestCodec(requested_raw) => {
                            let requested = normalize_codec_setting(&requested_raw)
                                .unwrap_or(requested_raw);
                            let current = decoder.codec().name().to_string();
                            let target_codec = if requested == "auto" {
                                negotiate_video_codec(
                                    local_v2_cap_bits(),
                                    connected.peer_cert.cap_bits,
                                    None,
                                )
                                .ok()
                            } else {
                                VideoCodec::parse_name(&requested).ok()
                            };
                            if target_codec == Some(decoder.codec()) {
                                pending_codec_req = None;
                                let _ = actor_tx.try_send(ActorMessage::InternalEvent {
                                    session_gen: gen,
                                    event: ActorEvent::CodecAck {
                                        active_codec: current,
                                        requested_codec: Some(requested),
                                        accepted: true,
                                    },
                                });
                            } else if let Some(target) = target_codec {
                                let common_caps =
                                    local_v2_cap_bits() & connected.peer_cert.cap_bits;
                                let supported = (common_caps & target.cap_bit()) != 0;
                                if supported
                                    && !is_blackholed()
                                    && ctrl_sess
                                        .send_control(
                                            CTRL_MSG_CODEC_SWITCH_REQ,
                                            &[target.codec_id()],
                                        )
                                        .await
                                        .is_ok()
                                {
                                    pending_codec_req = Some((requested, Instant::now()));
                                } else {
                                    pending_codec_req = None;
                                    let _ = actor_tx.try_send(ActorMessage::InternalEvent {
                                        session_gen: gen,
                                        event: ActorEvent::CodecAck {
                                            active_codec: current,
                                            requested_codec: Some(requested),
                                            accepted: false,
                                        },
                                    });
                                }
                            } else {
                                pending_codec_req = None;
                                let _ = actor_tx.try_send(ActorMessage::InternalEvent {
                                    session_gen: gen,
                                    event: ActorEvent::CodecAck {
                                        active_codec: current,
                                        requested_codec: Some(requested),
                                        accepted: false,
                                    },
                                });
                            }
                        }
                        SessionAction::SendHid(payload) => {
                            hid_state.record_outbound(&payload);
                            if !is_blackholed() {
                                if let Ok(frame) = encode_hid_frame(&payload) {
                                    let _ = ctrl_sess.send_hid(&frame).await;
                                }
                            }
                        }
                        SessionAction::ReleaseAll { keys, buttons, ack } => {
                            let (payloads, released_keys, released_buttons) =
                                hid_state.take_release_all_payloads(&keys, buttons, now_epoch_ms());
                            if !is_blackholed() {
                                let _ = tokio::time::timeout(RELEASE_ALL_FLUSH_TIMEOUT, async {
                                    for payload in &payloads {
                                        if let Ok(frame) = encode_hid_frame(payload) {
                                            let _ = ctrl_sess.send_hid(&frame).await;
                                        }
                                    }
                                })
                                .await;
                            }
                            if let Some(tx) = ack {
                                let _ = tx.send((released_keys, released_buttons));
                            }
                        }
                        SessionAction::SendClipboard { mime_kind, bytes } => {
                            if !is_blackholed()
                                && clipboard_sync_enabled.load(Ordering::Acquire)
                                && effective_policy.allow_clipboard()
                            {
                                let cid = next_clip_id;
                                next_clip_id += 1;
                                let paused = ctrl_sess.is_bulk_paused();
                                if let Ok(xfer) = prepare_outbound_clipboard(&effective_policy, mime_kind, &bytes, cid, cid, paused) {
                                    if let Ok(sync_bytes) = xfer.sync.encode() {
                                        send_or_queue_clip_frame(&mut ctrl_sess, &mut pending_clip_frames, CLIP_MSG_SYNC, &sync_bytes).await;
                                    }
                                    for ch in &xfer.chunks {
                                        if let Ok(enc) = ch.encode() {
                                            send_or_queue_clip_frame(&mut ctrl_sess, &mut pending_clip_frames, CLIP_MSG_CHUNK, &enc).await;
                                        }
                                    }
                                }
                            }
                        }
                        SessionAction::SendFile { cmd_id, path, rel_name } => {
                            let tid = next_transfer_id;
                            next_transfer_id += 1;
                            outbound_files.start_transfer(
                                &mut ctrl_sess,
                                tid,
                                cmd_id,
                                path,
                                rel_name,
                                &effective_policy,
                                gen,
                                &actor_tx,
                            ).await;
                        }
                        SessionAction::CancelFile { transfer_id } => {
                            outbound_files.cancel_transfer(&mut ctrl_sess, transfer_id, gen, &actor_tx).await;
                        }
                        SessionAction::RefreshPolicy { cmd_id } => {
                            let cfg_c = cfg.clone();
                            let cancel_c = cancel.clone();
                            let pol_tx_c = pol_tx.clone();
                            tokio::spawn(async move {
                                let res = refresh_policy_from_cp(&cfg_c, &cancel_c).await;
                                let _ = pol_tx_c.send((cmd_id, res)).await;
                            });
                        }
                    }
                }
                _ = file_tick.tick(), if outbound_files.has_active() || !pending_clip_frames.is_empty() => {
                    if !is_blackholed() && !pending_clip_frames.is_empty() {
                        drain_pending_clip_frames(&mut ctrl_sess, &mut pending_clip_frames).await;
                    }
                    if outbound_files.has_active() {
                        outbound_files
                            .pump_one_step(&mut ctrl_sess, &effective_policy, gen, &actor_tx)
                            .await;
                    }
                }
                recv_res = ctrl_sess.recv_v124_event(Duration::from_millis(25)) => {
                    match recv_res {
                        Ok(V2RecvEvent::Transport(TransportEvent::VideoFrame(vf))) => {
                            hud_window_bytes = hud_window_bytes.saturating_add(vf.data.len() as u64);
                            let decode_started = Instant::now();
                            match decoder.decode_raw_frame(&vf.data) {
                                Ok(DecodedVideoFrame::Bgra(bgra)) => {
                                    let d_ms = decode_started.elapsed().as_secs_f64() * 1000.0;
                                    if d_ms.is_finite() && d_ms >= 0.0 {
                                        hud_decode_ms_sum += d_ms;
                                        hud_decode_ms_count = hud_decode_ms_count.saturating_add(1);
                                    }
                                    hud_window_frames = hud_window_frames.saturating_add(1);
                                    video_frames_decoded += 1;
                                    if mailbox
                                        .publish_raw_for_session(
                                            gen,
                                            bgra.width as u32,
                                            bgra.height as u32,
                                            bgra.stride as u32,
                                            PixelFormat::Bgra8,
                                            now_epoch_ms(),
                                            bgra.data,
                                        )
                                        .is_ok()
                                    {
                                        events.notify_frame_published();
                                    }
                                }
                                Ok(DecodedVideoFrame::I420(i420)) => {
                                    let d_ms = decode_started.elapsed().as_secs_f64() * 1000.0;
                                    if d_ms.is_finite() && d_ms >= 0.0 {
                                        hud_decode_ms_sum += d_ms;
                                        hud_decode_ms_count = hud_decode_ms_count.saturating_add(1);
                                    }
                                    hud_window_frames = hud_window_frames.saturating_add(1);
                                    video_frames_decoded += 1;
                                    if mailbox
                                        .publish_i420_for_session(
                                            gen,
                                            &i420,
                                            PixelFormat::Bgra8,
                                            now_epoch_ms(),
                                        )
                                        .is_ok()
                                    {
                                        events.notify_frame_published();
                                    }
                                }
                                Err(VideoError::NeedIdr(_)) => {
                                    if !is_blackholed()
                                        && last_idr_req_at.is_none_or(|t| {
                                            t.elapsed() >= Duration::from_millis(IDR_MIN_INTERVAL_MS)
                                        })
                                        && ctrl_sess
                                            .send_control(
                                                CTRL_MSG_REQUEST_IDR,
                                                &vf.frame_id.to_be_bytes(),
                                            )
                                            .await
                                            .is_ok()
                                    {
                                        last_idr_req_at = Some(Instant::now());
                                    }
                                }
                                Err(
                                    e @ (VideoError::CodecFailed { .. }
                                    | VideoError::HardwareUnavailable(_)),
                                ) => {
                                    break format!("video_codec_failed: {e}");
                                }
                                Err(_) => {}
                            }
                        }
                        Ok(V2RecvEvent::AudioRaw(raw)) => {
                            if !audio_muted && effective_policy.allow_audio() {
                                if let Ok(wire) = OpusWireFrame::decode(&raw.body) {
                                    if wire.dtx {
                                        audio_dtx_frames += 1;
                                    }
                                    let _ = audio_jitter.push(wire);
                                    if let Some(dec) = audio_dec.as_mut() {
                                        let action = audio_jitter.pop_playout();
                                        if let Ok(pcm) = dec.execute_playout(action) {
                                            audio_frames_decoded += 1;
                                            let _ = os_audio_out.write_frame(&pcm);
                                        }
                                    }
                                }
                            }
                        }
                        Ok(V2RecvEvent::ClipboardRaw(raw)) => {
                            if let Ok(ClipMessage::Ack(ack)) = decode_clipboard_l4(&raw.header, &raw.body) {
                                if ack.status != CLIP_ACK_OK {
                                    let _ = actor_tx.send(ActorMessage::InternalEvent {
                                        session_gen: gen,
                                        event: ActorEvent::SecurityEvent(SecurityEvent::PolicyDegraded {
                                            reason: format!("remote clipboard ack status={}", ack.status),
                                        }),
                                    }).await;
                                }
                            } else {
                                match clip_receiver.on_l4_frame(&raw.header, &raw.body, Instant::now(), &mut clip_err_counter) {
                                    ClipboardRecvAction::SendAck(ack) => {
                                        if let Ok(enc) = ack.encode() {
                                            let _ = ctrl_sess.send_l4_raw(CHAN_CLIPBOARD, CLIP_MSG_ACK, 0, false, &enc).await;
                                        }
                                    }
                                    ClipboardRecvAction::DeliverAndAck { delivered, ack } => {
                                        if let Ok(enc) = ack.encode() {
                                            let _ = ctrl_sess.send_l4_raw(CHAN_CLIPBOARD, CLIP_MSG_ACK, 0, false, &enc).await;
                                        }
                                        if delivered.mime_kind == CLIP_MIME_TEXT_UTF8 {
                                            if let Ok(s) = std::str::from_utf8(&delivered.payload) {
                                                let _ = clip_poller.apply_remote_text(s);
                                            }
                                        }
                                        let _ = actor_tx.send(ActorMessage::InternalEvent {
                                            session_gen: gen,
                                            event: ActorEvent::ClipboardReceived {
                                                mime_kind: delivered.mime_kind,
                                                byte_count: delivered.payload.len(),
                                                sha256_hex: hex::encode(delivered.sha256),
                                            },
                                        }).await;
                                    }
                                    ClipboardRecvAction::SessionFatal(reason) => {
                                        break format!("clipboard_fatal: {reason}");
                                    }
                                    ClipboardRecvAction::None => {}
                                }
                            }
                        }
                        Ok(V2RecvEvent::FileTransferRaw(raw)) => {
                            if let Some(fatal) = route_inbound_file_l4(
                                &mut ctrl_sess,
                                &raw.header,
                                &raw.body,
                                &mut outbound_files,
                                &mut file_receiver,
                                &mut file_err_counter,
                                gen,
                                &actor_tx,
                            )
                            .await
                            {
                                break fatal;
                            }
                        }
                        Ok(V2RecvEvent::Transport(TransportEvent::Control(ctrl))) => {
                            if let Some(code) = parse_session_close(&ctrl) {
                                break format!("peer_closed({code:#06x})");
                            }
                            if let Some((mut peer_accepted, peer_codec)) =
                                parse_codec_switch_ack(&ctrl)
                            {
                                let req = pending_codec_req.take().map(|(r, _)| r);
                                if peer_accepted && peer_codec != decoder.codec() {
                                    match V2VideoDecoder::new(peer_codec) {
                                        Ok(new_dec) => {
                                            decoder = new_dec;
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "[codec-switch] controller decoder rebuild for {} failed: {e}",
                                                peer_codec.name()
                                            );
                                            peer_accepted = false;
                                        }
                                    }
                                }
                                let _ = actor_tx
                                    .send(ActorMessage::InternalEvent {
                                        session_gen: gen,
                                        event: ActorEvent::CodecAck {
                                            active_codec: decoder.codec().name().to_string(),
                                            requested_codec: req,
                                            accepted: peer_accepted,
                                        },
                                    })
                                    .await;
                            }
                        }
                        Ok(V2RecvEvent::Transport(_)) => {}
                        Err(v2_client::ClientError::Timeout(_)) => {}
                        Err(e) => {
                            break format!("transport_error: {e}");
                        }
                    }
                }
            }
        }
    };

    // Flush any remaining held controller HID keys/buttons BEFORE data-plane teardown!
    if !is_blackholed() && hid_state.has_pressed() {
        let (payloads, _, _) = hid_state.take_release_all_payloads(&[], 0, now_epoch_ms());
        let _ = tokio::time::timeout(RELEASE_ALL_FLUSH_TIMEOUT, async {
            for payload in &payloads {
                if let Ok(frame) = encode_hid_frame(payload) {
                    let _ = ctrl_sess.send_hid(&frame).await;
                }
            }
        })
        .await;
    }
    let _ = tokio::time::timeout(
        Duration::from_millis(500),
        outbound_files.abort_all_on_teardown(&mut ctrl_sess, gen, &actor_tx),
    )
    .await;
    if !is_blackholed() {
        let _ = ctrl_sess
            .send_control(CTRL_MSG_SESSION_CLOSE, &0u16.to_be_bytes())
            .await;
    }
    let _ = connected.lease_renewal.shutdown().await;
    let _ = actor_tx
        .send(ActorMessage::InternalEvent {
            session_gen: gen,
            event: ActorEvent::SessionEnded {
                return_to_listening: false,
                reason: end_reason,
            },
        })
        .await;
}

async fn emit_file_cmd_result(
    gen: u64,
    cmd_id: u64,
    actor_tx: &mpsc::Sender<ActorMessage>,
    res: Result<serde_json::Value, (String, String)>,
) {
    let event = match res {
        Ok(data) => ActorEvent::CommandResult {
            cmd_id,
            ok: true,
            data: Some(data),
            error_code: None,
            error: None,
        },
        Err((code, msg)) => ActorEvent::CommandResult {
            cmd_id,
            ok: false,
            data: None,
            error_code: Some(code),
            error: Some(msg),
        },
    };
    let _ = actor_tx
        .send(ActorMessage::InternalEvent {
            session_gen: gen,
            event,
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bridge::json_abi::scan_json_for_secret_canaries, session::DEFAULT_V2_CAP_BITS};

    fn sample_cert() -> SignalingDeviceCert {
        SignalingDeviceCert {
            version: 1,
            cert_id: [0x11; 16],
            device_id: [0x22; 16],
            tenant_id: [0x33; 16],
            p256_pub_der: vec![0x30, 0x59],
            key_epoch: 1,
            policy_hash: [0x44; 32],
            cap_bits: DEFAULT_V2_CAP_BITS,
            iat_unix: 100,
            exp_unix: u64::MAX,
            ca_key_id: 1,
            ca_sig: vec![0x30, 0x06],
        }
    }

    #[tokio::test]
    async fn runtime_can_be_created_and_destroyed_safely_inside_outer_tokio_runtime() {
        let rt = V2BridgeRuntime::new().unwrap();
        let snap: serde_json::Value = serde_json::from_str(&rt.snapshot_json()).unwrap();
        assert_eq!(snap["v"], 1);
        assert_eq!(snap["state"], "idle");

        // Idempotent stop_host when not running -> already_stopped: true
        let stop_reply: serde_json::Value =
            serde_json::from_str(&rt.exec_json(r#"{"v":1,"cmd":"stop_host"}"#)).unwrap();
        assert_eq!(stop_reply["ok"], true);
        assert_eq!(stop_reply["already_stopped"], true);

        // Dial when not ready -> Busy
        let dial_reply: serde_json::Value = serde_json::from_str(
            &rt.exec_json(
                r#"{"v":1,"cmd":"dial","target_device_id_hex":"0102030405060708090a0b0c0d0e0f10"}"#,
            ),
        )
        .unwrap();
        assert_eq!(dial_reply["ok"], false);
        assert_eq!(dial_reply["error_code"], "Busy");

        // Destroy inside #[tokio::test] MUST NOT panic or deadlock; double-destroy is idempotent.
        rt.destroy();
        rt.destroy();
        assert_eq!(rt.active_task_count(), 0);
    }

    #[test]
    fn runtime_concurrent_destroy_and_exec_json_race_is_safe() {
        let rt = Arc::new(V2BridgeRuntime::new().unwrap());
        let rt_d1 = Arc::clone(&rt);
        let rt_d2 = Arc::clone(&rt);
        let rt_cmd = Arc::clone(&rt);

        let h1 = thread::spawn(move || rt_d1.destroy());
        let h2 = thread::spawn(move || rt_d2.destroy());
        let h3 = thread::spawn(move || {
            for _ in 0..20 {
                let _ = rt_cmd.exec_json(r#"{"v":1,"cmd":"stop_host"}"#);
            }
        });
        h1.join().unwrap();
        h2.join().unwrap();
        h3.join().unwrap();

        // Subsequent exec_json MUST fail closed with Destroyed.
        let reply: serde_json::Value =
            serde_json::from_str(&rt.exec_json(r#"{"v":1,"cmd":"stop_host"}"#)).unwrap();
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error_code"], "Destroyed");
        assert_eq!(rt.active_task_count(), 0);
    }

    #[test]
    fn runtime_incoming_stale_id_rejected_and_stale_gen_audits_security_and_cmd_results() {
        let rt = V2BridgeRuntime::new().unwrap();
        let (inc_id, dec_rx) = rt.inject_test_incoming([0xAA; 16], sample_cert());

        // Mismatched incoming_id -> StaleIncoming
        let bad: serde_json::Value = serde_json::from_str(&rt.exec_json(
            r#"{"v":1,"cmd":"accept_incoming","incoming_id":"inc-wrong-999"}"#,
        ))
        .unwrap();
        assert_eq!(bad["ok"], false);
        assert_eq!(bad["error_code"], "StaleIncoming");

        // Stale session_gen event without cmd_id is dropped; with cmd_id emits StaleGeneration!
        rt.simulate_stale_event(0, None);
        rt.simulate_stale_event(0, Some(777));
        // Stale SecurityEvent is NEVER dropped and uses structured redacted fields!
        rt.simulate_stale_security_event(0);

        let mut saw_stale_cmd_err = false;
        let mut saw_stale_sec = false;
        while let Some(raw) = rt.poll_event_json() {
            let ev: serde_json::Value = serde_json::from_str(&raw).unwrap();
            if ev["kind"] == "CommandResult"
                && ev["payload"]["cmd_id"] == 777
                && ev["payload"]["error_code"] == "StaleGeneration"
            {
                saw_stale_cmd_err = true;
            }
            if ev["kind"] == "SecurityEvent"
                && ev["payload"]["stale_generation"] == true
                && ev["payload"]["detail"]["event"] == "ReplaySessionRejected"
            {
                // Negative redaction assertion: structured JSON (no raw Debug enum/key dumps)
                assert!(!raw.contains("ReplaySessionRejected {"));
                assert!(!raw.contains("BEGIN PRIVATE KEY"));
                assert!(!raw.contains("residual_keys"));
                saw_stale_sec = true;
            }
        }
        assert!(saw_stale_cmd_err, "stale cmd_id must emit StaleGeneration");
        assert!(saw_stale_sec, "stale SecurityEvent must never be dropped");

        // Valid incoming_id succeeds and delivers CallDecision::Accept
        let ok: serde_json::Value = serde_json::from_str(&rt.exec_json(&format!(
            r#"{{"v":1,"cmd":"accept_incoming","incoming_id":"{inc_id}"}}"#
        )))
        .unwrap();
        assert_eq!(ok["ok"], true);
        assert_eq!(dec_rx.blocking_recv().unwrap(), CallDecision::Accept);

        // Second accept on same incoming_id -> StaleIncoming
        let second: serde_json::Value = serde_json::from_str(&rt.exec_json(&format!(
            r#"{{"v":1,"cmd":"accept_incoming","incoming_id":"{inc_id}"}}"#
        )))
        .unwrap();
        assert_eq!(second["ok"], false);
        assert_eq!(second["error_code"], "StaleIncoming");

        // Verify dropping pending incoming on destroy triggers RecvError or explicit Reject
        let (_inc2, dec_rx2) = rt.inject_test_incoming([0xBB; 16], sample_cert());
        rt.destroy();
        assert!(matches!(
            dec_rx2.blocking_recv(),
            Err(_) | Ok(CallDecision::Reject { .. })
        ));
    }

    #[test]
    fn policy_refresh_refuses_downgrade_or_degraded_overwrite_of_unexpired_valid_policy() {
        let valid_v2 = EffectiveTenantPolicy {
            version: 2,
            exp_unix: 10_000,
            degraded: false,
            degraded_reason: None,
            ..EffectiveTenantPolicy::degraded([1u8; 16], [0u8; 32], "base")
        };
        let degraded = EffectiveTenantPolicy::degraded([1u8; 16], [0u8; 32], "cp down");
        assert!(should_accept_policy_update(Some(&valid_v2), &degraded, 5_000).is_err());

        // Higher version (v3) with degraded=true MUST STILL be rejected over unexpired valid v2!
        let degraded_v3 = EffectiveTenantPolicy {
            version: 3,
            exp_unix: 20_000,
            degraded: true,
            degraded_reason: Some("partial_verify".into()),
            ..valid_v2.clone()
        };
        assert!(should_accept_policy_update(Some(&valid_v2), &degraded_v3, 5_000).is_err());

        let valid_v1 = EffectiveTenantPolicy {
            version: 1,
            exp_unix: 10_000,
            degraded: false,
            degraded_reason: None,
            ..valid_v2.clone()
        };
        assert!(should_accept_policy_update(Some(&valid_v2), &valid_v1, 5_000).is_err());

        let valid_v3 = EffectiveTenantPolicy {
            version: 3,
            exp_unix: 12_000,
            degraded: false,
            degraded_reason: None,
            ..valid_v2.clone()
        };
        assert!(should_accept_policy_update(Some(&valid_v2), &valid_v3, 5_000).is_ok());
    }

    #[test]
    fn runtime_redaction_property_never_leaks_canary_secrets() {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("zd-rt-redact-{}-{uniq}", std::process::id()));
        let cfg_path = dir.join("cfg.json");

        let canary_token = "CANARY_ENROLLMENT_TOKEN_9f8e7d6c";
        let canary_privkey = "CANARY_PRIVATE_KEY_deadbeef";
        let rt = V2BridgeRuntime::new().unwrap();

        let save_cmd = serde_json::json!({
            "v": 1,
            "cmd": "save_config",
            "path": cfg_path.display().to_string(),
            "config": {
                "v": 1,
                "control_plane_endpoint": "http://127.0.0.1:8080",
                "signaling_addr": "127.0.0.1:9001",
                "enrollment_token": canary_token,
                "identity_dir": dir.join("id").display().to_string(),
                "transport_mode": "auto"
            }
        });
        let save_reply = rt.exec_json(&save_cmd.to_string());
        let snap = rt.snapshot_json();
        let canaries = [canary_token, canary_privkey];
        assert!(scan_json_for_secret_canaries(&save_reply, &canaries).is_ok());
        assert!(scan_json_for_secret_canaries(&snap, &canaries).is_ok());
        while let Some(ev) = rt.poll_event_json() {
            assert!(scan_json_for_secret_canaries(&ev, &canaries).is_ok());
        }
        rt.destroy();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn task_panic_triggers_emergency_key_release_and_clears_releaser_slot() {
        let journal = DryRunHidJournal::new();
        let mut sink = DryRunHidSink::with_journal(journal.clone());
        let releaser = sink.emergency_releaser();
        let slot: Arc<Mutex<Option<Arc<dyn EmergencyKeyReleaser>>>> = Arc::new(Mutex::new(None));
        sink.send_key(&KeyEvent {
            down: true,
            modifiers: 0,
            usb_hid_usage: 0x04,
            unicode_scalar: 0,
            client_ts_ms: 1,
        })
        .unwrap();
        assert_eq!(journal.pressed_keys(), vec![0x04]);

        let start = Instant::now();
        let slot_bg = Arc::clone(&slot);
        let handle = thread::spawn(move || {
            let _ = catch_unwind(AssertUnwindSafe(|| {
                let _guard = ReleaserDropGuard::arm(releaser, slot_bg);
                panic!("simulated worker panic while key held");
            }));
        });
        handle.join().unwrap();
        assert!(start.elapsed() <= Duration::from_millis(500));
        assert!(journal.is_all_released());
        assert!(slot.lock().unwrap().is_none(), "ReleaserDropGuard must clear slot on panic");
    }

    #[test]
    fn validate_download_dir_rejects_relative_and_symlink() {
        assert!(validate_download_dir(Path::new("relative/dir")).is_err());
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("zd-dl-test-{}-{uniq}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        assert!(validate_download_dir(&base).is_ok());
        #[cfg(unix)]
        {
            let link = base.join("sym_dl");
            std::os::unix::fs::symlink(&base, &link).unwrap();
            assert!(validate_download_dir(&link).is_err());
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    struct VecWireTx {
        frames: Vec<(u8, Vec<u8>)>,
    }

    impl FileL4Sender for VecWireTx {
        fn send_file_l4<'a>(
            &'a mut self,
            msg_type: u8,
            body: &'a [u8],
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), FileSendError>> + Send + 'a>,
        > {
            let body_owned = body.to_vec();
            Box::pin(async move {
                self.frames.push((msg_type, body_owned));
                Ok(())
            })
        }
    }

    fn make_l4_hdr(msg_type: u8, body_len: usize) -> v2_transport::L4Header {
        v2_transport::L4Header {
            msg_type,
            flags: 0,
            stream_seq: 0,
            body_len: body_len as u16,
        }
    }

    fn allow_file_policy(max_file_mb: u32) -> EffectiveTenantPolicy {
        use crate::session::policy::{TenantPolicyBody, POLICY_FLAG_ALLOW_FILE_TRANSFER};
        EffectiveTenantPolicy {
            tenant_id: [0x11; 16],
            version: 1,
            exp_unix: u64::MAX,
            policy_hash: [0x22; 32],
            body: TenantPolicyBody {
                schema_ver: 1,
                flags: POLICY_FLAG_ALLOW_FILE_TRANSFER,
                max_bw_kbps: 50_000,
                max_file_mb,
                max_clipboard_kb: 256,
            },
            degraded: false,
            degraded_reason: None,
        }
    }

    #[tokio::test]
    async fn outbound_file_manager_and_receiver_multichunk_abort_and_policy_end_to_end() {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("zd-ft-e2e-{}-{uniq}", std::process::id()));
        let host_dl = base.join("host_dl");
        let ctrl_dl = base.join("ctrl_dl");
        std::fs::create_dir_all(&host_dl).unwrap();
        std::fs::create_dir_all(&ctrl_dl).unwrap();

        let sample_path = base.join("phase5_sample.bin");
        let sample_data: Vec<u8> = (0..8192usize).map(|i| ((i * 29 + 7) & 0xFF) as u8).collect();
        let sample_sha = hex::encode(Sha256::digest(&sample_data));
        std::fs::write(&sample_path, &sample_data).unwrap();

        let allow_pol = allow_file_policy(16);
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<ActorMessage>(64);
        let (host_tx, mut host_rx) = mpsc::channel::<ActorMessage>(64);

        let mut ctrl_out = OutboundFileManager::new();
        let mut ctrl_in = FileTransferReceiver::new(allow_pol.clone(), ctrl_dl);
        let mut ctrl_err = ChannelFramingErrorCounter::new();
        let mut ctrl_wire = VecWireTx { frames: Vec::new() };

        let mut host_out = OutboundFileManager::new();
        let mut host_in = FileTransferReceiver::new(allow_pol.clone(), host_dl.clone());
        let mut host_err = ChannelFramingErrorCounter::new();
        let mut host_wire = VecWireTx { frames: Vec::new() };

        // 1. Multi-chunk 8192B (8 chunks) transfer: OFFER -> ACCEPT -> 8x CHUNK/ACK -> COMPLETE -> COMPLETE_ACK(OK)
        ctrl_out
            .start_transfer(
                &mut ctrl_wire,
                1,
                101,
                sample_path.clone(),
                "phase5_sample.bin".into(),
                &allow_pol,
                1,
                &ctrl_tx,
            )
            .await;
        assert!(ctrl_out.has_active());

        for _step in 0..32 {
            // Deliver all ctrl -> host frames
            for (mt, body) in ctrl_wire.frames.drain(..) {
                let hdr = make_l4_hdr(mt, body.len());
                let fatal = route_inbound_file_l4(
                    &mut host_wire,
                    &hdr,
                    &body,
                    &mut host_out,
                    &mut host_in,
                    &mut host_err,
                    1,
                    &host_tx,
                )
                .await;
                assert!(fatal.is_none(), "unexpected host fatal: {fatal:?}");
            }
            // Deliver all host -> ctrl frames (ACCEPT, 8x ACK, COMPLETE_ACK)
            for (mt, body) in host_wire.frames.drain(..) {
                let hdr = make_l4_hdr(mt, body.len());
                let fatal = route_inbound_file_l4(
                    &mut ctrl_wire,
                    &hdr,
                    &body,
                    &mut ctrl_out,
                    &mut ctrl_in,
                    &mut ctrl_err,
                    1,
                    &ctrl_tx,
                )
                .await;
                assert!(fatal.is_none(), "unexpected ctrl fatal: {fatal:?}");
            }
            if ctrl_out.has_active() {
                ctrl_out
                    .pump_one_step(&mut ctrl_wire, &allow_pol, 1, &ctrl_tx)
                    .await;
            } else {
                break;
            }
        }
        assert!(!ctrl_out.has_active(), "outbound transfer should have completed");

        // Verify Host emitted FileComplete with matching SHA-256 and exact file on disk!
        let mut host_saved_path: Option<String> = None;
        while let Ok(msg) = host_rx.try_recv() {
            if let ActorMessage::InternalEvent {
                event:
                    ActorEvent::FileComplete {
                        sha256_hex,
                        saved_path,
                        ..
                    },
                ..
            } = msg
            {
                assert_eq!(sha256_hex, sample_sha);
                host_saved_path = saved_path;
            }
        }
        let saved = host_saved_path.expect("host must emit FileComplete with saved_path");
        let on_disk = std::fs::read(&saved).unwrap();
        assert_eq!(on_disk, sample_data);

        // Verify Controller emitted CommandResult { cmd_id: 101, ok: true }!
        let mut ctrl_cmd_ok = false;
        while let Ok(msg) = ctrl_rx.try_recv() {
            if let ActorMessage::InternalEvent {
                event: ActorEvent::CommandResult { cmd_id: 101, ok, .. },
                ..
            } = msg
            {
                ctrl_cmd_ok = ok;
            }
        }
        assert!(ctrl_cmd_ok, "controller must emit CommandResult ok=true after CompleteAck");

        // 2. Pre-hash policy denial BEFORE Offer MUST NOT send a spurious FILE_MSG_ABORT!
        let deny_pol = EffectiveTenantPolicy::degraded([0x11; 16], [0x22; 32], "denied");
        ctrl_wire.frames.clear();
        ctrl_out
            .start_transfer(
                &mut ctrl_wire,
                2,
                102,
                sample_path.clone(),
                "phase5_sample.bin".into(),
                &deny_pol,
                1,
                &ctrl_tx,
            )
            .await;
        assert!(ctrl_wire.frames.is_empty(), "pre-offer policy deny must send zero wire frames");
        assert!(!ctrl_out.has_active());

        // 3. Mid-flight policy revocation + peer-abort inbound cleanup fallthrough!
        ctrl_out
            .start_transfer(
                &mut ctrl_wire,
                3,
                103,
                sample_path.clone(),
                "revoked.bin".into(),
                &allow_pol,
                1,
                &ctrl_tx,
            )
            .await;
        // Deliver OFFER to Host so Host opens an active inbound slot (active_count == 1).
        for (mt, body) in ctrl_wire.frames.drain(..) {
            let hdr = make_l4_hdr(mt, body.len());
            assert!(route_inbound_file_l4(
                &mut host_wire,
                &hdr,
                &body,
                &mut host_out,
                &mut host_in,
                &mut host_err,
                1,
                &host_tx,
            )
            .await
            .is_none());
        }
        assert_eq!(host_in.active_count(), 1);
        // Flip policy to deny -> pump_one_step MUST abort transfer #3 with FILE_ERR_POLICY_DENIED!
        ctrl_out
            .pump_one_step(&mut ctrl_wire, &deny_pol, 1, &ctrl_tx)
            .await;
        assert!(!ctrl_out.has_active());
        assert_eq!(ctrl_wire.frames.len(), 1);
        assert_eq!(ctrl_wire.frames[0].0, FILE_MSG_ABORT);
        // Deliver Controller's ABORT to Host -> handle_remote_abort returns false -> falls through
        // to `host_in` and immediately cleans up the inbound slot!
        for (mt, body) in ctrl_wire.frames.drain(..) {
            let hdr = make_l4_hdr(mt, body.len());
            assert!(route_inbound_file_l4(
                &mut host_wire,
                &hdr,
                &body,
                &mut host_out,
                &mut host_in,
                &mut host_err,
                1,
                &host_tx,
            )
            .await
            .is_none());
        }
        assert_eq!(
            host_in.active_count(),
            0,
            "peer ABORT must fall through to FileTransferReceiver and clean up active inbound slot"
        );

        // 4. Stale/unmatched Accept, Ack, and CompleteAck after cancel_transfer MUST NEVER fall
        //    through to FileTransferReceiver or trigger 0x0103 / SessionFatal (even >= 3 frames)!
        ctrl_out
            .start_transfer(
                &mut ctrl_wire,
                4,
                104,
                sample_path.clone(),
                "cancelled.bin".into(),
                &allow_pol,
                1,
                &ctrl_tx,
            )
            .await;
        ctrl_out
            .cancel_transfer(&mut ctrl_wire, 4, 1, &ctrl_tx)
            .await;
        assert!(!ctrl_out.has_active());
        ctrl_wire.frames.clear();

        let dropped_before = ctrl_out.unknown_peer_msgs_dropped;
        let stale_accept = FileAccept {
            transfer_id: 4,
            resume_offset: 0,
            initial_window_end_offset: 4096,
        }
        .encode()
        .unwrap();
        let stale_ack = FileAck {
            transfer_id: 4,
            next_expected_offset: 1024,
            window_end_offset: 4096,
        }
        .encode()
        .unwrap();
        let stale_cack = crate::session::file_transfer::FileCompleteAck {
            transfer_id: 4,
            status: FILE_COMPLETE_ACK_OK,
        }
        .encode()
        .unwrap();

        for (mt, body) in [
            (FILE_MSG_ACCEPT, stale_accept.to_vec()),
            (FILE_MSG_ACK, stale_ack.to_vec()),
            (FILE_MSG_ACK, stale_ack.to_vec()),
            (FILE_MSG_COMPLETE_ACK, stale_cack.to_vec()),
        ] {
            let hdr = make_l4_hdr(mt, body.len());
            let fatal = route_inbound_file_l4(
                &mut ctrl_wire,
                &hdr,
                &body,
                &mut ctrl_out,
                &mut ctrl_in,
                &mut ctrl_err,
                1,
                &ctrl_tx,
            )
            .await;
            assert!(
                fatal.is_none(),
                "stale sender-bound reply must never trigger 0x0103/SessionFatal: {fatal:?}"
            );
        }
        assert_eq!(ctrl_out.unknown_peer_msgs_dropped, dropped_before + 4);
        assert!(
            ctrl_wire.frames.is_empty(),
            "stale Accept/Ack/CompleteAck must produce zero wire replies"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn get_snapshot_command_and_watchdog_report_validation() {
        // Empty watchdog_report_path must fail closed.
        let empty_res = V2BridgeRuntime::with_options(V2BridgeRuntimeOptions {
            watchdog_report_path: Some(PathBuf::new()),
            ..V2BridgeRuntimeOptions::default()
        });
        assert!(empty_res.is_err());

        // Real input + dry-run watchdog_report_path must be mutually exclusive.
        #[cfg(feature = "real-input")]
        {
            let permit = Arc::new(RealInputPermit::from_explicit_opt_in(true).unwrap());
            let conflict = V2BridgeRuntime::with_options(V2BridgeRuntimeOptions {
                real_input_permit: Some(permit),
                watchdog_report_path: Some(PathBuf::from("/tmp/should-be-rejected.json")),
                ..V2BridgeRuntimeOptions::default()
            });
            assert!(conflict.is_err());
        }

        // get_snapshot command must return structured BridgeSnapshot in data.
        let rt = V2BridgeRuntime::new().unwrap();
        let raw = rt.exec_json(r#"{"v":1,"cmd":"get_snapshot"}"#);
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed["ok"].as_bool(), Some(true));
        assert_eq!(parsed["data"]["v"].as_u64(), Some(1));
        assert_eq!(parsed["data"]["state"].as_str(), Some("idle"));
        rt.destroy();
    }

    struct ControllableFileTx {
        frames: Vec<(u8, Vec<u8>)>,
        bulk_paused: bool,
        inject_backpressure_once: bool,
    }

    impl FileL4Sender for ControllableFileTx {
        fn send_file_l4<'a>(
            &'a mut self,
            msg_type: u8,
            body: &'a [u8],
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), FileSendError>> + Send + 'a>,
        > {
            let body_owned = body.to_vec();
            Box::pin(async move {
                if self.inject_backpressure_once {
                    self.inject_backpressure_once = false;
                    return Err(FileSendError::Backpressure);
                }
                self.frames.push((msg_type, body_owned));
                Ok(())
            })
        }

        fn is_bulk_paused(&self) -> bool {
            self.bulk_paused
        }
    }

    #[tokio::test]
    async fn outbound_file_manager_zero_byte_backpressure_bulk_pause_and_no_progress_timeout() {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("zd-ft-ofm-{}-{uniq}", std::process::id()));
        let dl_dir = base.join("dl");
        std::fs::create_dir_all(&dl_dir).unwrap();

        let allow_pol = allow_file_policy(16);
        let (tx_chan, mut rx_chan) = mpsc::channel::<ActorMessage>(64);

        // 1. 0-byte file: FILE_OFFER -> FILE_ACCEPT -> FILE_COMPLETE immediately (zero chunks)
        let empty_path = base.join("zero.bin");
        std::fs::write(&empty_path, b"").unwrap();
        let mut ofm = OutboundFileManager::new();
        let mut wire = ControllableFileTx {
            frames: Vec::new(),
            bulk_paused: false,
            inject_backpressure_once: false,
        };
        ofm.start_transfer(
            &mut wire,
            10,
            201,
            empty_path,
            "zero.bin".into(),
            &allow_pol,
            1,
            &tx_chan,
        )
        .await;
        assert_eq!(wire.frames.len(), 1);
        assert_eq!(wire.frames[0].0, FILE_MSG_OFFER);
        wire.frames.clear();

        assert!(
            ofm.handle_accept(
                &mut wire,
                &FileAccept {
                    transfer_id: 10,
                    resume_offset: 0,
                    initial_window_end_offset: 0,
                },
                1,
                &tx_chan,
            )
            .await
        );
        // Bulk pause MUST block even FILE_COMPLETE for a 0-byte file.
        wire.bulk_paused = true;
        ofm.pump_one_step(&mut wire, &allow_pol, 1, &tx_chan).await;
        assert!(wire.frames.is_empty());

        wire.bulk_paused = false;
        ofm.pump_one_step(&mut wire, &allow_pol, 1, &tx_chan).await;
        assert_eq!(wire.frames.len(), 1);
        assert_eq!(wire.frames[0].0, FILE_MSG_COMPLETE);
        assert!(
            ofm.handle_complete_ack(10, FILE_COMPLETE_ACK_OK, 1, &tx_chan)
                .await
        );
        assert!(!ofm.has_active());
        wire.frames.clear();

        // 2. Non-zero 2048B file: Backpressure rewinds file cursor without corrupting bytes,
        //    and FILE_COMPLETE is strictly withheld until FILE_ACK(next_expected_offset == 2048).
        let data_path = base.join("two_chunks.bin");
        let payload: Vec<u8> = (0..2048usize).map(|i| ((i * 31 + 5) & 0xFF) as u8).collect();
        std::fs::write(&data_path, &payload).unwrap();
        ofm.start_transfer(
            &mut wire,
            11,
            202,
            data_path,
            "two_chunks.bin".into(),
            &allow_pol,
            1,
            &tx_chan,
        )
        .await;
        wire.frames.clear();

        assert!(
            ofm.handle_accept(
                &mut wire,
                &FileAccept {
                    transfer_id: 11,
                    resume_offset: 0,
                    initial_window_end_offset: 2048,
                },
                1,
                &tx_chan,
            )
            .await
        );

        // Inject Backpressure on chunk 0: must rewind cursor and send exact bytes 0..1024 on retry!
        wire.inject_backpressure_once = true;
        ofm.pump_one_step(&mut wire, &allow_pol, 1, &tx_chan).await;
        assert!(wire.frames.is_empty());
        assert!(ofm.has_active());

        ofm.pump_one_step(&mut wire, &allow_pol, 1, &tx_chan).await;
        ofm.pump_one_step(&mut wire, &allow_pol, 1, &tx_chan).await;
        assert_eq!(wire.frames.len(), 2);
        let ch0 = FileChunk::decode(&wire.frames[0].1).unwrap();
        let ch1 = FileChunk::decode(&wire.frames[1].1).unwrap();
        assert_eq!(ch0.offset, 0);
        assert_eq!(ch0.data, &payload[..1024]);
        assert_eq!(ch1.offset, 1024);
        assert_eq!(ch1.data, &payload[1024..]);
        wire.frames.clear();

        // All bytes sent, ZERO FILE_ACK received yet -> pump MUST NOT emit FILE_COMPLETE!
        ofm.pump_one_step(&mut wire, &allow_pol, 1, &tx_chan).await;
        assert!(wire.frames.is_empty());

        // Partial ACK (1024/2048) -> STILL MUST NOT emit FILE_COMPLETE!
        assert!(ofm.handle_ack(&FileAck {
            transfer_id: 11,
            next_expected_offset: 1024,
            window_end_offset: 2048,
        }));
        ofm.pump_one_step(&mut wire, &allow_pol, 1, &tx_chan).await;
        assert!(wire.frames.is_empty());

        // Spoofed ACK past total_bytes is ignored without mutating acked_offset or unlocking FILE_COMPLETE.
        assert!(ofm.handle_ack(&FileAck {
            transfer_id: 11,
            next_expected_offset: 4096,
            window_end_offset: 4096,
        }));
        assert_eq!(ofm.active.get(&11).unwrap().acked_offset, 1024);
        ofm.pump_one_step(&mut wire, &allow_pol, 1, &tx_chan).await;
        assert!(wire.frames.is_empty());

        // Final ACK (2048/2048) -> unlocks FILE_COMPLETE!
        assert!(ofm.handle_ack(&FileAck {
            transfer_id: 11,
            next_expected_offset: 2048,
            window_end_offset: 2048,
        }));
        ofm.pump_one_step(&mut wire, &allow_pol, 1, &tx_chan).await;
        assert_eq!(wire.frames.len(), 1);
        assert_eq!(wire.frames[0].0, FILE_MSG_COMPLETE);
        assert!(
            ofm.handle_complete_ack(11, FILE_COMPLETE_ACK_OK, 1, &tx_chan)
                .await
        );
        wire.frames.clear();

        // 3. No-progress timeout (30s) aborts cleanly and emits Timeout command error.
        let stall_path = base.join("stall.bin");
        std::fs::write(&stall_path, b"stall").unwrap();
        ofm.start_transfer(
            &mut wire,
            12,
            203,
            stall_path,
            "stall.bin".into(),
            &allow_pol,
            1,
            &tx_chan,
        )
        .await;
        wire.frames.clear();
        ofm.active.get_mut(&12).unwrap().last_activity_at =
            Instant::now() - FILE_NO_PROGRESS_TIMEOUT - Duration::from_secs(1);
        ofm.pump_one_step(&mut wire, &allow_pol, 1, &tx_chan).await;
        assert!(!ofm.has_active());
        assert_eq!(wire.frames.len(), 1);
        assert_eq!(wire.frames[0].0, FILE_MSG_ABORT);

        let mut saw_timeout = false;
        while let Ok(msg) = rx_chan.try_recv() {
            if let ActorMessage::InternalEvent {
                event:
                    ActorEvent::CommandResult {
                        cmd_id: 203,
                        ok: false,
                        error_code: Some(code),
                        ..
                    },
                ..
            } = msg
            {
                if code == "Timeout" {
                    saw_timeout = true;
                }
            }
        }
        assert!(saw_timeout, "expected Timeout CommandResult for cmd_id=203");

        let _ = std::fs::remove_dir_all(&base);
    }

    struct ControllableClipTx {
        frames: Vec<(u8, Vec<u8>)>,
        backpressure_count: usize,
    }

    impl ClipL4Sender for ControllableClipTx {
        fn send_clip_l4<'a>(
            &'a mut self,
            msg_type: u8,
            body: &'a [u8],
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), FileSendError>> + Send + 'a>,
        > {
            let body_owned = body.to_vec();
            Box::pin(async move {
                if self.backpressure_count > 0 {
                    self.backpressure_count -= 1;
                    return Err(FileSendError::Backpressure);
                }
                self.frames.push((msg_type, body_owned));
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn outbound_file_manager_resume_offset_ctrl_priority_and_clip_queue() {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("zd-ft-res-{}-{uniq}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();

        let allow_pol = allow_file_policy(16);
        let deny_pol = EffectiveTenantPolicy::degraded([1; 16], [2; 32], "denied");
        let (tx_chan, _rx_chan) = mpsc::channel::<ActorMessage>(64);
        let mut ofm = OutboundFileManager::new();
        let mut wire = ControllableFileTx {
            frames: Vec::new(),
            bulk_paused: false,
            inject_backpressure_once: false,
        };

        let payload: Vec<u8> = (0..2048usize).map(|i| ((i * 19 + 3) & 0xFF) as u8).collect();
        let path = base.join("resume_me.bin");
        std::fs::write(&path, &payload).unwrap();

        // 1. resume_offset == total_bytes > 0 -> immediately emits FILE_COMPLETE without chunks
        ofm.start_transfer(
            &mut wire,
            30,
            301,
            path.clone(),
            "resume_me.bin".into(),
            &allow_pol,
            1,
            &tx_chan,
        )
        .await;
        wire.frames.clear();
        assert!(
            ofm.handle_accept(
                &mut wire,
                &FileAccept {
                    transfer_id: 30,
                    resume_offset: 2048,
                    initial_window_end_offset: 2048,
                },
                1,
                &tx_chan,
            )
            .await
        );
        ofm.pump_one_step(&mut wire, &allow_pol, 1, &tx_chan).await;
        assert_eq!(wire.frames.len(), 1);
        assert_eq!(wire.frames[0].0, FILE_MSG_COMPLETE);
        assert!(
            ofm.handle_complete_ack(30, FILE_COMPLETE_ACK_OK, 1, &tx_chan)
                .await
        );
        wire.frames.clear();

        // 2. 0 < resume_offset < total_bytes -> seeks to exact offset, sends 1024..2048, waits for ACK
        ofm.start_transfer(
            &mut wire,
            31,
            302,
            path.clone(),
            "resume_me.bin".into(),
            &allow_pol,
            1,
            &tx_chan,
        )
        .await;
        wire.frames.clear();
        assert!(
            ofm.handle_accept(
                &mut wire,
                &FileAccept {
                    transfer_id: 31,
                    resume_offset: 1024,
                    initial_window_end_offset: 2048,
                },
                1,
                &tx_chan,
            )
            .await
        );
        ofm.pump_one_step(&mut wire, &allow_pol, 1, &tx_chan).await;
        assert_eq!(wire.frames.len(), 1);
        assert_eq!(wire.frames[0].0, FILE_MSG_CHUNK);
        let resumed_chunk = FileChunk::decode(&wire.frames[0].1).unwrap();
        assert_eq!(resumed_chunk.offset, 1024);
        assert_eq!(resumed_chunk.data, &payload[1024..]);
        wire.frames.clear();

        // Must NOT emit FILE_COMPLETE until FILE_ACK(2048) arrives
        ofm.pump_one_step(&mut wire, &allow_pol, 1, &tx_chan).await;
        assert!(wire.frames.is_empty());
        assert!(ofm.handle_ack(&FileAck {
            transfer_id: 31,
            next_expected_offset: 2048,
            window_end_offset: 2048,
        }));
        ofm.pump_one_step(&mut wire, &allow_pol, 1, &tx_chan).await;
        assert_eq!(wire.frames.len(), 1);
        assert_eq!(wire.frames[0].0, FILE_MSG_COMPLETE);
        assert!(
            ofm.handle_complete_ack(31, FILE_COMPLETE_ACK_OK, 1, &tx_chan)
                .await
        );
        wire.frames.clear();

        // 3. Invalid resume_offset > total_bytes -> aborts immediately (does not hang for 30s!)
        ofm.start_transfer(
            &mut wire,
            32,
            303,
            path,
            "resume_me.bin".into(),
            &allow_pol,
            1,
            &tx_chan,
        )
        .await;
        wire.frames.clear();
        assert!(
            ofm.handle_accept(
                &mut wire,
                &FileAccept {
                    transfer_id: 32,
                    resume_offset: 4096,
                    initial_window_end_offset: 4096,
                },
                1,
                &tx_chan,
            )
            .await
        );
        assert!(!ofm.has_active());
        assert_eq!(wire.frames.len(), 1);
        assert_eq!(wire.frames[0].0, FILE_MSG_ABORT);
        wire.frames.clear();

        // 4. Control-frame retry queue priority: evicts oldest FILE_MSG_ACK at cap 128 while
        //    preserving ACCEPT/COMPLETE_ACK/ABORT; policy deny drops ACCEPT; bulk pause still drains ABORT!
        for _ in 0..PENDING_FILE_CTRL_CAP {
            ofm.enqueue_ctrl_retry(FILE_MSG_ACK, b"ack");
        }
        ofm.enqueue_ctrl_retry(FILE_MSG_COMPLETE_ACK, b"cack");
        ofm.enqueue_ctrl_retry(FILE_MSG_ACCEPT, b"acc");
        ofm.enqueue_ctrl_retry(FILE_MSG_ABORT, b"ab");
        assert_eq!(ofm.pending_ctrl_frames.len(), PENDING_FILE_CTRL_CAP);
        assert!(ofm
            .pending_ctrl_frames
            .iter()
            .any(|(mt, _)| *mt == FILE_MSG_COMPLETE_ACK));
        assert!(ofm
            .pending_ctrl_frames
            .iter()
            .any(|(mt, _)| *mt == FILE_MSG_ACCEPT));
        assert!(ofm
            .pending_ctrl_frames
            .iter()
            .any(|(mt, _)| *mt == FILE_MSG_ABORT));

        // With policy revoked AND bulk_paused=true: FILE_MSG_ACCEPT dropped, FILE_MSG_ABORT still drains!
        wire.bulk_paused = true;
        ofm.pump_one_step(&mut wire, &deny_pol, 1, &tx_chan).await;
        assert!(!ofm
            .pending_ctrl_frames
            .iter()
            .any(|(mt, _)| *mt == FILE_MSG_ACCEPT));
        assert_eq!(wire.frames.len(), 1);
        assert_eq!(wire.frames[0].0, FILE_MSG_ABORT);
        wire.frames.clear();

        // 5. PendingClipQueue: backpressure retry, superseded CLIP_MSG_SYNC eviction, and 4 MiB byte cap!
        let mut clip_tx = ControllableClipTx {
            frames: Vec::new(),
            backpressure_count: 2,
        };
        let mut clip_q = PendingClipQueue::new();
        send_or_queue_clip_frame(&mut clip_tx, &mut clip_q, CLIP_MSG_SYNC, b"old-sync").await;
        send_or_queue_clip_frame(&mut clip_tx, &mut clip_q, CLIP_MSG_CHUNK, b"old-chunk-1").await;
        assert_eq!(clip_q.frames.len(), 2);

        // Starting a new clipboard transfer (CLIP_MSG_SYNC) evicts stale queued frames!
        send_or_queue_clip_frame(&mut clip_tx, &mut clip_q, CLIP_MSG_SYNC, b"new-sync").await;
        send_or_queue_clip_frame(&mut clip_tx, &mut clip_q, CLIP_MSG_CHUNK, b"new-chunk-1").await;
        assert_eq!(clip_q.frames.len(), 2);
        assert_eq!(clip_q.frames[0], (CLIP_MSG_SYNC, b"new-sync".to_vec()));
        assert_eq!(clip_q.frames[1], (CLIP_MSG_CHUNK, b"new-chunk-1".to_vec()));

        // Drain after backpressure clears delivers ONLY the new transfer in order!
        drain_pending_clip_frames(&mut clip_tx, &mut clip_q).await;
        assert!(clip_q.is_empty());
        assert_eq!(clip_q.buffered_bytes, 0);
        assert_eq!(
            clip_tx.frames,
            vec![
                (CLIP_MSG_SYNC, b"new-sync".to_vec()),
                (CLIP_MSG_CHUNK, b"new-chunk-1".to_vec()),
            ]
        );

        // Hard 4 MiB byte cap prevents unbounded RAM growth even under <256 frames!
        let big_chunk = vec![0x77u8; 1024 * 1024];
        for _ in 0..6 {
            clip_q.push(CLIP_MSG_CHUNK, &big_chunk);
        }
        assert_eq!(clip_q.buffered_bytes, PENDING_CLIP_BYTES_CAP);
        assert_eq!(clip_q.frames.len(), 4);

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn controller_hid_state_release_all_encodes_spec04_frames_and_is_idempotent() {
        let mut st = ControllerHidState::default();
        assert!(!st.has_pressed());

        st.record_outbound(&HidPayload::Key(KeyEvent {
            down: true,
            modifiers: 0x02,
            usb_hid_usage: 0xE0, // LeftCtrl
            unicode_scalar: 0,
            client_ts_ms: 100,
        }));
        st.record_outbound(&HidPayload::Key(KeyEvent {
            down: true,
            modifiers: 0x02,
            usb_hid_usage: 0x04, // A
            unicode_scalar: 0,
            client_ts_ms: 101,
        }));
        st.record_outbound(&HidPayload::Mouse(MouseEvent {
            kind: MouseKind::Down,
            buttons: 0x05, // Left + Middle
            x_or_dx: 320,
            y_or_dy: 240,
            wheel_dx: 0,
            wheel_dy: 0,
            client_ts_ms: 102,
        }));
        assert!(st.has_pressed());

        let (payloads, rel_keys, rel_btns) = st.take_release_all_payloads(&[0x05], 0x02, 200);
        assert_eq!(rel_keys, 3); // A (0x04), B (0x05), LeftCtrl (0xE0)
        assert_eq!(rel_btns, 3); // Left + Right + Middle (0x07)
        assert!(!st.has_pressed());

        // Regular keys released before modifiers, followed by Mouse Up with buttons=0.
        assert_eq!(payloads.len(), 4);
        match payloads[0] {
            HidPayload::Key(k) => {
                assert!(!k.down);
                assert_eq!(k.usb_hid_usage, 0x04);
            }
            _ => panic!("expected regular key release first"),
        }
        match payloads[2] {
            HidPayload::Key(k) => {
                assert!(!k.down);
                assert_eq!(k.usb_hid_usage, 0xE0);
            }
            _ => panic!("expected modifier key release after regular keys"),
        }
        match payloads[3] {
            HidPayload::Mouse(m) => {
                assert_eq!(m.kind, MouseKind::Up);
                assert_eq!(m.buttons, 0);
                assert_eq!((m.x_or_dx, m.y_or_dy), (320, 240));
            }
            _ => panic!("expected mouse release last"),
        }
        for p in &payloads {
            let wire = encode_hid_frame(p).expect("release_all payload must be spec/04 valid");
            assert_eq!(decode_hid_frame(&wire).unwrap(), *p);
        }

        // Second release_all is a safe idempotent no-op.
        let (payloads2, rel_keys2, rel_btns2) = st.take_release_all_payloads(&[], 0, 201);
        assert!(payloads2.is_empty());
        assert_eq!(rel_keys2, 0);
        assert_eq!(rel_btns2, 0);
    }

    #[test]
    fn bridge_runtime_release_all_and_codec_selection_commands() {
        let rt = V2BridgeRuntime::new().unwrap();

        // release_all when idle is an idempotent no-op.
        let rel: serde_json::Value = serde_json::from_str(
            &rt.exec_json(r#"{"v":1,"cmd":"release_all","keys":[4,224],"buttons":1}"#),
        )
        .unwrap();
        assert_eq!(rel["ok"], true);
        assert_eq!(rel["data"]["active_session"], false);
        assert_eq!(rel["data"]["released_keys"], 0);

        // release_all rejects reserved mouse button bits (> 0x1F).
        let bad_rel: serde_json::Value =
            serde_json::from_str(&rt.exec_json(r#"{"v":1,"cmd":"release_all","buttons":128}"#))
                .unwrap();
        assert_eq!(bad_rel["ok"], false);
        assert_eq!(bad_rel["error_code"], "InvalidArgument");

        // key_down / key_up require active Streaming session.
        let kd: serde_json::Value = serde_json::from_str(
            &rt.exec_json(r#"{"v":1,"cmd":"key_down","usage_id":4,"modifiers":0}"#),
        )
        .unwrap();
        assert_eq!(kd["ok"], false);
        assert_eq!(kd["error_code"], "IllegalStateTransition");

        // set_codec accepts auto/hevc/h264/vp9/av1 and rejects invalid names.
        for codec in ["auto", "hevc", "h264", "vp9", "av1"] {
            let reply: serde_json::Value = serde_json::from_str(
                &rt.exec_json(&format!(r#"{{"v":1,"cmd":"set_codec","codec":"{codec}"}}"#)),
            )
            .unwrap();
            assert_eq!(reply["ok"], true, "codec {codec} should be accepted");
            assert_eq!(reply["data"]["codec"], codec);
        }
        let bad_codec: serde_json::Value =
            serde_json::from_str(&rt.exec_json(r#"{"v":1,"cmd":"set_codec","codec":"mpeg2"}"#))
                .unwrap();
        assert_eq!(bad_codec["ok"], false);
        assert_eq!(bad_codec["error_code"], "InvalidArgument");
    }

    #[test]
    fn streaming_set_input_enabled_enforces_authoritative_probe_and_emergency_escape() {
        use crate::os::input::PermissionProbeSource;

        struct TestProbe {
            screen: AtomicBool,
            ax: AtomicBool,
            authoritative: AtomicBool,
        }
        impl PermissionProbe for TestProbe {
            fn probe(
                &self,
                _watchdog_ax_override: Option<bool>,
                enable_os_input: bool,
            ) -> PermissionStatusReport {
                PermissionStatusReport {
                    screen_capture_granted: self.screen.load(Ordering::Acquire),
                    accessibility_granted: self.ax.load(Ordering::Acquire),
                    probe_source: if self.authoritative.load(Ordering::Acquire) {
                        PermissionProbeSource::Watchdog
                    } else {
                        PermissionProbeSource::UiProcessHint
                    },
                    enable_os_input,
                    secure_event_input_enabled: Some(false),
                }
            }
        }

        let probe = Arc::new(TestProbe {
            screen: AtomicBool::new(true),
            ax: AtomicBool::new(true),
            authoritative: AtomicBool::new(false),
        });
        let rt = V2BridgeRuntime::with_options(V2BridgeRuntimeOptions {
            permission_probe: Some(Arc::clone(&probe) as Arc<dyn PermissionProbe>),
            ..V2BridgeRuntimeOptions::default()
        })
        .unwrap();

        rt.simulate_streaming_for_test([0xAB; 16], sample_cert());
        assert_eq!(rt.snapshot().state, BridgeState::Streaming);
        assert_eq!(rt.snapshot().enable_os_input, Some(false));

        // 1. Streaming + ui_process_hint + ax=true + screen=true -> MUST fail closed (not_permitted)!
        let r1: serde_json::Value = serde_json::from_str(
            &rt.exec_json(r#"{"v":1,"cmd":"set_input_enabled","enabled":true}"#),
        )
        .unwrap();
        assert_eq!(r1["ok"], false);
        assert_eq!(r1["error_code"], "not_permitted");
        assert_eq!(rt.snapshot().enable_os_input, Some(false));

        // 2. Streaming + authoritative watchdog + screen=false + ax=true -> not_permitted!
        probe.authoritative.store(true, Ordering::Release);
        probe.screen.store(false, Ordering::Release);
        let r2: serde_json::Value = serde_json::from_str(
            &rt.exec_json(r#"{"v":1,"cmd":"set_input_enabled","enabled":true}"#),
        )
        .unwrap();
        assert_eq!(r2["ok"], false);
        assert_eq!(r2["error_code"], "not_permitted");
        assert_eq!(rt.snapshot().enable_os_input, Some(false));

        // 3. Streaming + authoritative watchdog + screen=true + ax=true -> succeeds!
        probe.screen.store(true, Ordering::Release);
        let r3: serde_json::Value = serde_json::from_str(
            &rt.exec_json(r#"{"v":1,"cmd":"set_input_enabled","enabled":true}"#),
        )
        .unwrap();
        assert_eq!(r3["ok"], true);
        assert_eq!(rt.snapshot().enable_os_input, Some(true));

        // 4. Streaming set_codec with no active_session_tx -> Unavailable (not ok)!
        let codec_unavail: serde_json::Value =
            serde_json::from_str(&rt.exec_json(r#"{"v":1,"cmd":"set_codec","codec":"avc1"}"#))
                .unwrap();
        assert_eq!(codec_unavail["ok"], false);
        assert_eq!(codec_unavail["error_code"], "Unavailable");

        // 5. Emergency escape (with invalid buttons bitmask 0xFF) unconditionally disables input!
        let esc: serde_json::Value = serde_json::from_str(
            &rt.exec_json(r#"{"v":1,"cmd":"release_all","emergency_escape":true,"buttons":255}"#),
        )
        .unwrap();
        assert_eq!(esc["ok"], true);
        assert_eq!(rt.snapshot().enable_os_input, Some(false));

        rt.destroy();
    }
}
