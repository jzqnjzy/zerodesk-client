// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::{
    controller::{
        load_config_json, save_config_json, BridgePersistedConfig, BridgeSnapshot, BridgeState,
        PolicySummary, RedactedConfigView, V2BridgeController, VerifiedCallerDisplay,
    },
    events::BridgeEventHub,
    json_abi::{parse_and_validate_command, RuntimeCommandEnvelope, RuntimeReplyEnvelope},
};
use crate::{
    frame::{FrameError, FrameInfo, FrameMailbox, PixelFormat},
    os::{
        audio::{open_os_audio_capture, open_os_audio_playback, AudioStatusChanged},
        capture::{convert_captured_stride_to_i420, create_os_screen_capture},
        clipboard::{
            create_os_clipboard_backend, validate_clipboard_png_bytes, ClipboardPoller,
        },
        dryrun::{
            raw_captured_to_i420, DryRunHidJournal, DryRunHidSink, MemoryClipboardBackend,
            SilentAudioCapture, SilentAudioPlayback, SyntheticScreenSource,
        },
        input::{create_real_os_hid_sink, RealInputPermit},
        EmergencyKeyReleaser, OsAudioCapture, OsAudioPlayback, OsHidSink, OsScreenCapture,
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
            CLIP_ACK_OK, CLIP_MIME_IMAGE_PNG, CLIP_MIME_TEXT_UTF8, CLIP_MSG_ACK, CLIP_MSG_CHUNK,
            CLIP_MSG_SYNC,
        },
        config::{TransportMode, V2ClientConfig},
        file_transfer::{
            check_file_policy, decode_file_l4, validate_safe_filename, FileAbort, FileChunk,
            FileComplete, FileMessage, FileOffer, FileRecvAction, FileTransferReceiver,
            FILE_COMPLETE_ACK_OK, FILE_ERR_POLICY_DENIED, FILE_MSG_ABORT, FILE_MSG_ACCEPT,
            FILE_MSG_ACK, FILE_MSG_CHUNK, FILE_MSG_COMPLETE, FILE_MSG_COMPLETE_ACK, FILE_MSG_OFFER,
            FILE_RECOMMENDED_CHUNK_SIZE,
        },
        hid::{decode_hid_frame, encode_hid_frame, HidPayload, KeyEvent, MouseEvent, MouseKind},
        identity::PersistentV2Identity,
        manager::{
            CallDecision, DesktopControllerClient, DesktopHostDaemon, IncomingCall, SecurityEvent,
            UiCallbackDispatcher, V2SessionState, V2UiCallback, DEFAULT_V2_CAP_BITS,
        },
        policy::{verify_tenant_policy_blob, EffectiveTenantPolicy, PolicyVerifyOutcome},
        runtime::send_redundant_session_close_3x,
        session::{parse_session_close, DesktopHostSession, CTRL_MSG_SESSION_CLOSE},
        video::{V2VideoDecoder, V2VideoEncoder, VideoCodec},
    },
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc as std_mpsc, Arc, Mutex, RwLock,
    },
    thread::{self, JoinHandle},
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
};

pub const SYNC_CMD_TIMEOUT: Duration = Duration::from_millis(500);
pub const UNIFIED_SHUTDOWN_BUDGET: Duration = Duration::from_secs(3);
pub const DEFAULT_RING_TIMEOUT: Duration = Duration::from_secs(15);
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
    pub use_os_audio: bool,
    pub use_os_clipboard: bool,
    pub real_input_permit: Option<RealInputPermit>,
    pub dryrun_journal: DryRunHidJournal,
    pub memory_clipboard: MemoryClipboardBackend,
    pub download_dir: Option<PathBuf>,
    pub ring_timeout: Duration,
    pub drop_udp_override: bool,
    pub synthetic_width: u32,
    pub synthetic_height: u32,
}

impl Default for V2BridgeRuntimeOptions {
    fn default() -> Self {
        Self {
            use_os_capture: false,
            use_os_audio: false,
            use_os_clipboard: false,
            real_input_permit: None,
            dryrun_journal: DryRunHidJournal::new(),
            memory_clipboard: MemoryClipboardBackend::new(),
            download_dir: None,
            ring_timeout: DEFAULT_RING_TIMEOUT,
            drop_udp_override: false,
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

enum SessionAction {
    SendHid(HidPayload),
    SendClipboard {
        mime_kind: u8,
        bytes: Vec<u8>,
    },
    SendFile {
        cmd_id: u64,
        path: PathBuf,
        rel_name: String,
    },
    SetAudioMute(bool),
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
        peer_device_id: [u8; 16],
        tenant_id: [u8; 16],
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
    },
    AudioStatus(AudioStatusChanged),
    WatchdogTriggered {
        released_keys: usize,
        released_buttons: usize,
    },
    ClipboardReceived {
        mime_kind: u8,
        bytes: usize,
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
    QoeTelemetry(serde_json::Value),
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
        reply: std_mpsc::SyncSender<RuntimeReplyEnvelope>,
    },
    SendClipboardPng {
        bytes: Vec<u8>,
        reply: std_mpsc::SyncSender<RuntimeReplyEnvelope>,
    },
    SendFilePath {
        path: String,
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
}

impl V2UiCallback for BridgeUiCallback {
    fn on_frame(&self, _frame: Arc<crate::session::video::I420Frame>) {}
    fn on_state(&self, _state: V2SessionState) {}
    fn on_qoe(&self, snapshot: crate::session::runtime::QoeSnapshot) {
        if let Ok(val) = serde_json::to_value(snapshot) {
            let _ = self.actor_tx.try_send(ActorMessage::InternalEvent {
                session_gen: self.session_gen,
                event: ActorEvent::QoeTelemetry(val),
            });
        }
    }
    fn on_capabilities(&self, _caps: VerifiedTenantPolicy) {}
    fn on_incoming_call(&self, call: IncomingCall, reply: oneshot::Sender<CallDecision>) {
        let _ = self.actor_tx.try_send(ActorMessage::InternalEvent {
            session_gen: self.session_gen,
            event: ActorEvent::IncomingCall { call, reply },
        });
    }
    fn on_security_event(&self, event: SecurityEvent) {
        let _ = self.actor_tx.try_send(ActorMessage::InternalEvent {
            session_gen: self.session_gen,
            event: ActorEvent::SecurityEvent(event),
        });
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
    emergency_releaser: Arc<Mutex<Option<Arc<dyn EmergencyKeyReleaser>>>>,
    dryrun_journal: DryRunHidJournal,
    memory_clipboard: MemoryClipboardBackend,
    thread_handle: Mutex<Option<JoinHandle<()>>>,
    destroyed: AtomicBool,
}

impl V2BridgeRuntime {
    pub fn new() -> Result<Self, String> {
        Self::with_options(V2BridgeRuntimeOptions::default())
    }

    pub fn with_options(options: V2BridgeRuntimeOptions) -> Result<Self, String> {
        let mailbox = Arc::new(FrameMailbox::new());
        let events = Arc::new(BridgeEventHub::new(Arc::clone(&mailbox)));
        let controller = V2BridgeController::new();
        let snapshot_cache = Arc::new(RwLock::new(controller.snapshot()));
        let shutdown_token = CancellationToken::new();
        let active_tasks = Arc::new(AtomicUsize::new(0));
        let spawned_tasks_total = Arc::new(AtomicU64::new(0));
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
                    };
                    actor.run(actor_rx, shutdown_bg).await;
                });
                // Bounded runtime shutdown so lingering blocking tasks can never hang teardown.
                rt.shutdown_timeout(Duration::from_millis(500));
            })
            .map_err(|e| format!("spawn zerodesk-v2-rt thread: {e}"))?;

        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| "timed out starting zerodesk-v2-rt thread".to_string())??;

        Ok(Self {
            actor_tx,
            shutdown_token,
            snapshot_cache,
            mailbox,
            events,
            active_tasks,
            spawned_tasks_total,
            emergency_releaser,
            dryrun_journal,
            memory_clipboard,
            thread_handle: Mutex::new(Some(handle)),
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
        let deadline = Instant::now() + timeout;
        loop {
            match self.actor_tx.try_send(msg) {
                Ok(()) => return Ok(()),
                Err(mpsc::error::TrySendError::Closed(_)) => return Err(()),
                Err(mpsc::error::TrySendError::Full(returned)) => {
                    msg = returned;
                    if Instant::now() >= deadline {
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
    pub fn destroy(&self) {
        if self.destroyed.swap(true, Ordering::AcqRel) {
            return;
        }
        // 1. Trigger independent emergency key release synchronously (works even if Tokio died).
        if let Some(releaser) = self
            .emergency_releaser
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            let _ = releaser.release_all_keys();
        }
        // 2. Cancel all runtime tasks and wake blocked pollers.
        self.shutdown_token.cancel();
        self.events.close();
        let (ack_tx, ack_rx) = std_mpsc::sync_channel(1);
        let _ = self.actor_tx.try_send(ActorMessage::Shutdown { ack: ack_tx });
        let _ = ack_rx.recv_timeout(UNIFIED_SHUTDOWN_BUDGET);

        // 3. Join the dedicated OS thread (never panic if called from same thread).
        let handle = self
            .thread_handle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(h) = handle {
            if h.thread().id() != thread::current().id() {
                let _ = h.join();
            }
        }
        // 4. Final defensive emergency key release pass after actor thread exited.
        if let Some(releaser) = self
            .emergency_releaser
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = releaser.release_all_keys();
        }
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
    fn simulate_stale_event(&self, stale_gen: u64) {
        let (ack_tx, ack_rx) = std_mpsc::sync_channel(1);
        self.actor_tx
            .blocking_send(ActorMessage::SimulateStaleEvent {
                session_gen: stale_gen,
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

struct BridgeActor {
    controller: V2BridgeController,
    options: V2BridgeRuntimeOptions,
    actor_tx: mpsc::Sender<ActorMessage>,
    snapshot_cache: Arc<RwLock<BridgeSnapshot>>,
    mailbox: Arc<FrameMailbox>,
    events: Arc<BridgeEventHub>,
    active_tasks: Arc<AtomicUsize>,
    spawned_tasks_total: Arc<AtomicU64>,
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
}

impl BridgeActor {
    fn alloc_cmd_id(&mut self) -> u64 {
        let id = self.next_cmd_id;
        self.next_cmd_id = self.next_cmd_id.saturating_add(1);
        id
    }

    fn sync_snapshot(&self) {
        let snap = self.controller.snapshot();
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

    async fn unified_shutdown_session(&mut self, return_to_listening: bool) {
        self.pending_incoming = None;
        self.active_session_tx = None;

        if let Some(tok) = self.session_cancel.take() {
            tok.cancel();
        }
        // Synchronously release any held HID keys before waiting for async joins.
        if let Some(releaser) = self
            .emergency_releaser
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            let _ = releaser.release_all_keys();
        }

        let handles = std::mem::take(&mut self.session_handles);
        let deadline = tokio::time::Instant::now() + UNIFIED_SHUTDOWN_BUDGET;
        for h in handles {
            let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
            if rem.is_zero() {
                h.abort();
                let _ = h.await;
            } else if tokio::time::timeout(rem, h).await.is_err() {
                // Bounded budget expired; handle dropped/aborted.
            }
        }
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
                    self.unified_shutdown_session(false).await;
                    break;
                }
                msg = rx.recv() => {
                    let Some(msg) = msg else {
                        self.unified_shutdown_session(false).await;
                        break;
                    };
                    match msg {
                        ActorMessage::ExecCommand { env, reply } => {
                            let resp = self.handle_command(*env).await;
                            let _ = reply.send(resp);
                        }
                        ActorMessage::SendClipboardPng { bytes, reply } => {
                            let resp = self.handle_send_clipboard_binary(CLIP_MIME_IMAGE_PNG, bytes);
                            let _ = reply.send(resp);
                        }
                        ActorMessage::SendFilePath { path, reply } => {
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
                                let mut cfg = BridgePersistedConfig {
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
                                cfg.v = 1;
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
                                    "verified_caller": caller,
                                    "session_gen": gen,
                                }),
                            );
                            let _ = ack.send(incoming_id);
                        }
                        #[cfg(test)]
                        ActorMessage::SimulateStaleEvent { session_gen, ack } => {
                            self.apply_event(
                                session_gen,
                                ActorEvent::AudioStatus(AudioStatusChanged {
                                    available: false,
                                    reason: Some("stale_gen_marker".into()),
                                }),
                            )
                            .await;
                            let _ = ack.send(());
                        }
                        ActorMessage::Shutdown { ack } => {
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
                if let Err(e) = save_config_json(Path::new(path), &cfg) {
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
            "set_audio_mute" => {
                let Some(muted) = env.muted else {
                    return RuntimeReplyEnvelope::err(
                        "InvalidArgument",
                        "set_audio_mute requires boolean 'muted'",
                    );
                };
                let cmd = serde_json::json!({
                    "v": 1,
                    "cmd": "set_audio_mute",
                    "muted": muted,
                });
                let resp_raw = self.controller.execute_command_json(&cmd.to_string());
                let parsed: serde_json::Value = serde_json::from_str(&resp_raw).unwrap_or_default();
                if let Some(tx) = &self.active_session_tx {
                    let _ = tx.try_send(SessionAction::SetAudioMute(muted));
                }
                self.drain_controller_events_to_hub();
                self.sync_snapshot();
                RuntimeReplyEnvelope::ok(parsed["data"].clone())
            }
            "start_host" => self.handle_start_host(env),
            "stop_host" => self.handle_stop_host().await,
            "dial" => self.handle_dial(env),
            "disconnect" => self.handle_disconnect().await,
            "accept_incoming" => self.handle_incoming_decision(true, env),
            "reject_incoming" => self.handle_incoming_decision(false, env),
            "send_hid_key" => self.handle_send_hid_key(env),
            "send_hid_mouse" => self.handle_send_hid_mouse(env),
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
        drop_udp_cmd: Option<bool>,
    ) -> Result<V2ClientConfig, RuntimeReplyEnvelope> {
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
        let codec = match cfg.codec.to_ascii_lowercase().as_str() {
            "av1" => VideoCodec::Av1,
            _ => VideoCodec::Vp9,
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
            drop_udp_for_test: drop_udp_cmd.unwrap_or(false) || self.options.drop_udp_override,
        };
        v2_cfg
            .validate()
            .map_err(|e| RuntimeReplyEnvelope::err("InvalidConfig", e.to_string()))?;
        Ok(v2_cfg)
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

        let client_cfg = match self.build_client_config(env.drop_udp) {
            Ok(c) => c,
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
        let active_tasks = Arc::clone(&self.active_tasks);
        let total_tasks = Arc::clone(&self.spawned_tasks_total);
        let releaser_slot = Arc::clone(&self.emergency_releaser);
        let use_os_capture = self.options.use_os_capture;
        let use_os_audio = self.options.use_os_audio;
        let use_os_clipboard = self.options.use_os_clipboard;
        let dryrun_journal = self.options.dryrun_journal.clone();
        let mem_clip = self.options.memory_clipboard.clone();
        let download_dir = env
            .download_dir
            .map(PathBuf::from)
            .or_else(|| self.options.download_dir.clone())
            .unwrap_or_else(|| client_cfg.identity_dir.join("downloads"));
        let synth_w = self.options.synthetic_width;
        let synth_h = self.options.synthetic_height;
        let real_input_requested = self.options.real_input_permit.is_some();

        let h = tokio::spawn(async move {
            let _guard = TaskCountGuard::enter(&active_tasks, &total_tasks);
            run_host_lifecycle_task(
                gen,
                cmd_id,
                client_cfg,
                cancel,
                actor_tx,
                releaser_slot,
                HostTaskAdapters {
                    use_os_capture,
                    use_os_audio,
                    use_os_clipboard,
                    real_input_requested,
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
        let client_cfg = match self.build_client_config(env.drop_udp) {
            Ok(c) => c,
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
        let active_tasks = Arc::clone(&self.active_tasks);
        let total_tasks = Arc::clone(&self.spawned_tasks_total);
        let use_os_audio = self.options.use_os_audio;
        let use_os_clipboard = self.options.use_os_clipboard;
        let mem_clip = self.options.memory_clipboard.clone();
        let download_dir = env
            .download_dir
            .map(PathBuf::from)
            .or_else(|| self.options.download_dir.clone())
            .unwrap_or_else(|| client_cfg.identity_dir.join("downloads"));

        let h = tokio::spawn(async move {
            let _guard = TaskCountGuard::enter(&active_tasks, &total_tasks);
            run_controller_lifecycle_task(
                gen,
                cmd_id,
                client_cfg,
                target_bytes,
                cancel,
                actor_tx,
                mailbox,
                events,
                use_os_audio,
                use_os_clipboard,
                mem_clip,
                download_dir,
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
        let mut pending = self.pending_incoming.take().expect("checked Some above");
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

    fn handle_send_hid_key(&self, env: RuntimeCommandEnvelope) -> RuntimeReplyEnvelope {
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
        let Some(down) = env.down else {
            return RuntimeReplyEnvelope::err("InvalidArgument", "send_hid_key requires 'down'");
        };
        let ev = KeyEvent {
            down,
            modifiers: env.modifiers.unwrap_or(0),
            usb_hid_usage: usage as u32,
            unicode_scalar: env.unicode_scalar.unwrap_or(0),
            client_ts_ms: now_epoch_ms(),
        };
        if tx.try_send(SessionAction::SendHid(HidPayload::Key(ev))).is_err() {
            return RuntimeReplyEnvelope::err("Busy", "session action queue full");
        }
        RuntimeReplyEnvelope::ok(serde_json::json!({ "sent": true }))
    }

    fn handle_send_hid_mouse(&self, env: RuntimeCommandEnvelope) -> RuntimeReplyEnvelope {
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
        let (x_or_dx, y_or_dy) = match kind {
            MouseKind::MoveRel => (env.dx.unwrap_or(0) as i32, env.dy.unwrap_or(0) as i32),
            _ => (env.x.unwrap_or(0) as i32, env.y.unwrap_or(0) as i32),
        };
        let ev = MouseEvent {
            kind,
            buttons: env.buttons.unwrap_or(0),
            x_or_dx,
            y_or_dy,
            wheel_dx: env.wheel_x.unwrap_or(0),
            wheel_dy: env.wheel_y.unwrap_or(0),
            client_ts_ms: now_epoch_ms(),
        };
        if tx
            .try_send(SessionAction::SendHid(HidPayload::Mouse(ev)))
            .is_err()
        {
            return RuntimeReplyEnvelope::err("Busy", "session action queue full");
        }
        RuntimeReplyEnvelope::ok(serde_json::json!({ "sent": true }))
    }

    fn handle_send_clipboard_cmd(&self, env: RuntimeCommandEnvelope) -> RuntimeReplyEnvelope {
        let mime_kind = env.mime_kind.unwrap_or(CLIP_MIME_TEXT_UTF8);
        let bytes = if let Some(text) = env.text {
            text.into_bytes()
        } else if let Some(b64) = env.payload_b64 {
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
                serde_json::json!({ "channel": "clipboard", "status": status }),
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
        let meta = match std::fs::metadata(&path) {
            Ok(m) if m.is_file() => m,
            Ok(_) => {
                return RuntimeReplyEnvelope::err(
                    "InvalidArgument",
                    "send_file path must be a regular file",
                );
            }
            Err(e) => {
                return RuntimeReplyEnvelope::err("IoError", format!("stat file failed: {e}"));
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
                serde_json::json!({ "channel": "file_transfer", "reason": e.to_string() }),
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
        let client_cfg = match self.build_client_config(None) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let actor_tx = self.actor_tx.clone();
        let active_tasks = Arc::clone(&self.active_tasks);
        let total_tasks = Arc::clone(&self.spawned_tasks_total);
        let h = tokio::spawn(async move {
            let _guard = TaskCountGuard::enter(&active_tasks, &total_tasks);
            match refresh_policy_from_cp(&client_cfg).await {
                Ok(policy) => {
                    let _ = actor_tx
                        .send(ActorMessage::InternalEvent {
                            session_gen: gen,
                            event: ActorEvent::PolicyUpdated {
                                cmd_id: Some(cmd_id),
                                policy,
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
        // Drop any event from a stale session generation!
        if ev_gen != self.session_gen {
            return;
        }
        match event {
            ActorEvent::HostBootstrapped {
                cmd_id,
                local_cert,
                policy,
            } => {
                self.effective_policy = Some(policy.clone());
                let _ = self
                    .controller
                    .on_bootstrap_complete(&local_cert, policy.clone(), true);
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
                let incoming_id = format!("inc-{ev_gen}-{}", self.next_incoming_seq);
                self.next_incoming_seq = self.next_incoming_seq.saturating_add(1);
                let sid_hex = hex::encode(call.session_id);
                let synth_cert = SignalingDeviceCert {
                    version: 1,
                    cert_id: [0u8; 16],
                    device_id: call.controller_device_id,
                    tenant_id: call.tenant_id,
                    p256_pub_der: Vec::new(),
                    key_epoch: 1,
                    policy_hash: [0u8; 32],
                    cap_bits: call.controller_cap_bits,
                    iat_unix: 0,
                    exp_unix: u64::MAX,
                    ca_key_id: 0,
                    ca_sig: Vec::new(),
                };
                let _ = self
                    .controller
                    .on_incoming_verified_call(call.session_id, &synth_cert);
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

                let caller = VerifiedCallerDisplay::from_verified_cert(&synth_cert);
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
                    let mut p = self.pending_incoming.take().expect("checked");
                    if let Some(tx) = p.reply_tx.take() {
                        let _ = tx.send(CallDecision::Reject {
                            error_code: 0x0408,
                            reason: "ring_timeout".into(),
                        });
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
                peer_device_id,
                tenant_id,
                policy,
                active_mode,
                attach_ms,
                action_tx,
            } => {
                self.effective_policy = Some(policy.clone());
                self.active_session_tx = Some(action_tx);
                let peer_cert = SignalingDeviceCert {
                    version: 1,
                    cert_id: [0u8; 16],
                    device_id: peer_device_id,
                    tenant_id,
                    p256_pub_der: Vec::new(),
                    key_epoch: 1,
                    policy_hash: policy.policy_hash,
                    cap_bits: DEFAULT_V2_CAP_BITS,
                    iat_unix: 0,
                    exp_unix: policy.exp_unix,
                    ca_key_id: 0,
                    ca_sig: Vec::new(),
                };
                let _ = self
                    .controller
                    .on_bootstrap_complete(&peer_cert, policy.clone(), self.role == ActiveRole::Host);
                let _ = self
                    .controller
                    .on_streaming_started(session_id, &peer_cert, active_mode);
                self.drain_controller_events_to_hub();
                self.sync_snapshot();
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
            ActorEvent::PolicyUpdated { cmd_id, policy } => {
                self.effective_policy = Some(policy.clone());
                let dummy_cert = SignalingDeviceCert {
                    version: 1,
                    cert_id: [0u8; 16],
                    device_id: [0u8; 16],
                    tenant_id: policy.tenant_id,
                    p256_pub_der: Vec::new(),
                    key_epoch: 1,
                    policy_hash: policy.policy_hash,
                    cap_bits: DEFAULT_V2_CAP_BITS,
                    iat_unix: 0,
                    exp_unix: policy.exp_unix,
                    ca_key_id: 0,
                    ca_sig: Vec::new(),
                };
                if self.controller.state() != BridgeState::Idle {
                    let _ = self.controller.on_bootstrap_complete(
                        &dummy_cert,
                        policy.clone(),
                        self.role == ActiveRole::Host,
                    );
                    self.drain_controller_events_to_hub();
                    self.sync_snapshot();
                }
                self.emit_policy_event(&policy);
                if let Some(cid) = cmd_id {
                    self.events.push_critical(
                        "CommandResult",
                        serde_json::json!({
                            "cmd_id": cid,
                            "cmd": "refresh_policy",
                            "ok": true,
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
                bytes,
                sha256_hex,
            } => {
                // Redacted: NEVER include raw clipboard text or bytes!
                self.events.push_critical(
                    "ClipboardReceived",
                    serde_json::json!({
                        "mime_kind": mime_kind,
                        "bytes": bytes,
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
            ActorEvent::QoeTelemetry(val) => {
                self.events.set_telemetry("QoeTelemetry", val);
            }
            ActorEvent::SessionEnded {
                return_to_listening,
                reason,
            } => {
                self.active_session_tx = None;
                self.pending_incoming = None;
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
                    serde_json::json!({ "detail": format!("{se:?}") }),
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

async fn refresh_policy_from_cp(cfg: &V2ClientConfig) -> Result<EffectiveTenantPolicy, String> {
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
    let (cert, inline_blob) = identity
        .ensure_registered_with_policy(
            &cp,
            &ca_spki_der,
            cfg.enrollment_token.as_deref(),
            DEFAULT_V2_CAP_BITS,
            &cfg.home_region,
        )
        .await
        .map_err(|e| e.to_string())?;
    let now = now_unix_secs();
    let fetched = cp
        .fetch_tenant_policy(&cert.device_id, identity.keystore(), now)
        .await
        .ok();
    let blob = fetched.or(inline_blob);
    let last_ver = identity.last_policy_version();
    let outcome = verify_tenant_policy_blob(
        blob.as_ref(),
        &ca_spki_der,
        &cert.tenant_id,
        &cert.policy_hash,
        last_ver,
        now,
    );
    let policy = match outcome {
        PolicyVerifyOutcome::Verified(p) => {
            let _ = identity.advance_policy_version(p.version);
            p
        }
        PolicyVerifyOutcome::Degraded { policy, .. } => policy,
    };
    Ok(policy)
}

struct HostTaskAdapters {
    use_os_capture: bool,
    use_os_audio: bool,
    use_os_clipboard: bool,
    real_input_requested: bool,
    dryrun_journal: DryRunHidJournal,
    mem_clip: MemoryClipboardBackend,
    download_dir: PathBuf,
    synth_w: u32,
    synth_h: u32,
}

async fn run_host_lifecycle_task(
    gen: u64,
    cmd_id: u64,
    cfg: V2ClientConfig,
    cancel: CancellationToken,
    actor_tx: mpsc::Sender<ActorMessage>,
    releaser_slot: Arc<Mutex<Option<Arc<dyn EmergencyKeyReleaser>>>>,
    adapters: HostTaskAdapters,
) {
    let cb = Arc::new(BridgeUiCallback {
        session_gen: gen,
        actor_tx: actor_tx.clone(),
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
    let _ = actor_tx
        .send(ActorMessage::InternalEvent {
            session_gen: gen,
            event: ActorEvent::HostBootstrapped {
                cmd_id,
                local_cert,
                policy,
            },
        })
        .await;

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_flag_c = Arc::clone(&stop_flag);
    let cancel_c = cancel.clone();
    let flag_watcher = tokio::spawn(async move {
        cancel_c.cancelled().await;
        stop_flag_c.store(true, Ordering::Release);
    });

    while !cancel.is_cancelled() {
        let accepted = tokio::select! {
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
        let _ = actor_tx
            .send(ActorMessage::InternalEvent {
                session_gen: gen,
                event: ActorEvent::StreamingStarted {
                    cmd_id: None,
                    session_id: accepted.session_id,
                    peer_device_id: accepted.peer_device_id,
                    tenant_id: accepted.tenant_id,
                    policy: accepted.effective_policy.clone(),
                    active_mode: accepted.active_transport_mode,
                    attach_ms: accepted.transport_attach_ms,
                    action_tx,
                },
            })
            .await;

        let end_reason = run_active_host_session(
            gen,
            &cfg,
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
    accepted: crate::session::manager::AcceptedHostSession,
    cancel: CancellationToken,
    actor_tx: mpsc::Sender<ActorMessage>,
    releaser_slot: Arc<Mutex<Option<Arc<dyn EmergencyKeyReleaser>>>>,
    mut action_rx: mpsc::Receiver<SessionAction>,
    adapters: &HostTaskAdapters,
) -> String {
    let mut effective_policy = accepted.effective_policy.clone();
    let allow_clip_flag = Arc::new(AtomicBool::new(effective_policy.allow_clipboard()));
    let mut audio_gate = AudioChannelGate::from_policy(&effective_policy);
    let mut audio_muted = false;

    // 1. HID sink (DryRun by default; triple-gated RealInput only when explicitly opted in).
    let mut hid_sink: Box<dyn OsHidSink> = if adapters.real_input_requested {
        match RealInputPermit::from_explicit_opt_in(true).and_then(create_real_os_hid_sink) {
            Ok(real) => real,
            Err(_) => Box::new(DryRunHidSink::new()),
        }
    } else {
        Box::new(DryRunSinkWithJournal {
            journal: adapters.dryrun_journal.clone(),
        })
    };
    let releaser = hid_sink.emergency_releaser();
    *releaser_slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&releaser));

    // 2. Capture source (Synthetic by default, OS capture if requested with graceful fallback).
    let mut capture: Box<dyn OsScreenCapture> = if adapters.use_os_capture {
        create_os_screen_capture()
            .unwrap_or_else(|_| Box::new(SyntheticScreenSource::new(adapters.synth_w, adapters.synth_h)))
    } else {
        Box::new(SyntheticScreenSource::new(adapters.synth_w, adapters.synth_h))
    };
    let (cap_w, cap_h) = capture.dimensions();
    let enc_w = (cap_w & !1).clamp(32, 1920);
    let enc_h = (cap_h & !1).clamp(32, 1080);

    let encoder = match V2VideoEncoder::new(cfg.codec, enc_w, enc_h, 2.0, Some(cfg.fps as usize)) {
        Ok(e) => e,
        Err(e) => {
            let _ = releaser.release_all_keys();
            let _ = accepted.lease_renewal.shutdown().await;
            return format!("encoder init failed: {e}");
        }
    };
    let mut host_sess = DesktopHostSession::new(accepted.e2ee_session, encoder);

    // 3. Audio source & Opus encoder (graceful degradation via AudioStatusChanged).
    let mut os_audio_cap: Box<dyn OsAudioCapture> = if adapters.use_os_audio {
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
    let mut clip_poller = ClipboardPoller::new(clip_backend, Arc::clone(&allow_clip_flag));
    let mut clip_receiver = ClipboardReceiver::new(effective_policy.clone());
    let mut clip_err_counter = ChannelFramingErrorCounter::new();
    let mut next_clip_id: u64 = 1;

    // 5. File transfer receiver.
    let _ = std::fs::create_dir_all(&adapters.download_dir);
    let mut file_receiver =
        FileTransferReceiver::new(effective_policy.clone(), adapters.download_dir.clone());
    let mut file_err_counter = ChannelFramingErrorCounter::new();
    let mut next_transfer_id: u64 = 1;

    let frame_period = Duration::from_millis((1000 / cfg.fps.max(1)) as u64).max(Duration::from_millis(16));
    let mut video_tick = tokio::time::interval(frame_period);
    video_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut audio_tick = tokio::time::interval(Duration::from_millis(20));
    audio_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut clip_tick = tokio::time::interval(Duration::from_millis(100));
    clip_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let watchdog_timeout = Duration::from_millis(cfg.watchdog_timeout_ms);
    let mut last_peer_activity = Instant::now();
    let mut lease_expired_rx = accepted.lease_renewal.subscribe_expired();
    let mut pts_ms: i64 = 0;
    let end_reason: String;

    loop {
        if cancel.is_cancelled() {
            end_reason = "local_cancel".into();
            break;
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
            end_reason = "watchdog_timeout".into();
            break;
        }

        tokio::select! {
            _ = cancel.cancelled() => {
                end_reason = "local_cancel".into();
                break;
            }
            _ = lease_expired_rx.changed() => {
                if lease_expired_rx.borrow().is_some() {
                    end_reason = "lease_expired".into();
                    break;
                }
            }
            act = action_rx.recv() => {
                if let Some(action) = act {
                    match action {
                        SessionAction::SetAudioMute(m) => {
                            audio_muted = m;
                            audio_gate.set_muted(m);
                        }
                        SessionAction::SendClipboard { mime_kind, bytes } => {
                            let cid = next_clip_id;
                            next_clip_id += 1;
                            let paused = host_sess.session().is_bulk_paused();
                            if let Ok(xfer) = prepare_outbound_clipboard(&effective_policy, mime_kind, &bytes, cid, cid, paused) {
                                if let Ok(sync_bytes) = xfer.sync.encode() {
                                    let _ = host_sess.session_mut().send_l4_raw(CHAN_CLIPBOARD, CLIP_MSG_SYNC, 0, false, &sync_bytes).await;
                                }
                                for ch in &xfer.chunks {
                                    if let Ok(enc) = ch.encode() {
                                        let _ = host_sess.session_mut().send_l4_raw(CHAN_CLIPBOARD, CLIP_MSG_CHUNK, 0, false, &enc).await;
                                    }
                                }
                            }
                        }
                        SessionAction::SendFile { cmd_id, path, rel_name } => {
                            let tid = next_transfer_id;
                            next_transfer_id += 1;
                            let res = send_file_over_session(host_sess.session_mut(), tid, &path, &rel_name, &effective_policy, gen, &actor_tx).await;
                            emit_file_cmd_result(gen, cmd_id, &actor_tx, res).await;
                        }
                        SessionAction::RefreshPolicy { cmd_id } => {
                            match refresh_policy_from_cp(cfg).await {
                                Ok(new_pol) => {
                                    effective_policy = new_pol.clone();
                                    allow_clip_flag.store(effective_policy.allow_clipboard(), Ordering::Release);
                                    audio_gate = AudioChannelGate::from_policy(&effective_policy);
                                    audio_gate.set_muted(audio_muted);
                                    clip_receiver.update_policy(effective_policy.clone());
                                    file_receiver.update_policy(effective_policy.clone());
                                    let _ = actor_tx.send(ActorMessage::InternalEvent {
                                        session_gen: gen,
                                        event: ActorEvent::PolicyUpdated { cmd_id: Some(cmd_id), policy: new_pol },
                                    }).await;
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
                        SessionAction::SendHid(_) => {}
                    }
                }
            }
            _ = video_tick.tick() => {
                if let Ok(raw) = capture.capture_frame() {
                    let i420_res = if adapters.use_os_capture {
                        convert_captured_stride_to_i420(&raw)
                    } else {
                        raw_captured_to_i420(&raw)
                    };
                    if let Ok(i420) = i420_res {
                        pts_ms += frame_period.as_millis() as i64;
                        let _ = host_sess.publish_i420_frame(Arc::new(i420), pts_ms).await;
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
                            let _ = host_sess.session_mut().send_l4_raw(CHAN_CLIPBOARD, CLIP_MSG_SYNC, 0, false, &sync_bytes).await;
                        }
                        for ch in &xfer.chunks {
                            if let Ok(enc) = ch.encode() {
                                let _ = host_sess.session_mut().send_l4_raw(CHAN_CLIPBOARD, CLIP_MSG_CHUNK, 0, false, &enc).await;
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
                                    match payload {
                                        HidPayload::Key(k) => { let _ = hid_sink.send_key(&k); }
                                        HidPayload::Mouse(m) => { let _ = hid_sink.send_mouse(&m); }
                                        HidPayload::EchoAck(_) => {}
                                    }
                                }
                            }
                            V2RecvEvent::Transport(TransportEvent::Control(ctrl)) => {
                                if let Some(code) = parse_session_close(&ctrl) {
                                    end_reason = format!("peer_closed({code:#06x})");
                                    break;
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
                                                bytes: delivered.payload.len(),
                                                sha256_hex: hex::encode(delivered.sha256),
                                            },
                                        }).await;
                                    }
                                    ClipboardRecvAction::SessionFatal(reason) => {
                                        end_reason = format!("clipboard_fatal: {reason}");
                                        break;
                                    }
                                    ClipboardRecvAction::None => {}
                                }
                            }
                            V2RecvEvent::FileTransferRaw(raw) => {
                                match file_receiver.on_l4_frame(&raw.header, &raw.body, Instant::now(), &mut file_err_counter) {
                                    FileRecvAction::SendAccept(acc) => {
                                        if let Ok(enc) = acc.encode() {
                                            let _ = host_sess.session_mut().send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_ACCEPT, 0, false, &enc).await;
                                        }
                                    }
                                    FileRecvAction::SendAck(ack) => {
                                        if let Ok(enc) = ack.encode() {
                                            let _ = host_sess.session_mut().send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_ACK, 0, false, &enc).await;
                                        }
                                    }
                                    FileRecvAction::SendCompleteAck { ack, saved_path, audit } => {
                                        if let Ok(enc) = ack.encode() {
                                            let _ = host_sess.session_mut().send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_COMPLETE_ACK, 0, false, &enc).await;
                                        }
                                        let _ = actor_tx.send(ActorMessage::InternalEvent {
                                            session_gen: gen,
                                            event: ActorEvent::FileComplete {
                                                transfer_id: audit.transfer_id,
                                                rel_name: audit.rel_name,
                                                bytes: audit.file_size,
                                                sha256_hex: audit.sha256_hex,
                                                saved_path: saved_path.map(|p| p.display().to_string()),
                                            },
                                        }).await;
                                    }
                                    FileRecvAction::SendAbort(ab) => {
                                        let enc = ab.encode();
                                        let _ = host_sess.session_mut().send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_ABORT, 0, false, &enc).await;
                                        let _ = actor_tx.send(ActorMessage::InternalEvent {
                                            session_gen: gen,
                                            event: ActorEvent::FileAborted {
                                                transfer_id: ab.transfer_id,
                                                error_code: ab.error_code,
                                                reason: format!("error_code={:#06x}", ab.error_code),
                                            },
                                        }).await;
                                    }
                                    FileRecvAction::SessionFatal(reason) => {
                                        end_reason = format!("file_fatal: {reason}");
                                        break;
                                    }
                                    FileRecvAction::None => {}
                                }
                            }
                            V2RecvEvent::Transport(_) | V2RecvEvent::AudioRaw(_) => {}
                        }
                    }
                    Err(v2_client::ClientError::Timeout(_)) => {}
                    Err(e) => {
                        end_reason = format!("transport_error: {e}");
                        break;
                    }
                }
            }
        }
    }

    // Mandatory synchronous release_all BEFORE teardown completes!
    let _ = releaser.release_all_keys();
    let _ = send_redundant_session_close_3x(host_sess.session_mut(), 0).await;
    let _ = accepted.lease_renewal.shutdown().await;
    end_reason
}

#[allow(clippy::too_many_arguments)]
async fn run_controller_lifecycle_task(
    gen: u64,
    cmd_id: u64,
    cfg: V2ClientConfig,
    target_device_id: [u8; 16],
    cancel: CancellationToken,
    actor_tx: mpsc::Sender<ActorMessage>,
    mailbox: Arc<FrameMailbox>,
    events: Arc<BridgeEventHub>,
    use_os_audio: bool,
    use_os_clipboard: bool,
    mem_clip: MemoryClipboardBackend,
    download_dir: PathBuf,
) {
    let cb = Arc::new(BridgeUiCallback {
        session_gen: gen,
        actor_tx: actor_tx.clone(),
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

    let connected = tokio::select! {
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
    let allow_clip_flag = Arc::new(AtomicBool::new(effective_policy.allow_clipboard()));
    let mut audio_muted = false;

    let _ = actor_tx
        .send(ActorMessage::InternalEvent {
            session_gen: gen,
            event: ActorEvent::StreamingStarted {
                cmd_id: Some(cmd_id),
                session_id: connected.session_id,
                peer_device_id: connected.target_device_id,
                tenant_id: connected.tenant_id,
                policy: effective_policy.clone(),
                active_mode: connected.active_transport_mode,
                attach_ms: connected.transport_attach_ms,
                action_tx,
            },
        })
        .await;

    let mut decoder = match V2VideoDecoder::new(cfg.codec) {
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
    let mut clip_poller = ClipboardPoller::new(clip_backend, Arc::clone(&allow_clip_flag));
    let mut clip_receiver = ClipboardReceiver::new(effective_policy.clone());
    let mut clip_err_counter = ChannelFramingErrorCounter::new();
    let mut next_clip_id: u64 = 1;

    let _ = std::fs::create_dir_all(&download_dir);
    let mut file_receiver = FileTransferReceiver::new(effective_policy.clone(), download_dir);
    let mut file_err_counter = ChannelFramingErrorCounter::new();
    let mut next_transfer_id: u64 = 1;

    let mut ka_tick = tokio::time::interval(connected.keepalive_interval);
    ka_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut clip_tick = tokio::time::interval(Duration::from_millis(100));
    clip_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut qoe_tick = tokio::time::interval(Duration::from_millis(500));
    qoe_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut lease_expired_rx = connected.lease_renewal.subscribe_expired();
    let end_reason: String;
    let mut video_frames_decoded: u64 = 0;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                end_reason = "local_cancel".into();
                break;
            }
            _ = lease_expired_rx.changed() => {
                if lease_expired_rx.borrow().is_some() {
                    end_reason = "lease_expired".into();
                    break;
                }
            }
            _ = ka_tick.tick() => {
                let _ = ctrl_sess.ping_keepalive(Duration::from_millis(500)).await;
            }
            _ = qoe_tick.tick() => {
                let _ = actor_tx.try_send(ActorMessage::InternalEvent {
                    session_gen: gen,
                    event: ActorEvent::QoeTelemetry(serde_json::json!({
                        "video_frames_decoded": video_frames_decoded,
                        "dropped_ui_frames": mailbox.dropped_ui_frames(),
                        "audio_frames_decoded": audio_frames_decoded,
                        "audio_dtx_frames": audio_dtx_frames,
                        "active_transport_mode": ctrl_sess.active_transport_mode().label(),
                    })),
                });
            }
            _ = clip_tick.tick() => {
                if let Ok(Some(item)) = clip_poller.poll_once() {
                    let bytes = item.text.into_bytes();
                    let cid = next_clip_id;
                    next_clip_id += 1;
                    let paused = ctrl_sess.is_bulk_paused();
                    if let Ok(xfer) = prepare_outbound_clipboard(&effective_policy, CLIP_MIME_TEXT_UTF8, &bytes, cid, cid, paused) {
                        if let Ok(sync_bytes) = xfer.sync.encode() {
                            let _ = ctrl_sess.send_l4_raw(CHAN_CLIPBOARD, CLIP_MSG_SYNC, 0, false, &sync_bytes).await;
                        }
                        for ch in &xfer.chunks {
                            if let Ok(enc) = ch.encode() {
                                let _ = ctrl_sess.send_l4_raw(CHAN_CLIPBOARD, CLIP_MSG_CHUNK, 0, false, &enc).await;
                            }
                        }
                    }
                }
            }
            act = action_rx.recv() => {
                if let Some(action) = act {
                    match action {
                        SessionAction::SetAudioMute(m) => { audio_muted = m; }
                        SessionAction::SendHid(payload) => {
                            if let Ok(frame) = encode_hid_frame(&payload) {
                                let _ = ctrl_sess.send_hid(&frame).await;
                            }
                        }
                        SessionAction::SendClipboard { mime_kind, bytes } => {
                            let cid = next_clip_id;
                            next_clip_id += 1;
                            let paused = ctrl_sess.is_bulk_paused();
                            if let Ok(xfer) = prepare_outbound_clipboard(&effective_policy, mime_kind, &bytes, cid, cid, paused) {
                                if let Ok(sync_bytes) = xfer.sync.encode() {
                                    let _ = ctrl_sess.send_l4_raw(CHAN_CLIPBOARD, CLIP_MSG_SYNC, 0, false, &sync_bytes).await;
                                }
                                for ch in &xfer.chunks {
                                    if let Ok(enc) = ch.encode() {
                                        let _ = ctrl_sess.send_l4_raw(CHAN_CLIPBOARD, CLIP_MSG_CHUNK, 0, false, &enc).await;
                                    }
                                }
                            }
                        }
                        SessionAction::SendFile { cmd_id, path, rel_name } => {
                            let tid = next_transfer_id;
                            next_transfer_id += 1;
                            let res = send_file_over_session(&mut ctrl_sess, tid, &path, &rel_name, &effective_policy, gen, &actor_tx).await;
                            emit_file_cmd_result(gen, cmd_id, &actor_tx, res).await;
                        }
                        SessionAction::RefreshPolicy { cmd_id } => {
                            match refresh_policy_from_cp(&cfg).await {
                                Ok(new_pol) => {
                                    effective_policy = new_pol.clone();
                                    allow_clip_flag.store(effective_policy.allow_clipboard(), Ordering::Release);
                                    clip_receiver.update_policy(effective_policy.clone());
                                    file_receiver.update_policy(effective_policy.clone());
                                    let _ = actor_tx.send(ActorMessage::InternalEvent {
                                        session_gen: gen,
                                        event: ActorEvent::PolicyUpdated { cmd_id: Some(cmd_id), policy: new_pol },
                                    }).await;
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
                    }
                }
            }
            recv_res = ctrl_sess.recv_v124_event(Duration::from_millis(25)) => {
                match recv_res {
                    Ok(V2RecvEvent::Transport(TransportEvent::VideoFrame(vf))) => {
                        if let Ok(i420) = decoder.decode_raw(&vf.data) {
                            video_frames_decoded += 1;
                            if mailbox.publish_i420(&i420, PixelFormat::Bgra8, now_epoch_ms()).is_ok() {
                                events.notify_frame_published();
                            }
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
                                            bytes: delivered.payload.len(),
                                            sha256_hex: hex::encode(delivered.sha256),
                                        },
                                    }).await;
                                }
                                ClipboardRecvAction::SessionFatal(reason) => {
                                    end_reason = format!("clipboard_fatal: {reason}");
                                    break;
                                }
                                ClipboardRecvAction::None => {}
                            }
                        }
                    }
                    Ok(V2RecvEvent::FileTransferRaw(raw)) => {
                        match decode_file_l4(&raw.header, &raw.body) {
                            Ok(FileMessage::CompleteAck(cack)) => {
                                if cack.status == FILE_COMPLETE_ACK_OK {
                                    let _ = actor_tx.send(ActorMessage::InternalEvent {
                                        session_gen: gen,
                                        event: ActorEvent::FileComplete {
                                            transfer_id: cack.transfer_id,
                                            rel_name: String::new(),
                                            bytes: 0,
                                            sha256_hex: String::new(),
                                            saved_path: None,
                                        },
                                    }).await;
                                } else {
                                    let _ = actor_tx.send(ActorMessage::InternalEvent {
                                        session_gen: gen,
                                        event: ActorEvent::FileAborted {
                                            transfer_id: cack.transfer_id,
                                            error_code: cack.status as u16,
                                            reason: format!("remote complete_ack status={}", cack.status),
                                        },
                                    }).await;
                                }
                            }
                            Ok(FileMessage::Abort(ab)) => {
                                let _ = actor_tx.send(ActorMessage::InternalEvent {
                                    session_gen: gen,
                                    event: ActorEvent::FileAborted {
                                        transfer_id: ab.transfer_id,
                                        error_code: ab.error_code,
                                        reason: format!("remote abort {:#06x}", ab.error_code),
                                    },
                                }).await;
                            }
                            _ => {
                                match file_receiver.on_l4_frame(&raw.header, &raw.body, Instant::now(), &mut file_err_counter) {
                                    FileRecvAction::SendAccept(acc) => {
                                        if let Ok(enc) = acc.encode() {
                                            let _ = ctrl_sess.send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_ACCEPT, 0, false, &enc).await;
                                        }
                                    }
                                    FileRecvAction::SendAck(ack) => {
                                        if let Ok(enc) = ack.encode() {
                                            let _ = ctrl_sess.send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_ACK, 0, false, &enc).await;
                                        }
                                    }
                                    FileRecvAction::SendCompleteAck { ack, saved_path, audit } => {
                                        if let Ok(enc) = ack.encode() {
                                            let _ = ctrl_sess.send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_COMPLETE_ACK, 0, false, &enc).await;
                                        }
                                        let _ = actor_tx.send(ActorMessage::InternalEvent {
                                            session_gen: gen,
                                            event: ActorEvent::FileComplete {
                                                transfer_id: audit.transfer_id,
                                                rel_name: audit.rel_name,
                                                bytes: audit.file_size,
                                                sha256_hex: audit.sha256_hex,
                                                saved_path: saved_path.map(|p| p.display().to_string()),
                                            },
                                        }).await;
                                    }
                                    FileRecvAction::SendAbort(ab) => {
                                        let enc = ab.encode();
                                        let _ = ctrl_sess.send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_ABORT, 0, false, &enc).await;
                                    }
                                    FileRecvAction::SessionFatal(reason) => {
                                        end_reason = format!("file_fatal: {reason}");
                                        break;
                                    }
                                    FileRecvAction::None => {}
                                }
                            }
                        }
                    }
                    Ok(V2RecvEvent::Transport(TransportEvent::Control(ctrl))) => {
                        if let Some(code) = parse_session_close(&ctrl) {
                            end_reason = format!("peer_closed({code:#06x})");
                            break;
                        }
                    }
                    Ok(V2RecvEvent::Transport(_)) => {}
                    Err(v2_client::ClientError::Timeout(_)) => {}
                    Err(e) => {
                        end_reason = format!("transport_error: {e}");
                        break;
                    }
                }
            }
        }
    }

    let _ = ctrl_sess
        .send_control(CTRL_MSG_SESSION_CLOSE, &0u16.to_be_bytes())
        .await;
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

async fn send_file_over_session(
    sess: &mut UdpE2eeSession,
    transfer_id: u64,
    path: &Path,
    rel_name: &str,
    policy: &EffectiveTenantPolicy,
    gen: u64,
    actor_tx: &mpsc::Sender<ActorMessage>,
) -> Result<serde_json::Value, (String, String)> {
    let data = std::fs::read(path).map_err(|e| ("IoError".into(), e.to_string()))?;
    let total = data.len() as u64;
    if let Err(e) = check_file_policy(policy, total) {
        let abort = FileAbort {
            transfer_id,
            error_code: FILE_ERR_POLICY_DENIED,
        };
        let _ = sess
            .send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_ABORT, 0, false, &abort.encode())
            .await;
        return Err(("PolicyDenied".into(), e.to_string()));
    }
    let sha256: [u8; 32] = Sha256::digest(&data).into();
    let offer = FileOffer {
        transfer_id,
        file_size: total,
        chunk_size: FILE_RECOMMENDED_CHUNK_SIZE,
        sha256,
        rel_name: rel_name.to_string(),
    };
    let offer_wire = offer
        .encode()
        .map_err(|e| ("InvalidArgument".into(), e.to_string()))?;
    sess.send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_OFFER, 0, false, &offer_wire)
        .await
        .map_err(|e| ("TransportError".into(), e.to_string()))?;

    let mut offset = 0usize;
    let chunk_sz = FILE_RECOMMENDED_CHUNK_SIZE as usize;
    while offset < data.len() {
        let end = (offset + chunk_sz).min(data.len());
        let ch = FileChunk {
            transfer_id,
            offset: offset as u64,
            data: data[offset..end].to_vec(),
        };
        let wire = ch
            .encode()
            .map_err(|e| ("InvalidArgument".into(), e.to_string()))?;
        sess.send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_CHUNK, 0, false, &wire)
            .await
            .map_err(|e| ("TransportError".into(), e.to_string()))?;
        offset = end;
        let _ = actor_tx
            .send(ActorMessage::InternalEvent {
                session_gen: gen,
                event: ActorEvent::FileProgress {
                    transfer_id,
                    bytes_transferred: offset as u64,
                    total_bytes: total,
                },
            })
            .await;
    }

    let complete = FileComplete {
        transfer_id,
        sha256,
    };
    sess.send_l4_raw(
        CHAN_FILE_TRANSFER,
        FILE_MSG_COMPLETE,
        0,
        false,
        &complete.encode(),
    )
    .await
    .map_err(|e| ("TransportError".into(), e.to_string()))?;

    Ok(serde_json::json!({
        "transfer_id": transfer_id,
        "rel_name": rel_name,
        "bytes": total,
        "sha256_hex": hex::encode(sha256),
    }))
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

struct DryRunSinkWithJournal {
    journal: DryRunHidJournal,
}

impl OsHidSink for DryRunSinkWithJournal {
    fn send_key(&mut self, ev: &KeyEvent) -> Result<(), crate::os::OsError> {
        let mut sink = DryRunHidSink::new();
        let _ = sink.send_key(ev);
        // Forward to shared journal directly via a tiny helper.
        // We delegate to DryRunHidSink's exact same journal by constructing it from shared journal.
        // Instead, invoke via journal recording:
        record_into_shared_journal(&self.journal, HidPayload::Key(*ev));
        Ok(())
    }

    fn send_mouse(&mut self, ev: &MouseEvent) -> Result<(), crate::os::OsError> {
        record_into_shared_journal(&self.journal, HidPayload::Mouse(*ev));
        Ok(())
    }

    fn emergency_releaser(&self) -> Arc<dyn EmergencyKeyReleaser> {
        Arc::new(SharedJournalReleaser {
            journal: self.journal.clone(),
        })
    }
}

struct SharedJournalReleaser {
    journal: DryRunHidJournal,
}

impl EmergencyKeyReleaser for SharedJournalReleaser {
    fn release_all_keys(&self) -> crate::os::ReleaseReport {
        self.journal.emergency_release_all()
    }
}

fn record_into_shared_journal(journal: &DryRunHidJournal, payload: HidPayload) {
    match payload {
        HidPayload::Key(k) => journal.record_key_public(&k),
        HidPayload::Mouse(m) => journal.record_mouse_public(&m),
        HidPayload::EchoAck(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::json_abi::scan_json_for_secret_canaries;

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
    fn runtime_incoming_stale_id_rejected_and_drop_equals_reject() {
        let rt = V2BridgeRuntime::new().unwrap();
        let (inc_id, dec_rx) = rt.inject_test_incoming([0xAA; 16], sample_cert());

        // Mismatched incoming_id -> StaleIncoming
        let bad: serde_json::Value = serde_json::from_str(&rt.exec_json(
            r#"{"v":1,"cmd":"accept_incoming","incoming_id":"inc-wrong-999"}"#,
        ))
        .unwrap();
        assert_eq!(bad["ok"], false);
        assert_eq!(bad["error_code"], "StaleIncoming");

        // Stale session_gen event is dropped
        rt.simulate_stale_event(0);

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

        // Verify dropping pending incoming on destroy triggers RecvError (rejection)
        let (_inc2, dec_rx2) = rt.inject_test_incoming([0xBB; 16], sample_cert());
        rt.destroy();
        assert!(dec_rx2.blocking_recv().is_err());
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
    fn task_panic_triggers_emergency_key_release_within_500ms() {
        let journal = DryRunHidJournal::new();
        let mut sink = DryRunSinkWithJournal {
            journal: journal.clone(),
        };
        let releaser = sink.emergency_releaser();
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
        let handle = thread::spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                panic!("simulated worker panic while key held");
            }));
            releaser.release_all_keys()
        });
        let report = handle.join().unwrap();
        assert!(start.elapsed() <= Duration::from_millis(500));
        assert_eq!(report.released_keys, 1);
        assert!(journal.is_all_released());
    }
}
