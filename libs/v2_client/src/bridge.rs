// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use crate::{error::ClientError, udp_session::UdpE2eeSession};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    io::{self, Read, Write},
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc as std_mpsc, Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, watch},
    task::JoinHandle,
};
use v2_transport::{
    TransportEvent, VerifiedTenantPolicy, CHAN_CLIPBOARD, CHAN_FILE_TRANSFER, CHAN_INPUT_HID,
    CHAN_TRANSPORT_CTRL,
};

pub const BRIDGE_MAX_CHUNK_BYTES: usize = 1000;
pub const BRIDGE_CHANNEL_CAPACITY: usize = 256;
pub const MAX_REORDER_WINDOW: usize = 256;
pub const MAX_RETRANSMIT_ATTEMPTS: u32 = 16;
pub const MAX_RETRANSMIT_TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
pub const PEER_EOF_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

const TUNNEL_MSG_DATA: u8 = 0x10;
const TUNNEL_MSG_EOF: u8 = 0x11;
const TUNNEL_MSG_ACK: u8 = 0x12;
const TUNNEL_MAX_INFLIGHT: usize = 4;
const TUNNEL_RTO: Duration = Duration::from_millis(80);

/// Strictly internal seam for unit-testing `V2ServiceStream` and `V2LoopbackBridge`
/// without requiring live UDP sockets.
#[allow(dead_code)]
pub(crate) trait V2DesktopTransport: Send + 'static {
    fn policy(&self) -> VerifiedTenantPolicy;

    fn send_chunk(
        &mut self,
        chan_id: u8,
        msg_type: u8,
        payload: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), ClientError>> + Send;

    fn recv_chunk(
        &mut self,
        timeout: Duration,
    ) -> impl std::future::Future<Output = Result<Option<(u8, u8, Vec<u8>)>, ClientError>> + Send;
}

impl V2DesktopTransport for UdpE2eeSession {
    fn policy(&self) -> VerifiedTenantPolicy {
        self.policy().clone()
    }

    async fn send_chunk(
        &mut self,
        chan_id: u8,
        msg_type: u8,
        payload: Vec<u8>,
    ) -> Result<(), ClientError> {
        self.send_channel_frame(chan_id, msg_type, 0, false, &payload)
            .await?;
        Ok(())
    }

    async fn recv_chunk(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<(u8, u8, Vec<u8>)>, ClientError> {
        match self.recv_event(timeout).await {
            Ok(TransportEvent::Control(f)) => {
                Ok(Some((CHAN_TRANSPORT_CTRL, f.msg_type, f.payload.to_vec())))
            }
            Ok(TransportEvent::Hid(f)) => {
                Ok(Some((CHAN_INPUT_HID, f.msg_type, f.payload.to_vec())))
            }
            Ok(TransportEvent::Clipboard(f)) => {
                Ok(Some((CHAN_CLIPBOARD, 0x01, f.payload.to_vec())))
            }
            Ok(TransportEvent::FileTransfer(f)) => {
                Ok(Some((CHAN_FILE_TRANSFER, f.msg_type, f.payload.to_vec())))
            }
            Ok(_) => Ok(None),
            Err(ClientError::Timeout(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[derive(Debug, Clone)]
struct OutboundChunk {
    chan_id: u8,
    msg_type: u8,
    payload: Vec<u8>,
}

type TunnelChannelPair = (
    mpsc::Sender<OutboundChunk>,
    mpsc::Receiver<(u8, Vec<u8>)>,
);

enum StreamSink {
    Sync {
        tx: Option<std_mpsc::SyncSender<Vec<u8>>>,
        overflowed: Arc<AtomicBool>,
    },
    Async(mpsc::Sender<(u8, Vec<u8>)>),
}

/// Bounded sliding-window reorder buffer (`MAX_REORDER_WINDOW = 256`) for TCP-over-V2 tunnel frames.
/// Rejects forged or out-of-window future `seq` values (`seq.wrapping_sub(next_rx_seq) >= 256`)
/// so a hostile peer can never grow memory past `MAX_REORDER_WINDOW`.
#[derive(Debug, Default)]
pub struct TunnelReorderBuffer {
    next_rx_seq: u32,
    buf: BTreeMap<u32, (u8, Vec<u8>)>,
}

impl TunnelReorderBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn next_rx_seq(&self) -> u32 {
        self.next_rx_seq
    }

    /// Inserts an arriving `(seq, msg_type, data)` if within `[next_rx_seq, next_rx_seq + MAX_REORDER_WINDOW)`.
    /// Returns `(should_ack, ready_in_order_items)`.
    pub fn insert_and_drain(
        &mut self,
        seq: u32,
        msg_type: u8,
        data: Vec<u8>,
    ) -> (bool, Vec<(u8, Vec<u8>)>) {
        let offset = seq.wrapping_sub(self.next_rx_seq);
        if offset >= 0x8000_0000 {
            let behind = self.next_rx_seq.wrapping_sub(seq);
            return (behind <= MAX_REORDER_WINDOW as u32, Vec::new());
        }
        if offset >= MAX_REORDER_WINDOW as u32 {
            return (false, Vec::new());
        }
        if !self.buf.contains_key(&seq) && self.buf.len() >= MAX_REORDER_WINDOW {
            return (false, Vec::new());
        }
        self.buf.entry(seq).or_insert((msg_type, data));

        let mut ready = Vec::new();
        while let Some(item) = self.buf.remove(&self.next_rx_seq) {
            self.next_rx_seq = self.next_rx_seq.wrapping_add(1);
            ready.push(item);
        }
        (true, ready)
    }
}

/// Multi-stream multiplexer owning a live E2EE V2 session on a background Tokio task,
/// demultiplexing incoming L4 channel payloads into per-`chan_id` `V2ServiceStream`s
/// or `V2LoopbackBridge` TCP tunnels while enforcing `VerifiedTenantPolicy`.
pub struct V2SessionMux {
    policy: VerifiedTenantPolicy,
    tx_out: mpsc::Sender<OutboundChunk>,
    sinks: Arc<Mutex<HashMap<u8, StreamSink>>>,
    shutdown_tx: watch::Sender<bool>,
    pump_task: Option<JoinHandle<()>>,
}

impl V2SessionMux {
    pub fn spawn_udp(session: UdpE2eeSession) -> Self {
        Self::spawn_internal(session)
    }

    pub(crate) fn spawn_internal<T: V2DesktopTransport>(mut transport: T) -> Self {
        let policy = transport.policy();
        let policy_bg = policy.clone();
        let (tx_out, mut rx_out) = mpsc::channel::<OutboundChunk>(BRIDGE_CHANNEL_CAPACITY);
        let sinks: Arc<Mutex<HashMap<u8, StreamSink>>> = Arc::new(Mutex::new(HashMap::new()));
        let sinks_bg = Arc::clone(&sinks);
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let pump_task = tokio::spawn(async move {
            loop {
                if *shutdown_rx.borrow() {
                    break;
                }
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    maybe_out = rx_out.recv() => {
                        match maybe_out {
                            Some(chunk) => {
                                if policy_bg.enforce_channel(chunk.chan_id, false).is_err() {
                                    continue;
                                }
                                if transport.send_chunk(chunk.chan_id, chunk.msg_type, chunk.payload).await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                    recv_res = transport.recv_chunk(Duration::from_millis(20)) => {
                        match recv_res {
                            Ok(Some((chan_id, msg_type, data))) => {
                                let mut guard = sinks_bg.lock().unwrap_or_else(|e| e.into_inner());
                                if let Some(sink) = guard.get_mut(&chan_id) {
                                    match sink {
                                        StreamSink::Sync { tx, overflowed } => {
                                            if let Some(sender) = tx.as_ref() {
                                                match sender.try_send(data) {
                                                    Ok(()) => {}
                                                    Err(std_mpsc::TrySendError::Full(_)) => {
                                                        // V2ServiceStream has no transport-layer retransmit:
                                                        // poison and disconnect the sink instead of silently dropping bytes.
                                                        overflowed.store(true, Ordering::Release);
                                                        *tx = None;
                                                    }
                                                    Err(std_mpsc::TrySendError::Disconnected(_)) => {
                                                        *tx = None;
                                                    }
                                                }
                                            }
                                        }
                                        StreamSink::Async(tx) => {
                                            // V2LoopbackBridge uses sequence-numbered ARQ retransmit;
                                            // dropping on full queue triggers peer RTO without head-of-line
                                            // blocking other multiplexed channels.
                                            let _ = tx.try_send((msg_type, data));
                                        }
                                    }
                                }
                            }
                            Ok(None) => {}
                            Err(ClientError::Transport(v2_transport::TransportError::Closed)) => break,
                            Err(_) => {}
                        }
                    }
                }
            }
            // Drain any already-queued outbound chunks (including TUNNEL_MSG_EOF) before exit.
            while let Ok(chunk) = rx_out.try_recv() {
                if policy_bg.enforce_channel(chunk.chan_id, false).is_err() {
                    continue;
                }
                if transport
                    .send_chunk(chunk.chan_id, chunk.msg_type, chunk.payload)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        Self {
            policy,
            tx_out,
            sinks,
            shutdown_tx,
            pump_task: Some(pump_task),
        }
    }

    pub fn policy(&self) -> &VerifiedTenantPolicy {
        &self.policy
    }

    /// Opens a synchronous `std::io::Read + std::io::Write` service stream bound to `chan_id`,
    /// enforcing `VerifiedTenantPolicy::enforce_channel` before opening.
    pub fn open_service_stream(
        &self,
        chan_id: u8,
        read_timeout: Option<Duration>,
    ) -> Result<V2ServiceStream, ClientError> {
        self.open_service_stream_internal(chan_id, read_timeout, false)
    }

    /// Opens a synchronous TCP-tunnel `V2ServiceStream`, enforcing both `enforce_tcp_tunnel`
    /// and `enforce_channel` before opening and on every write.
    pub fn open_tcp_tunnel_stream(
        &self,
        chan_id: u8,
        read_timeout: Option<Duration>,
    ) -> Result<V2ServiceStream, ClientError> {
        self.open_service_stream_internal(chan_id, read_timeout, true)
    }

    fn open_service_stream_internal(
        &self,
        chan_id: u8,
        read_timeout: Option<Duration>,
        require_tcp_tunnel: bool,
    ) -> Result<V2ServiceStream, ClientError> {
        if require_tcp_tunnel {
            self.policy.enforce_tcp_tunnel()?;
        }
        self.policy.enforce_channel(chan_id, false)?;
        let (tx_in, rx_in) = std_mpsc::sync_channel(BRIDGE_CHANNEL_CAPACITY);
        let inbound_overflowed = Arc::new(AtomicBool::new(false));
        {
            let mut guard = self.sinks.lock().unwrap_or_else(|e| e.into_inner());
            if guard.contains_key(&chan_id) {
                return Err(ClientError::Config(format!(
                    "channel {chan_id:#04x} already bound to a service stream"
                )));
            }
            guard.insert(
                chan_id,
                StreamSink::Sync {
                    tx: Some(tx_in),
                    overflowed: Arc::clone(&inbound_overflowed),
                },
            );
        }
        Ok(V2ServiceStream {
            chan_id,
            policy: self.policy.clone(),
            require_tcp_tunnel,
            tx_out: self.tx_out.clone(),
            rx_in,
            inbound_overflowed,
            read_buf: VecDeque::new(),
            read_timeout,
            sinks: Arc::clone(&self.sinks),
        })
    }

    fn open_async_tunnel_channel(&self, chan_id: u8) -> Result<TunnelChannelPair, ClientError> {
        self.policy.enforce_tcp_tunnel()?;
        self.policy.enforce_channel(chan_id, false)?;
        let (tx_in, rx_in) = mpsc::channel(BRIDGE_CHANNEL_CAPACITY);
        {
            let mut guard = self.sinks.lock().unwrap_or_else(|e| e.into_inner());
            if guard.contains_key(&chan_id) {
                return Err(ClientError::Config(format!(
                    "channel {chan_id:#04x} already bound"
                )));
            }
            guard.insert(chan_id, StreamSink::Async(tx_in));
        }
        Ok((self.tx_out.clone(), rx_in))
    }

    pub async fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.pump_task.take() {
            let abort_handle = handle.abort_handle();
            if tokio::time::timeout(Duration::from_secs(2), handle)
                .await
                .is_err()
            {
                abort_handle.abort();
            }
        }
    }
}

impl Drop for V2SessionMux {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// External Integration Seam #1: synchronous `std::io::Read + std::io::Write` byte stream
/// multiplexed over a specific V2 L4 `ChannelId` (`0x00..0x06`), with bounded queues and
/// active `VerifiedTenantPolicy` enforcement.
pub struct V2ServiceStream {
    chan_id: u8,
    policy: VerifiedTenantPolicy,
    require_tcp_tunnel: bool,
    tx_out: mpsc::Sender<OutboundChunk>,
    rx_in: std_mpsc::Receiver<Vec<u8>>,
    inbound_overflowed: Arc<AtomicBool>,
    read_buf: VecDeque<u8>,
    read_timeout: Option<Duration>,
    sinks: Arc<Mutex<HashMap<u8, StreamSink>>>,
}

impl V2ServiceStream {
    pub fn channel_id(&self) -> u8 {
        self.chan_id
    }

    pub fn policy(&self) -> &VerifiedTenantPolicy {
        &self.policy
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }
}

impl Drop for V2ServiceStream {
    fn drop(&mut self) {
        let mut guard = self.sinks.lock().unwrap_or_else(|e| e.into_inner());
        guard.remove(&self.chan_id);
    }
}

impl Write for V2ServiceStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.require_tcp_tunnel {
            self.policy
                .enforce_tcp_tunnel()
                .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
        }
        self.policy
            .enforce_channel(self.chan_id, false)
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
        if buf.is_empty() {
            return Ok(0);
        }
        let mut written = 0usize;
        for chunk in buf.chunks(BRIDGE_MAX_CHUNK_BYTES) {
            match self.tx_out.try_send(OutboundChunk {
                chan_id: self.chan_id,
                msg_type: TUNNEL_MSG_DATA,
                payload: chunk.to_vec(),
            }) {
                Ok(()) => written += chunk.len(),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    if written > 0 {
                        return Ok(written);
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "V2 outbound queue full (backpressure)",
                    ));
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "V2 mux closed"));
                }
            }
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for V2ServiceStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.inbound_overflowed.load(Ordering::Acquire) {
            return Err(io::Error::other(
                "V2ServiceStream inbound queue overflowed (frames dropped)",
            ));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        if self.read_buf.is_empty() {
            let chunk = match self.read_timeout {
                Some(dur) => self.rx_in.recv_timeout(dur).map_err(|e| match e {
                    std_mpsc::RecvTimeoutError::Timeout => {
                        io::Error::new(io::ErrorKind::TimedOut, "V2ServiceStream read timed out")
                    }
                    std_mpsc::RecvTimeoutError::Disconnected => {
                        if self.inbound_overflowed.load(Ordering::Acquire) {
                            io::Error::other(
                                "V2ServiceStream inbound queue overflowed (frames dropped)",
                            )
                        } else {
                            io::Error::new(io::ErrorKind::UnexpectedEof, "V2ServiceStream closed")
                        }
                    }
                })?,
                None => self.rx_in.recv().map_err(|_| {
                    if self.inbound_overflowed.load(Ordering::Acquire) {
                        io::Error::other(
                            "V2ServiceStream inbound queue overflowed (frames dropped)",
                        )
                    } else {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "V2ServiceStream closed")
                    }
                })?,
            };
            self.read_buf.extend(chunk);
        }
        let n = buf.len().min(self.read_buf.len());
        for slot in buf.iter_mut().take(n) {
            if let Some(b) = self.read_buf.pop_front() {
                *slot = b;
            }
        }
        Ok(n)
    }
}

/// External Integration Seam #2: `127.0.0.1:<port>` local TCP proxy that transparently
/// tunnels raw TCP byte streams over an authenticated E2EE V2 session.
pub struct V2LoopbackBridge {
    local_addr: SocketAddr,
    listener: TcpListener,
    chan_id: u8,
    policy: VerifiedTenantPolicy,
    tx_out: mpsc::Sender<OutboundChunk>,
    rx_in: mpsc::Receiver<(u8, Vec<u8>)>,
    sinks: Arc<Mutex<HashMap<u8, StreamSink>>>,
}

impl Drop for V2LoopbackBridge {
    fn drop(&mut self) {
        let mut guard = self.sinks.lock().unwrap_or_else(|e| e.into_inner());
        guard.remove(&self.chan_id);
    }
}

impl V2LoopbackBridge {
    /// Binds a loopback-only (`127.0.0.1:<port>`) TCP listener backed by `chan_id` on `mux`.
    /// Enforces `VerifiedTenantPolicy::enforce_tcp_tunnel` and `enforce_channel` before binding.
    pub async fn bind(
        listen_addr: &str,
        mux: &V2SessionMux,
        chan_id: u8,
    ) -> Result<Self, ClientError> {
        mux.policy.enforce_tcp_tunnel()?;
        mux.policy.enforce_channel(chan_id, false)?;
        let parsed: SocketAddr = listen_addr.parse().map_err(|e| {
            ClientError::Config(format!("invalid loopback listen addr '{listen_addr}': {e}"))
        })?;
        if !parsed.ip().is_loopback() {
            return Err(ClientError::Config(format!(
                "V2LoopbackBridge MUST bind to a loopback address, refused '{parsed}'"
            )));
        }
        let listener = TcpListener::bind(parsed).await?;
        let local_addr = listener.local_addr()?;
        let (tx_out, rx_in) = mux.open_async_tunnel_channel(chan_id)?;
        Ok(Self {
            local_addr,
            listener,
            chan_id,
            policy: mux.policy.clone(),
            tx_out,
            rx_in,
            sinks: Arc::clone(&mux.sinks),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Accepts one local TCP connection and pumps raw bytes bidirectionally over the E2EE V2 tunnel.
    /// Returns `(bytes_tx_to_v2, bytes_rx_from_v2)`.
    pub async fn serve_one(mut self) -> Result<(u64, u64), ClientError> {
        self.policy.enforce_tcp_tunnel()?;
        self.policy.enforce_channel(self.chan_id, false)?;
        let (tcp, _) = self.listener.accept().await?;
        let _ = tcp.set_nodelay(true);
        let res = pipe_tcp_over_v2(
            tcp,
            self.chan_id,
            self.tx_out.clone(),
            &mut self.rx_in,
            MAX_RETRANSMIT_ATTEMPTS,
            MAX_RETRANSMIT_TOTAL_TIMEOUT,
            PEER_EOF_IDLE_TIMEOUT,
        )
        .await;
        let mut guard = self.sinks.lock().unwrap_or_else(|e| e.into_inner());
        guard.remove(&self.chan_id);
        res
    }

    /// Peer-side counterpart: connects to a local loopback TCP target and pipes bytes
    /// bidirectionally with the E2EE V2 tunnel channel.
    pub async fn forward_to_loopback_target(
        target_addr: SocketAddr,
        mux: &V2SessionMux,
        chan_id: u8,
    ) -> Result<(u64, u64), ClientError> {
        mux.policy.enforce_tcp_tunnel()?;
        mux.policy.enforce_channel(chan_id, false)?;
        if !target_addr.ip().is_loopback() {
            return Err(ClientError::Config(format!(
                "forward target must be loopback, refused '{target_addr}'"
            )));
        }
        let (tx_out, mut rx_in) = mux.open_async_tunnel_channel(chan_id)?;
        let tcp = match TcpStream::connect(target_addr).await {
            Ok(s) => s,
            Err(e) => {
                let mut guard = mux.sinks.lock().unwrap_or_else(|e| e.into_inner());
                guard.remove(&chan_id);
                return Err(e.into());
            }
        };
        let _ = tcp.set_nodelay(true);
        let res = pipe_tcp_over_v2(
            tcp,
            chan_id,
            tx_out,
            &mut rx_in,
            MAX_RETRANSMIT_ATTEMPTS,
            MAX_RETRANSMIT_TOTAL_TIMEOUT,
            PEER_EOF_IDLE_TIMEOUT,
        )
        .await;
        let mut guard = mux.sinks.lock().unwrap_or_else(|e| e.into_inner());
        guard.remove(&chan_id);
        res
    }
}

struct UnackedEntry {
    msg_type: u8,
    framed: Vec<u8>,
    first_sent: Instant,
    last_sent: Instant,
    attempts: u32,
}

async fn pipe_tcp_over_v2(
    tcp: TcpStream,
    chan_id: u8,
    tx_out: mpsc::Sender<OutboundChunk>,
    rx_in: &mut mpsc::Receiver<(u8, Vec<u8>)>,
    max_retransmit_attempts: u32,
    max_retransmit_total_timeout: Duration,
    peer_eof_idle_timeout: Duration,
) -> Result<(u64, u64), ClientError> {
    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    let mut tx_bytes = 0u64;
    let mut rx_bytes = 0u64;
    let mut read_buf = [0u8; BRIDGE_MAX_CHUNK_BYTES];
    let mut local_eof = false;
    let mut last_peer_rx_at = Instant::now();
    let mut remote_eof = false;

    let mut next_tx_seq = 0u32;
    let mut unacked: BTreeMap<u32, UnackedEntry> = BTreeMap::new();
    let mut reorder = TunnelReorderBuffer::new();
    let mut rto_tick = tokio::time::interval(Duration::from_millis(40));

    while !(local_eof && unacked.is_empty() && remote_eof) {
        let can_read_local = !local_eof && unacked.len() < TUNNEL_MAX_INFLIGHT;
        let monitor_timeout = !unacked.is_empty() || (local_eof && !remote_eof);
        tokio::select! {
            _ = rto_tick.tick(), if monitor_timeout => {
                let now = Instant::now();
                for entry in unacked.values_mut() {
                    if now.duration_since(entry.first_sent) >= max_retransmit_total_timeout {
                        let _ = tcp_w.shutdown().await;
                        return Err(ClientError::Timeout(
                            "V2 tunnel retransmit total timeout exceeded (peer unresponsive)".into(),
                        ));
                    }
                    if now.duration_since(entry.last_sent) >= TUNNEL_RTO {
                        if entry.attempts >= max_retransmit_attempts {
                            let _ = tcp_w.shutdown().await;
                            return Err(ClientError::Timeout(format!(
                                "V2 tunnel retransmit max attempts ({max_retransmit_attempts}) exceeded (peer unresponsive)"
                            )));
                        }
                        entry.attempts = entry.attempts.saturating_add(1);
                        entry.last_sent = now;
                        tx_out
                            .send(OutboundChunk {
                                chan_id,
                                msg_type: entry.msg_type,
                                payload: entry.framed.clone(),
                            })
                            .await
                            .map_err(|_| ClientError::Protocol("V2 mux closed during retransmit".into()))?;
                    }
                }
                if local_eof
                    && unacked.is_empty()
                    && !remote_eof
                    && last_peer_rx_at.elapsed() >= peer_eof_idle_timeout
                {
                    let _ = tcp_w.shutdown().await;
                    return Err(ClientError::Timeout(
                        "V2 tunnel timed out waiting for peer EOF".into(),
                    ));
                }
            }
            read_res = tcp_r.read(&mut read_buf), if can_read_local => {
                let n = read_res?;
                let seq = next_tx_seq;
                next_tx_seq = next_tx_seq.wrapping_add(1);
                let now = Instant::now();
                let (msg_type, framed) = if n == 0 {
                    local_eof = true;
                    last_peer_rx_at = now;
                    (TUNNEL_MSG_EOF, seq.to_be_bytes().to_vec())
                } else {
                    tx_bytes = tx_bytes.saturating_add(n as u64);
                    let mut v = Vec::with_capacity(4 + n);
                    v.extend_from_slice(&seq.to_be_bytes());
                    v.extend_from_slice(&read_buf[..n]);
                    (TUNNEL_MSG_DATA, v)
                };
                unacked.insert(
                    seq,
                    UnackedEntry {
                        msg_type,
                        framed: framed.clone(),
                        first_sent: now,
                        last_sent: now,
                        attempts: 0,
                    },
                );
                tx_out
                    .send(OutboundChunk {
                        chan_id,
                        msg_type,
                        payload: framed,
                    })
                    .await
                    .map_err(|_| ClientError::Protocol("V2 mux closed while forwarding TCP".into()))?;
            }
            maybe_in = rx_in.recv() => {
                let Some((msg_type, payload)) = maybe_in else {
                    let _ = tcp_w.shutdown().await;
                    return Err(ClientError::Protocol("V2 tunnel inbound channel closed before EOF".into()));
                };
                if payload.len() < 4 {
                    continue;
                }
                let seq = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                match msg_type {
                    TUNNEL_MSG_ACK => {
                        if unacked.remove(&seq).is_some() && local_eof {
                            last_peer_rx_at = Instant::now();
                        }
                    }
                    TUNNEL_MSG_DATA | TUNNEL_MSG_EOF => {
                        let has_data = payload.len() > 4;
                        let prev_reorder_len = reorder.len();
                        let (should_ack, ready) =
                            reorder.insert_and_drain(seq, msg_type, payload[4..].to_vec());
                        if has_data && (reorder.len() > prev_reorder_len || !ready.is_empty()) {
                            last_peer_rx_at = Instant::now();
                        }
                        if should_ack {
                            tx_out
                                .send(OutboundChunk {
                                    chan_id,
                                    msg_type: TUNNEL_MSG_ACK,
                                    payload: seq.to_be_bytes().to_vec(),
                                })
                                .await
                                .map_err(|_| ClientError::Protocol("V2 mux closed while sending ACK".into()))?;
                        }
                        for (kind, data) in ready {
                            if kind == TUNNEL_MSG_EOF {
                                remote_eof = true;
                                let _ = tcp_w.shutdown().await;
                            } else if !data.is_empty() {
                                tcp_w.write_all(&data).await?;
                                tcp_w.flush().await?;
                                rx_bytes = rx_bytes.saturating_add(data.len() as u64);
                                last_peer_rx_at = Instant::now();
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok((tx_bytes, rx_bytes))
}

/// Default V2 channel used by `V2LoopbackBridge` when tunneling desktop bytes (`p3`, bulk-safe).
pub const DEFAULT_BRIDGE_CHANNEL: u8 = CHAN_FILE_TRANSFER;

#[cfg(test)]
mod tests {
    use super::*;
    use v2_identity::{DeviceCert, DeviceKeyStore, SoftwareDeviceKeyStore, TenantPolicyBlob};
    use v2_transport::{QuotaExhaustPolicy, TenantPolicyRules};

    fn make_policy(allow_tcp_tunnel: bool, allow_file_transfer: bool) -> VerifiedTenantPolicy {
        let ca = SoftwareDeviceKeyStore::generate();
        let ca_spki = ca.public_key_spki_der().unwrap();
        let dev = SoftwareDeviceKeyStore::generate();
        let rules = TenantPolicyRules {
            allow_file_transfer,
            allow_clipboard: true,
            allow_file_clipboard: allow_file_transfer,
            allow_tcp_tunnel,
            allow_terminal: false,
            allow_realtime_actuator: false,
            bw_cap_kbps: 10_000,
            exhaust_policy: QuotaExhaustPolicy::Throttle256Kbps,
        };
        let mut cert = DeviceCert {
            version: 1,
            cert_id: [1; 16],
            device_id: [2; 16],
            tenant_id: [3; 16],
            p256_pub_der: dev.public_key_spki_der().unwrap(),
            key_epoch: 1,
            policy_hash: rules.canonical_hash(),
            cap_bits: 0x3FFF,
            iat_unix: 100,
            exp_unix: 10_000,
            hardware_backed: false,
            sig_der: Vec::new(),
        };
        cert.sig_der = ca.sign_p256_low_s(&cert.tbs_bytes().unwrap()).unwrap();
        let mut blob = TenantPolicyBlob {
            tenant_id: [3; 16],
            version: 1,
            policy_hash: rules.canonical_hash(),
            iat_unix: 100,
            exp_unix: 10_000,
            sig_der: Vec::new(),
        };
        blob.sig_der = ca.sign_p256_low_s(&blob.tbs_bytes()).unwrap();
        VerifiedTenantPolicy::from_verified_blob(&blob, &cert, &rules, &ca_spki, 200).unwrap()
    }

    struct BlackholeTransport {
        policy: VerifiedTenantPolicy,
    }

    impl V2DesktopTransport for BlackholeTransport {
        fn policy(&self) -> VerifiedTenantPolicy {
            self.policy.clone()
        }

        async fn send_chunk(
            &mut self,
            _chan_id: u8,
            _msg_type: u8,
            _payload: Vec<u8>,
        ) -> Result<(), ClientError> {
            Ok(())
        }

        async fn recv_chunk(
            &mut self,
            timeout: Duration,
        ) -> Result<Option<(u8, u8, Vec<u8>)>, ClientError> {
            tokio::time::sleep(timeout).await;
            Ok(None)
        }
    }

    struct SlowSendTransport {
        policy: VerifiedTenantPolicy,
        release: Arc<tokio::sync::Notify>,
    }

    impl V2DesktopTransport for SlowSendTransport {
        fn policy(&self) -> VerifiedTenantPolicy {
            self.policy.clone()
        }

        async fn send_chunk(
            &mut self,
            _chan_id: u8,
            _msg_type: u8,
            _payload: Vec<u8>,
        ) -> Result<(), ClientError> {
            self.release.notified().await;
            Err(ClientError::Transport(v2_transport::TransportError::Closed))
        }

        async fn recv_chunk(
            &mut self,
            timeout: Duration,
        ) -> Result<Option<(u8, u8, Vec<u8>)>, ClientError> {
            tokio::time::sleep(timeout).await;
            Ok(None)
        }
    }

    #[test]
    fn reorder_buffer_bounds_forged_future_seqs() {
        let mut reorder = TunnelReorderBuffer::new();
        for forged_seq in 256u32..5000u32 {
            let (ack, ready) = reorder.insert_and_drain(forged_seq, TUNNEL_MSG_DATA, vec![0xAA; 16]);
            assert!(!ack, "forged future seq {forged_seq} must not be ACKed");
            assert!(ready.is_empty());
            assert_eq!(reorder.len(), 0);
        }
        for seq in 1u32..500u32 {
            let (ack, ready) = reorder.insert_and_drain(seq, TUNNEL_MSG_DATA, vec![seq as u8]);
            if seq < MAX_REORDER_WINDOW as u32 {
                assert!(ack);
            } else {
                assert!(!ack);
            }
            assert!(ready.is_empty());
            assert!(reorder.len() <= MAX_REORDER_WINDOW);
        }
        assert_eq!(reorder.len(), MAX_REORDER_WINDOW - 1);

        let (ack, ready) = reorder.insert_and_drain(0, TUNNEL_MSG_DATA, vec![0]);
        assert!(ack);
        assert_eq!(ready.len(), MAX_REORDER_WINDOW);
        assert_eq!(reorder.len(), 0);
        assert_eq!(reorder.next_rx_seq(), MAX_REORDER_WINDOW as u32);
    }

    #[tokio::test]
    async fn vanished_peer_terminates_cleanly_with_retransmit_error() {
        let policy = make_policy(true, true);
        let mux = V2SessionMux::spawn_internal(BlackholeTransport { policy });
        let bridge = V2LoopbackBridge::bind("127.0.0.1:0", &mux, DEFAULT_BRIDGE_CHANNEL)
            .await
            .unwrap();
        let addr = bridge.local_addr();
        let serve = tokio::spawn(bridge.serve_one());

        let mut cli = TcpStream::connect(addr).await.unwrap();
        cli.write_all(b"hello-to-vanished-peer").await.unwrap();
        cli.shutdown().await.unwrap();

        let res = tokio::time::timeout(Duration::from_secs(5), serve)
            .await
            .expect("serve_one must terminate via bounded retransmit instead of hanging")
            .unwrap();
        assert!(matches!(res, Err(ClientError::Timeout(_))));
        mux.shutdown().await;
    }

    #[tokio::test]
    async fn service_stream_bounded_outbound_backpressure() {
        let policy = make_policy(true, true);
        let release = Arc::new(tokio::sync::Notify::new());
        let mux = V2SessionMux::spawn_internal(SlowSendTransport {
            policy,
            release: Arc::clone(&release),
        });
        let mut stream = mux
            .open_service_stream(CHAN_INPUT_HID, Some(Duration::from_millis(50)))
            .unwrap();

        let mut hit_backpressure = false;
        for _ in 0..(BRIDGE_CHANNEL_CAPACITY + 32) {
            match stream.write(b"ping") {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    hit_backpressure = true;
                    break;
                }
                Err(e) => panic!("unexpected write error: {e}"),
            }
        }
        assert!(
            hit_backpressure,
            "bounded outbound channel must apply WouldBlock backpressure instead of OOM"
        );
        release.notify_waiters();
        mux.shutdown().await;
    }

    struct FloodRecvTransport {
        policy: VerifiedTenantPolicy,
        chan_id: u8,
        remaining: usize,
        start_rx: watch::Receiver<bool>,
        done_tx: watch::Sender<bool>,
    }

    impl V2DesktopTransport for FloodRecvTransport {
        fn policy(&self) -> VerifiedTenantPolicy {
            self.policy.clone()
        }

        async fn send_chunk(
            &mut self,
            _chan_id: u8,
            _msg_type: u8,
            _payload: Vec<u8>,
        ) -> Result<(), ClientError> {
            Ok(())
        }

        async fn recv_chunk(
            &mut self,
            timeout: Duration,
        ) -> Result<Option<(u8, u8, Vec<u8>)>, ClientError> {
            if !*self.start_rx.borrow() {
                let _ = tokio::time::timeout(timeout, self.start_rx.changed()).await;
                return Ok(None);
            }
            if self.remaining > 0 {
                self.remaining -= 1;
                return Ok(Some((
                    self.chan_id,
                    TUNNEL_MSG_DATA,
                    b"flood-chunk".to_vec(),
                )));
            }
            let _ = self.done_tx.send(true);
            tokio::time::sleep(timeout).await;
            Ok(None)
        }
    }

    #[tokio::test]
    async fn half_closed_bridge_stays_alive_while_peer_streams_data_past_idle_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (cli_res, srv_res) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let mut cli = cli_res.unwrap();
        let (srv, _) = srv_res.unwrap();

        let (tx_out, mut rx_out) = mpsc::channel::<OutboundChunk>(BRIDGE_CHANNEL_CAPACITY);
        let (tx_in, mut rx_in) = mpsc::channel::<(u8, Vec<u8>)>(BRIDGE_CHANNEL_CAPACITY);
        let idle_timeout = Duration::from_millis(200);

        let pipe = tokio::spawn(async move {
            pipe_tcp_over_v2(
                srv,
                DEFAULT_BRIDGE_CHANNEL,
                tx_out,
                &mut rx_in,
                MAX_RETRANSMIT_ATTEMPTS,
                MAX_RETRANSMIT_TOTAL_TIMEOUT,
                idle_timeout,
            )
            .await
        });

        cli.write_all(b"req").await.unwrap();
        cli.shutdown().await.unwrap();

        let mut expected = Vec::new();
        let peer = tokio::spawn(async move {
            // ACK local DATA (seq 0) and local EOF (seq 1).
            let mut saw_local_eof = false;
            while !saw_local_eof {
                let chunk = rx_out.recv().await.unwrap();
                let seq = u32::from_be_bytes(chunk.payload[..4].try_into().unwrap());
                if chunk.msg_type == TUNNEL_MSG_EOF {
                    saw_local_eof = true;
                }
                tx_in
                    .send((TUNNEL_MSG_ACK, seq.to_be_bytes().to_vec()))
                    .await
                    .unwrap();
            }

            // Stream 6 chunks spaced 80ms apart (~480ms > 200ms idle_timeout) after local EOF.
            let mut sent = Vec::new();
            for seq in 0u32..6u32 {
                tokio::time::sleep(Duration::from_millis(80)).await;
                let piece = format!("chunk-{seq}|");
                sent.extend_from_slice(piece.as_bytes());
                let mut framed = Vec::with_capacity(4 + piece.len());
                framed.extend_from_slice(&seq.to_be_bytes());
                framed.extend_from_slice(piece.as_bytes());
                tx_in.send((TUNNEL_MSG_DATA, framed)).await.unwrap();
            }
            tx_in
                .send((TUNNEL_MSG_EOF, 6u32.to_be_bytes().to_vec()))
                .await
                .unwrap();
            // Drain ACKs including ACK for peer EOF so tx_out stays open until pipe finishes.
            while let Some(chunk) = rx_out.recv().await {
                if chunk.msg_type == TUNNEL_MSG_ACK
                    && chunk.payload.len() >= 4
                    && u32::from_be_bytes(chunk.payload[..4].try_into().unwrap()) == 6
                {
                    break;
                }
            }
            sent
        });

        let mut received = Vec::new();
        cli.read_to_end(&mut received).await.unwrap();
        expected.extend_from_slice(&peer.await.unwrap());

        let (tx_bytes, rx_bytes) = tokio::time::timeout(Duration::from_secs(3), pipe)
            .await
            .expect("pipe must complete once peer sends EOF")
            .unwrap()
            .expect("active inbound traffic must keep half-closed bridge alive past idle timeout");
        assert_eq!(tx_bytes, 3);
        assert_eq!(rx_bytes, expected.len() as u64);
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn half_closed_bridge_times_out_when_peer_stalls_without_eof() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (cli_res, srv_res) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let mut cli = cli_res.unwrap();
        let (srv, _) = srv_res.unwrap();

        let (tx_out, mut rx_out) = mpsc::channel::<OutboundChunk>(BRIDGE_CHANNEL_CAPACITY);
        let (tx_in, mut rx_in) = mpsc::channel::<(u8, Vec<u8>)>(BRIDGE_CHANNEL_CAPACITY);
        let idle_timeout = Duration::from_millis(200);

        let pipe = tokio::spawn(async move {
            pipe_tcp_over_v2(
                srv,
                DEFAULT_BRIDGE_CHANNEL,
                tx_out,
                &mut rx_in,
                MAX_RETRANSMIT_ATTEMPTS,
                MAX_RETRANSMIT_TOTAL_TIMEOUT,
                idle_timeout,
            )
            .await
        });

        cli.write_all(b"req").await.unwrap();
        cli.shutdown().await.unwrap();

        let _peer = tokio::spawn(async move {
            let mut saw_local_eof = false;
            while !saw_local_eof {
                let chunk = rx_out.recv().await.unwrap();
                let seq = u32::from_be_bytes(chunk.payload[..4].try_into().unwrap());
                if chunk.msg_type == TUNNEL_MSG_EOF {
                    saw_local_eof = true;
                }
                tx_in
                    .send((TUNNEL_MSG_ACK, seq.to_be_bytes().to_vec()))
                    .await
                    .unwrap();
            }
            tokio::time::sleep(Duration::from_millis(80)).await;
            let mut framed = Vec::new();
            framed.extend_from_slice(&0u32.to_be_bytes());
            framed.extend_from_slice(b"partial");
            tx_in.send((TUNNEL_MSG_DATA, framed)).await.unwrap();
            // Keep tx_in open and never send TUNNEL_MSG_EOF to simulate a stalled peer.
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(tx_in);
        });

        let mut received = Vec::new();
        cli.read_to_end(&mut received).await.unwrap();
        let res = tokio::time::timeout(Duration::from_secs(2), pipe)
            .await
            .expect("stalled peer must time out cleanly")
            .unwrap();
        assert!(matches!(res, Err(ClientError::Timeout(_))));
        assert_eq!(received, b"partial");
    }

    #[tokio::test]
    async fn service_stream_inbound_overflow_returns_error_instead_of_silent_drop() {
        let policy = make_policy(true, true);
        let (start_tx, start_rx) = watch::channel(false);
        let (done_tx, mut done_rx) = watch::channel(false);
        let mux = V2SessionMux::spawn_internal(FloodRecvTransport {
            policy,
            chan_id: CHAN_INPUT_HID,
            remaining: BRIDGE_CHANNEL_CAPACITY + 4,
            start_rx,
            done_tx,
        });
        let mut stream = mux
            .open_service_stream(CHAN_INPUT_HID, Some(Duration::from_millis(200)))
            .unwrap();

        start_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), done_rx.wait_for(|&done| done))
            .await
            .expect("flood transport should finish delivering chunks")
            .unwrap();

        let mut buf = [0u8; 64];
        let err = stream
            .read(&mut buf)
            .expect_err("inbound queue overflow must return an error instead of silently dropping");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(
            err.to_string().contains("overflow"),
            "unexpected error message: {err}"
        );
        mux.shutdown().await;
    }
}
