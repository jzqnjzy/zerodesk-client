use crate::{error::ClientError, udp_session::UdpE2eeSession};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    io::{self, Read, Write},
    net::SocketAddr,
    sync::{mpsc as std_mpsc, Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, watch},
    task::JoinHandle,
};
use v2_transport::{
    TransportEvent, CHAN_CLIPBOARD, CHAN_FILE_TRANSFER, CHAN_INPUT_HID, CHAN_TRANSPORT_CTRL,
};

pub const BRIDGE_MAX_CHUNK_BYTES: usize = 1000;
const TUNNEL_MSG_DATA: u8 = 0x10;
const TUNNEL_MSG_EOF: u8 = 0x11;
const TUNNEL_MSG_ACK: u8 = 0x12;
const TUNNEL_MAX_INFLIGHT: usize = 4;
const TUNNEL_RTO: Duration = Duration::from_millis(80);

/// Strictly internal seam for unit-testing `V2ServiceStream` and `V2LoopbackBridge`
/// without requiring live UDP sockets.
#[allow(dead_code)]
pub(crate) trait V2DesktopTransport: Send + 'static {
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
    mpsc::UnboundedSender<OutboundChunk>,
    mpsc::UnboundedReceiver<(u8, Vec<u8>)>,
);

enum StreamSink {
    Sync(std_mpsc::Sender<Vec<u8>>),
    Async(mpsc::UnboundedSender<(u8, Vec<u8>)>),
}

/// Multi-stream multiplexer owning a live E2EE V2 session on a background Tokio task,
/// demultiplexing incoming L4 channel payloads into per-`chan_id` `V2ServiceStream`s
/// or `V2LoopbackBridge` TCP tunnels.
pub struct V2SessionMux {
    tx_out: mpsc::UnboundedSender<OutboundChunk>,
    sinks: Arc<Mutex<HashMap<u8, StreamSink>>>,
    shutdown_tx: watch::Sender<bool>,
    pump_task: Option<JoinHandle<()>>,
}

impl V2SessionMux {
    pub fn spawn_udp(session: UdpE2eeSession) -> Self {
        Self::spawn_internal(session)
    }

    pub(crate) fn spawn_internal<T: V2DesktopTransport>(mut transport: T) -> Self {
        let (tx_out, mut rx_out) = mpsc::unbounded_channel::<OutboundChunk>();
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
                                let guard = sinks_bg.lock().unwrap_or_else(|e| e.into_inner());
                                if let Some(sink) = guard.get(&chan_id) {
                                    match sink {
                                        StreamSink::Sync(tx) => {
                                            let _ = tx.send(data);
                                        }
                                        StreamSink::Async(tx) => {
                                            let _ = tx.send((msg_type, data));
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
            tx_out,
            sinks,
            shutdown_tx,
            pump_task: Some(pump_task),
        }
    }

    /// Opens a synchronous `std::io::Read + std::io::Write` service stream bound to `chan_id`,
    /// ready for Phase 2 `hbb_common::SocketClient` integration.
    pub fn open_service_stream(
        &self,
        chan_id: u8,
        read_timeout: Option<Duration>,
    ) -> Result<V2ServiceStream, ClientError> {
        let (tx_in, rx_in) = std_mpsc::channel();
        {
            let mut guard = self.sinks.lock().unwrap_or_else(|e| e.into_inner());
            if guard.contains_key(&chan_id) {
                return Err(ClientError::Config(format!(
                    "channel {chan_id:#04x} already bound to a service stream"
                )));
            }
            guard.insert(chan_id, StreamSink::Sync(tx_in));
        }
        Ok(V2ServiceStream {
            chan_id,
            tx_out: self.tx_out.clone(),
            rx_in,
            read_buf: VecDeque::new(),
            read_timeout,
            sinks: Arc::clone(&self.sinks),
        })
    }

    fn open_async_tunnel_channel(&self, chan_id: u8) -> Result<TunnelChannelPair, ClientError> {
        let (tx_in, rx_in) = mpsc::unbounded_channel();
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
            let _ = handle.await;
        }
    }
}

impl Drop for V2SessionMux {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// External Integration Seam #1: synchronous `std::io::Read + std::io::Write` byte stream
/// multiplexed over a specific V2 L4 `ChannelId` (`0x00..0x06`).
pub struct V2ServiceStream {
    chan_id: u8,
    tx_out: mpsc::UnboundedSender<OutboundChunk>,
    rx_in: std_mpsc::Receiver<Vec<u8>>,
    read_buf: VecDeque<u8>,
    read_timeout: Option<Duration>,
    sinks: Arc<Mutex<HashMap<u8, StreamSink>>>,
}

impl V2ServiceStream {
    pub fn channel_id(&self) -> u8 {
        self.chan_id
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
        if buf.is_empty() {
            return Ok(0);
        }
        for chunk in buf.chunks(BRIDGE_MAX_CHUNK_BYTES) {
            self.tx_out
                .send(OutboundChunk {
                    chan_id: self.chan_id,
                    msg_type: TUNNEL_MSG_DATA,
                    payload: chunk.to_vec(),
                })
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "V2 mux closed"))?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for V2ServiceStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
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
                        io::Error::new(io::ErrorKind::UnexpectedEof, "V2ServiceStream closed")
                    }
                })?,
                None => self.rx_in.recv().map_err(|_| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "V2ServiceStream closed")
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
    tx_out: mpsc::UnboundedSender<OutboundChunk>,
    rx_in: mpsc::UnboundedReceiver<(u8, Vec<u8>)>,
    sinks: Arc<Mutex<HashMap<u8, StreamSink>>>,
}

impl V2LoopbackBridge {
    /// Binds a loopback-only (`127.0.0.1:<port>`) TCP listener backed by `chan_id` on `mux`.
    pub async fn bind(
        listen_addr: &str,
        mux: &V2SessionMux,
        chan_id: u8,
    ) -> Result<Self, ClientError> {
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
        let (tcp, _) = self.listener.accept().await?;
        let _ = tcp.set_nodelay(true);
        let res = pipe_tcp_over_v2(tcp, self.chan_id, self.tx_out.clone(), &mut self.rx_in).await;
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
        if !target_addr.ip().is_loopback() {
            return Err(ClientError::Config(format!(
                "forward target must be loopback, refused '{target_addr}'"
            )));
        }
        let (tx_out, mut rx_in) = mux.open_async_tunnel_channel(chan_id)?;
        let tcp = TcpStream::connect(target_addr).await?;
        let _ = tcp.set_nodelay(true);
        let res = pipe_tcp_over_v2(tcp, chan_id, tx_out, &mut rx_in).await;
        let mut guard = mux.sinks.lock().unwrap_or_else(|e| e.into_inner());
        guard.remove(&chan_id);
        res
    }
}

async fn pipe_tcp_over_v2(
    tcp: TcpStream,
    chan_id: u8,
    tx_out: mpsc::UnboundedSender<OutboundChunk>,
    rx_in: &mut mpsc::UnboundedReceiver<(u8, Vec<u8>)>,
) -> Result<(u64, u64), ClientError> {
    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    let mut tx_bytes = 0u64;
    let mut rx_bytes = 0u64;
    let mut read_buf = [0u8; BRIDGE_MAX_CHUNK_BYTES];
    let mut local_eof = false;
    let mut remote_eof = false;

    let mut next_tx_seq = 0u32;
    let mut unacked: BTreeMap<u32, (u8, Vec<u8>, Instant)> = BTreeMap::new();
    let mut next_rx_seq = 0u32;
    let mut reorder_buf: BTreeMap<u32, (u8, Vec<u8>)> = BTreeMap::new();
    let mut rto_tick = tokio::time::interval(Duration::from_millis(40));

    while !(local_eof && unacked.is_empty() && remote_eof) {
        let can_read_local = !local_eof && unacked.len() < TUNNEL_MAX_INFLIGHT;
        tokio::select! {
            _ = rto_tick.tick(), if !unacked.is_empty() => {
                let now = Instant::now();
                for (msg_type, framed, last_sent) in unacked.values_mut() {
                    if now.duration_since(*last_sent) >= TUNNEL_RTO {
                        *last_sent = now;
                        let _ = tx_out.send(OutboundChunk {
                            chan_id,
                            msg_type: *msg_type,
                            payload: framed.clone(),
                        });
                    }
                }
            }
            read_res = tcp_r.read(&mut read_buf), if can_read_local => {
                let n = read_res?;
                let seq = next_tx_seq;
                next_tx_seq = next_tx_seq.wrapping_add(1);
                let (msg_type, framed) = if n == 0 {
                    local_eof = true;
                    (TUNNEL_MSG_EOF, seq.to_be_bytes().to_vec())
                } else {
                    tx_bytes = tx_bytes.saturating_add(n as u64);
                    let mut v = Vec::with_capacity(4 + n);
                    v.extend_from_slice(&seq.to_be_bytes());
                    v.extend_from_slice(&read_buf[..n]);
                    (TUNNEL_MSG_DATA, v)
                };
                unacked.insert(seq, (msg_type, framed.clone(), Instant::now()));
                tx_out
                    .send(OutboundChunk {
                        chan_id,
                        msg_type,
                        payload: framed,
                    })
                    .map_err(|_| ClientError::Protocol("V2 mux closed while forwarding TCP".into()))?;
            }
            maybe_in = rx_in.recv() => {
                let Some((msg_type, payload)) = maybe_in else {
                    let _ = tcp_w.shutdown().await;
                    break;
                };
                if payload.len() < 4 {
                    continue;
                }
                let seq = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                match msg_type {
                    TUNNEL_MSG_ACK => {
                        unacked.remove(&seq);
                    }
                    TUNNEL_MSG_DATA | TUNNEL_MSG_EOF => {
                        let _ = tx_out.send(OutboundChunk {
                            chan_id,
                            msg_type: TUNNEL_MSG_ACK,
                            payload: seq.to_be_bytes().to_vec(),
                        });
                        if seq >= next_rx_seq {
                            reorder_buf
                                .entry(seq)
                                .or_insert_with(|| (msg_type, payload[4..].to_vec()));
                        }
                        while let Some((kind, data)) = reorder_buf.remove(&next_rx_seq) {
                            next_rx_seq = next_rx_seq.wrapping_add(1);
                            if kind == TUNNEL_MSG_EOF {
                                remote_eof = true;
                                let _ = tcp_w.shutdown().await;
                            } else if !data.is_empty() {
                                tcp_w.write_all(&data).await?;
                                tcp_w.flush().await?;
                                rx_bytes = rx_bytes.saturating_add(data.len() as u64);
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
