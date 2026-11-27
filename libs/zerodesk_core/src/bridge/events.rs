// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::controller::{BridgeEvent, BRIDGE_ABI_VERSION};
use crate::frame::FrameMailbox;
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    time::{Duration, Instant},
};

pub const CRITICAL_EVENT_QUEUE_CAP: usize = 512;

struct EventQueues {
    critical: VecDeque<BridgeEvent>,
    telemetry_latest: Option<BridgeEvent>,
    last_notified_frame_seq: u64,
    closed: bool,
}

/// Stratified event hub separating:
/// 1. Lossless bounded critical events (state transitions, incoming calls, policy, errors,
///    transport changes, watchdog, audio status, clipboard/file events, command results).
/// 2. On-demand synthesized `VideoFrameReady` from `FrameMailbox` (never enqueued, naturally coalesced).
/// 3. Single-slot overwrite telemetry (`QoeTelemetry`) that never blocks or evicts critical events.
///
/// Backed by `Mutex + Condvar` so C-ABI `poll_event_json_timeout` blocks cleanly with zero busy-spin
/// and zero Tokio dependency on the caller thread.
pub struct BridgeEventHub {
    queues: Mutex<EventQueues>,
    cvar: Condvar,
    seq: AtomicU64,
    mailbox: Arc<FrameMailbox>,
}

impl BridgeEventHub {
    pub fn new(mailbox: Arc<FrameMailbox>) -> Self {
        Self {
            queues: Mutex::new(EventQueues {
                critical: VecDeque::with_capacity(64),
                telemetry_latest: None,
                last_notified_frame_seq: 0,
                closed: false,
            }),
            cvar: Condvar::new(),
            seq: AtomicU64::new(0),
            mailbox,
        }
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Pushes a lossless critical event (wakes any thread blocked in `poll_event_timeout`).
    pub fn push_critical(&self, kind: &str, payload: serde_json::Value) {
        let ev = BridgeEvent {
            v: BRIDGE_ABI_VERSION,
            seq: self.next_seq(),
            kind: kind.to_string(),
            payload,
        };
        let mut g = self.queues.lock().unwrap_or_else(|e| e.into_inner());
        while g.critical.len() >= CRITICAL_EVENT_QUEUE_CAP {
            g.critical.pop_front();
        }
        g.critical.push_back(ev);
        self.cvar.notify_all();
    }

    /// Overwrites the droppable telemetry slot (never fills or evicts critical events).
    pub fn set_telemetry(&self, kind: &str, payload: serde_json::Value) {
        let ev = BridgeEvent {
            v: BRIDGE_ABI_VERSION,
            seq: self.next_seq(),
            kind: kind.to_string(),
            payload,
        };
        let mut g = self.queues.lock().unwrap_or_else(|e| e.into_inner());
        g.telemetry_latest = Some(ev);
        self.cvar.notify_all();
    }

    /// Notifies blocked pollers that `FrameMailbox` has a newer frame available for on-demand
    /// `VideoFrameReady` synthesis (without pushing anything onto any queue!).
    pub fn notify_frame_published(&self) {
        let _g = self.queues.lock().unwrap_or_else(|e| e.into_inner());
        self.cvar.notify_all();
    }

    /// Signals shutdown so any blocked `poll_event_timeout` wakes promptly.
    pub fn close(&self) {
        let mut g = self.queues.lock().unwrap_or_else(|e| e.into_inner());
        g.closed = true;
        self.cvar.notify_all();
    }

    fn try_pop_locked(&self, g: &mut EventQueues) -> Option<BridgeEvent> {
        // 1. Lossless critical queue first.
        if let Some(ev) = g.critical.pop_front() {
            return Some(ev);
        }
        // 2. Synthesize VideoFrameReady on demand if mailbox has a newer seq.
        let latest_seq = self.mailbox.latest_seq();
        if latest_seq > g.last_notified_frame_seq {
            if let Ok(info) = self.mailbox.frame_info() {
                g.last_notified_frame_seq = info.seq;
                return Some(BridgeEvent {
                    v: BRIDGE_ABI_VERSION,
                    seq: self.next_seq(),
                    kind: "VideoFrameReady".to_string(),
                    payload: serde_json::json!({
                        "frame_seq": info.seq,
                        "width": info.width,
                        "height": info.height,
                        "stride": info.stride,
                        "pixel_format": info.pixel_format.as_u32(),
                        "byte_len": info.byte_len,
                        "pts_ms": info.pts_ms,
                        "dropped_ui_frames": info.dropped_ui_frames,
                    }),
                });
            }
        }
        // 3. Droppable overwrite telemetry slot last.
        g.telemetry_latest.take()
    }

    /// Non-blocking poll. Returns `None` if no critical event, new frame, or telemetry is pending.
    pub fn poll_event(&self) -> Option<BridgeEvent> {
        let mut g = self.queues.lock().unwrap_or_else(|e| e.into_inner());
        self.try_pop_locked(&mut g)
    }

    /// Blocks up to `timeout` without busy-spinning until an event or new video frame is available.
    pub fn poll_event_timeout(&self, timeout: Duration) -> Option<BridgeEvent> {
        let deadline = Instant::now() + timeout;
        let mut g = self.queues.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(ev) = self.try_pop_locked(&mut g) {
                return Some(ev);
            }
            if g.closed {
                return None;
            }
            let rem = deadline.checked_duration_since(Instant::now())?;
            if rem.is_zero() {
                return None;
            }
            let (guard, wait_res) = self
                .cvar
                .wait_timeout(g, rem)
                .unwrap_or_else(|e| e.into_inner());
            g = guard;
            if let Some(ev) = self.try_pop_locked(&mut g) {
                return Some(ev);
            }
            if wait_res.timed_out() || g.closed {
                return None;
            }
        }
    }

    pub fn critical_len(&self) -> usize {
        self.queues
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .critical
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::PixelFormat;

    #[test]
    fn event_hub_synthesizes_video_frame_ready_on_demand_and_coalesces() {
        let mb = Arc::new(FrameMailbox::new());
        let hub = BridgeEventHub::new(Arc::clone(&mb));

        // Publish 5 frames rapidly without polling -> queue stays 0, single coalesced event synthesized!
        for i in 1..=5 {
            mb.publish_raw(4, 4, 16, PixelFormat::Bgra8, i * 16, vec![i as u8; 64])
                .unwrap();
            hub.notify_frame_published();
        }
        assert_eq!(hub.critical_len(), 0);

        let ev = hub.poll_event().expect("should synthesize VideoFrameReady");
        assert_eq!(ev.kind, "VideoFrameReady");
        assert_eq!(ev.payload["frame_seq"], 5);
        // Polling again without a new frame returns None (already notified seq=5).
        assert!(hub.poll_event().is_none());
    }

    #[test]
    fn event_hub_telemetry_overwrites_without_evicting_critical_events() {
        let mb = Arc::new(FrameMailbox::new());
        let hub = BridgeEventHub::new(mb);

        hub.push_critical("PolicyUpdated", serde_json::json!({ "version": 3 }));
        for i in 0..100 {
            hub.set_telemetry("QoeTelemetry", serde_json::json!({ "tick": i }));
        }
        let first = hub.poll_event().unwrap();
        assert_eq!(first.kind, "PolicyUpdated");
        let second = hub.poll_event().unwrap();
        assert_eq!(second.kind, "QoeTelemetry");
        assert_eq!(second.payload["tick"], 99);
        assert!(hub.poll_event().is_none());
    }
}
