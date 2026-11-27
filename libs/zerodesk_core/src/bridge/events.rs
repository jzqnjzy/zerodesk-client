// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::controller::{BridgeEvent, BRIDGE_ABI_VERSION};
use crate::frame::FrameMailbox;
use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

pub const CRITICAL_EVENT_QUEUE_CAP: usize = 512;
pub const MAX_POLL_TIMEOUT: Duration = Duration::from_secs(60);

struct EventQueues {
    seq: u64,
    critical: VecDeque<BridgeEvent>,
    dropped_critical: u64,
    telemetry_latest: Option<BridgeEvent>,
    last_notified_frame_seq: u64,
    closed: bool,
}

impl EventQueues {
    fn next_seq(&mut self) -> u64 {
        self.seq = self.seq.saturating_add(1);
        self.seq
    }
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
    mailbox: Arc<FrameMailbox>,
}

impl BridgeEventHub {
    pub fn new(mailbox: Arc<FrameMailbox>) -> Self {
        Self {
            queues: Mutex::new(EventQueues {
                seq: 0,
                critical: VecDeque::with_capacity(64),
                dropped_critical: 0,
                telemetry_latest: None,
                last_notified_frame_seq: 0,
                closed: false,
            }),
            cvar: Condvar::new(),
            mailbox,
        }
    }

    /// Pushes a critical event (wakes any thread blocked in `poll_event_timeout`).
    /// Assigns `seq` under the mutex so dequeue order is strictly monotonic.
    /// If the queue is full, increments `dropped_critical` so the next poll emits
    /// `EventsOverflowed { dropped }` instead of silently discarding events.
    pub fn push_critical(&self, kind: &str, payload: serde_json::Value) {
        let mut g = self.queues.lock().unwrap_or_else(|e| e.into_inner());
        while g.critical.len() >= CRITICAL_EVENT_QUEUE_CAP {
            g.critical.pop_front();
            g.dropped_critical = g.dropped_critical.saturating_add(1);
        }
        let seq = g.next_seq();
        g.critical.push_back(BridgeEvent {
            v: BRIDGE_ABI_VERSION,
            seq,
            kind: kind.to_string(),
            payload,
        });
        self.cvar.notify_all();
    }

    /// Overwrites the droppable telemetry slot (never fills or evicts critical events).
    pub fn set_telemetry(&self, kind: &str, payload: serde_json::Value) {
        let mut g = self.queues.lock().unwrap_or_else(|e| e.into_inner());
        let seq = g.next_seq();
        g.telemetry_latest = Some(BridgeEvent {
            v: BRIDGE_ABI_VERSION,
            seq,
            kind: kind.to_string(),
            payload,
        });
        self.cvar.notify_all();
    }

    /// Notifies blocked pollers that `FrameMailbox` has a newer frame available for on-demand
    /// `VideoFrameReady` synthesis (without pushing anything onto any queue!).
    /// Acquires and drops `self.queues` before notifying to guarantee zero lost-wakeup window.
    pub fn notify_frame_published(&self) {
        {
            let _g = self.queues.lock().unwrap_or_else(|e| e.into_inner());
        }
        self.cvar.notify_all();
    }

    /// Signals shutdown so any blocked `poll_event_timeout` wakes promptly.
    pub fn close(&self) {
        let mut g = self.queues.lock().unwrap_or_else(|e| e.into_inner());
        g.closed = true;
        self.cvar.notify_all();
    }

    /// Attempts to pop an event without ever calling `self.mailbox.frame_info()` while holding
    /// `self.queues`. Takes ownership of the mutex guard and returns either an event or the
    /// re-acquired guard.
    fn try_pop_without_nested_locks<'a>(
        &'a self,
        mut g: std::sync::MutexGuard<'a, EventQueues>,
    ) -> Result<BridgeEvent, std::sync::MutexGuard<'a, EventQueues>> {
        // 0. If critical events overflowed, synthesize EventsOverflowed first.
        if g.dropped_critical > 0 {
            let dropped = g.dropped_critical;
            g.dropped_critical = 0;
            let seq = g.next_seq();
            return Ok(BridgeEvent {
                v: BRIDGE_ABI_VERSION,
                seq,
                kind: "EventsOverflowed".to_string(),
                payload: serde_json::json!({ "dropped": dropped }),
            });
        }
        // 1. Lossless critical queue first.
        if let Some(ev) = g.critical.pop_front() {
            return Ok(ev);
        }
        // 2. Check atomic `latest_seq` under lock, drop lock before reading `mailbox.frame_info()`,
        //    and retry up to 3 times if `latest_seq` changed while unlocked so no wakeup is missed.
        for _ in 0..3 {
            let latest_seq = self.mailbox.latest_seq();
            if latest_seq <= g.last_notified_frame_seq {
                break;
            }
            drop(g);
            let frame_res = self.mailbox.frame_info();
            g = self.queues.lock().unwrap_or_else(|e| e.into_inner());
            // Re-check higher-priority overflow/critical queues that may have arrived while unlocked.
            if g.dropped_critical > 0 {
                let dropped = g.dropped_critical;
                g.dropped_critical = 0;
                let seq = g.next_seq();
                return Ok(BridgeEvent {
                    v: BRIDGE_ABI_VERSION,
                    seq,
                    kind: "EventsOverflowed".to_string(),
                    payload: serde_json::json!({ "dropped": dropped }),
                });
            }
            if let Some(ev) = g.critical.pop_front() {
                return Ok(ev);
            }
            match frame_res {
                Ok(info) if info.seq > g.last_notified_frame_seq => {
                    g.last_notified_frame_seq = info.seq;
                    let seq = g.next_seq();
                    return Ok(BridgeEvent {
                        v: BRIDGE_ABI_VERSION,
                        seq,
                        kind: "VideoFrameReady".to_string(),
                        payload: serde_json::json!({
                            "frame_seq": info.seq,
                            "session_gen": info.session_gen,
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
                Err(_) => {
                    if self.mailbox.latest_seq() != latest_seq {
                        continue;
                    }
                    // Mailbox was cleared concurrently; advance cursor past cleared seq so we do not spin.
                    if latest_seq > g.last_notified_frame_seq {
                        g.last_notified_frame_seq = latest_seq;
                    }
                    break;
                }
                Ok(_) => {
                    if self.mailbox.latest_seq() != latest_seq {
                        continue;
                    }
                    break;
                }
            }
        }
        // 3. Droppable overwrite telemetry slot last.
        if let Some(ev) = g.telemetry_latest.take() {
            return Ok(ev);
        }
        Err(g)
    }

    /// Non-blocking poll. Returns `None` if no critical event, new frame, or telemetry is pending.
    pub fn poll_event(&self) -> Option<BridgeEvent> {
        let g = self.queues.lock().unwrap_or_else(|e| e.into_inner());
        self.try_pop_without_nested_locks(g).ok()
    }

    /// Blocks up to `timeout` (clamped to `MAX_POLL_TIMEOUT` with overflow-safe deadline math)
    /// without busy-spinning until an event or new video frame is available.
    pub fn poll_event_timeout(&self, timeout: Duration) -> Option<BridgeEvent> {
        let clamped = timeout.min(MAX_POLL_TIMEOUT);
        let deadline = Instant::now().checked_add(clamped);
        let mut g = self.queues.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            match self.try_pop_without_nested_locks(g) {
                Ok(ev) => return Some(ev),
                Err(guard) => g = guard,
            }
            if g.closed {
                return None;
            }
            let rem = match deadline {
                Some(dl) => match dl.checked_duration_since(Instant::now()) {
                    Some(r) if !r.is_zero() => r,
                    _ => return None,
                },
                None => clamped,
            };
            let (guard, wait_res) = self
                .cvar
                .wait_timeout(g, rem)
                .unwrap_or_else(|e| e.into_inner());
            g = guard;
            match self.try_pop_without_nested_locks(g) {
                Ok(ev) => return Some(ev),
                Err(guard) => g = guard,
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
        mb.reset_for_session(7);
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
        assert_eq!(ev.payload["session_gen"], 7);
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

    #[test]
    fn event_hub_synthesizes_events_overflowed_and_preserves_monotonic_seq() {
        let mb = Arc::new(FrameMailbox::new());
        let hub = BridgeEventHub::new(mb);

        for i in 0..(CRITICAL_EVENT_QUEUE_CAP + 5) {
            hub.push_critical("Tick", serde_json::json!({ "i": i }));
        }
        let overflow = hub.poll_event().expect("overflow event");
        assert_eq!(overflow.kind, "EventsOverflowed");
        assert_eq!(overflow.payload["dropped"], 5);

        let mut prev_seq = 0u64;
        while let Some(ev) = hub.poll_event() {
            assert_eq!(ev.kind, "Tick");
            assert!(ev.seq > prev_seq, "critical event seq must be strictly monotonic");
            prev_seq = ev.seq;
        }
    }

    #[test]
    fn poll_event_timeout_clamps_duration_max_without_panicking() {
        let mb = Arc::new(FrameMailbox::new());
        let hub = BridgeEventHub::new(mb);
        hub.close();
        assert!(hub.poll_event_timeout(Duration::MAX).is_none());
    }
}
