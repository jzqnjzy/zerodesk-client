use serde::{Deserialize, Serialize};

pub const DUAL_SEND_MIN_MS: u64 = 200;
pub const DUAL_SEND_MAX_MS: u64 = 300;
pub const PATH_PROBE_INTERVAL_MS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PathId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportMode {
    P2p,
    RelayUdp,
    Tcp443Fallback,
    WebTransport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathState {
    Probing,
    Ready,
    DualSend,
    Active,
    Draining,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathHandle {
    pub id: PathId,
    pub mode: TransportMode,
    pub pop_id: Option<[u8; 8]>,
    pub route_cid: Option<[u8; 8]>,
    pub state: PathState,
    pub rtt_ms: u32,
    pub loss_pct: f32,
    pub estimated_bw_kbps: u32,
    pub last_probe_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DualSendWindow {
    pub target_path: PathId,
    pub started_ms: u64,
    pub duration_ms: u64,
}

/// Multipath manager owning `active` and `standby` paths with seamless
/// bandwidth-inherited hot switch and 200~300ms dual-send deduplication window.
#[derive(Debug, Clone)]
pub struct PathSet {
    pub active: PathHandle,
    pub standby: Vec<PathHandle>,
    pub dual_send: Option<DualSendWindow>,
    pub active_active_survival: bool,
    pub switch_count: u32,
}

impl PathSet {
    pub fn new(active: PathHandle) -> Self {
        let mut active = active;
        active.state = PathState::Active;
        Self {
            active,
            standby: Vec::new(),
            dual_send: None,
            active_active_survival: false,
            switch_count: 0,
        }
    }

    pub fn add_standby(&mut self, handle: PathHandle) {
        if let Some(existing) = self.standby.iter_mut().find(|p| p.id == handle.id) {
            *existing = handle;
        } else {
            self.standby.push(handle);
        }
    }

    pub fn mark_probe_response(&mut self, path_id: PathId, rtt_ms: u32, now_ms: u64) -> bool {
        if self.active.id == path_id {
            self.active.rtt_ms = rtt_ms;
            self.active.last_probe_ms = now_ms;
            return true;
        }
        if let Some(p) = self.standby.iter_mut().find(|p| p.id == path_id) {
            p.rtt_ms = rtt_ms;
            p.last_probe_ms = now_ms;
            if p.state == PathState::Probing {
                p.state = PathState::Ready;
            }
            return true;
        }
        false
    }

    /// Initiates a 200~300ms dual-send hot switch to a ready standby path and
    /// inherits the active path's congestion-control bandwidth estimate.
    pub fn begin_hot_switch(
        &mut self,
        target_id: PathId,
        now_ms: u64,
        dual_send_ms: u64,
    ) -> bool {
        let inherited_bw = self.active.estimated_bw_kbps;
        let Some(target) = self
            .standby
            .iter_mut()
            .find(|p| p.id == target_id && matches!(p.state, PathState::Ready | PathState::DualSend))
        else {
            return false;
        };
        if target.estimated_bw_kbps == 0 {
            target.estimated_bw_kbps = inherited_bw;
        }
        target.state = PathState::DualSend;
        let clamped_ms = dual_send_ms.clamp(DUAL_SEND_MIN_MS, DUAL_SEND_MAX_MS);
        self.dual_send = Some(DualSendWindow {
            target_path: target_id,
            started_ms: now_ms,
            duration_ms: clamped_ms,
        });
        true
    }

    /// Returns the list of PathIds that should receive outgoing packets right now.
    /// During hot-switch dual-send or Survival Mode Active-Active, returns both paths.
    pub fn tx_paths(&self, is_high_priority_or_ref: bool) -> Vec<PathId> {
        let mut out = vec![self.active.id];
        if let Some(ds) = &self.dual_send {
            if ds.target_path != self.active.id {
                out.push(ds.target_path);
            }
            return out;
        }
        if self.active_active_survival && is_high_priority_or_ref {
            if let Some(ready) = self.standby.iter().find(|p| p.state == PathState::Ready) {
                out.push(ready.id);
            }
        }
        out
    }

    /// Commits a pending hot switch once the 200~300ms dual-send window elapses
    /// (or when explicitly forced on `PATH_SWITCH_COMMIT`).
    pub fn commit_hot_switch(&mut self, now_ms: u64, force: bool) -> Option<PathId> {
        let ds = self.dual_send.as_ref()?;
        if !force && now_ms.saturating_sub(ds.started_ms) < ds.duration_ms {
            return None;
        }
        let target_id = ds.target_path;
        let idx = self.standby.iter().position(|p| p.id == target_id)?;
        let mut new_active = self.standby.remove(idx);
        new_active.state = PathState::Active;
        let mut old_active = std::mem::replace(&mut self.active, new_active);
        old_active.state = PathState::Draining;
        self.standby.push(old_active);
        self.dual_send = None;
        self.switch_count = self.switch_count.saturating_add(1);
        Some(target_id)
    }

    pub fn set_survival_active_active(&mut self, enable: bool) {
        self.active_active_survival = enable;
    }
}
