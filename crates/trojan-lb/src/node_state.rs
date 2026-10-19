//! Live node budgets are separate from transient backend health.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use trojan_protocol::{NodeState, NodeStateSnapshot};

/// Atomically replaceable node state received from the panel.
#[derive(Debug, Default)]
pub struct NodeStateStore {
    current: RwLock<Arc<NodeStateView>>,
    grace: Duration,
}

/// An immutable set of node states used throughout one routing decision.
#[derive(Debug, Default)]
pub struct NodeStateView {
    generated_at: Option<u64>,
    valid_until: u64,
    grace_until: u64,
    nodes: HashMap<String, NodeState>,
}

impl NodeStateStore {
    /// Permit expired snapshots until their generation time plus `grace`.
    /// Zero preserves strict expiry and billing-period checks.
    pub fn with_grace(grace: Duration) -> Self {
        Self {
            grace,
            ..Self::default()
        }
    }

    /// Clear the snapshot while preserving the local grace policy.
    pub fn clear(&self) {
        *self.current.write().expect("node state lock poisoned") = Arc::default();
    }

    /// Replace the snapshot and return whether the snapshot was accepted.
    /// Reject snapshots older than the current snapshot.
    pub fn update(&self, snapshot: NodeStateSnapshot) -> bool {
        let mut current = self.current.write().expect("node state lock poisoned");
        if current
            .generated_at
            .is_none_or(|time| snapshot.generated_at >= time)
        {
            *current = Arc::new(NodeStateView {
                generated_at: Some(snapshot.generated_at),
                valid_until: snapshot.valid_until,
                grace_until: snapshot.generated_at.saturating_add(self.grace.as_secs()),
                nodes: snapshot
                    .nodes
                    .into_iter()
                    .map(|node| (node.node_id.clone(), node))
                    .collect(),
            });
            true
        } else {
            false
        }
    }

    /// Read one snapshot for a complete routing decision.
    pub fn snapshot(&self) -> Arc<NodeStateView> {
        self.current
            .read()
            .expect("node state lock poisoned")
            .clone()
    }

    /// Return the remaining fraction, or `None` when the node cannot accept traffic.
    pub fn remaining_fraction(&self, node_id: &str) -> Option<f64> {
        self.snapshot().remaining_fraction(node_id)
    }
}

impl NodeStateView {
    /// Return the generation time in Unix seconds, or `None` before the first snapshot.
    pub fn generated_at(&self) -> Option<u64> {
        self.generated_at
    }

    /// Return a fraction in `(0, 1]`; unlimited nodes have a fraction of `1`.
    ///
    /// Missing, stale, disabled, offline, and depleted nodes are unavailable.
    /// A finite quota requires supported node accounting.
    /// During grace, expired billing periods retain the last known usage.
    /// Grace never restores disabled, offline, or depleted nodes.
    pub fn remaining_fraction(&self, node_id: &str) -> Option<f64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before Unix epoch")
            .as_secs();
        self.remaining_fraction_at(node_id, now)
    }

    fn remaining_fraction_at(&self, node_id: &str, now: u64) -> Option<f64> {
        let generated_at = self.generated_at?;
        let within_grace = now < self.grace_until;
        if now < generated_at || (now >= self.valid_until && !within_grace) {
            return None;
        }
        let node = self.nodes.get(node_id)?;
        if !node.enabled
            || !node.online
            || now < node.period_start
            || (now >= node.reset_at && !within_grace)
        {
            return None;
        }
        if node.traffic_limit == 0 {
            return Some(1.0);
        }
        if !node.traffic_supported {
            return None;
        }
        let remaining = node.traffic_limit.saturating_sub(node.used_bytes);
        (remaining > 0).then(|| remaining as f64 / node.traffic_limit as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> NodeStateSnapshot {
        NodeStateSnapshot {
            generated_at: 10,
            valid_until: 100,
            nodes: vec![NodeState {
                node_id: "exit".into(),
                enabled: true,
                online: true,
                traffic_supported: true,
                traffic_limit: 100,
                used_bytes: 80,
                period_start: 0,
                reset_at: 90,
            }],
        }
    }

    #[test]
    fn grace_uses_generation_time_and_expires_at_the_deadline() {
        let store = NodeStateStore::with_grace(Duration::from_secs(200));
        store.update(snapshot());
        let view = store.snapshot();
        for (now, expected) in [
            (9, None),
            (10, Some(0.2)),
            (90, Some(0.2)),
            (100, Some(0.2)),
            (209, Some(0.2)),
            (210, None),
        ] {
            assert_eq!(
                view.remaining_fraction_at("exit", now),
                expected,
                "at {now}"
            );
        }
        assert_eq!(view.remaining_fraction_at("missing", 100), None);
    }

    #[test]
    fn short_grace_does_not_shorten_panel_validity() {
        let store = NodeStateStore::with_grace(Duration::from_secs(20));
        store.update(snapshot());
        let view = store.snapshot();
        assert_eq!(view.remaining_fraction_at("exit", 50), Some(0.2));
        assert_eq!(view.remaining_fraction_at("exit", 90), None);
        assert_eq!(view.remaining_fraction_at("exit", 100), None);
    }

    #[test]
    fn grace_preserves_availability_accounting_and_last_period_usage() {
        let store = NodeStateStore::with_grace(Duration::from_secs(200));
        for (enabled, online, supported, used, limit, start, expected) in [
            (true, true, true, 80, 100, 0, Some(0.2)),
            (true, true, false, u64::MAX, 0, 0, Some(1.0)),
            (false, true, true, 0, 100, 0, None),
            (true, false, true, 0, 100, 0, None),
            (true, true, false, 0, 100, 0, None),
            (true, true, true, 100, 100, 0, None),
            (true, true, true, 120, 100, 0, None),
            (true, true, true, 0, 100, 101, None),
        ] {
            let mut snapshot = snapshot();
            let node = &mut snapshot.nodes[0];
            node.enabled = enabled;
            node.online = online;
            node.traffic_supported = supported;
            node.used_bytes = used;
            node.traffic_limit = limit;
            node.period_start = start;
            store.update(snapshot);
            assert_eq!(
                store.snapshot().remaining_fraction_at("exit", 100),
                expected
            );
        }
    }

    #[test]
    fn fresh_snapshots_replace_grace_states_without_extending_old_views() {
        let store = NodeStateStore::with_grace(Duration::from_secs(200));
        assert!(store.update(snapshot()));
        let old = store.snapshot();
        let mut fresh = snapshot();
        fresh.generated_at = 150;
        fresh.valid_until = 240;
        fresh.nodes[0].enabled = false;
        assert!(store.update(fresh));
        assert!(!store.update(snapshot()));
        assert_eq!(store.snapshot().remaining_fraction_at("exit", 150), None);
        assert_eq!(old.remaining_fraction_at("exit", 150), Some(0.2));
        assert_eq!(old.remaining_fraction_at("exit", 210), None);
        store.clear();
        assert_eq!(store.snapshot().generated_at(), None);
        assert_eq!(store.snapshot().remaining_fraction_at("exit", 150), None);
        store.update(snapshot());
        assert_eq!(
            store.snapshot().remaining_fraction_at("exit", 150),
            Some(0.2)
        );
    }

    #[test]
    fn state_expiry_and_rollover_require_fresh_snapshots() {
        let store = NodeStateStore::with_grace(Duration::ZERO);
        store.update(snapshot());
        let old = store.snapshot();
        assert_eq!(old.remaining_fraction_at("exit", 10), Some(0.2));
        assert_eq!(old.remaining_fraction_at("missing", 10), None);
        assert_eq!(old.remaining_fraction_at("exit", 9), None);
        assert_eq!(old.remaining_fraction_at("exit", 90), None);
        assert_eq!(old.remaining_fraction_at("exit", 100), None);
        let mut fresh = snapshot();
        fresh.generated_at = 90;
        fresh.valid_until = 180;
        fresh.nodes[0].period_start = 90;
        fresh.nodes[0].reset_at = 180;
        fresh.nodes[0].used_bytes = 0;
        store.update(fresh);
        store.update(snapshot());
        assert_eq!(
            store.snapshot().remaining_fraction_at("exit", 91),
            Some(1.0)
        );
        assert_eq!(old.remaining_fraction_at("exit", 91), None);
    }

    #[test]
    fn unavailable_states_and_unlimited_budget() {
        let store = NodeStateStore::default();
        for (enabled, online, used, limit, expected) in [
            (false, true, 0, 100, None),
            (true, false, 0, 100, None),
            (true, true, 100, 100, None),
            (true, true, 120, 100, None),
            (true, true, u64::MAX, 0, Some(1.0)),
        ] {
            let mut state = snapshot();
            state.nodes[0].enabled = enabled;
            state.nodes[0].online = online;
            state.nodes[0].used_bytes = used;
            state.nodes[0].traffic_limit = limit;
            store.update(state);
            assert_eq!(store.snapshot().remaining_fraction_at("exit", 10), expected);
        }
    }

    #[test]
    fn legacy_nodes_cannot_satisfy_a_finite_quota() {
        let store = NodeStateStore::default();
        let mut state = snapshot();
        state.nodes[0].traffic_supported = false;
        state.nodes[0].used_bytes = 0;
        store.update(state.clone());
        assert_eq!(store.snapshot().remaining_fraction_at("exit", 10), None);
        state.nodes[0].traffic_limit = 0;
        store.update(state);
        assert_eq!(
            store.snapshot().remaining_fraction_at("exit", 10),
            Some(1.0)
        );
    }
}
