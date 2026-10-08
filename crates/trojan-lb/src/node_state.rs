//! Live node budgets are separate from transient backend health.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use trojan_protocol::{NodeState, NodeStateSnapshot};

/// Atomically replaceable node state received from the panel.
#[derive(Debug, Default)]
pub struct NodeStateStore {
    current: RwLock<Arc<NodeStateView>>,
}

/// An immutable set of node states used throughout one routing decision.
#[derive(Debug, Default)]
pub struct NodeStateView {
    generated_at: u64,
    valid_until: u64,
    nodes: HashMap<String, NodeState>,
}

impl NodeStateStore {
    /// Replace the current snapshot unless a newer snapshot already arrived.
    pub fn update(&self, snapshot: NodeStateSnapshot) {
        let mut current = self.current.write().expect("node state lock poisoned");
        if snapshot.generated_at >= current.generated_at {
            *current = Arc::new(NodeStateView {
                generated_at: snapshot.generated_at,
                valid_until: snapshot.valid_until,
                nodes: snapshot
                    .nodes
                    .into_iter()
                    .map(|node| (node.node_id.clone(), node))
                    .collect(),
            });
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
    /// Return a fraction in `(0, 1]`; unlimited nodes have a fraction of `1`.
    ///
    /// Missing, stale, disabled, offline, and depleted nodes are unavailable.
    /// A finite quota requires supported node accounting.
    /// A new billing period requires a fresh panel snapshot.
    pub fn remaining_fraction(&self, node_id: &str) -> Option<f64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before Unix epoch")
            .as_secs();
        self.remaining_fraction_at(node_id, now)
    }

    fn remaining_fraction_at(&self, node_id: &str, now: u64) -> Option<f64> {
        if now < self.generated_at || now >= self.valid_until {
            return None;
        }
        let node = self.nodes.get(node_id)?;
        if !node.enabled || !node.online || now < node.period_start || now >= node.reset_at {
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
    fn state_expiry_and_rollover_require_fresh_snapshots() {
        let store = NodeStateStore::default();
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
