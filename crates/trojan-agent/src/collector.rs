//! Per-user traffic accumulator.
//!
//! Records per-user byte counts in-memory and drains them for
//! periodic batch reporting to the panel.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::protocol::TrafficRecord;

/// Thread-safe per-user traffic accumulator.
///
/// Cloning shares one set of totals, so the service can hold a handle while
/// the reporter drains from another.
#[derive(Debug, Clone, Default)]
pub struct TrafficCollector {
    inner: Arc<Mutex<HashMap<String, u64>>>,
}

impl TrafficCollector {
    /// Create a new empty collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record traffic for a user (additive).
    pub fn record(&self, user_id: &str, bytes: u64) {
        let mut map = self.inner.lock().expect("traffic collector lock poisoned");
        *map.entry(user_id.to_string()).or_default() += bytes;
    }

    /// Drain all accumulated traffic records and reset counters.
    pub fn drain(&self) -> Vec<TrafficRecord> {
        let mut map = self.inner.lock().expect("traffic collector lock poisoned");
        map.drain()
            .map(|(user_id, bytes)| TrafficRecord { user_id, bytes })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_drain() {
        let collector = TrafficCollector::new();
        collector.record("alice", 100);
        collector.record("bob", 50);
        collector.record("alice", 100);

        let mut records = collector.drain();
        records.sort_by(|a, b| a.user_id.cmp(&b.user_id));
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].user_id, "alice");
        assert_eq!(records[0].bytes, 200);
        assert_eq!(records[1].user_id, "bob");
        assert_eq!(records[1].bytes, 50);
    }

    #[test]
    fn drain_clears() {
        let collector = TrafficCollector::new();
        collector.record("alice", 100);
        let _ = collector.drain();
        assert!(collector.drain().is_empty());
    }

    #[test]
    fn clone_shares_state() {
        let a = TrafficCollector::new();
        let b = a.clone();
        a.record("alice", 10);
        b.record("alice", 30);
        let records = a.drain();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].bytes, 40);
    }
}
