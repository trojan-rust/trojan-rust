//! Per-user traffic accumulator.
//!
//! Records per-user byte counts in-memory and drains them for
//! periodic batch reporting to the panel.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::protocol::TrafficRecord;

/// Accumulated traffic for a single user.
#[derive(Debug, Default)]
struct UserTraffic {
    bytes_up: u64,
    bytes_down: u64,
}

/// Thread-safe per-user traffic accumulator.
#[derive(Debug, Clone)]
pub struct TrafficCollector {
    inner: Arc<Mutex<HashMap<String, UserTraffic>>>,
}

impl TrafficCollector {
    /// Create a new empty collector.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Record traffic for a user (additive).
    pub fn record(&self, user_id: &str, bytes_up: u64, bytes_down: u64) {
        let mut map = self.inner.lock().expect("traffic collector lock poisoned");
        let entry = map.entry(user_id.to_string()).or_default();
        entry.bytes_up += bytes_up;
        entry.bytes_down += bytes_down;
    }

    /// Drain all accumulated traffic records and reset counters.
    pub fn drain(&self) -> Vec<TrafficRecord> {
        let mut map = self.inner.lock().expect("traffic collector lock poisoned");
        let records: Vec<TrafficRecord> = map
            .drain()
            .map(|(user_id, traffic)| TrafficRecord {
                user_id,
                bytes_up: traffic.bytes_up,
                bytes_down: traffic.bytes_down,
            })
            .collect();
        records
    }
}

impl Default for TrafficCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_drain() {
        let collector = TrafficCollector::new();
        collector.record("alice", 100, 200);
        collector.record("bob", 50, 75);
        collector.record("alice", 100, 100);

        let mut records = collector.drain();
        records.sort_by(|a, b| a.user_id.cmp(&b.user_id));
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].user_id, "alice");
        assert_eq!(records[0].bytes_up, 200);
        assert_eq!(records[0].bytes_down, 300);
        assert_eq!(records[1].user_id, "bob");
        assert_eq!(records[1].bytes_up, 50);
    }

    #[test]
    fn drain_clears() {
        let collector = TrafficCollector::new();
        collector.record("alice", 100, 200);
        let _ = collector.drain();
        let records = collector.drain();
        assert!(records.is_empty());
    }

    #[test]
    fn clone_shares_state() {
        let a = TrafficCollector::new();
        let b = a.clone();
        a.record("alice", 10, 20);
        b.record("alice", 30, 40);
        let records = a.drain();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].bytes_up, 40);
        assert_eq!(records[0].bytes_down, 60);
    }
}
