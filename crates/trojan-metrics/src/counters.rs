//! Counter handles held for the life of one relay session, and the node-wide
//! totals they roll up into.
//!
//! Two consumers want the same numbers in different shapes. A Prometheus
//! scraper diffs successive samples itself, so counters are enough for it. The
//! panel agent has no scraper — it pushes heartbeats — so it needs the absolute
//! totals a node has carried since it started, readable at any moment. Both are
//! fed from one recording call: [`RelayCounters`] increments the Prometheus
//! counters and, when a node's [`NodeStats`] is attached, that node's running
//! totals.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use metrics::{Counter, counter};
use trojan_core::io::RelayMetrics;

use crate::{BYTES_RECEIVED_TOTAL, BYTES_SENT_TOTAL, ENTRY_RULE_BYTES_TOTAL, TARGET_BYTES_TOTAL};

// ============================================================================
// Node-wide totals
// ============================================================================

/// Traffic and connection totals for one node, shared by every session on it.
///
/// This is the reporting path, not the observability path: the agent drains it
/// into panel heartbeats. Prometheus covers the scrape side, and both are fed
/// by the same [`RelayCounters`] call.
#[derive(Debug, Default)]
pub struct NodeStats {
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    connections_total: AtomicU64,
    connections_active: AtomicU64,
}

/// A point-in-time read of [`NodeStats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NodeSnapshot {
    /// Bytes carried from clients into the node.
    pub bytes_in: u64,
    /// Bytes carried from the node back to clients.
    pub bytes_out: u64,
    /// Connections accepted since the node started.
    pub connections_total: u64,
    /// Connections open right now.
    pub connections_active: u64,
}

impl NodeStats {
    /// A fresh set of totals, all zero.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Read every total.
    ///
    /// The four loads are individually atomic but not atomic as a group, so a
    /// snapshot may straddle a session's update. That is fine for reporting,
    /// where the next heartbeat corrects any skew, and wrong for anything
    /// needing the numbers to agree exactly.
    pub fn snapshot(&self) -> NodeSnapshot {
        NodeSnapshot {
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            connections_total: self.connections_total.load(Ordering::Relaxed),
            connections_active: self.connections_active.load(Ordering::Relaxed),
        }
    }

    /// Count a connection as open until the returned guard drops.
    pub fn connection_started(self: &Arc<Self>) -> ActiveConnection {
        self.connections_total.fetch_add(1, Ordering::Relaxed);
        self.connections_active.fetch_add(1, Ordering::Relaxed);
        ActiveConnection {
            stats: Arc::clone(self),
        }
    }

    #[inline]
    fn add_in(&self, bytes: u64) {
        self.bytes_in.fetch_add(bytes, Ordering::Relaxed);
    }

    #[inline]
    fn add_out(&self, bytes: u64) {
        self.bytes_out.fetch_add(bytes, Ordering::Relaxed);
    }
}

/// Holds a node's active-connection count up for the life of one session.
///
/// Every increment is paired with this guard rather than an explicit
/// decrement, so a session that ends by panic, cancellation, or early return
/// still leaves the count right.
#[derive(Debug)]
pub struct ActiveConnection {
    stats: Arc<NodeStats>,
}

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.stats
            .connections_active
            .fetch_sub(1, Ordering::Relaxed);
    }
}

// ============================================================================
// Per-session counters
// ============================================================================

/// The optional labelled breakdown a session reports alongside the global
/// counters — per destination on an exit node, per rule on an entry node.
#[derive(Debug, Clone)]
struct LabelledCounters {
    /// Bytes leaving this node towards the target or tunnel.
    sent: Counter,
    /// Bytes arriving from the target or tunnel.
    received: Counter,
}

impl LabelledCounters {
    /// Resolve both directions of `metric`, labelled `key=value`.
    fn new(metric: &'static str, key: &'static str, value: &str) -> Self {
        Self {
            sent: counter!(metric, key => value.to_owned(), "direction" => "sent"),
            received: counter!(metric, key => value.to_owned(), "direction" => "received"),
        }
    }
}

/// Counter handles resolved once for the lifetime of a relay session.
///
/// Resolving a metric through `counter!` builds its key — which allocates a
/// `Vec` and a `String` when a label value is dynamic — and hashes that key
/// against the recorder registry. The relay reports bytes once per *flush*
/// rather than once per connection (see `trojan_core::io::relay`), so doing
/// that work per report puts an allocation and a registry lookup directly in
/// the data path. Resolving the handles at session start reduces each report
/// to an atomic add.
///
/// Handles are resolved against whichever recorder is installed at
/// construction time; build them after `init_metrics_server`, otherwise they
/// bind to the no-op recorder for the whole session.
#[derive(Debug, Clone)]
pub struct RelayCounters {
    /// Global bytes received from clients.
    received: Counter,
    /// Global bytes sent to clients.
    sent: Counter,
    /// Per-target or per-rule breakdown, when the caller asked for one.
    labelled: Option<LabelledCounters>,
    /// Node-wide totals this session rolls up into, when one was attached.
    node: Option<Arc<NodeStats>>,
    /// Bytes reported in either direction so far.
    ///
    /// The relay returns its `RelayStats` only on success, so a session that
    /// ends in error takes its byte counts with it. Accumulating here instead
    /// lets a caller settle the account however the relay ended — which is
    /// what traffic-limited deployments need, since an aborted connection is
    /// the common case, not the exception.
    ///
    /// Shared across clones so they observe one running total.
    total: Arc<AtomicU64>,
    /// Per-direction splits, for callers that report them separately.
    to_target: Arc<AtomicU64>,
    to_client: Arc<AtomicU64>,
}

impl RelayCounters {
    /// Handles for the global byte counters only.
    pub fn global() -> Self {
        Self {
            received: counter!(BYTES_RECEIVED_TOTAL),
            sent: counter!(BYTES_SENT_TOTAL),
            labelled: None,
            node: None,
            total: Arc::new(AtomicU64::new(0)),
            to_target: Arc::new(AtomicU64::new(0)),
            to_client: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Handles for the global byte counters plus a per-target breakdown.
    ///
    /// An empty `target` behaves like [`global`](Self::global).
    ///
    /// Each distinct `target` adds two time series that live as long as the
    /// process. Deployments with an unbounded destination set should prefer
    /// [`global`](Self::global) — see `metrics.per_target` in the server
    /// config.
    pub fn with_target(target: &str) -> Self {
        Self::labelled(TARGET_BYTES_TOTAL, "target", target)
    }

    /// Handles for the global byte counters plus a per-rule breakdown.
    ///
    /// An empty `rule` behaves like [`global`](Self::global). Unlike
    /// [`with_target`](Self::with_target) the label set is bounded: an entry
    /// node has as many rules as its config lists.
    pub fn with_rule(rule: &str) -> Self {
        Self::labelled(ENTRY_RULE_BYTES_TOTAL, "rule", rule)
    }

    /// Also roll this session's bytes up into a node's running totals.
    pub fn with_node_stats(mut self, stats: Arc<NodeStats>) -> Self {
        self.node = Some(stats);
        self
    }

    /// Global counters plus one labelled breakdown, skipped for an empty value.
    fn labelled(metric: &'static str, key: &'static str, value: &str) -> Self {
        let mut counters = Self::global();
        if !value.is_empty() {
            counters.labelled = Some(LabelledCounters::new(metric, key, value));
        }
        counters
    }

    /// Bytes reported in either direction since this handle was built.
    ///
    /// Valid whether the relay succeeded or failed, unlike `RelayStats`.
    #[inline]
    pub fn total_bytes(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// Bytes carried client → target.
    #[inline]
    pub fn sent_to_target(&self) -> u64 {
        self.to_target.load(Ordering::Relaxed)
    }

    /// Bytes carried target → client.
    #[inline]
    pub fn sent_to_client(&self) -> u64 {
        self.to_client.load(Ordering::Relaxed)
    }

    /// Record bytes flowing client → target.
    #[inline]
    pub fn add_to_target(&self, bytes: u64) {
        self.total.fetch_add(bytes, Ordering::Relaxed);
        self.to_target.fetch_add(bytes, Ordering::Relaxed);
        self.received.increment(bytes);
        if let Some(ref labelled) = self.labelled {
            labelled.sent.increment(bytes);
        }
        if let Some(ref node) = self.node {
            node.add_in(bytes);
        }
    }

    /// Record bytes flowing target → client.
    #[inline]
    pub fn add_to_client(&self, bytes: u64) {
        self.total.fetch_add(bytes, Ordering::Relaxed);
        self.to_client.fetch_add(bytes, Ordering::Relaxed);
        self.sent.increment(bytes);
        if let Some(ref labelled) = self.labelled {
            labelled.received.increment(bytes);
        }
        if let Some(ref node) = self.node {
            node.add_out(bytes);
        }
    }
}

impl RelayMetrics for RelayCounters {
    #[inline]
    fn record_inbound(&self, bytes: u64) {
        self.add_to_target(bytes);
    }

    #[inline]
    fn record_outbound(&self, bytes: u64) {
        self.add_to_client(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_stats_accumulate_from_a_session() {
        let stats = NodeStats::new();
        let counters = RelayCounters::global().with_node_stats(Arc::clone(&stats));

        counters.record_inbound(120);
        counters.record_outbound(300);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.bytes_in, 120);
        assert_eq!(snapshot.bytes_out, 300);
        assert_eq!(counters.total_bytes(), 420);
    }

    #[test]
    fn active_connections_fall_back_to_zero_when_guards_drop() {
        let stats = NodeStats::new();

        let first = stats.connection_started();
        let second = stats.connection_started();
        assert_eq!(stats.snapshot().connections_active, 2);

        drop(first);
        assert_eq!(stats.snapshot().connections_active, 1);

        drop(second);
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.connections_active, 0);
        // Accepted connections are cumulative — closing them does not undo the count.
        assert_eq!(snapshot.connections_total, 2);
    }

    #[test]
    fn sessions_without_node_stats_leave_totals_alone() {
        let stats = NodeStats::new();
        let counters = RelayCounters::global();

        counters.record_inbound(64);

        assert_eq!(stats.snapshot(), NodeSnapshot::default());
        assert_eq!(counters.total_bytes(), 64);
    }
}
