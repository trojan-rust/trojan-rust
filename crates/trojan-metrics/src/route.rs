//! Entry route metrics with handles resolved once per configured rule.

use std::time::Instant;

use metrics::{Counter, Histogram, counter, histogram};

/// Route selections, labelled by configured rule and `selected` or `unavailable` outcome.
pub const ROUTE_SELECTIONS_TOTAL: &str = "trojan_route_selections_total";
/// Tunnel setup attempts, labelled by configured rule and fixed outcome.
pub const ROUTE_SETUP_TOTAL: &str = "trojan_route_setup_total";
/// Tunnel setup duration, labelled by configured rule and fixed outcome.
pub const ROUTE_SETUP_DURATION_SECONDS: &str = "trojan_route_setup_duration_seconds";
/// Alternate routes attempted after a failure, labelled by configured rule and failure reason.
pub const ROUTE_FAILOVERS_TOTAL: &str = "trojan_route_failovers_total";

/// The part of a route that failed before client payload forwarding began.
#[derive(Debug, Clone, Copy)]
pub enum RouteFailure {
    /// A relay connection, authentication, or handshake failed.
    Relay,
    /// The final destination connection failed.
    Destination,
}

#[derive(Debug)]
struct SetupMetrics {
    total: Counter,
    duration: Histogram,
}

impl SetupMetrics {
    fn new(rule: &str, outcome: &'static str) -> Self {
        Self {
            total: counter!(ROUTE_SETUP_TOTAL, "rule" => rule.to_owned(), "outcome" => outcome),
            duration: histogram!(ROUTE_SETUP_DURATION_SECONDS, "rule" => rule.to_owned(), "outcome" => outcome),
        }
    }
}

/// Cached route metrics for one configured entry rule.
///
/// Construct after installing the recorder. Share the handles across sessions.
/// Labels contain no client addresses, destination addresses, or error messages.
#[derive(Debug)]
pub struct RouteMetrics {
    selected: Counter,
    unavailable: Counter,
    connected: SetupMetrics,
    relay_error: SetupMetrics,
    destination_error: SetupMetrics,
    cancelled: SetupMetrics,
    relay_failover: Counter,
    destination_failover: Counter,
}

impl RouteMetrics {
    /// Resolve the bounded set of metric handles for a configured rule.
    pub fn new(rule: &str) -> Self {
        Self {
            selected: counter!(ROUTE_SELECTIONS_TOTAL, "rule" => rule.to_owned(), "outcome" => "selected"),
            unavailable: counter!(ROUTE_SELECTIONS_TOTAL, "rule" => rule.to_owned(), "outcome" => "unavailable"),
            connected: SetupMetrics::new(rule, "connected"),
            relay_error: SetupMetrics::new(rule, "relay_error"),
            destination_error: SetupMetrics::new(rule, "destination_error"),
            cancelled: SetupMetrics::new(rule, "cancelled"),
            relay_failover: counter!(ROUTE_FAILOVERS_TOTAL, "rule" => rule.to_owned(), "reason" => "relay"),
            destination_failover: counter!(ROUTE_FAILOVERS_TOTAL, "rule" => rule.to_owned(), "reason" => "destination"),
        }
    }

    /// Record a selected route before beginning tunnel setup.
    pub fn selected(&self) {
        self.selected.increment(1);
    }

    /// Record that no eligible route remains, including exhausted retry candidates.
    pub fn unavailable(&self) {
        self.unavailable.increment(1);
    }

    /// Record an actual alternate route attempt after the specified failure.
    pub fn failover(&self, failure: RouteFailure) {
        match failure {
            RouteFailure::Relay => &self.relay_failover,
            RouteFailure::Destination => &self.destination_failover,
        }
        .increment(1);
    }

    /// Begin a setup attempt that records cancellation if no result is supplied.
    pub fn setup_started(&self) -> RouteAttempt<'_> {
        RouteAttempt {
            metrics: self,
            outcome: &self.cancelled,
            started: Instant::now(),
        }
    }
}

/// A tunnel setup attempt that records its outcome and duration exactly once.
#[must_use = "dropping an unfinished attempt records cancellation"]
#[derive(Debug)]
pub struct RouteAttempt<'a> {
    metrics: &'a RouteMetrics,
    outcome: &'a SetupMetrics,
    started: Instant,
}

impl RouteAttempt<'_> {
    /// Finish setup after every tunnel handshake succeeds.
    pub fn connected(mut self) {
        self.outcome = &self.metrics.connected;
    }

    /// Finish setup with the part of the route that failed.
    pub fn failed(mut self, failure: RouteFailure) {
        self.outcome = match failure {
            RouteFailure::Relay => &self.metrics.relay_error,
            RouteFailure::Destination => &self.metrics.destination_error,
        };
    }
}

impl Drop for RouteAttempt<'_> {
    fn drop(&mut self) {
        self.outcome.total.increment(1);
        self.outcome
            .duration
            .record(self.started.elapsed().as_secs_f64());
    }
}
