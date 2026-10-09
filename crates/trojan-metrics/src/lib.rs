//! Metrics collection and Prometheus exporter for trojan-rs.
//!
//! This module provides metrics instrumentation for the trojan server,
//! including connection counts, bytes transferred, and error rates.

use std::net::SocketAddr;

use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;

mod connection;
mod counters;
mod route;
mod server;

pub use connection::ConnectionMetrics;
pub use counters::{ActiveConnection, NodeSnapshot, NodeStats, RelayCounters};
pub use route::{
    ROUTE_FAILOVERS_TOTAL, ROUTE_SELECTIONS_TOTAL, ROUTE_SETUP_DURATION_SECONDS, ROUTE_SETUP_TOTAL,
    RouteAttempt, RouteFailure, RouteMetrics,
};
pub use server::{MetricsError, MetricsServer, init_metrics_server};

/// Initialize Prometheus metrics exporter (legacy function).
///
/// Starts an HTTP server on the given address to expose metrics.
/// Returns an error message if binding fails.
#[deprecated(since = "0.2.0", note = "Use init_metrics_server instead")]
pub fn init_prometheus(listen: &str) -> Result<(), String> {
    let addr: SocketAddr = listen
        .parse()
        .map_err(|e| format!("invalid metrics listen address: {}", e))?;

    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()
        .map_err(|e| format!("failed to install prometheus exporter: {}", e))?;

    Ok(())
}

// ============================================================================
// Metric Names
// ============================================================================

/// Total number of TCP connections accepted.
pub const CONNECTIONS_TOTAL: &str = "trojan_connections_total";
/// Number of currently active connections.
pub const CONNECTIONS_ACTIVE: &str = "trojan_connections_active";
/// Total number of successful authentications.
pub const AUTH_SUCCESS_TOTAL: &str = "trojan_auth_success_total";
/// Total number of failed authentications.
pub const AUTH_FAILURE_TOTAL: &str = "trojan_auth_failure_total";
/// Total number of fallback connections (non-trojan traffic).
pub const FALLBACK_TOTAL: &str = "trojan_fallback_total";
/// Total bytes received from clients.
pub const BYTES_RECEIVED_TOTAL: &str = "trojan_bytes_received_total";
/// Total bytes sent to clients.
pub const BYTES_SENT_TOTAL: &str = "trojan_bytes_sent_total";
/// Total number of CONNECT requests.
pub const CONNECT_REQUESTS_TOTAL: &str = "trojan_connect_requests_total";
/// Total number of UDP associate requests.
pub const UDP_ASSOCIATE_REQUESTS_TOTAL: &str = "trojan_udp_associate_requests_total";
/// Total number of UDP packets relayed.
pub const UDP_PACKETS_TOTAL: &str = "trojan_udp_packets_total";
/// Connection duration histogram (seconds).
pub const CONNECTION_DURATION_SECONDS: &str = "trojan_connection_duration_seconds";
/// Total number of errors by type.
pub const ERRORS_TOTAL: &str = "trojan_errors_total";
/// Total number of connections rejected (rate limit, max connections).
pub const CONNECTIONS_REJECTED_TOTAL: &str = "trojan_connections_rejected_total";
/// TLS handshake duration histogram (seconds).
pub const TLS_HANDSHAKE_DURATION_SECONDS: &str = "trojan_tls_handshake_duration_seconds";
/// Caller-supplied connection queue depth. Server listeners do not emit this metric.
pub const CONNECTION_QUEUE_DEPTH: &str = "trojan_connection_queue_depth";
/// Per-target connection counts (by destination).
pub const TARGET_CONNECTIONS_TOTAL: &str = "trojan_target_connections_total";
/// Per-target bytes transferred.
pub const TARGET_BYTES_TOTAL: &str = "trojan_target_bytes_total";
/// Per-rule bytes transferred on an entry node.
pub const ENTRY_RULE_BYTES_TOTAL: &str = "trojan_entry_rule_bytes_total";
/// Current size of the fallback warm pool.
pub const FALLBACK_POOL_SIZE: &str = "trojan_fallback_pool_size";
/// Total number of warm-fill connection failures.
pub const FALLBACK_POOL_WARM_FAIL_TOTAL: &str = "trojan_fallback_pool_warm_fail_total";
/// DNS resolution duration histogram (seconds).
pub const DNS_RESOLVE_DURATION_SECONDS: &str = "trojan_dns_resolve_duration_seconds";
/// Target connection establishment duration histogram (seconds).
pub const TARGET_CONNECT_DURATION_SECONDS: &str = "trojan_target_connect_duration_seconds";
/// Total number of successful rule engine updates (hot-reload).
pub const RULE_UPDATES_TOTAL: &str = "trojan_rule_updates_total";
/// Total number of failed rule engine update attempts (hot-reload).
pub const RULE_UPDATE_ERRORS_TOTAL: &str = "trojan_rule_update_errors_total";
/// Total connections by source country.
pub const CONNECTIONS_BY_COUNTRY: &str = "trojan_connections_by_country_total";
/// Total bytes by source country and direction.
pub const BYTES_BY_COUNTRY: &str = "trojan_bytes_by_country_total";
/// Total auth failures by source country.
pub const AUTH_FAILURE_BY_COUNTRY: &str = "trojan_auth_failure_by_country_total";

// ============================================================================
// Metric Recording Functions
// ============================================================================

/// Record a new connection accepted. Prefer [`ConnectionMetrics`] for owned sessions.
#[inline]
pub fn record_connection_accepted() {
    counter!(CONNECTIONS_TOTAL).increment(1);
    gauge!(CONNECTIONS_ACTIVE).increment(1.0);
}

/// Record a connection closed. Prefer [`ConnectionMetrics`] for owned sessions.
#[inline]
pub fn record_connection_closed(duration_secs: f64) {
    gauge!(CONNECTIONS_ACTIVE).decrement(1.0);
    histogram!(CONNECTION_DURATION_SECONDS).record(duration_secs);
}

/// Record successful authentication.
#[inline]
pub fn record_auth_success() {
    counter!(AUTH_SUCCESS_TOTAL).increment(1);
}

/// Record failed authentication (triggers fallback).
#[inline]
pub fn record_auth_failure() {
    counter!(AUTH_FAILURE_TOTAL).increment(1);
}

/// Record fallback to HTTP backend.
#[inline]
pub fn record_fallback() {
    counter!(FALLBACK_TOTAL).increment(1);
}

/// Record a CONNECT request.
#[inline]
pub fn record_connect_request() {
    counter!(CONNECT_REQUESTS_TOTAL).increment(1);
}

/// Record a UDP associate request.
#[inline]
pub fn record_udp_associate_request() {
    counter!(UDP_ASSOCIATE_REQUESTS_TOTAL).increment(1);
}

/// Record UDP packets relayed (direction: "inbound" or "outbound").
#[inline]
pub fn record_udp_packet(direction: &'static str) {
    counter!(UDP_PACKETS_TOTAL, "direction" => direction).increment(1);
}

/// Record an error by type.
#[inline]
pub fn record_error(error_type: &'static str) {
    counter!(ERRORS_TOTAL, "type" => error_type).increment(1);
}

/// Record a rejected connection (reason: "max_connections", "rate_limit").
#[inline]
pub fn record_connection_rejected(reason: &'static str) {
    counter!(CONNECTIONS_REJECTED_TOTAL, "reason" => reason).increment(1);
}

/// Record TLS handshake duration.
#[inline]
pub fn record_tls_handshake_duration(duration_secs: f64) {
    histogram!(TLS_HANDSHAKE_DURATION_SECONDS).record(duration_secs);
}

/// Set an actual connection queue measurement, not semaphore availability.
///
/// Server listeners do not call this function because they cannot observe the TCP backlog.
#[inline]
pub fn set_connection_queue_depth(depth: f64) {
    gauge!(CONNECTION_QUEUE_DEPTH).set(depth);
}

/// Record a connection to a target (by destination host).
///
/// The target should be sanitized (e.g., IP address or domain without port).
/// Called once per connection, so resolving the labelled key here is fine;
/// for anything recorded more often than that use [`RelayCounters`].
#[inline]
pub fn record_target_connection(target: &str) {
    counter!(TARGET_CONNECTIONS_TOTAL, "target" => target.to_owned()).increment(1);
}

/// Set current fallback pool size.
#[inline]
pub fn set_fallback_pool_size(size: usize) {
    gauge!(FALLBACK_POOL_SIZE).set(size as f64);
}

/// Record warm-fill connection failure.
#[inline]
pub fn record_fallback_pool_warm_fail() {
    counter!(FALLBACK_POOL_WARM_FAIL_TOTAL).increment(1);
}

/// Record DNS resolution duration.
#[inline]
pub fn record_dns_resolve_duration(duration_secs: f64) {
    histogram!(DNS_RESOLVE_DURATION_SECONDS).record(duration_secs);
}

/// Record target connection establishment duration.
#[inline]
pub fn record_target_connect_duration(duration_secs: f64) {
    histogram!(TARGET_CONNECT_DURATION_SECONDS).record(duration_secs);
}

/// Record a successful rule engine update (hot-reload).
#[inline]
pub fn record_rule_update() {
    counter!(RULE_UPDATES_TOTAL).increment(1);
}

/// Record a failed rule engine update attempt (hot-reload).
#[inline]
pub fn record_rule_update_error() {
    counter!(RULE_UPDATE_ERRORS_TOTAL).increment(1);
}

/// Record a connection with source country label.
#[inline]
pub fn record_connection_with_geo(country: &str) {
    counter!(CONNECTIONS_BY_COUNTRY, "country" => country.to_owned()).increment(1);
}

/// Record bytes transferred with source country label.
/// Direction: "sent" or "received".
#[inline]
pub fn record_bytes_with_geo(country: &str, direction: &'static str, bytes: u64) {
    counter!(BYTES_BY_COUNTRY, "country" => country.to_owned(), "direction" => direction)
        .increment(bytes);
}

/// Record an authentication failure with source country label.
#[inline]
pub fn record_auth_failure_with_geo(country: &str) {
    counter!(AUTH_FAILURE_BY_COUNTRY, "country" => country.to_owned()).increment(1);
}

// ============================================================================
// Error Type Constants (re-exported from trojan-core)
// ============================================================================

pub use trojan_core::{
    ERROR_AUTH, ERROR_CONFIG, ERROR_IO, ERROR_PROTOCOL, ERROR_RESOLVE, ERROR_TIMEOUT,
    ERROR_TLS_HANDSHAKE,
};
