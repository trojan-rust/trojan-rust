//! Metrics collection and Prometheus exporter for trojan-rs.
//!
//! This module provides metrics instrumentation for the trojan server,
//! including connection counts, bytes transferred, and error rates.

use std::net::SocketAddr;

use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;

/// Initialize Prometheus metrics exporter.
///
/// Starts an HTTP server on the given address to expose metrics.
/// Returns an error message if binding fails.
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
/// Connection queue depth (pending connections in accept backlog).
pub const CONNECTION_QUEUE_DEPTH: &str = "trojan_connection_queue_depth";
/// Per-target connection counts (by destination).
pub const TARGET_CONNECTIONS_TOTAL: &str = "trojan_target_connections_total";
/// Per-target bytes transferred.
pub const TARGET_BYTES_TOTAL: &str = "trojan_target_bytes_total";
/// Current size of the fallback warm pool.
pub const FALLBACK_POOL_SIZE: &str = "trojan_fallback_pool_size";
/// Total number of warm-fill connection failures.
pub const FALLBACK_POOL_WARM_FAIL_TOTAL: &str = "trojan_fallback_pool_warm_fail_total";

// ============================================================================
// Metric Recording Functions
// ============================================================================

/// Record a new connection accepted.
#[inline]
pub fn record_connection_accepted() {
    counter!(CONNECTIONS_TOTAL).increment(1);
    gauge!(CONNECTIONS_ACTIVE).increment(1.0);
}

/// Record a connection closed.
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

/// Record bytes received from client.
#[inline]
pub fn record_bytes_received(bytes: u64) {
    counter!(BYTES_RECEIVED_TOTAL).increment(bytes);
}

/// Record bytes sent to client.
#[inline]
pub fn record_bytes_sent(bytes: u64) {
    counter!(BYTES_SENT_TOTAL).increment(bytes);
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

/// Set connection queue depth gauge.
#[inline]
pub fn set_connection_queue_depth(depth: f64) {
    gauge!(CONNECTION_QUEUE_DEPTH).set(depth);
}

/// Record a connection to a target (by destination host).
/// The target should be sanitized (e.g., IP address or domain without port).
/// Note: This function allocates a String for the label. For hot paths with repeated calls,
/// consider caching the String at the call site.
#[inline]
pub fn record_target_connection(target: &str) {
    counter!(TARGET_CONNECTIONS_TOTAL, "target" => target.to_owned()).increment(1);
}

/// Record bytes transferred to/from a target.
/// Direction: "sent" or "received".
/// Note: This function allocates a String for the label. For hot paths with repeated calls,
/// consider caching the String at the call site.
#[inline]
pub fn record_target_bytes(target: &str, direction: &'static str, bytes: u64) {
    counter!(TARGET_BYTES_TOTAL, "target" => target.to_owned(), "direction" => direction)
        .increment(bytes);
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

// ============================================================================
// Error Type Constants (re-exported from trojan-core)
// ============================================================================

pub use trojan_core::{
    ERROR_AUTH, ERROR_CONFIG, ERROR_IO, ERROR_PROTOCOL, ERROR_RESOLVE, ERROR_TIMEOUT,
    ERROR_TLS_HANDSHAKE,
};
