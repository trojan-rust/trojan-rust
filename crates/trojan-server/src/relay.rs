//! Bidirectional data relay with Prometheus metrics.
//!
//! This module wraps the generic relay from `trojan-core` with server-specific
//! metrics recording using Prometheus.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use trojan_core::io::{RelayMetrics, relay_bidirectional};
use trojan_metrics::{record_bytes_received, record_bytes_sent, record_target_bytes};

use crate::error::ServerError;

/// Metrics recorder for global bytes tracking only.
struct GlobalMetrics;

impl RelayMetrics for GlobalMetrics {
    #[inline]
    fn record_inbound(&self, bytes: u64) {
        record_bytes_received(bytes);
    }
    #[inline]
    fn record_outbound(&self, bytes: u64) {
        record_bytes_sent(bytes);
    }
}

/// Metrics recorder with per-target tracking.
struct TargetMetrics<'a> {
    target_label: &'a str,
}

impl RelayMetrics for TargetMetrics<'_> {
    #[inline]
    fn record_inbound(&self, bytes: u64) {
        record_bytes_received(bytes);
        record_target_bytes(self.target_label, "sent", bytes);
    }
    #[inline]
    fn record_outbound(&self, bytes: u64) {
        record_bytes_sent(bytes);
        record_target_bytes(self.target_label, "received", bytes);
    }
}

/// Bidirectional relay with proper half-close handling and metrics.
///
/// When one side closes, we continue reading from the other side until it also closes,
/// ensuring all data is properly transferred in both directions.
pub async fn relay_with_idle_timeout_and_metrics<A, B>(
    inbound: A,
    outbound: B,
    idle_timeout: Duration,
    buffer_size: usize,
) -> Result<(), ServerError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    relay_bidirectional(inbound, outbound, idle_timeout, buffer_size, &GlobalMetrics)
        .await
        .map_err(ServerError::from)
}

/// Bidirectional relay with per-target metrics tracking.
pub async fn relay_with_idle_timeout_and_metrics_per_target<A, B>(
    inbound: A,
    outbound: B,
    idle_timeout: Duration,
    buffer_size: usize,
    target_label: &str,
) -> Result<(), ServerError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    if target_label.is_empty() {
        return relay_with_idle_timeout_and_metrics(inbound, outbound, idle_timeout, buffer_size)
            .await;
    }

    let metrics = TargetMetrics { target_label };
    relay_bidirectional(inbound, outbound, idle_timeout, buffer_size, &metrics)
        .await
        .map_err(ServerError::from)
}
