//! Bidirectional data relay with Prometheus metrics.
//!
//! This module wraps the generic relay from `trojan-core` with server-specific
//! metrics recording using Prometheus.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use trojan_core::io::{RelayStats, relay_bidirectional};
use trojan_metrics::RelayCounters;

use crate::error::ServerError;

/// Bidirectional relay with proper half-close handling and metrics.
///
/// When one side closes, we continue reading from the other side until it also
/// closes, ensuring all data is properly transferred in both directions.
///
/// The relay reports bytes once per flush, so `counters` is resolved by the
/// caller once per session — see [`RelayCounters`].
pub async fn relay_with_counters<A, B>(
    inbound: A,
    outbound: B,
    idle_timeout: Duration,
    buffer_size: usize,
    counters: &RelayCounters,
) -> Result<RelayStats, ServerError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    relay_bidirectional(inbound, outbound, idle_timeout, buffer_size, counters)
        .await
        .map_err(ServerError::from)
}
