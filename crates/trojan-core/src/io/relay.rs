//! Bidirectional data relay with configurable metrics.
//!
//! This module provides a generic bidirectional relay that can be used by both
//! server and client implementations. Metrics recording is abstracted via the
//! `RelayMetrics` trait, allowing each implementation to provide its own
//! metrics backend.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant as TokioInstant;

/// Trait for recording relay metrics.
///
/// Implementors can record bytes transferred in each direction.
/// The server implementation typically records to Prometheus,
/// while clients may use a no-op or custom implementation.
pub trait RelayMetrics {
    /// Record bytes received from inbound (client -> server direction).
    fn record_inbound(&self, bytes: u64);
    /// Record bytes sent to outbound (server -> target direction).
    fn record_outbound(&self, bytes: u64);
}

/// No-op metrics implementation for cases where metrics aren't needed.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpMetrics;

impl RelayMetrics for NoOpMetrics {
    #[inline]
    fn record_inbound(&self, _bytes: u64) {}
    #[inline]
    fn record_outbound(&self, _bytes: u64) {}
}

/// Bidirectional relay with proper half-close handling.
///
/// When one side closes, we continue reading from the other side until it also closes,
/// ensuring all data is properly transferred in both directions.
///
/// # Arguments
///
/// * `inbound` - The inbound stream (e.g., client connection)
/// * `outbound` - The outbound stream (e.g., target server connection)
/// * `idle_timeout` - Maximum time without data transfer before closing
/// * `buffer_size` - Size of the read buffers
/// * `metrics` - Metrics recorder for tracking bytes transferred
///
/// # Example
///
/// ```ignore
/// use trojan_core::io::{relay_bidirectional, NoOpMetrics};
/// use std::time::Duration;
///
/// relay_bidirectional(
///     client_stream,
///     target_stream,
///     Duration::from_secs(300),
///     8192,
///     &NoOpMetrics,
/// ).await?;
/// ```
pub async fn relay_bidirectional<A, B, M>(
    inbound: A,
    outbound: B,
    idle_timeout: Duration,
    buffer_size: usize,
    metrics: &M,
) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
    M: RelayMetrics,
{
    let (mut in_r, mut in_w) = tokio::io::split(inbound);
    let (mut out_r, mut out_w) = tokio::io::split(outbound);

    let mut buf_in = vec![0u8; buffer_size];
    let mut buf_out = vec![0u8; buffer_size];
    let idle_sleep = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_sleep);

    let mut in_closed = false;
    let mut out_closed = false;

    loop {
        if in_closed && out_closed {
            return Ok(());
        }

        tokio::select! {
            res = in_r.read(&mut buf_in), if !in_closed => {
                match res {
                    Ok(0) => {
                        in_closed = true;
                        let _ = out_w.shutdown().await;
                    }
                    Ok(n) => {
                        metrics.record_inbound(n as u64);
                        out_w.write_all(&buf_in[..n]).await?;
                        idle_sleep.as_mut().reset(TokioInstant::now() + idle_timeout);
                    }
                    Err(e) => return Err(e),
                }
            }
            res = out_r.read(&mut buf_out), if !out_closed => {
                match res {
                    Ok(0) => {
                        out_closed = true;
                        let _ = in_w.shutdown().await;
                    }
                    Ok(n) => {
                        metrics.record_outbound(n as u64);
                        in_w.write_all(&buf_out[..n]).await?;
                        idle_sleep.as_mut().reset(TokioInstant::now() + idle_timeout);
                    }
                    Err(e) => return Err(e),
                }
            }
            _ = &mut idle_sleep => {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::duplex;

    struct TestMetrics {
        inbound: AtomicU64,
        outbound: AtomicU64,
    }

    impl TestMetrics {
        fn new() -> Self {
            Self {
                inbound: AtomicU64::new(0),
                outbound: AtomicU64::new(0),
            }
        }
    }

    impl RelayMetrics for TestMetrics {
        fn record_inbound(&self, bytes: u64) {
            self.inbound.fetch_add(bytes, Ordering::Relaxed);
        }
        fn record_outbound(&self, bytes: u64) {
            self.outbound.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    #[tokio::test]
    async fn test_relay_basic() {
        let (client, server_side) = duplex(1024);
        let (target_side, target) = duplex(1024);

        let metrics = TestMetrics::new();

        // Spawn relay
        let relay_handle = tokio::spawn(async move {
            relay_bidirectional(
                server_side,
                target_side,
                Duration::from_secs(5),
                1024,
                &metrics,
            )
            .await
        });

        // Client sends data
        let (mut client_r, mut client_w) = tokio::io::split(client);
        let (mut target_r, mut target_w) = tokio::io::split(target);

        client_w.write_all(b"hello").await.unwrap();
        drop(client_w); // Close write side

        let mut buf = vec![0u8; 1024];
        let n = target_r.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        // Target sends response
        target_w.write_all(b"world").await.unwrap();
        drop(target_w);

        let n = client_r.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"world");

        // Relay should complete
        relay_handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_relay_idle_timeout() {
        let (client, server_side) = duplex(1024);
        let (target_side, _target) = duplex(1024);

        let start = TokioInstant::now();
        let result = relay_bidirectional(
            server_side,
            target_side,
            Duration::from_millis(50),
            1024,
            &NoOpMetrics,
        )
        .await;

        assert!(result.is_ok());
        assert!(start.elapsed() >= Duration::from_millis(50));

        drop(client); // cleanup
    }
}
