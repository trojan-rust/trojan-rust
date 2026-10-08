//! Bidirectional data relay with Prometheus metrics.
//!
//! This module wraps the generic relay from `trojan-core` with server-specific
//! metrics recording using Prometheus.

use std::{io, time::Duration};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use trojan_core::io::{RelayStats, relay_bidirectional};
use trojan_metrics::RelayCounters;

use crate::error::ServerError;

/// Bidirectional relay with proper half-close handling and metrics.
///
/// When one side closes, we continue reading from the other side until it also
/// closes, ensuring all data is properly transferred in both directions.
///
/// The relay reports bytes after each write, so `counters` is resolved by the
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

/// Count accepted bytes before a later write can fail or be cancelled.
pub(crate) async fn write_all_counted<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut bytes: &[u8],
    record: impl Fn(u64),
) -> io::Result<()> {
    while !bytes.is_empty() {
        let written = writer.write(bytes).await?;
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        record(written as u64);
        bytes = &bytes[written..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::task::{Context, Waker};
    use tokio::io::{AsyncReadExt, duplex};
    use trojan_metrics::NodeStats;

    #[tokio::test]
    async fn initial_payload_keeps_partial_write_after_cancellation() {
        let (mut writer, mut reader) = duplex(1);
        let stats = NodeStats::new();
        let counters = RelayCounters::global().with_node_stats(stats.clone());
        let mut writing = Box::pin(write_all_counted(&mut writer, b"ab", |bytes| {
            counters.add_to_target(bytes);
        }));

        assert!(
            writing
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(stats.snapshot().bytes_in, 1);
        drop(writing);
        drop(writer);

        let mut received = Vec::new();
        reader.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"a");
        assert_eq!(stats.snapshot().bytes_in, 1);
    }

    #[tokio::test]
    async fn initial_payload_keeps_partial_write_after_error() {
        let (mut writer, reader) = duplex(1);
        let stats = NodeStats::new();
        let counters = RelayCounters::global().with_node_stats(stats.clone());
        let mut writing = Box::pin(write_all_counted(&mut writer, b"ab", |bytes| {
            counters.add_to_target(bytes);
        }));

        assert!(
            writing
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(stats.snapshot().bytes_in, 1);
        drop(reader);

        assert_eq!(writing.await.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(stats.snapshot().bytes_in, 1);
    }

    #[tokio::test]
    async fn zero_write_fails_without_recording_bytes() {
        struct ZeroWriter;

        impl AsyncWrite for ZeroWriter {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &[u8],
            ) -> std::task::Poll<io::Result<usize>> {
                std::task::Poll::Ready(Ok(0))
            }

            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                unreachable!("counted writes do not flush");
            }

            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                unreachable!("counted writes do not shut down");
            }
        }

        let error = write_all_counted(&mut ZeroWriter, b"a", |_| {
            panic!("zero writes must not add traffic");
        })
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    }
}
