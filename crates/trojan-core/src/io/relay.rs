//! Bidirectional data relay with configurable metrics.
//!
//! This module provides a generic bidirectional relay that can be used by both
//! server and client implementations. Metrics recording is abstracted via the
//! `RelayMetrics` trait, allowing each implementation to provide its own
//! metrics backend.
//!
//! Each direction is driven as an independent poll-based state machine within
//! a single future, so back-pressure on one direction never stalls the other.
//! This prevents deadlocks in multi-hop relay chains.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
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

/// State machine for one-directional copy with flush.
enum CopyState {
    Reading,
    Writing(usize, usize), // (pos, len)
    Flushing(usize),       // bytes flushing
    ShuttingDown,
    Done,
}

/// Result of polling one copy direction.
enum CopyPoll {
    /// Data was flushed — contains byte count for metrics.
    Flushed(usize),
    /// Direction finished (EOF + shutdown).
    Finished,
}

/// Poll-driven one-directional copy: read → write → flush.
fn poll_copy_direction<R, W>(
    cx: &mut Context<'_>,
    reader: &mut R,
    writer: &mut W,
    buf: &mut [u8],
    state: &mut CopyState,
) -> Poll<io::Result<CopyPoll>>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    loop {
        match state {
            CopyState::Reading => {
                let mut read_buf = ReadBuf::new(buf);
                match Pin::new(&mut *reader).poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = read_buf.filled().len();
                        if n == 0 {
                            *state = CopyState::ShuttingDown;
                        } else {
                            *state = CopyState::Writing(0, n);
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            CopyState::Writing(pos, len) => {
                match Pin::new(&mut *writer).poll_write(cx, &buf[*pos..*len]) {
                    Poll::Ready(Ok(n)) => {
                        *pos += n;
                        if *pos >= *len {
                            let total = *len;
                            *state = CopyState::Flushing(total);
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            CopyState::Flushing(bytes) => {
                let bytes = *bytes;
                match Pin::new(&mut *writer).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {
                        *state = CopyState::Reading;
                        return Poll::Ready(Ok(CopyPoll::Flushed(bytes)));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            CopyState::ShuttingDown => match Pin::new(&mut *writer).poll_shutdown(cx) {
                Poll::Ready(_) => {
                    *state = CopyState::Done;
                    return Poll::Ready(Ok(CopyPoll::Finished));
                }
                Poll::Pending => return Poll::Pending,
            },
            CopyState::Done => return Poll::Ready(Ok(CopyPoll::Finished)),
        }
    }
}

/// Bidirectional relay with proper half-close handling.
///
/// Both directions run concurrently within a single task using poll-based
/// I/O, so back-pressure on one direction cannot stall the other. An
/// idle-timeout fires when **neither** direction has transferred data
/// within `idle_timeout`.
///
/// # Arguments
///
/// * `inbound` - The inbound stream (e.g., client connection)
/// * `outbound` - The outbound stream (e.g., target server connection)
/// * `idle_timeout` - Maximum time without data transfer before closing
/// * `buffer_size` - Size of the read buffers
/// * `metrics` - Metrics recorder for tracking bytes transferred
pub async fn relay_bidirectional<A, B, M>(
    inbound: A,
    outbound: B,
    idle_timeout: Duration,
    buffer_size: usize,
    metrics: &M,
) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
    M: RelayMetrics,
{
    let (mut in_r, mut in_w) = tokio::io::split(inbound);
    let (mut out_r, mut out_w) = tokio::io::split(outbound);

    let mut buf_a = vec![0u8; buffer_size];
    let mut buf_b = vec![0u8; buffer_size];
    let mut state_a = CopyState::Reading;
    let mut state_b = CopyState::Reading;

    let idle_sleep = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_sleep);

    let mut a_done = false;
    let mut b_done = false;

    loop {
        if a_done && b_done {
            return Ok(());
        }

        // Build a future that polls both directions concurrently.
        // Each direction registers its own waker so either can make progress
        // independently — one blocked write cannot stall the other direction.
        let both = std::future::poll_fn(|cx| {
            let mut any_ready = false;
            let mut activity = false;
            let mut error: Option<io::Error> = None;

            if !a_done {
                match poll_copy_direction(cx, &mut in_r, &mut out_w, &mut buf_a, &mut state_a) {
                    Poll::Ready(Ok(CopyPoll::Flushed(n))) => {
                        metrics.record_inbound(n as u64);
                        activity = true;
                        any_ready = true;
                    }
                    Poll::Ready(Ok(CopyPoll::Finished)) => {
                        a_done = true;
                        any_ready = true;
                    }
                    Poll::Ready(Err(e)) => {
                        error = Some(e);
                        any_ready = true;
                    }
                    Poll::Pending => {}
                }
            }

            if !b_done {
                match poll_copy_direction(cx, &mut out_r, &mut in_w, &mut buf_b, &mut state_b) {
                    Poll::Ready(Ok(CopyPoll::Flushed(n))) => {
                        metrics.record_outbound(n as u64);
                        activity = true;
                        any_ready = true;
                    }
                    Poll::Ready(Ok(CopyPoll::Finished)) => {
                        b_done = true;
                        any_ready = true;
                    }
                    Poll::Ready(Err(e)) => {
                        error = Some(e);
                        any_ready = true;
                    }
                    Poll::Pending => {}
                }
            }

            if let Some(e) = error {
                return Poll::Ready(Err(e));
            }

            if any_ready {
                Poll::Ready(Ok(activity))
            } else {
                Poll::Pending
            }
        });

        tokio::select! {
            result = both => {
                let activity = result?;
                if activity {
                    idle_sleep.as_mut().reset(TokioInstant::now() + idle_timeout);
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

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

        result.unwrap();
        assert!(start.elapsed() >= Duration::from_millis(50));

        drop(client); // cleanup
    }
}
