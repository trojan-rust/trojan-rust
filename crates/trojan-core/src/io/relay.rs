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

/// State machine for one-directional copy with deferred flush.
///
/// Unlike a naive read→write→flush loop, this batches multiple read/write
/// cycles before flushing. A flush only happens when the reader returns
/// `Pending` (no more data immediately available) or on EOF. This mirrors
/// the strategy used by `tokio::io::copy` and avoids excessive flush
/// syscalls on buffered writers like TLS streams.
enum CopyState {
    Reading(usize),               // accumulated bytes since last flush
    Writing(usize, usize, usize), // (pos, len, accumulated)
    Flushing(usize, bool),        // (total bytes to report, is_eof)
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

/// Poll-driven one-directional copy with deferred flush.
///
/// Reads and writes in a loop, only flushing when the reader has no more
/// data immediately available (`Pending`) or at EOF. This batches multiple
/// read/write cycles into a single flush, reducing syscall overhead on
/// buffered writers (e.g. TLS streams).
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
            CopyState::Reading(flushed) => {
                let mut read_buf = ReadBuf::new(buf);
                match Pin::new(&mut *reader).poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = read_buf.filled().len();
                        if n == 0 {
                            // EOF — flush any accumulated bytes, then shut down.
                            if *flushed > 0 {
                                let total = *flushed;
                                *state = CopyState::Flushing(total, true);
                            } else {
                                *state = CopyState::ShuttingDown;
                            }
                        } else {
                            let acc = *flushed;
                            *state = CopyState::Writing(0, n, acc);
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        // Reader has no more data — flush accumulated bytes.
                        if *flushed > 0 {
                            let total = *flushed;
                            *state = CopyState::Flushing(total, false);
                        } else {
                            return Poll::Pending;
                        }
                    }
                }
            }
            CopyState::Writing(pos, len, acc) => {
                match Pin::new(&mut *writer).poll_write(cx, &buf[*pos..*len]) {
                    Poll::Ready(Ok(n)) => {
                        *pos += n;
                        if *pos >= *len {
                            let total = *acc + *len;
                            // Don't flush yet — try to read more data first.
                            *state = CopyState::Reading(total);
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            CopyState::Flushing(bytes, is_eof) => {
                let bytes = *bytes;
                let eof = *is_eof;
                match Pin::new(&mut *writer).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {
                        if eof {
                            *state = CopyState::ShuttingDown;
                        } else {
                            *state = CopyState::Reading(0);
                        }
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

/// Bytes transferred in each direction during a relay session.
#[derive(Debug, Clone, Copy, Default)]
pub struct RelayStats {
    /// Bytes from inbound to outbound (client → target).
    pub inbound: u64,
    /// Bytes from outbound to inbound (target → client).
    pub outbound: u64,
}

impl RelayStats {
    /// Total bytes transferred in both directions.
    #[inline]
    pub fn total(self) -> u64 {
        self.inbound + self.outbound
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
) -> io::Result<RelayStats>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
    M: RelayMetrics,
{
    let (mut in_r, mut in_w) = tokio::io::split(inbound);
    let (mut out_r, mut out_w) = tokio::io::split(outbound);

    let mut buf_a = vec![0u8; buffer_size];
    let mut buf_b = vec![0u8; buffer_size];
    let mut state_a = CopyState::Reading(0);
    let mut state_b = CopyState::Reading(0);

    let idle_sleep = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_sleep);

    let mut a_done = false;
    let mut b_done = false;
    let mut total_inbound: u64 = 0;
    let mut total_outbound: u64 = 0;

    loop {
        if a_done && b_done {
            return Ok(RelayStats {
                inbound: total_inbound,
                outbound: total_outbound,
            });
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
                        let bytes = n as u64;
                        metrics.record_inbound(bytes);
                        total_inbound += bytes;
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
                        let bytes = n as u64;
                        metrics.record_outbound(bytes);
                        total_outbound += bytes;
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
                return Ok(RelayStats {
                    inbound: total_inbound,
                    outbound: total_outbound,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
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

    // ── Flush-batching tests ──

    /// A mock reader that yields chunks from a queue.
    /// Returns `Pending` (with waker notification) between groups separated
    /// by `None` entries, simulating data arriving in bursts.
    struct MockReader {
        /// `Some(data)` = a read returning data, `None` = return Pending once.
        chunks: VecDeque<Option<Vec<u8>>>,
        pending_waker: Option<std::task::Waker>,
    }

    impl MockReader {
        fn new(chunks: Vec<Option<Vec<u8>>>) -> Self {
            Self {
                chunks: chunks.into(),
                pending_waker: None,
            }
        }
    }

    impl AsyncRead for MockReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.chunks.front() {
                Some(Some(_)) => {
                    let data = self.chunks.pop_front().unwrap().unwrap();
                    buf.put_slice(&data);
                    Poll::Ready(Ok(()))
                }
                Some(None) => {
                    // Consume the Pending marker, wake immediately so the
                    // next poll will return the next chunk.
                    self.chunks.pop_front();
                    self.pending_waker = Some(cx.waker().clone());
                    // Schedule a wake so the state machine advances.
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                None => {
                    // EOF
                    Poll::Ready(Ok(()))
                }
            }
        }
    }

    /// A writer that counts flush calls and records written data.
    struct FlushCountingWriter {
        written: Vec<u8>,
        flush_count: usize,
    }

    impl FlushCountingWriter {
        fn new() -> Self {
            Self {
                written: Vec::new(),
                flush_count: 0,
            }
        }
    }

    impl AsyncWrite for FlushCountingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flush_count += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_flush_batching_consecutive_reads() {
        // Simulate 3 chunks arriving in a burst (no Pending between them),
        // followed by EOF. The state machine should batch all 3 writes into
        // a single flush (the EOF flush).
        let mut reader = MockReader::new(vec![
            Some(b"aaa".to_vec()),
            Some(b"bbb".to_vec()),
            Some(b"ccc".to_vec()),
            // EOF follows (empty queue)
        ]);
        let mut writer = FlushCountingWriter::new();
        let mut buf = vec![0u8; 64];
        let mut state = CopyState::Reading(0);

        let mut total_bytes = 0;
        loop {
            let result = std::future::poll_fn(|cx| {
                poll_copy_direction(cx, &mut reader, &mut writer, &mut buf, &mut state)
            })
            .await
            .unwrap();
            match result {
                CopyPoll::Flushed(n) => total_bytes += n,
                CopyPoll::Finished => break,
            }
        }

        assert_eq!(writer.written, b"aaabbbccc");
        assert_eq!(total_bytes, 9);
        // All 3 chunks were available consecutively — should batch into 1 flush
        // (the EOF-triggered flush), not 3 separate flushes.
        assert_eq!(
            writer.flush_count, 1,
            "consecutive reads should batch flushes"
        );
    }

    #[tokio::test]
    async fn test_flush_on_pending() {
        // Simulate: chunk1, Pending, chunk2, Pending, EOF.
        // Should flush after each Pending (2 flushes) plus EOF flush (but
        // EOF after Pending with 0 accumulated goes straight to shutdown).
        // Actually: chunk1 → write → Reading(3) → Pending → Flushing(3) → flush#1
        //           chunk2 → write → Reading(3) → Pending → but no accumulated → Pending
        //           Wait, after flush#1 we reset to Reading(0), then read chunk2...
        // Let me trace: chunk1 → write → Reading(3) → Pending → Flush(3, false) → flush#1
        //               Reading(0) → chunk2 → write → Reading(3) → Pending → Flush(3, false) → flush#2
        //               Reading(0) → EOF → ShuttingDown → Finished
        let mut reader = MockReader::new(vec![
            Some(b"aaa".to_vec()),
            None, // Pending
            Some(b"bbb".to_vec()),
            None, // Pending
                  // EOF
        ]);
        let mut writer = FlushCountingWriter::new();
        let mut buf = vec![0u8; 64];
        let mut state = CopyState::Reading(0);

        let mut total_bytes = 0;
        loop {
            let result = std::future::poll_fn(|cx| {
                poll_copy_direction(cx, &mut reader, &mut writer, &mut buf, &mut state)
            })
            .await
            .unwrap();
            match result {
                CopyPoll::Flushed(n) => total_bytes += n,
                CopyPoll::Finished => break,
            }
        }

        assert_eq!(writer.written, b"aaabbb");
        assert_eq!(total_bytes, 6);
        // 2 flushes: one after each Pending gap.
        assert_eq!(writer.flush_count, 2, "should flush once per Pending gap");
    }

    #[tokio::test]
    async fn test_flush_batching_burst_then_pending() {
        // 3 chunks in a burst, then Pending, then 1 more chunk, then EOF.
        // Should produce 2 flushes: one for the burst (at Pending), one at EOF.
        let mut reader = MockReader::new(vec![
            Some(b"a".to_vec()),
            Some(b"b".to_vec()),
            Some(b"c".to_vec()),
            None, // Pending — triggers flush of accumulated 3 bytes
            Some(b"d".to_vec()),
            // EOF — triggers flush of 1 byte
        ]);
        let mut writer = FlushCountingWriter::new();
        let mut buf = vec![0u8; 64];
        let mut state = CopyState::Reading(0);

        let mut total_bytes = 0;
        loop {
            let result = std::future::poll_fn(|cx| {
                poll_copy_direction(cx, &mut reader, &mut writer, &mut buf, &mut state)
            })
            .await
            .unwrap();
            match result {
                CopyPoll::Flushed(n) => total_bytes += n,
                CopyPoll::Finished => break,
            }
        }

        assert_eq!(writer.written, b"abcd");
        assert_eq!(total_bytes, 4);
        assert_eq!(
            writer.flush_count, 2,
            "burst then pending then EOF = 2 flushes"
        );
    }
}
