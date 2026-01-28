//! Prefixed stream adapter for replaying buffered data.
//!
//! This module provides `PrefixedStream`, a stream wrapper that yields
//! pre-buffered bytes before reading from the inner stream. This is useful
//! for protocol detection where you need to peek at incoming data without
//! consuming it from the underlying stream.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A stream wrapper that yields a prefetched prefix before reading from the inner stream.
///
/// This is commonly used in mixed-mode protocol detection (e.g., WebSocket upgrade)
/// where we need to read HTTP headers to determine the protocol, then replay those
/// bytes to the actual protocol handler.
///
/// # Example
///
/// ```ignore
/// use trojan_core::io::PrefixedStream;
/// use bytes::Bytes;
///
/// // After reading some bytes for protocol detection
/// let buffered = Bytes::from(b"GET / HTTP/1.1\r\n...");
/// let prefixed = PrefixedStream::new(buffered, tcp_stream);
///
/// // Now the prefixed stream will first yield the buffered bytes,
/// // then continue reading from tcp_stream
/// ```
pub struct PrefixedStream<S> {
    prefix: Bytes,
    pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    /// Create a new prefixed stream.
    ///
    /// # Arguments
    ///
    /// * `prefix` - The buffered bytes to yield first
    /// * `inner` - The underlying stream to read from after prefix is exhausted
    pub fn new(prefix: Bytes, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }

    /// Returns the remaining unread prefix bytes.
    pub fn prefix_remaining(&self) -> usize {
        self.prefix.len().saturating_sub(self.pos)
    }

    /// Consumes the wrapper, returning the inner stream.
    ///
    /// Note: Any unread prefix bytes will be lost.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // First, yield any remaining prefix bytes
        if self.pos < self.prefix.len() {
            let remaining = &self.prefix[self.pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.pos += to_copy;
            return Poll::Ready(Ok(()));
        }
        // Then delegate to inner stream
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn test_prefixed_stream_read() {
        let (mut client, server) = duplex(1024);

        // Server will read from prefixed stream
        let prefix = Bytes::from_static(b"prefix:");
        let mut prefixed = PrefixedStream::new(prefix, server);

        // Client sends some data
        client.write_all(b"suffix").await.unwrap();
        drop(client);

        // Read should yield prefix first, then inner stream data
        let mut buf = vec![0u8; 1024];
        let mut total = Vec::new();

        loop {
            let n = prefixed.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            total.extend_from_slice(&buf[..n]);
        }

        assert_eq!(total, b"prefix:suffix");
    }

    #[tokio::test]
    async fn test_prefixed_stream_partial_read() {
        let (_client, server) = duplex(1024);

        let prefix = Bytes::from_static(b"hello world");
        let mut prefixed = PrefixedStream::new(prefix, server);

        // Read with small buffer
        let mut buf = [0u8; 5];
        let n = prefixed.read(&mut buf).await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");

        let n = prefixed.read(&mut buf).await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b" worl");

        let n = prefixed.read(&mut buf).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(&buf[..1], b"d");
    }

    #[tokio::test]
    async fn test_prefixed_stream_write_passthrough() {
        let (mut client, server) = duplex(1024);

        let prefix = Bytes::from_static(b"prefix");
        let mut prefixed = PrefixedStream::new(prefix, server);

        // Write should go directly to inner stream
        prefixed.write_all(b"hello").await.unwrap();

        let mut buf = [0u8; 10];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[tokio::test]
    async fn test_prefix_remaining() {
        let (_client, server) = duplex(1024);

        let prefix = Bytes::from_static(b"hello");
        let mut prefixed = PrefixedStream::new(prefix, server);

        assert_eq!(prefixed.prefix_remaining(), 5);

        let mut buf = [0u8; 3];
        prefixed.read(&mut buf).await.unwrap();

        assert_eq!(prefixed.prefix_remaining(), 2);
    }
}
