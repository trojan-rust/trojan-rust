//! Utility functions for server operations.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use bytes::Bytes;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::error::ServerError;

/// Tracks active connections for graceful shutdown.
#[derive(Clone)]
pub struct ConnectionTracker {
    active: Arc<AtomicUsize>,
    zero_notify: Arc<Notify>,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            active: Arc::new(AtomicUsize::new(0)),
            zero_notify: Arc::new(Notify::new()),
        }
    }

    pub fn increment(&self) {
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement(&self) {
        // AcqRel: Acquire to see previous increments, Release to make decrement visible
        if self.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.zero_notify.notify_waiters();
        }
    }

    pub fn count(&self) -> usize {
        // Acquire to synchronize with Release from decrement
        self.active.load(Ordering::Acquire)
    }

    pub async fn wait_for_zero(&self, timeout: Duration) -> bool {
        if self.count() == 0 {
            return true;
        }
        tokio::select! {
            _ = self.zero_notify.notified() => {
                // Double-check in case of race
                self.count() == 0
            }
            _ = tokio::time::sleep(timeout) => false,
        }
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Guard that decrements connection count on drop.
pub struct ConnectionGuard {
    tracker: ConnectionTracker,
}

impl ConnectionGuard {
    pub fn new(tracker: ConnectionTracker) -> Self {
        Self { tracker }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.tracker.decrement();
    }
}

/// Create a TCP listener with custom backlog.
pub fn create_listener(addr: SocketAddr, backlog: u32) -> Result<TcpListener, ServerError> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(backlog as i32)?;
    let listener = TcpListener::from_std(std::net::TcpListener::from(socket))?;
    Ok(listener)
}

/// A stream wrapper that yields a prefetched prefix before reading from the inner stream.
pub struct PrefixedStream<S> {
    prefix: Bytes,
    pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Bytes, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let remaining = &self.prefix[self.pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.pos += to_copy;
            return Poll::Ready(Ok(()));
        }
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

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Connect to target with optional socket buffer configuration.
pub async fn connect_with_buffers(
    target: SocketAddr,
    send_buf: usize,
    recv_buf: usize,
) -> std::io::Result<TcpStream> {
    let socket = if target.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    if send_buf > 0 {
        socket.set_send_buffer_size(send_buf as u32)?;
    }
    if recv_buf > 0 {
        socket.set_recv_buffer_size(recv_buf as u32)?;
    }
    socket.connect(target).await
}
