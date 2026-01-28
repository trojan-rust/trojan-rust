//! Utility functions for server operations.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use trojan_config::TcpConfig;

use crate::error::ServerError;

// Re-export PrefixedStream from trojan-core for backward compatibility
pub use trojan_core::io::PrefixedStream;

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

/// Create a TCP listener with custom backlog and TCP options.
pub fn create_listener(
    addr: SocketAddr,
    backlog: u32,
    tcp_cfg: &TcpConfig,
) -> Result<TcpListener, ServerError> {
    // Suppress unused warning on Windows where reuse_port/fast_open are not available
    #[cfg(not(unix))]
    let _ = tcp_cfg;

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;

    // SO_REUSEPORT for multi-process load balancing
    #[cfg(unix)]
    if tcp_cfg.reuse_port {
        socket.set_reuse_port(true)?;
    }

    // TCP Fast Open (server-side, Linux only)
    #[cfg(target_os = "linux")]
    if tcp_cfg.fast_open {
        use std::os::unix::io::AsRawFd;
        // TCP_FASTOPEN = 23 on Linux
        const TCP_FASTOPEN: libc::c_int = 23;
        let qlen = tcp_cfg.fast_open_qlen as libc::c_int;
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                TCP_FASTOPEN,
                &qlen as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            let e = std::io::Error::last_os_error();
            tracing::warn!(error = %e, "failed to enable TCP Fast Open (kernel support required)");
        }
    }

    socket.bind(&addr.into())?;
    socket.listen(backlog as i32)?;
    let listener = TcpListener::from_std(std::net::TcpListener::from(socket))?;
    Ok(listener)
}

/// Apply TCP socket options to an accepted connection.
pub fn apply_tcp_options(stream: &TcpStream, tcp_cfg: &TcpConfig) -> std::io::Result<()> {
    // TCP_NODELAY - disable Nagle's algorithm for lower latency
    stream.set_nodelay(tcp_cfg.no_delay)?;

    // TCP Keep-Alive
    if tcp_cfg.keepalive_secs > 0 {
        let socket = socket2::SockRef::from(stream);
        let keepalive = TcpKeepalive::new().with_time(Duration::from_secs(tcp_cfg.keepalive_secs));
        // On Linux/macOS, also set interval
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let keepalive = keepalive.with_interval(Duration::from_secs(tcp_cfg.keepalive_secs / 3));
        socket.set_tcp_keepalive(&keepalive)?;
    }

    Ok(())
}

/// Connect to target with optional socket buffer configuration.
pub async fn connect_with_buffers(
    target: SocketAddr,
    send_buf: usize,
    recv_buf: usize,
    tcp_cfg: &TcpConfig,
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

    let stream = socket.connect(target).await?;

    // Apply TCP options to outbound connection
    stream.set_nodelay(tcp_cfg.no_delay)?;

    Ok(stream)
}
