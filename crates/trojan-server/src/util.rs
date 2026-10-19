//! Utility functions for server operations.

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use futures_util::{StreamExt, stream::FuturesUnordered};
use socket2::TcpKeepalive;
#[cfg(all(test, windows))]
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use trojan_config::TcpConfig;
use trojan_core::net::prepare_tcp_listener_socket;

use crate::error::ServerError;

pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Create a TCP listener with custom backlog and TCP options.
pub fn create_listener(
    addr: SocketAddr,
    backlog: u32,
    tcp_cfg: &TcpConfig,
) -> Result<TcpListener, ServerError> {
    let socket = prepare_tcp_listener_socket(addr, tcp_cfg.ipv6_only)?;

    // Windows SO_REUSEADDR permits a second live listener on the same address.
    #[cfg(not(windows))]
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
        let qlen = libc::c_int::try_from(tcp_cfg.fast_open_qlen).unwrap_or(libc::c_int::MAX);
        // Conversions rather than `as`: usize is 4 bytes on the i686 and armv7
        // targets we release and 8 on the rest, so a cast would truncate on
        // only half of them — and any lint suppression for it would be
        // unfulfilled on the other half.
        let qlen_size =
            libc::socklen_t::try_from(size_of::<libc::c_int>()).unwrap_or(libc::socklen_t::MAX);
        // SAFETY: libc FFI calls require unsafe; the socket fd and address pointers are valid.
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                TCP_FASTOPEN,
                (&qlen as *const libc::c_int).cast::<libc::c_void>(),
                qlen_size,
            )
        };
        if ret != 0 {
            let e = std::io::Error::last_os_error();
            tracing::warn!(error = %e, "failed to enable TCP Fast Open (kernel support required)");
        }
    }

    socket.bind(&addr.into())?;
    socket.listen(i32::try_from(backlog).unwrap_or(i32::MAX))?;
    if addr.is_ipv6() {
        tracing::info!(
            address = %addr,
            ipv6_only = socket.only_v6()?,
            "IPv6 listener mode configured"
        );
    }
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
    tokio::time::timeout(
        CONNECT_TIMEOUT,
        connect_socket(target, None, send_buf, recv_buf, tcp_cfg),
    )
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

/// Race resolved addresses with alternating address families and a shared deadline.
pub(crate) async fn connect_candidates(
    targets: Vec<SocketAddr>,
    bind: Option<IpAddr>,
    send_buf: usize,
    recv_buf: usize,
    tcp_cfg: &TcpConfig,
) -> io::Result<(TcpStream, SocketAddr)> {
    let targets = targets
        .into_iter()
        .filter(|target| bind.is_none_or(|ip| ip.is_ipv4() == target.is_ipv4()))
        .collect();
    race_addresses(
        targets,
        Duration::from_millis(250),
        CONNECT_TIMEOUT,
        |target| connect_socket(target, bind, send_buf, recv_buf, tcp_cfg),
    )
    .await
}

async fn race_addresses<T, F, Fut>(
    targets: Vec<SocketAddr>,
    delay: Duration,
    timeout: Duration,
    connect: F,
) -> io::Result<(T, SocketAddr)>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = io::Result<T>>,
{
    let first_v4 = targets.first().is_some_and(SocketAddr::is_ipv4);
    let (mut preferred, mut other): (VecDeque<_>, VecDeque<_>) = targets
        .into_iter()
        .partition(|target| target.is_ipv4() == first_v4);
    let mut ordered = VecDeque::new();
    while !preferred.is_empty() || !other.is_empty() {
        ordered.extend(preferred.pop_front());
        ordered.extend(other.pop_front());
    }
    let mut attempts = FuturesUnordered::new();
    let mut next = tokio::time::Instant::now();
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let mut last_error = io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "no compatible target address",
    );
    loop {
        if (attempts.is_empty() || tokio::time::Instant::now() >= next)
            && let Some(target) = ordered.pop_front()
        {
            let attempt = connect(target);
            attempts.push(async move { (target, attempt.await) });
            next = tokio::time::Instant::now() + delay;
        }
        if attempts.is_empty() {
            return Err(last_error);
        }
        tokio::select! {
            biased;
            _ = &mut deadline => return Err(io::ErrorKind::TimedOut.into()),
            Some((target, result)) = attempts.next() => {
                match result {
                    Ok(stream) => return Ok((stream, target)),
                    Err(error) => {
                        tracing::debug!(%target, %error, "connect attempt failed");
                        last_error = error;
                    }
                }
            }
            _ = tokio::time::sleep_until(next), if !ordered.is_empty() => {}
        }
    }
}

async fn connect_socket(
    target: SocketAddr,
    bind: Option<IpAddr>,
    send_buf: usize,
    recv_buf: usize,
    tcp_cfg: &TcpConfig,
) -> io::Result<TcpStream> {
    let socket = if target.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    if send_buf > 0 {
        socket.set_send_buffer_size(u32::try_from(send_buf).unwrap_or(u32::MAX))?;
    }
    if recv_buf > 0 {
        socket.set_recv_buffer_size(u32::try_from(recv_buf).unwrap_or(u32::MAX))?;
    }

    if let Some(ip) = bind {
        socket.bind(SocketAddr::new(ip, 0))?;
    }
    let stream = socket.connect(target).await?;

    // Apply TCP options to outbound connection
    stream.set_nodelay(tcp_cfg.no_delay)?;

    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn dual_stack_listener_accepts_both_families() {
        let config = TcpConfig {
            ipv6_only: Some(false),
            ..Default::default()
        };
        let listener = create_listener("[::]:0".parse().unwrap(), 128, &config).unwrap();
        let port = listener.local_addr().unwrap().port();

        let ipv4 = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (_, peer4) = listener.accept().await.unwrap();
        let IpAddr::V6(mapped) = peer4.ip() else {
            panic!("IPv4 peer on an IPv6 dual-stack socket should be IPv4-mapped");
        };
        assert_eq!(mapped.to_ipv4_mapped(), Some(std::net::Ipv4Addr::LOCALHOST));
        drop(ipv4);

        let ipv6 = TcpStream::connect(("::1", port)).await.unwrap();
        let (_, peer6) = listener.accept().await.unwrap();
        assert_eq!(peer6.ip(), IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
        drop(ipv6);
    }

    #[tokio::test]
    async fn ipv6_only_listener_rejects_ipv4() {
        let config = TcpConfig {
            ipv6_only: Some(true),
            ..Default::default()
        };
        let listener = create_listener("[::]:0".parse().unwrap(), 128, &config).unwrap();
        let port = listener.local_addr().unwrap().port();

        TcpStream::connect(("127.0.0.1", port))
            .await
            .expect_err("IPv6-only listener must reject IPv4");
        let ipv6 = TcpStream::connect(("::1", port)).await.unwrap();
        let (_, peer) = listener.accept().await.unwrap();
        assert_eq!(peer.ip(), IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
        drop(ipv6);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_dual_stack_listener_exclusively_owns_ipv4_port() {
        let config = TcpConfig {
            ipv6_only: Some(false),
            ..Default::default()
        };
        let listener = create_listener("[::]:0".parse().unwrap(), 128, &config).unwrap();
        let port = listener.local_addr().unwrap().port();

        let second = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        second.set_reuse_address(true).unwrap();
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        second
            .bind(&addr.into())
            .expect_err("a second IPv4 listener must not overlap an IPv6 dual-stack listener");
    }

    #[tokio::test]
    async fn stalled_preferred_family_does_not_block_ipv4_and_loser_is_cancelled() {
        struct Cancelled<'a>(&'a AtomicBool);
        impl Drop for Cancelled<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let cancelled = AtomicBool::new(false);
        let starts = std::sync::Mutex::new(Vec::new());
        let first: SocketAddr = "[::1]:1".parse().unwrap();
        let second: SocketAddr = "[::1]:2".parse().unwrap();
        let ipv4: SocketAddr = "127.0.0.1:3".parse().unwrap();
        let (value, target) = race_addresses(
            vec![first, second, ipv4],
            Duration::from_millis(10),
            Duration::from_secs(5),
            |address| {
                let cancelled = &cancelled;
                starts.lock().unwrap().push(address);
                async move {
                    if address.is_ipv6() {
                        let _guard = Cancelled(cancelled);
                        std::future::pending::<()>().await;
                    }
                    Ok(7)
                }
            },
        )
        .await
        .unwrap();
        assert_eq!((value, target), (7, ipv4));
        assert_eq!(*starts.lock().unwrap(), [first, ipv4]);
        assert!(cancelled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn all_stalled_connections_share_one_deadline() {
        let result = race_addresses(
            vec![
                "127.0.0.1:1".parse().unwrap(),
                "127.0.0.1:2".parse().unwrap(),
            ],
            Duration::from_millis(5),
            Duration::from_millis(20),
            |_| std::future::pending::<io::Result<()>>(),
        )
        .await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn direct_connection_preserves_bind_family_and_socket_options() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let config = TcpConfig {
            no_delay: true,
            ..Default::default()
        };
        let (stream, address) = connect_candidates(
            vec!["[::1]:1".parse().unwrap(), target],
            Some("127.0.0.1".parse().unwrap()),
            8192,
            8192,
            &config,
        )
        .await
        .unwrap();
        assert_eq!(address, target);
        assert_eq!(stream.local_addr().unwrap().ip(), target.ip());
        assert!(stream.nodelay().unwrap());
        let (accepted, _) = listener.accept().await.unwrap();
        assert_eq!(accepted.peer_addr().unwrap(), stream.local_addr().unwrap());
    }
}
