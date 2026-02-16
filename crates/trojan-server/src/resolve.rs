//! Address resolution utilities.

use std::borrow::Cow;
use std::fmt::Write;
use std::net::SocketAddr;

use tokio::time::Instant;
use trojan_metrics::record_dns_resolve_duration;
use trojan_proto::{AddressRef, HostRef};

use crate::error::ServerError;

/// Resolve a string address (host:port) to a SocketAddr.
///
/// When `prefer_ipv4` is true, iterates all DNS results and returns the
/// first IPv4 address if available; otherwise falls back to the first result.
pub async fn resolve_sockaddr(target: &str, prefer_ipv4: bool) -> Result<SocketAddr, ServerError> {
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(target)
        .await
        .map_err(|_| ServerError::Resolve)?
        .collect();
    if prefer_ipv4 && let Some(v4) = addrs.iter().find(|a| a.is_ipv4()) {
        return Ok(*v4);
    }
    addrs.into_iter().next().ok_or(ServerError::Resolve)
}

/// Resolve a trojan AddressRef to a SocketAddr.
#[inline]
pub async fn resolve_address(
    address: &AddressRef<'_>,
    prefer_ipv4: bool,
) -> Result<SocketAddr, ServerError> {
    match address.host {
        HostRef::Ipv4(ip) => Ok(SocketAddr::from((ip, address.port))),
        HostRef::Ipv6(ip) => Ok(SocketAddr::from((ip, address.port))),
        HostRef::Domain(domain) => {
            let host = std::str::from_utf8(domain).map_err(|_| ServerError::Resolve)?;
            // Use stack buffer to avoid heap allocation (domain max 255 + ":" + port max 5 = 261)
            let mut buf = StackString::<270>::new();
            let _ = write!(buf, "{}:{}", host, address.port);

            // Measure DNS resolution time
            let start = Instant::now();
            let result = resolve_sockaddr(buf.as_str(), prefer_ipv4).await;
            record_dns_resolve_duration(start.elapsed().as_secs_f64());
            result
        }
    }
}

/// Stack-allocated string buffer to avoid heap allocation for small strings.
struct StackString<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> StackString<N> {
    #[inline]
    fn new() -> Self {
        Self {
            buf: [0u8; N],
            len: 0,
        }
    }

    #[inline]
    fn as_str(&self) -> &str {
        // SAFETY: we only write valid UTF-8 via fmt::Write
        unsafe { std::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }
}

impl<const N: usize> Write for StackString<N> {
    #[inline]
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let bytes = s.as_bytes();
        let remaining = N - self.len;
        if bytes.len() > remaining {
            return Err(std::fmt::Error);
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

/// Convert a SocketAddr to an AddressRef.
#[inline]
pub fn address_from_socket(addr: SocketAddr) -> AddressRef<'static> {
    match addr {
        SocketAddr::V4(v4) => AddressRef {
            host: HostRef::Ipv4(v4.ip().octets()),
            port: v4.port(),
        },
        SocketAddr::V6(v6) => AddressRef {
            host: HostRef::Ipv6(v6.ip().octets()),
            port: v6.port(),
        },
    }
}

/// Convert address to a label suitable for metrics (domain or IP, no port).
/// Returns Cow to avoid allocation for domain names (which are already UTF-8 strings).
#[inline]
pub fn target_to_label<'a>(address: &AddressRef<'a>) -> Cow<'a, str> {
    match address.host {
        HostRef::Ipv4(ip) => Cow::Owned(std::net::Ipv4Addr::from(ip).to_string()),
        HostRef::Ipv6(ip) => Cow::Owned(std::net::Ipv6Addr::from(ip).to_string()),
        HostRef::Domain(domain) => {
            // Domain names in trojan protocol are ASCII, so from_utf8 should always succeed.
            // Use Borrowed to avoid allocation.
            match std::str::from_utf8(domain) {
                Ok(s) => Cow::Borrowed(s),
                Err(_) => Cow::Borrowed("unknown"),
            }
        }
    }
}
