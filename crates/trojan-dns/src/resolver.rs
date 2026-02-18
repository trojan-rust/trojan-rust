//! Async DNS resolver backed by hickory-resolver.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use hickory_proto::xfer::Protocol;
use hickory_resolver::Resolver;
use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, ResolverConfig, ResolverOpts,
};
use hickory_resolver::name_server::TokioConnectionProvider;
use tracing::debug;

use crate::config::{DnsConfig, DnsStrategy};
use crate::error::DnsError;

/// Shared async DNS resolver.
///
/// Wraps `hickory_resolver::Resolver` with:
/// - Built-in async caching with TTL
/// - Configurable nameservers (UDP/TCP/DoH/DoT)
/// - `prefer_ipv4` support
///
/// Thread-safe and cheaply cloneable (wraps `Arc` internally).
#[derive(Clone)]
pub struct DnsResolver {
    inner: Arc<Inner>,
}

struct Inner {
    resolver: Resolver<TokioConnectionProvider>,
    prefer_ipv4: bool,
}

impl std::fmt::Debug for DnsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsResolver")
            .field("prefer_ipv4", &self.inner.prefer_ipv4)
            .finish()
    }
}

impl DnsResolver {
    /// Build a resolver from configuration.
    ///
    /// Call once at startup and share via `Clone`.
    pub fn new(config: &DnsConfig) -> Result<Self, DnsError> {
        let resolver = match config.strategy {
            DnsStrategy::System => {
                let mut builder = Resolver::builder_tokio()
                    .map_err(|e| DnsError::InvalidServer(format!("system config: {e}")))?;
                let opts = builder.options_mut();
                opts.cache_size = config.cache_size;
                opts.preserve_intermediates = true;
                builder.build()
            }
            DnsStrategy::Custom => {
                let name_servers = parse_server_urls(&config.servers)?;
                let resolver_config = ResolverConfig::from_parts(None, vec![], name_servers);
                let mut opts = ResolverOpts::default();
                opts.cache_size = config.cache_size;
                opts.preserve_intermediates = true;
                let mut builder = Resolver::builder_with_config(
                    resolver_config,
                    TokioConnectionProvider::default(),
                );
                *builder.options_mut() = opts;
                builder.build()
            }
        };

        Ok(Self {
            inner: Arc::new(Inner {
                resolver,
                prefer_ipv4: config.prefer_ipv4,
            }),
        })
    }

    /// Resolve `"host:port"` to a `SocketAddr`.
    ///
    /// If the host part is already an IP address, parses directly without
    /// performing a DNS query. Otherwise, performs an async DNS lookup
    /// and selects an address based on `prefer_ipv4`.
    pub async fn resolve(&self, addr: &str) -> Result<SocketAddr, DnsError> {
        // Fast path: already a SocketAddr
        if let Ok(sa) = addr.parse::<SocketAddr>() {
            return Ok(sa);
        }

        // Split host:port
        let (host, port) = split_host_port(addr)?;

        // Fast path: host is an IP literal
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }

        // DNS lookup
        let response = self.inner.resolver.lookup_ip(host).await?;

        let ip = if self.inner.prefer_ipv4 {
            // Try IPv4 first, fall back to any
            response
                .iter()
                .find(|ip| ip.is_ipv4())
                .or_else(|| response.iter().next())
        } else {
            response.iter().next()
        };

        match ip {
            Some(ip) => {
                let sa = SocketAddr::new(ip, port);
                debug!(host = %host, resolved = %sa, "dns resolved");
                Ok(sa)
            }
            None => Err(DnsError::NoResults(addr.to_string())),
        }
    }
}

/// Split `"host:port"` into (host, port).
///
/// Handles IPv6 bracket notation: `"[::1]:443"` → `("::1", 443)`.
fn split_host_port(addr: &str) -> Result<(&str, u16), DnsError> {
    // IPv6 bracket notation: [::1]:443
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some((host, port_str)) = rest.split_once("]:") {
            let port = port_str
                .parse::<u16>()
                .map_err(|_| DnsError::InvalidAddress(addr.to_string()))?;
            return Ok((host, port));
        }
        return Err(DnsError::InvalidAddress(addr.to_string()));
    }

    // Regular host:port (exactly one colon)
    if let Some((host, port_str)) = addr.rsplit_once(':') {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| DnsError::InvalidAddress(addr.to_string()))?;
        Ok((host, port))
    } else {
        Err(DnsError::InvalidAddress(format!(
            "missing port in address: {addr}"
        )))
    }
}

/// Parse server URL strings into hickory `NameServerConfigGroup`.
fn parse_server_urls(urls: &[String]) -> Result<NameServerConfigGroup, DnsError> {
    let mut configs = Vec::with_capacity(urls.len());

    for url in urls {
        let (protocol, rest) = url
            .split_once("://")
            .ok_or_else(|| DnsError::InvalidServer(format!("missing scheme: {url}")))?;

        match protocol {
            "udp" | "tcp" => {
                if rest.contains('/') {
                    return Err(DnsError::InvalidServer(format!(
                        "unexpected path for {protocol} server: {url}"
                    )));
                }
                let proto = if protocol == "udp" {
                    Protocol::Udp
                } else {
                    Protocol::Tcp
                };
                let socket_addr = parse_socket_addr(rest, 53)?;
                configs.push(NameServerConfig {
                    socket_addr,
                    protocol: proto,
                    tls_dns_name: None,
                    http_endpoint: None,
                    trust_negative_responses: false,
                    bind_addr: None,
                });
            }
            "tls" => {
                if rest.contains('/') {
                    return Err(DnsError::InvalidServer(format!(
                        "unexpected path for tls server: {url}"
                    )));
                }
                // tls://1.1.1.1 or tls://dns.name:853
                let (host, port) = parse_host_port(rest, 853)?;
                let socket_addr = resolve_server_addr(host, port)?;
                configs.push(NameServerConfig {
                    socket_addr,
                    protocol: Protocol::Tls,
                    tls_dns_name: Some(host.to_string()),
                    http_endpoint: None,
                    trust_negative_responses: false,
                    bind_addr: None,
                });
            }
            "https" => {
                // https://dns.google/dns-query
                let (authority, path) = match rest.split_once('/') {
                    Some((authority, path)) => (authority, format!("/{path}")),
                    None => (rest, "/dns-query".to_string()),
                };
                let (host, port) = parse_host_port(authority, 443)?;
                let socket_addr = resolve_server_addr(host, port)?;
                configs.push(NameServerConfig {
                    socket_addr,
                    protocol: Protocol::Https,
                    tls_dns_name: Some(host.to_string()),
                    http_endpoint: Some(path),
                    trust_negative_responses: false,
                    bind_addr: None,
                });
            }
            _ => {
                return Err(DnsError::InvalidServer(format!(
                    "unsupported protocol: {protocol}"
                )));
            }
        }
    }

    if configs.is_empty() {
        return Err(DnsError::InvalidServer(
            "no dns servers configured".to_string(),
        ));
    }

    Ok(NameServerConfigGroup::from(configs))
}

/// Parse "host:port", "[ipv6]:port", "host", or "[ipv6]" with a default port.
fn parse_host_port(s: &str, default_port: u16) -> Result<(&str, u16), DnsError> {
    // Bracketed IPv6: [::1]:853 or [::1]
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| DnsError::InvalidServer(format!("invalid IPv6 host in: {s}")))?;
        if host.is_empty() {
            return Err(DnsError::InvalidServer(format!("empty host in: {s}")));
        }
        if tail.is_empty() {
            return Ok((host, default_port));
        }
        let port_str = tail.strip_prefix(':').ok_or_else(|| {
            DnsError::InvalidServer(format!("invalid port separator in bracketed host: {s}"))
        })?;
        let port = port_str
            .parse::<u16>()
            .map_err(|_| DnsError::InvalidServer(format!("invalid port in: {s}")))?;
        return Ok((host, port));
    }

    // Unbracketed host:port.
    // Note: raw IPv6 literals in server URLs must use brackets.
    if let Some((host, port_str)) = s.rsplit_once(':') {
        if host.contains(':') {
            return Err(DnsError::InvalidServer(format!(
                "ipv6 host must be bracketed in server url: {s}"
            )));
        }
        if host.is_empty() {
            return Err(DnsError::InvalidServer(format!("empty host in: {s}")));
        }
        let port = port_str
            .parse::<u16>()
            .map_err(|_| DnsError::InvalidServer(format!("invalid port in: {s}")))?;
        return Ok((host, port));
    }

    if s.is_empty() {
        return Err(DnsError::InvalidServer("empty host".to_string()));
    }

    Ok((s, default_port))
}

/// Parse a "host:port" or "host" string into a SocketAddr (for UDP/TCP servers).
fn parse_socket_addr(s: &str, default_port: u16) -> Result<SocketAddr, DnsError> {
    // Try direct SocketAddr parse first
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(sa);
    }

    let (host, port) = parse_host_port(s, default_port)?;
    resolve_server_addr(host, port)
}

/// Resolve a DNS server host to a SocketAddr.
///
/// Supports both IP literals and hostnames. Hostnames are resolved once at
/// startup via the system resolver.
fn resolve_server_addr(host: &str, port: u16) -> Result<SocketAddr, DnsError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    let mut addrs = (host, port).to_socket_addrs().map_err(|e| {
        DnsError::InvalidServer(format!("failed to resolve dns server host '{host}': {e}"))
    })?;
    addrs
        .next()
        .ok_or_else(|| DnsError::InvalidServer(format!("dns server host has no addresses: {host}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_host_port_basic() {
        let (host, port) = split_host_port("example.com:443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn split_host_port_ipv6() {
        let (host, port) = split_host_port("[::1]:8080").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn split_host_port_missing_port() {
        split_host_port("example.com").unwrap_err();
    }

    #[test]
    fn parse_server_urls_udp() {
        let urls = vec!["udp://8.8.8.8".to_string()];
        let group = parse_server_urls(&urls).unwrap();
        assert_eq!(group.len(), 1);
    }

    #[test]
    fn parse_server_urls_tcp_with_port() {
        let urls = vec!["tcp://1.1.1.1:5353".to_string()];
        let group = parse_server_urls(&urls).unwrap();
        assert_eq!(group.len(), 1);
    }

    #[test]
    fn parse_server_urls_tls() {
        let urls = vec!["tls://1.1.1.1".to_string()];
        let group = parse_server_urls(&urls).unwrap();
        assert_eq!(group.len(), 1);
    }

    #[test]
    fn parse_server_urls_https() {
        let urls = vec!["https://8.8.8.8/dns-query".to_string()];
        let group = parse_server_urls(&urls).unwrap();
        assert_eq!(group.len(), 1);
    }

    #[test]
    fn parse_server_urls_mixed() {
        let urls = vec![
            "udp://8.8.8.8".to_string(),
            "tls://1.1.1.1".to_string(),
            "https://8.8.4.4/dns-query".to_string(),
        ];
        let group = parse_server_urls(&urls).unwrap();
        assert_eq!(group.len(), 3);
    }

    #[test]
    fn parse_server_urls_invalid_scheme() {
        let urls = vec!["ftp://8.8.8.8".to_string()];
        parse_server_urls(&urls).unwrap_err();
    }

    #[test]
    fn parse_server_urls_empty() {
        let urls: Vec<String> = vec![];
        parse_server_urls(&urls).unwrap_err();
    }

    #[test]
    fn parse_server_urls_domain_supported() {
        let urls = vec!["udp://localhost".to_string()];
        let group = parse_server_urls(&urls).unwrap();
        assert_eq!(group.len(), 1);
    }

    #[test]
    fn resolve_already_socket_addr() {
        let config = DnsConfig::default();
        let resolver = DnsResolver::new(&config).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let addr = rt.block_on(resolver.resolve("127.0.0.1:8080")).unwrap();
        assert_eq!(addr, "127.0.0.1:8080".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn resolve_ip_literal_with_port() {
        let config = DnsConfig::default();
        let resolver = DnsResolver::new(&config).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let addr = rt.block_on(resolver.resolve("10.0.0.1:443")).unwrap();
        assert_eq!(addr, "10.0.0.1:443".parse::<SocketAddr>().unwrap());
    }
}
