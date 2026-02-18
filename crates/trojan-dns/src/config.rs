//! DNS resolver configuration.

use serde::{Deserialize, Serialize};

/// DNS resolver configuration.
///
/// Controls how domain names are resolved to IP addresses. When omitted
/// from config files, all fields use sensible defaults (system resolver
/// with caching enabled).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// DNS resolution strategy.
    ///
    /// - `"system"` (default): reads `/etc/resolv.conf` on Unix, system
    ///   DNS settings on Windows.
    /// - `"custom"`: uses the nameservers listed in `servers`.
    #[serde(default)]
    pub strategy: DnsStrategy,

    /// Custom nameserver URLs. Only used when `strategy = "custom"`.
    ///
    /// Supported formats:
    /// - `"udp://8.8.8.8"` or `"udp://8.8.8.8:53"` — plain UDP
    /// - `"tcp://8.8.8.8"` or `"tcp://8.8.8.8:53"` — plain TCP
    /// - `"tls://1.1.1.1"` or `"tls://dns.name:853"` — DNS-over-TLS
    /// - `"https://dns.google/dns-query"` — DNS-over-HTTPS
    ///
    /// When a port is omitted, the standard port for that protocol is used
    /// (53 for UDP/TCP, 853 for TLS, 443 for HTTPS).
    #[serde(default)]
    pub servers: Vec<String>,

    /// Prefer IPv4 addresses when both A and AAAA records exist.
    #[serde(default)]
    pub prefer_ipv4: bool,

    /// DNS cache capacity (number of entries). Set to 0 to disable caching.
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            strategy: DnsStrategy::default(),
            servers: Vec::new(),
            prefer_ipv4: false,
            cache_size: default_cache_size(),
        }
    }
}

/// DNS resolution strategy.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsStrategy {
    /// Use the system DNS resolver configuration.
    #[default]
    System,
    /// Use custom nameservers from the `servers` list.
    Custom,
}

fn default_cache_size() -> usize {
    256
}
