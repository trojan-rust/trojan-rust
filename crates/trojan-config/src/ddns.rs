//! Dynamic DNS configuration.

use serde::{Deserialize, Serialize};

/// Dynamic DNS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdnsConfig {
    /// Whether DDNS updates are enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Update interval in seconds.
    #[serde(default = "default_ddns_interval")]
    pub interval: u64,

    /// URLs to detect public IPv4 address (tried in order, first success wins).
    #[serde(default = "default_ipv4_urls")]
    pub ipv4_urls: Vec<String>,

    /// URLs to detect public IPv6 address (empty = disabled).
    #[serde(default)]
    pub ipv6_urls: Vec<String>,

    /// Cloudflare DNS provider configuration.
    #[serde(default)]
    pub cloudflare: Option<CloudflareDdnsConfig>,
}

impl Default for DdnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: default_ddns_interval(),
            ipv4_urls: default_ipv4_urls(),
            ipv6_urls: Vec::new(),
            cloudflare: None,
        }
    }
}

/// Cloudflare DNS provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareDdnsConfig {
    /// Cloudflare API token with DNS edit permissions.
    pub api_token: String,

    /// Zone (domain) name, e.g. "example.com".
    pub zone: String,

    /// DNS record names to update, e.g. ["example.com", "*.example.com"].
    pub records: Vec<String>,

    /// Whether to enable Cloudflare CDN proxy for the records.
    #[serde(default)]
    pub proxied: bool,

    /// DNS record TTL in seconds. 1 = automatic.
    #[serde(default = "default_ddns_ttl")]
    pub ttl: u32,
}

fn default_ddns_interval() -> u64 {
    300
}

fn default_ddns_ttl() -> u32 {
    1
}

fn default_ipv4_urls() -> Vec<String> {
    vec![
        "https://api.ipify.org".into(),
        "https://ifconfig.me/ip".into(),
        "https://ip.sb".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ddns_config_default() {
        let cfg = DdnsConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.interval, 300);
        assert!(!cfg.ipv4_urls.is_empty());
        assert!(cfg.ipv6_urls.is_empty());
        assert!(cfg.cloudflare.is_none());
    }

    #[test]
    fn ddns_config_deserialize_minimal() {
        let toml_str = r#"enabled = true"#;
        let cfg: DdnsConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.interval, 300);
        assert_eq!(cfg.ipv4_urls.len(), 3);
    }

    #[test]
    fn ddns_config_deserialize_full() {
        let toml_str = r#"
enabled = true
interval = 600
ipv4_urls = ["https://api.ipify.org"]

[cloudflare]
api_token = "test-token"
zone = "example.com"
records = ["example.com", "*.example.com"]
proxied = true
ttl = 300
"#;
        let cfg: DdnsConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.interval, 600);
        assert_eq!(cfg.ipv4_urls, vec!["https://api.ipify.org"]);
        let cf = cfg.cloudflare.unwrap();
        assert_eq!(cf.api_token, "test-token");
        assert_eq!(cf.zone, "example.com");
        assert_eq!(cf.records, vec!["example.com", "*.example.com"]);
        assert!(cf.proxied);
        assert_eq!(cf.ttl, 300);
    }
}
