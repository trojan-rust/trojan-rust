//! How a GeoIP database is obtained and kept current.
//!
//! Owned here rather than by the config crate because this crate is what acts
//! on it: it does the loading, the download and the background refresh. The
//! top-level config composes this type, the same way it composes the DNS
//! resolver's.

use serde::{Deserialize, Serialize};

/// GeoIP MaxMind database configuration.
///
/// Loading priority: `path` > `url` > `source` (built-in CDN).
/// When `auto_update` is true and no `path` is set, the database
/// is periodically re-downloaded in the background.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoipConfig {
    /// Built-in source name (e.g., "geolite2-country", "dbip-city").
    #[serde(default = "default_geoip_source")]
    pub source: String,
    /// Local file path (highest priority — skips download).
    #[serde(default)]
    pub path: Option<String>,
    /// Custom remote URL (overrides the built-in CDN URL for `source`).
    #[serde(default)]
    pub url: Option<String>,
    /// Enable automatic background updates.
    #[serde(default = "default_geoip_auto_update")]
    pub auto_update: bool,
    /// Update interval in seconds (default: 7 days = 604800).
    #[serde(default = "default_geoip_interval")]
    pub interval: u64,
    /// Cache file path for downloaded databases.
    #[serde(default)]
    pub cache_path: Option<String>,
}

impl Default for GeoipConfig {
    fn default() -> Self {
        Self {
            source: default_geoip_source(),
            path: None,
            url: None,
            auto_update: default_geoip_auto_update(),
            interval: default_geoip_interval(),
            cache_path: None,
        }
    }
}

fn default_geoip_source() -> String {
    "geolite2-country".to_string()
}

fn default_geoip_auto_update() -> bool {
    true
}

fn default_geoip_interval() -> u64 {
    604800 // 7 days
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geoip_config_defaults() {
        let cfg = GeoipConfig::default();
        assert_eq!(cfg.source, "geolite2-country");
        assert!(cfg.path.is_none());
        assert!(cfg.url.is_none());
        assert!(cfg.auto_update);
        assert_eq!(cfg.interval, 604800);
        assert!(cfg.cache_path.is_none());
    }

    #[test]
    fn geoip_config_deserialize_minimal() {
        let toml_str = r#"source = "dbip-city""#;
        let cfg: GeoipConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.source, "dbip-city");
        assert!(cfg.auto_update);
        assert_eq!(cfg.interval, 604800);
    }

    #[test]
    fn geoip_config_deserialize_full() {
        let toml_str = r#"
source = "geolite2-city"
path = "/tmp/test.mmdb"
url = "https://example.com/geo.mmdb"
auto_update = false
interval = 3600
cache_path = "/tmp/cache.mmdb"
"#;
        let cfg: GeoipConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.source, "geolite2-city");
        assert_eq!(cfg.path.as_deref(), Some("/tmp/test.mmdb"));
        assert_eq!(cfg.url.as_deref(), Some("https://example.com/geo.mmdb"));
        assert!(!cfg.auto_update);
        assert_eq!(cfg.interval, 3600);
        assert_eq!(cfg.cache_path.as_deref(), Some("/tmp/cache.mmdb"));
    }
}
