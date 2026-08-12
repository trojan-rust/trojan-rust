//! Analytics configuration for connection event collection.
//!
//! Owned here rather than by the config crate because this crate is what acts
//! on it. The top-level config composes this type.

use serde::{Deserialize, Serialize};
use trojan_rules::config::GeoipConfig;

/// Analytics configuration for connection event collection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalyticsConfig {
    /// Whether analytics is enabled (runtime switch).
    #[serde(default)]
    pub enabled: bool,

    /// ClickHouse configuration.
    #[serde(default)]
    pub clickhouse: Option<ClickHouseConfig>,

    /// Buffer configuration.
    #[serde(default)]
    pub buffer: AnalyticsBufferConfig,

    /// Sampling configuration.
    #[serde(default)]
    pub sampling: AnalyticsSamplingConfig,

    /// Privacy configuration.
    #[serde(default)]
    pub privacy: AnalyticsPrivacyConfig,

    /// Server identifier for multi-instance deployments.
    #[serde(default)]
    pub server_id: Option<String>,

    /// GeoIP database for analytics geo fields (city-level).
    #[serde(default)]
    pub geoip: Option<GeoipConfig>,
}

/// ClickHouse connection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickHouseConfig {
    /// ClickHouse URL (e.g., "http://localhost:8123").
    pub url: String,

    /// Database name.
    #[serde(default = "default_analytics_database")]
    pub database: String,

    /// Table name.
    #[serde(default = "default_analytics_table")]
    pub table: String,

    /// Username (optional).
    #[serde(default)]
    pub username: Option<String>,

    /// Password (optional).
    #[serde(default)]
    pub password: Option<String>,

    /// Connection timeout in seconds.
    #[serde(default = "default_analytics_connect_timeout")]
    pub connect_timeout_secs: u64,

    /// Write timeout in seconds.
    #[serde(default = "default_analytics_write_timeout")]
    pub write_timeout_secs: u64,
}

/// Buffer configuration for event batching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsBufferConfig {
    /// Maximum number of events to buffer in memory.
    #[serde(default = "default_analytics_buffer_size")]
    pub size: usize,

    /// Flush interval in seconds.
    #[serde(default = "default_analytics_flush_interval")]
    pub flush_interval_secs: u64,

    /// Batch size for writes.
    #[serde(default = "default_analytics_batch_size")]
    pub batch_size: usize,

    /// Fallback file path for failed writes.
    #[serde(default)]
    pub fallback_path: Option<String>,
}

impl Default for AnalyticsBufferConfig {
    fn default() -> Self {
        Self {
            size: default_analytics_buffer_size(),
            flush_interval_secs: default_analytics_flush_interval(),
            batch_size: default_analytics_batch_size(),
            fallback_path: None,
        }
    }
}

/// Sampling configuration for high-traffic scenarios.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsSamplingConfig {
    /// Sampling rate (0.0 - 1.0, where 1.0 = 100%).
    #[serde(default = "default_analytics_sample_rate")]
    pub rate: f64,

    /// Users to always record (not affected by sampling).
    #[serde(default)]
    pub always_record_users: Vec<String>,
}

impl Default for AnalyticsSamplingConfig {
    fn default() -> Self {
        Self {
            rate: default_analytics_sample_rate(),
            always_record_users: Vec::new(),
        }
    }
}

/// Privacy configuration for data collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsPrivacyConfig {
    /// Whether to record client IP addresses.
    /// When false, GeoIP fields are also left empty.
    #[serde(default = "default_true")]
    pub record_peer_ip: bool,

    /// Whether to record full user ID (false = prefix only).
    #[serde(default)]
    pub full_user_id: bool,

    /// User ID prefix length when full_user_id is false.
    #[serde(default = "default_analytics_user_id_prefix_len")]
    pub user_id_prefix_len: usize,

    /// Whether to record SNI.
    #[serde(default = "default_true")]
    pub record_sni: bool,

    /// How much of a GeoIP lookup to keep on an event.
    #[serde(default)]
    pub geo_precision: GeoPrecision,
}

/// How much of a GeoIP lookup an analytics event keeps.
///
/// A privacy setting, so the coarser values are not a degraded version of the
/// finer one — they are the point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GeoPrecision {
    /// Country, region, city, ASN, organisation and coordinates.
    #[default]
    City,
    /// Country code only.
    Country,
    /// Nothing at all.
    None,
}

impl Default for AnalyticsPrivacyConfig {
    fn default() -> Self {
        Self {
            record_peer_ip: true,
            full_user_id: false,
            user_id_prefix_len: default_analytics_user_id_prefix_len(),
            record_sni: true,
            geo_precision: GeoPrecision::default(),
        }
    }
}

// Analytics default value functions

fn default_analytics_database() -> String {
    "trojan".to_string()
}

fn default_analytics_table() -> String {
    "connections".to_string()
}

fn default_analytics_buffer_size() -> usize {
    10000
}

fn default_analytics_flush_interval() -> u64 {
    5
}

fn default_analytics_batch_size() -> usize {
    1000
}

fn default_analytics_sample_rate() -> f64 {
    1.0
}

fn default_analytics_user_id_prefix_len() -> usize {
    8
}

fn default_analytics_connect_timeout() -> u64 {
    10
}

fn default_analytics_write_timeout() -> u64 {
    30
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analytics_config_default() {
        let cfg = AnalyticsConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.clickhouse.is_none());
        assert!(cfg.server_id.is_none());
        assert!(cfg.geoip.is_none());
    }

    #[test]
    fn privacy_config_defaults() {
        let cfg = AnalyticsPrivacyConfig::default();
        assert!(cfg.record_peer_ip);
        assert!(!cfg.full_user_id);
        assert_eq!(cfg.user_id_prefix_len, 8);
        assert!(cfg.record_sni);
        assert_eq!(cfg.geo_precision, GeoPrecision::City);
    }

    #[test]
    fn privacy_config_deserialize_geo_precision() {
        let toml_str = r#"geo_precision = "country""#;
        let cfg: AnalyticsPrivacyConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.geo_precision, GeoPrecision::Country);
    }

    /// A misspelt precision used to parse as a `String` and then match no arm,
    /// silently dropping every geo field for the life of the process. It has
    /// to be a load error instead.
    #[test]
    fn an_unknown_geo_precision_is_rejected() {
        let err = toml::from_str::<AnalyticsPrivacyConfig>(r#"geo_precision = "City""#)
            .expect_err("a value outside the enum must not load");

        assert!(
            err.to_string().contains("city"),
            "the error should list what is accepted, got: {err}"
        );
    }

    #[test]
    fn sampling_config_defaults() {
        let cfg = AnalyticsSamplingConfig::default();
        assert_eq!(cfg.rate, 1.0);
        assert!(cfg.always_record_users.is_empty());
    }

    #[test]
    fn buffer_config_defaults() {
        let cfg = AnalyticsBufferConfig::default();
        assert_eq!(cfg.size, 10000);
        assert_eq!(cfg.flush_interval_secs, 5);
        assert_eq!(cfg.batch_size, 1000);
        assert!(cfg.fallback_path.is_none());
    }

    #[test]
    fn analytics_config_with_geoip() {
        let toml_str = r#"
enabled = true

[geoip]
source = "geolite2-city"
cache_path = "/tmp/geoip.mmdb"
"#;
        let cfg: AnalyticsConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.enabled);
        let geoip = cfg.geoip.unwrap();
        assert_eq!(geoip.source, "geolite2-city");
        assert_eq!(geoip.cache_path.as_deref(), Some("/tmp/geoip.mmdb"));
    }
}
