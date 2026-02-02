//! Analytics configuration for connection event collection.

use serde::{Deserialize, Serialize};

use crate::GeoipConfig;

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

    /// GeoIP precision for analytics events: "city", "country", or "none".
    /// - "city": record all geo fields (country, region, city, ASN, org, lat/lon)
    /// - "country": record only country code
    /// - "none": do not record any geo information
    #[serde(default = "default_geo_precision")]
    pub geo_precision: String,
}

impl Default for AnalyticsPrivacyConfig {
    fn default() -> Self {
        Self {
            record_peer_ip: true,
            full_user_id: false,
            user_id_prefix_len: default_analytics_user_id_prefix_len(),
            record_sni: true,
            geo_precision: default_geo_precision(),
        }
    }
}

fn default_geo_precision() -> String {
    "city".to_string()
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
        assert_eq!(cfg.geo_precision, "city");
    }

    #[test]
    fn privacy_config_deserialize_geo_precision() {
        let toml_str = r#"geo_precision = "country""#;
        let cfg: AnalyticsPrivacyConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.geo_precision, "country");
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
