//! Agent local configuration.
//!
//! This is the minimal TOML config the agent needs — everything else
//! comes from the panel.

use std::path::PathBuf;

use serde::Deserialize;

/// Minimal local config — everything else comes from the panel.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    /// Panel WebSocket URL (e.g. `wss://panel.example.com/ws/agent`).
    pub panel_url: String,

    /// Node authentication token (issued by the panel).
    pub token: String,

    /// Local cache directory for panel-down resilience.
    /// Stores last-received config so the agent can boot without the panel.
    #[serde(default)]
    pub cache_dir: Option<PathBuf>,

    /// Override report interval in seconds (default from panel or 30s).
    #[serde(default)]
    pub report_interval_secs: Option<u64>,

    /// Log level override (trace, debug, info, warn, error).
    #[serde(default)]
    pub log_level: Option<String>,

    /// Reconnect strategy.
    #[serde(default)]
    pub reconnect: ReconnectConfig,
}

/// Exponential backoff reconnect configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ReconnectConfig {
    /// Initial reconnect delay in milliseconds.
    #[serde(default = "default_initial_delay_ms")]
    pub initial_delay_ms: u64,

    /// Maximum reconnect delay in milliseconds.
    #[serde(default = "default_max_delay_ms")]
    pub max_delay_ms: u64,

    /// Backoff multiplier.
    #[serde(default = "default_multiplier")]
    pub multiplier: f64,

    /// Jitter factor (0.0 to 1.0).
    #[serde(default = "default_jitter")]
    pub jitter: f64,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            initial_delay_ms: default_initial_delay_ms(),
            max_delay_ms: default_max_delay_ms(),
            multiplier: default_multiplier(),
            jitter: default_jitter(),
        }
    }
}

fn default_initial_delay_ms() -> u64 {
    1000
}

fn default_max_delay_ms() -> u64 {
    60_000
}

fn default_multiplier() -> f64 {
    2.0
}

fn default_jitter() -> f64 {
    0.1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config_deserializes() {
        let toml_str = r#"
panel_url = "wss://panel.example.com/ws/agent"
token = "test-token"
"#;
        let config: AgentConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.panel_url, "wss://panel.example.com/ws/agent");
        assert_eq!(config.token, "test-token");
        assert!(config.cache_dir.is_none());
        assert!(config.report_interval_secs.is_none());
        assert_eq!(config.reconnect.initial_delay_ms, 1000);
        assert_eq!(config.reconnect.max_delay_ms, 60_000);
    }

    #[test]
    fn full_config_deserializes() {
        let toml_str = r#"
panel_url = "wss://panel.example.com/ws/agent"
token = "test-token"
cache_dir = "/var/cache/trojan"
report_interval_secs = 15
log_level = "debug"

[reconnect]
initial_delay_ms = 500
max_delay_ms = 30000
multiplier = 1.5
jitter = 0.2
"#;
        let config: AgentConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.cache_dir.unwrap().to_str().unwrap(),
            "/var/cache/trojan"
        );
        assert_eq!(config.report_interval_secs, Some(15));
        assert_eq!(config.log_level.as_deref(), Some("debug"));
        assert_eq!(config.reconnect.initial_delay_ms, 500);
        assert_eq!(config.reconnect.max_delay_ms, 30_000);
        assert!((config.reconnect.multiplier - 1.5).abs() < f64::EPSILON);
        assert!((config.reconnect.jitter - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn reconnect_defaults() {
        let cfg = ReconnectConfig::default();
        assert_eq!(cfg.initial_delay_ms, 1000);
        assert_eq!(cfg.max_delay_ms, 60_000);
        assert!((cfg.multiplier - 2.0).abs() < f64::EPSILON);
        assert!((cfg.jitter - 0.1).abs() < f64::EPSILON);
    }
}
