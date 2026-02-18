//! Client configuration.

use serde::Deserialize;
use trojan_config::{LoggingConfig, TcpConfig};

use crate::error::ClientError;

/// Top-level client configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    pub client: ClientSettings,
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Core client settings.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientSettings {
    /// Local SOCKS5 listen address, e.g. "127.0.0.1:1080".
    pub listen: String,

    /// Remote trojan server address, e.g. "example.com:443".
    pub remote: String,

    /// Password (plaintext, SHA-224 computed at runtime).
    pub password: String,

    /// TLS configuration.
    #[serde(default)]
    pub tls: ClientTlsConfig,

    /// TCP socket options.
    #[serde(default)]
    pub tcp: TcpConfig,

    /// DNS resolver configuration.
    #[serde(default)]
    pub dns: trojan_dns::DnsConfig,
}

/// Client-side TLS configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientTlsConfig {
    /// TLS SNI hostname. Defaults to the host portion of `remote`.
    pub sni: Option<String>,

    /// ALPN protocol list.
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,

    /// Skip certificate verification (for testing only).
    #[serde(default)]
    pub skip_verify: bool,

    /// Custom CA certificate path (PEM).
    pub ca: Option<String>,
}

impl Default for ClientTlsConfig {
    fn default() -> Self {
        Self {
            sni: None,
            alpn: default_alpn(),
            skip_verify: false,
            ca: None,
        }
    }
}

fn default_alpn() -> Vec<String> {
    vec!["h2".into(), "http/1.1".into()]
}

/// Load client configuration from a file path.
///
/// Supports TOML, JSON, and JSONC formats (detected by extension).
pub fn load_client_config(path: &std::path::Path) -> Result<ClientConfig, ClientError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ClientError::Config(format!("failed to read config: {e}")))?;

    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("toml");

    match ext {
        "toml" => toml::from_str(&content)
            .map_err(|e| ClientError::Config(format!("TOML parse error: {e}"))),
        "json" | "jsonc" => {
            // Strip single-line comments for JSONC support
            let stripped: String = content
                .lines()
                .map(|line| {
                    if let Some(idx) = line.find("//") {
                        // Only strip if not inside a string (simple heuristic)
                        let before = &line[..idx];
                        let quotes = before.chars().filter(|&c| c == '"').count();
                        if quotes % 2 == 0 { before } else { line }
                    } else {
                        line
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            serde_json::from_str(&stripped)
                .map_err(|e| ClientError::Config(format!("JSON parse error: {e}")))
        }
        _ => toml::from_str(&content)
            .map_err(|e| ClientError::Config(format!("config parse error: {e}"))),
    }
}
