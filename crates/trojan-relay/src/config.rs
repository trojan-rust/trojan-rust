//! Configuration structures for relay chain system.
//!
//! Entry node config defines named chains and rules that map listen
//! ports to chains + destinations. Relay node config defines the
//! transport listener (TLS or plain TCP) and authentication.

use std::collections::HashMap;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

// ── Entry Node Configuration ──

/// Top-level entry node configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryConfig {
    /// Named chains: name → chain definition.
    #[serde(default)]
    pub chains: HashMap<String, ChainConfig>,

    /// Routing rules: each rule binds a listen port to a chain + dest.
    #[serde(default)]
    pub rules: Vec<RuleConfig>,

    /// Global timeout settings.
    #[serde(default)]
    pub timeouts: TimeoutConfig,
}

/// A named relay chain — an ordered list of relay nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Ordered relay nodes. Empty list means direct connection to dest.
    #[serde(default)]
    pub nodes: Vec<ChainNodeConfig>,
}

/// A single relay node in a chain.
///
/// `transport` and `sni` describe how to reach this node.
/// For `nodes[0]`, the entry node uses them for the first hop.
/// For `nodes[1..]`, the entry sends them via handshake metadata so
/// the upstream relay uses the specified transport/sni for its outbound.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainNodeConfig {
    /// Relay node address (host:port).
    pub addr: String,

    /// Relay password for this node.
    #[serde(default)]
    pub password: Option<String>,

    /// Transport type to reach this node.
    #[serde(default)]
    pub transport: TransportType,

    /// TLS SNI to send when connecting to this node.
    #[serde(default = "default_sni")]
    pub sni: String,
}

/// A routing rule: maps a listen address to a chain and destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    /// Human-readable name for logging / metrics.
    pub name: String,

    /// Listen address (ip:port).
    pub listen: SocketAddr,

    /// Name of the chain to use.
    pub chain: String,

    /// Final destination address (the exit trojan-server, host:port).
    /// The last relay node connects here via plain TCP; the actual TLS
    /// handshake (including SNI) is performed end-to-end by the trojan client.
    pub dest: String,
}

// ── Relay Node Configuration ──

/// Top-level relay node configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayNodeConfig {
    /// Relay listener settings.
    pub relay: RelayListenerConfig,
}

/// Relay listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayListenerConfig {
    /// Listen address (ip:port).
    pub listen: SocketAddr,

    /// Inbound transport type.
    #[serde(default)]
    pub transport: TransportType,

    /// Optional TLS certificate/key. If absent, auto-generated.
    /// Only used when `transport = "tls"`.
    #[serde(default)]
    pub tls: Option<RelayTlsConfig>,

    /// Authentication settings.
    pub auth: RelayAuthConfig,

    /// Outbound connection settings.
    #[serde(default)]
    pub outbound: RelayOutboundConfig,

    /// Timeout settings.
    #[serde(default)]
    pub timeouts: TimeoutConfig,
}

/// Optional manual TLS certificate for relay node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayTlsConfig {
    pub cert: String,
    pub key: String,
}

/// Relay authentication configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayAuthConfig {
    /// Relay password (plain text, will be SHA-224 hashed on the wire).
    pub password: String,
}

/// Relay outbound connection settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayOutboundConfig {
    /// TLS SNI to send on outbound connections.
    #[serde(default = "default_sni")]
    pub sni: String,
}

impl Default for RelayOutboundConfig {
    fn default() -> Self {
        Self {
            sni: default_sni(),
        }
    }
}

// ── Transport ──

/// Transport type for relay connections.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    /// TLS transport (default). Auto-generates self-signed certs if not configured.
    #[default]
    Tls,
    /// Plain TCP (no encryption). For testing or trusted networks.
    Plain,
}

// ── Shared ──

/// Timeout and buffer configuration shared by entry and relay nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Timeout for establishing tunnel connections (seconds).
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,

    /// Idle connection timeout (seconds).
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,

    /// Relay handshake timeout (seconds). Only used by relay nodes.
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_secs: u64,

    /// Relay buffer size per direction (bytes).
    #[serde(default = "default_relay_buffer_size")]
    pub relay_buffer_size: usize,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            connect_timeout_secs: default_connect_timeout(),
            idle_timeout_secs: default_idle_timeout(),
            handshake_timeout_secs: default_handshake_timeout(),
            relay_buffer_size: default_relay_buffer_size(),
        }
    }
}

fn default_connect_timeout() -> u64 {
    10
}
fn default_idle_timeout() -> u64 {
    300
}
fn default_handshake_timeout() -> u64 {
    5
}
fn default_relay_buffer_size() -> usize {
    trojan_core::defaults::DEFAULT_RELAY_BUFFER_SIZE
}
fn default_sni() -> String {
    "crates.io".to_string()
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_entry_config() {
        let toml_str = r#"
[chains.jp]
nodes = [
  { addr = "relay-hk:443", password = "hk-secret" },
]

[chains.direct]
nodes = []

[[rules]]
name = "japan"
listen = "127.0.0.1:1080"
chain = "jp"
dest = "trojan-jp:443"

[[rules]]
name = "singapore"
listen = "127.0.0.1:1082"
chain = "direct"
dest = "trojan-sg:443"

[timeouts]
connect_timeout_secs = 15
"#;
        let config: EntryConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.chains.len(), 2);
        assert_eq!(config.rules.len(), 2);
        assert_eq!(config.chains["jp"].nodes.len(), 1);
        assert_eq!(config.chains["jp"].nodes[0].addr, "relay-hk:443");
        assert!(config.chains["direct"].nodes.is_empty());
        assert_eq!(config.rules[0].name, "japan");
        assert_eq!(config.rules[0].dest, "trojan-jp:443");
        assert_eq!(config.timeouts.connect_timeout_secs, 15);
        assert_eq!(config.timeouts.idle_timeout_secs, 300); // default
    }

    #[test]
    fn parse_relay_config() {
        let toml_str = r#"
[relay]
listen = "0.0.0.0:443"

[relay.auth]
password = "relay-secret"

[relay.timeouts]
handshake_timeout_secs = 3
"#;
        let config: RelayNodeConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.relay.auth.password, "relay-secret");
        assert!(config.relay.tls.is_none());
        assert_eq!(config.relay.outbound.sni, "crates.io");
        assert_eq!(config.relay.timeouts.handshake_timeout_secs, 3);
    }
}
