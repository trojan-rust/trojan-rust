//! Server state shared across connections.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::pool::ConnectionPool;
use trojan_config::{TcpConfig, WebSocketConfig};
use trojan_dns::DnsResolver;

/// Shared server state for all connections.
#[derive(Clone)]
pub struct ServerState {
    pub fallback_addr: SocketAddr,
    pub max_udp_payload: usize,
    pub max_udp_buffer_bytes: usize,
    pub max_header_bytes: usize,
    pub tcp_idle_timeout: Duration,
    pub udp_idle_timeout: Duration,
    pub fallback_pool: Option<Arc<ConnectionPool>>,
    pub relay_buffer_size: usize,
    pub tcp_send_buffer: usize,
    pub tcp_recv_buffer: usize,
    pub tcp_config: TcpConfig,
    pub websocket: WebSocketConfig,
    pub dns_resolver: DnsResolver,
    /// Analytics event collector (only available when analytics feature is enabled).
    #[cfg(feature = "analytics")]
    pub analytics: Option<trojan_analytics::EventCollector>,
    /// Rule engine for routing decisions (only available when rules feature is enabled).
    /// Uses `HotRuleEngine` for lock-free hot-reload support.
    #[cfg(feature = "rules")]
    pub rule_engine: Option<Arc<trojan_rules::HotRuleEngine>>,
    /// Named outbound connectors (only available when rules feature is enabled).
    #[cfg(feature = "rules")]
    pub outbounds: std::collections::HashMap<String, Arc<crate::outbound::Outbound>>,
    /// Shared GeoIP database for metrics country tagging (country-level).
    #[cfg(feature = "geoip")]
    pub geoip_metrics: Option<Arc<trojan_rules::geoip_db::GeoipDb>>,
    /// Shared GeoIP database for analytics geo fields (city-level).
    #[cfg(all(feature = "geoip", feature = "analytics"))]
    pub geoip_analytics: Option<Arc<trojan_rules::geoip_db::GeoipDb>>,
}
