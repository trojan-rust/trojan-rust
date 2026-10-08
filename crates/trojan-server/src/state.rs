//! Server state shared across connections.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::pool::ConnectionPool;
#[cfg(feature = "ws")]
use trojan_config::WebSocketConfig;
use trojan_config::{ProxyProtocolConfig, TcpConfig};
use trojan_dns::DnsResolver;
use trojan_metrics::{NodeStats, RelayCounters};

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
    #[cfg(feature = "ws")]
    pub websocket: WebSocketConfig,
    pub dns_resolver: DnsResolver,
    /// Traffic and connection totals for this node, for the panel agent.
    pub node_stats: Arc<NodeStats>,
    /// Senders whose PROXY protocol header names the client and the chain.
    pub proxy_protocol: ProxyProtocolConfig,
    /// Whether to emit destination-labelled byte and connection counters.
    /// See `metrics.per_target` — this is unbounded-cardinality when on.
    pub per_target_metrics: bool,
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

impl ServerState {
    /// Match the actual destination and retain any address resolved for IP rules.
    #[cfg(feature = "rules")]
    pub async fn route(
        &self,
        address: &trojan_proto::AddressRef<'_>,
        peer: SocketAddr,
    ) -> Result<(trojan_rules::Action, Option<SocketAddr>), crate::error::ServerError> {
        use trojan_proto::HostRef;
        use trojan_rules::rule::MatchContext;

        let Some(engine) = &self.rule_engine else {
            return Ok((trojan_rules::Action::Direct, None));
        };
        let mut ctx = MatchContext {
            domain: match address.host {
                HostRef::Domain(domain) => std::str::from_utf8(domain).ok(),
                _ => None,
            },
            dest_ip: match address.host {
                HostRef::Ipv4(ip) => Some(ip.into()),
                HostRef::Ipv6(ip) => Some(ip.into()),
                _ => None,
            },
            dest_port: address.port,
            src_ip: peer.ip(),
        };
        if ctx.dest_ip.is_none() && ctx.domain.is_some() && engine.has_ip_rules() {
            if let Some(action) = engine.match_request_lazy_ip(&ctx) {
                return Ok((action, None));
            }
            let resolved = crate::resolve::resolve_address(address, &self.dns_resolver).await?;
            ctx.dest_ip = Some(resolved.ip());
            return Ok((engine.match_request(&ctx), Some(resolved)));
        }
        Ok((engine.match_request(&ctx), None))
    }

    /// Record a target connection and resolve the session's counter handles.
    ///
    /// Done once per connection rather than per write; see [`RelayCounters`].
    /// `target` is the destination to break the bytes down by, and `None` for a
    /// session that has no single one — a UDP association reaches a different
    /// target per packet. A breakdown is only ever added when
    /// `metrics.per_target` asked for one.
    pub fn relay_counters(&self, target: Option<&str>) -> RelayCounters {
        let counters = match target {
            Some(label) if self.per_target_metrics => {
                trojan_metrics::record_target_connection(label);
                RelayCounters::with_target(label)
            }
            _ => RelayCounters::global(),
        };
        counters.with_node_stats(self.node_stats.clone())
    }
}
