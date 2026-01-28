//! Server state shared across connections.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::pool::ConnectionPool;
use trojan_config::WebSocketConfig;

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
    pub websocket: WebSocketConfig,
    /// Analytics event collector (only available when analytics feature is enabled).
    #[cfg(feature = "analytics")]
    pub analytics: Option<trojan_analytics::EventCollector>,
}
