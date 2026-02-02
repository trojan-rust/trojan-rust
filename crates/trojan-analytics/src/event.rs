//! Connection event types.

use std::net::IpAddr;

use clickhouse::Row;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// A connection event representing the full lifecycle of a single connection.
#[derive(Debug, Clone, Row, Serialize, Deserialize)]
pub struct ConnectionEvent {
    // === Time dimension ===
    /// Connection start time (UTC).
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    pub timestamp: OffsetDateTime,

    /// Connection duration in milliseconds.
    pub duration_ms: u64,

    // === Connection identity ===
    /// Connection ID (unique within server instance).
    pub conn_id: u64,

    /// Client IP address.
    pub peer_ip: IpAddr,

    /// Client port.
    pub peer_port: u16,

    // === User identity ===
    /// User identifier (password hash prefix or custom ID).
    pub user_id: String,

    /// Authentication result.
    pub auth_result: AuthResult,

    // === Target information ===
    /// Target address type.
    pub target_type: TargetType,

    /// Target host (IP or domain).
    pub target_host: String,

    /// Target port.
    pub target_port: u16,

    /// SNI (Server Name Indication), if available.
    pub sni: String,

    // === Traffic statistics ===
    /// Bytes sent (client → server → target).
    pub bytes_sent: u64,

    /// Bytes received (target → server → client).
    pub bytes_recv: u64,

    /// Packets sent (UDP only).
    pub packets_sent: u64,

    /// Packets received (UDP only).
    pub packets_recv: u64,

    // === Connection metadata ===
    /// Protocol type.
    pub protocol: Protocol,

    /// Transport layer.
    pub transport: Transport,

    /// Connection close reason.
    pub close_reason: CloseReason,

    /// Whether this was a fallback connection.
    pub is_fallback: bool,

    // === GeoIP information (peer_ip lookup) ===
    /// Source country ISO 3166-1 alpha-2 code (e.g., "CN", "US").
    pub peer_country: String,

    /// Source region/state/province (e.g., "Shanghai", "California").
    pub peer_region: String,

    /// Source city (e.g., "Shanghai", "Los Angeles").
    pub peer_city: String,

    /// Source ASN number (e.g., 4134).
    pub peer_asn: u32,

    /// Source ASN organization (e.g., "China Telecom").
    pub peer_org: String,

    /// Source longitude.
    pub peer_longitude: f64,

    /// Source latitude.
    pub peer_latitude: f64,

    // === Server information ===
    /// Server instance ID.
    pub server_id: String,
}

impl ConnectionEvent {
    /// Create a new connection event with default values.
    pub fn new(conn_id: u64, peer_ip: IpAddr, peer_port: u16) -> Self {
        Self {
            timestamp: OffsetDateTime::now_utc(),
            duration_ms: 0,
            conn_id,
            peer_ip,
            peer_port,
            user_id: String::new(),
            auth_result: AuthResult::Skipped,
            target_type: TargetType::Domain,
            target_host: String::new(),
            target_port: 0,
            sni: String::new(),
            bytes_sent: 0,
            bytes_recv: 0,
            packets_sent: 0,
            packets_recv: 0,
            protocol: Protocol::Tcp,
            transport: Transport::Direct,
            close_reason: CloseReason::Normal,
            is_fallback: false,
            peer_country: String::new(),
            peer_region: String::new(),
            peer_city: String::new(),
            peer_asn: 0,
            peer_org: String::new(),
            peer_longitude: 0.0,
            peer_latitude: 0.0,
            server_id: String::new(),
        }
    }
}

/// Authentication result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthResult {
    /// Authentication succeeded.
    Success,
    /// Authentication failed.
    Failed,
    /// Authentication was skipped (fallback traffic).
    Skipped,
}

impl From<AuthResult> for &'static str {
    fn from(r: AuthResult) -> Self {
        match r {
            AuthResult::Success => "success",
            AuthResult::Failed => "failed",
            AuthResult::Skipped => "skipped",
        }
    }
}

/// Target address type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetType {
    /// IPv4 address.
    Ipv4,
    /// IPv6 address.
    Ipv6,
    /// Domain name.
    Domain,
}

impl From<TargetType> for &'static str {
    fn from(t: TargetType) -> Self {
        match t {
            TargetType::Ipv4 => "ipv4",
            TargetType::Ipv6 => "ipv6",
            TargetType::Domain => "domain",
        }
    }
}

/// Connection protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// TCP connection.
    Tcp,
    /// UDP association.
    Udp,
}

impl From<Protocol> for &'static str {
    fn from(p: Protocol) -> Self {
        match p {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

/// Transport layer type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// Direct TLS connection.
    Direct,
    /// WebSocket transport.
    WebSocket,
}

impl From<Transport> for &'static str {
    fn from(t: Transport) -> Self {
        match t {
            Transport::Direct => "direct",
            Transport::WebSocket => "websocket",
        }
    }
}

/// Connection close reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseReason {
    /// Normal close.
    Normal,
    /// Idle timeout.
    Timeout,
    /// Error occurred.
    Error,
    /// Connection reset.
    Reset,
    /// Server shutdown.
    ServerShutdown,
}

impl From<CloseReason> for &'static str {
    fn from(r: CloseReason) -> Self {
        match r {
            CloseReason::Normal => "normal",
            CloseReason::Timeout => "timeout",
            CloseReason::Error => "error",
            CloseReason::Reset => "reset",
            CloseReason::ServerShutdown => "shutdown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn connection_event_new_defaults() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let event = ConnectionEvent::new(42, ip, 8080);

        assert_eq!(event.conn_id, 42);
        assert_eq!(event.peer_ip, ip);
        assert_eq!(event.peer_port, 8080);
        assert_eq!(event.duration_ms, 0);
        assert!(event.user_id.is_empty());
        assert_eq!(event.auth_result, AuthResult::Skipped);
        assert_eq!(event.target_type, TargetType::Domain);
        assert!(event.target_host.is_empty());
        assert_eq!(event.target_port, 0);
        assert_eq!(event.bytes_sent, 0);
        assert_eq!(event.bytes_recv, 0);
        assert_eq!(event.protocol, Protocol::Tcp);
        assert_eq!(event.transport, Transport::Direct);
        assert_eq!(event.close_reason, CloseReason::Normal);
        assert!(!event.is_fallback);
        // GeoIP fields default to empty
        assert!(event.peer_country.is_empty());
        assert!(event.peer_region.is_empty());
        assert!(event.peer_city.is_empty());
        assert_eq!(event.peer_asn, 0);
        assert!(event.peer_org.is_empty());
        assert_eq!(event.peer_longitude, 0.0);
        assert_eq!(event.peer_latitude, 0.0);
        assert!(event.server_id.is_empty());
    }

    #[test]
    fn enum_into_str() {
        let s: &str = AuthResult::Success.into();
        assert_eq!(s, "success");
        let s: &str = AuthResult::Failed.into();
        assert_eq!(s, "failed");
        let s: &str = AuthResult::Skipped.into();
        assert_eq!(s, "skipped");

        let s: &str = TargetType::Ipv4.into();
        assert_eq!(s, "ipv4");
        let s: &str = TargetType::Ipv6.into();
        assert_eq!(s, "ipv6");
        let s: &str = TargetType::Domain.into();
        assert_eq!(s, "domain");

        let s: &str = Protocol::Tcp.into();
        assert_eq!(s, "tcp");
        let s: &str = Protocol::Udp.into();
        assert_eq!(s, "udp");

        let s: &str = Transport::Direct.into();
        assert_eq!(s, "direct");
        let s: &str = Transport::WebSocket.into();
        assert_eq!(s, "websocket");

        let s: &str = CloseReason::Normal.into();
        assert_eq!(s, "normal");
        let s: &str = CloseReason::Timeout.into();
        assert_eq!(s, "timeout");
        let s: &str = CloseReason::Error.into();
        assert_eq!(s, "error");
        let s: &str = CloseReason::Reset.into();
        assert_eq!(s, "reset");
        let s: &str = CloseReason::ServerShutdown.into();
        assert_eq!(s, "shutdown");
    }

    #[test]
    fn enum_serde_roundtrip() {
        let auth = AuthResult::Failed;
        let json = serde_json::to_string(&auth).unwrap();
        assert_eq!(json, "\"failed\"");
        let back: AuthResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AuthResult::Failed);

        let proto = Protocol::Udp;
        let json = serde_json::to_string(&proto).unwrap();
        assert_eq!(json, "\"udp\"");
        let back: Protocol = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Protocol::Udp);

        let transport = Transport::WebSocket;
        let json = serde_json::to_string(&transport).unwrap();
        assert_eq!(json, "\"web_socket\"");
        let back: Transport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Transport::WebSocket);
    }
}
