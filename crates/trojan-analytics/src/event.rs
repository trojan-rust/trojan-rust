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
