//! WebSocket protocol message types shared between agent and panel.
//!
//! Messages are serialized with bincode for compact binary framing.
//! The `config` fields carry opaque JSON bytes — they are not interpreted
//! at the protocol layer and are parsed into typed configs by the runner.

use serde::{Deserialize, Serialize};

/// Protocol version — incremented on breaking changes.
pub const PROTOCOL_VERSION: u32 = 1;

/// Agent -> Panel messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentMessage {
    Register {
        protocol_version: u32,
        token: String,
        version: String,
        hostname: String,
        os: String,
        arch: String,
    },
    Heartbeat {
        connections_active: u32,
        bytes_in: u64,
        bytes_out: u64,
        uptime_secs: u64,
        memory_rss_bytes: Option<u64>,
        cpu_usage_percent: Option<f32>,
    },
    Traffic {
        records: Vec<TrafficRecord>,
    },
    ConfigAck {
        version: u32,
        ok: bool,
        message: Option<String>,
    },
    ServiceStatus {
        status: ServiceState,
        started_at: u64,
        config_version: u32,
    },
    Pong,
}

/// Panel -> Agent messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PanelMessage {
    Registered {
        node_id: String,
        node_type: NodeType,
        config_version: u32,
        report_interval_secs: u32,
        /// Opaque JSON bytes of the service config.
        config: Vec<u8>,
    },
    ConfigPush {
        version: u32,
        restart_required: bool,
        drain_timeout_secs: Option<u32>,
        /// Opaque JSON bytes of the service config.
        config: Vec<u8>,
    },
    Ping,
    Error {
        code: ErrorCode,
        message: String,
    },
}

/// Per-user traffic delta record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficRecord {
    pub user_id: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

/// Node type — determines which service the agent boots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeType {
    Server,
    Entry,
    Relay,
}

impl std::fmt::Display for NodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeType::Server => write!(f, "server"),
            NodeType::Entry => write!(f, "entry"),
            NodeType::Relay => write!(f, "relay"),
        }
    }
}

/// Service runtime state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceState {
    Starting,
    Running,
    Restarting,
    Stopped,
    Error,
}

/// Error codes from the panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    InvalidToken,
    NodeDisabled,
    NodeNotFound,
    ProtocolMismatch,
    RateLimited,
    InternalError,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_message_register_roundtrip() {
        let msg = AgentMessage::Register {
            protocol_version: PROTOCOL_VERSION,
            token: "test-token".to_string(),
            version: "0.5.0".to_string(),
            hostname: "node-01".to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
        };
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: AgentMessage = bincode::deserialize(&bytes).unwrap();
        match decoded {
            AgentMessage::Register {
                protocol_version,
                token,
                version,
                ..
            } => {
                assert_eq!(protocol_version, PROTOCOL_VERSION);
                assert_eq!(token, "test-token");
                assert_eq!(version, "0.5.0");
            }
            _ => panic!("expected Register"),
        }
    }

    #[test]
    fn panel_message_registered_roundtrip() {
        let config_json = serde_json::json!({"server": {"listen": "0.0.0.0:443"}});
        let config_bytes = serde_json::to_vec(&config_json).unwrap();

        let msg = PanelMessage::Registered {
            node_id: "hk-01".to_string(),
            node_type: NodeType::Server,
            config_version: 17,
            report_interval_secs: 30,
            config: config_bytes,
        };
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: PanelMessage = bincode::deserialize(&bytes).unwrap();
        match decoded {
            PanelMessage::Registered {
                node_id,
                node_type,
                config_version,
                config,
                ..
            } => {
                assert_eq!(node_id, "hk-01");
                assert_eq!(node_type, NodeType::Server);
                assert_eq!(config_version, 17);
                let val: serde_json::Value = serde_json::from_slice(&config).unwrap();
                assert_eq!(val["server"]["listen"], "0.0.0.0:443");
            }
            _ => panic!("expected Registered"),
        }
    }

    #[test]
    fn panel_message_ping_roundtrip() {
        let msg = PanelMessage::Ping;
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: PanelMessage = bincode::deserialize(&bytes).unwrap();
        assert!(matches!(decoded, PanelMessage::Ping));
    }

    #[test]
    fn panel_message_error_roundtrip() {
        let msg = PanelMessage::Error {
            code: ErrorCode::InvalidToken,
            message: "bad token".to_string(),
        };
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: PanelMessage = bincode::deserialize(&bytes).unwrap();
        match decoded {
            PanelMessage::Error { code, message } => {
                assert_eq!(code, ErrorCode::InvalidToken);
                assert_eq!(message, "bad token");
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn agent_message_heartbeat_roundtrip() {
        let msg = AgentMessage::Heartbeat {
            connections_active: 42,
            bytes_in: 1000,
            bytes_out: 2000,
            uptime_secs: 3600,
            memory_rss_bytes: Some(52_428_800),
            cpu_usage_percent: Some(12.5),
        };
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: AgentMessage = bincode::deserialize(&bytes).unwrap();
        match decoded {
            AgentMessage::Heartbeat {
                connections_active,
                uptime_secs,
                memory_rss_bytes,
                ..
            } => {
                assert_eq!(connections_active, 42);
                assert_eq!(uptime_secs, 3600);
                assert_eq!(memory_rss_bytes, Some(52_428_800));
            }
            _ => panic!("expected Heartbeat"),
        }
    }

    #[test]
    fn traffic_record_roundtrip() {
        let record = TrafficRecord {
            user_id: "alice".to_string(),
            bytes_up: 1024,
            bytes_down: 2048,
        };
        let bytes = bincode::serialize(&record).unwrap();
        let decoded: TrafficRecord = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.user_id, "alice");
        assert_eq!(decoded.bytes_up, 1024);
        assert_eq!(decoded.bytes_down, 2048);
    }

    #[test]
    fn node_type_display() {
        assert_eq!(NodeType::Server.to_string(), "server");
        assert_eq!(NodeType::Entry.to_string(), "entry");
        assert_eq!(NodeType::Relay.to_string(), "relay");
    }

    #[test]
    fn config_push_roundtrip() {
        let config_bytes = serde_json::to_vec(&serde_json::json!({})).unwrap();
        let msg = PanelMessage::ConfigPush {
            version: 18,
            restart_required: true,
            drain_timeout_secs: Some(30),
            config: config_bytes,
        };
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: PanelMessage = bincode::deserialize(&bytes).unwrap();
        match decoded {
            PanelMessage::ConfigPush {
                version,
                restart_required,
                drain_timeout_secs,
                ..
            } => {
                assert_eq!(version, 18);
                assert!(restart_required);
                assert_eq!(drain_timeout_secs, Some(30));
            }
            _ => panic!("expected ConfigPush"),
        }
    }

    #[test]
    fn pong_roundtrip() {
        let msg = AgentMessage::Pong;
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: AgentMessage = bincode::deserialize(&bytes).unwrap();
        assert!(matches!(decoded, AgentMessage::Pong));
    }

    #[test]
    fn bincode_is_compact() {
        // Verify bincode produces smaller output than JSON for typical messages
        let msg = AgentMessage::Heartbeat {
            connections_active: 42,
            bytes_in: 123_456_789,
            bytes_out: 987_654_321,
            uptime_secs: 86400,
            memory_rss_bytes: Some(52_428_800),
            cpu_usage_percent: Some(12.5),
        };
        let bincode_bytes = bincode::serialize(&msg).unwrap();
        let json_bytes = serde_json::to_vec(&msg).unwrap();
        assert!(bincode_bytes.len() < json_bytes.len());
    }
}
