//! Frozen protocol v1 clients must remain usable without node-accounting negotiation.

#![expect(
    clippy::tests_outside_test_module,
    reason = "integration tests are independent test crates"
)]

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::Message};

mod common;

use common::Dash;

// Keep these wire shapes independent from the current protocol crate.
mod v1 {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
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

    #[derive(Debug, Serialize, Deserialize)]
    pub enum PanelMessage {
        Registered {
            node_id: String,
            node_type: NodeType,
            config_version: u32,
            report_interval_secs: u32,
            config: Vec<u8>,
        },
        ConfigPush {
            version: u32,
            restart_required: bool,
            drain_timeout_secs: Option<u32>,
            config: Vec<u8>,
        },
        Ping,
        Error {
            code: ErrorCode,
            message: String,
        },
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct TrafficRecord {
        pub user_id: String,
        pub bytes: u64,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub enum NodeType {
        Server,
        Entry,
        Relay,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub enum ServiceState {
        Starting,
        Running,
        Restarting,
        Stopped,
        Error,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub enum ErrorCode {
        InvalidToken,
        NodeDisabled,
        NodeNotFound,
        ProtocolMismatch,
        RateLimited,
        InternalError,
    }
}

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

async fn send(socket: &mut Socket, message: v1::AgentMessage) {
    socket
        .send(Message::Binary(
            bincode::serialize(&message).unwrap().into(),
        ))
        .await
        .unwrap();
}

async fn frame(socket: &mut Socket) -> Message {
    tokio::time::timeout(Duration::from_secs(3), socket.next())
        .await
        .expect("dashboard did not respond")
        .expect("dashboard closed the legacy socket")
        .unwrap()
}

async fn connect(dash: &Dash, token: &str) -> Socket {
    let (mut socket, response) =
        tokio_tungstenite::connect_async(format!("{}/ws/agent", dash.base.replace("http:", "ws:")))
            .await
            .unwrap();
    assert!(response.headers().get("x-trojan-node-traffic").is_none());
    send(
        &mut socket,
        v1::AgentMessage::Register {
            protocol_version: 1,
            token: token.into(),
            version: "legacy-test".into(),
            hostname: "legacy-host".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
        },
    )
    .await;
    let Message::Binary(bytes) = frame(&mut socket).await else {
        panic!("expected a legacy registration response");
    };
    let registered: v1::PanelMessage = bincode::deserialize(&bytes).unwrap();
    assert!(matches!(registered, v1::PanelMessage::Registered { .. }));
    socket
}

async fn original_frames_through_pong(socket: &mut Socket) {
    socket
        .send(Message::Ping(b"barrier".to_vec().into()))
        .await
        .unwrap();
    loop {
        match frame(socket).await {
            Message::Pong(payload) => {
                assert_eq!(payload.as_ref(), b"barrier");
                return;
            }
            Message::Binary(bytes) => {
                let message: v1::PanelMessage = bincode::deserialize(&bytes)
                    .expect("dashboard sent an extension frame to a legacy agent");
                assert!(matches!(message, v1::PanelMessage::Ping));
                send(socket, v1::AgentMessage::Pong).await;
            }
            other => panic!("unexpected legacy socket frame: {other:?}"),
        }
    }
}

#[tokio::test]
async fn legacy_agent_keeps_heartbeat_and_user_traffic_without_extension_frames() {
    let dash = Dash::start().await;
    let (user_id, _) = dash.add_user("legacy-user").await;
    let node = dash
        .admin_post(
            "/admin/nodes",
            serde_json::json!({"name": "legacy-entry", "traffic_limit": 100}),
        )
        .await;
    let id = node["id"].as_u64().unwrap();
    let mut socket = connect(&dash, node["token"].as_str().unwrap()).await;
    original_frames_through_pong(&mut socket).await;
    send(
        &mut socket,
        v1::AgentMessage::Heartbeat {
            connections_active: 3,
            bytes_in: 1200,
            bytes_out: 3400,
            uptime_secs: 60,
            memory_rss_bytes: None,
            cpu_usage_percent: None,
        },
    )
    .await;
    send(
        &mut socket,
        v1::AgentMessage::Traffic {
            records: vec![v1::TrafficRecord {
                user_id: user_id.to_string(),
                bytes: 42,
            }],
        },
    )
    .await;
    original_frames_through_pong(&mut socket).await;

    let status = dash.admin_get(&format!("/admin/nodes/{id}")).await;
    assert_eq!(status["bytes_in"], 1200);
    assert_eq!(status["bytes_out"], 3400);
    assert_eq!(status["connections_active"], 3);
    assert_eq!(status["traffic_supported"], false);
    assert!(status["traffic_remaining"].is_null());
    assert_eq!(status["unavailable_reason"], "traffic_unsupported");
    assert_eq!(status["traffic_used"], 0);
    assert_eq!(
        dash.admin_get(&format!("/admin/users/{user_id}")).await["traffic_used"],
        42
    );
    assert_eq!(
        dash.admin_get("/admin/traffic")
            .await
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let response = dash
        .client
        .patch(format!("{}/admin/nodes/{id}", dash.base))
        .bearer_auth(common::ADMIN_TOKEN)
        .json(&serde_json::json!({"traffic_limit": 0}))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    original_frames_through_pong(&mut socket).await;
    let unlimited = dash.admin_get(&format!("/admin/nodes/{id}")).await;
    assert_eq!(unlimited["traffic_supported"], false);
    assert!(unlimited["traffic_remaining"].is_null());
    assert!(unlimited["unavailable_reason"].is_null());
    socket.close(None).await.unwrap();
}

#[tokio::test]
async fn unnegotiated_report_closes_without_charging_or_sending_extension_errors() {
    use trojan_protocol::{AgentMessage, NodeTrafficReport};

    let dash = Dash::start().await;
    let node = dash
        .admin_post("/admin/nodes", serde_json::json!({"name": "unnegotiated"}))
        .await;
    let mut socket = connect(&dash, node["token"].as_str().unwrap()).await;
    let report = AgentMessage::NodeTraffic {
        report: NodeTrafficReport {
            stream_id: "unnegotiated".into(),
            sequence: 1,
            observed_at: 0,
            bytes_in: 30,
            bytes_out: 10,
        },
    };
    socket
        .send(Message::Binary(bincode::serialize(&report).unwrap().into()))
        .await
        .unwrap();
    match tokio::time::timeout(Duration::from_secs(3), socket.next())
        .await
        .expect("dashboard did not close an unnegotiated extension session")
    {
        None | Some(Ok(Message::Close(_))) => {}
        Some(Err(tokio_tungstenite::tungstenite::Error::Protocol(
            tokio_tungstenite::tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
        ))) => {}
        other => panic!("unnegotiated extension received an unexpected frame: {other:?}"),
    }
    let id = node["id"].as_u64().unwrap();
    let stored = dash.admin_get(&format!("/admin/nodes/{id}")).await;
    assert_eq!(stored["traffic_used"], 0);
    assert_eq!(stored["period_bytes_in"], 0);
    assert_eq!(stored["period_bytes_out"], 0);
}

#[tokio::test]
async fn any_legacy_session_marks_node_accounting_incomplete_without_erasing_history() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use trojan_protocol::{AgentMessage, NodeTrafficReport, PanelMessage};

    let dash = Dash::start().await;
    let node = dash
        .admin_post(
            "/admin/nodes",
            serde_json::json!({"name": "mixed", "traffic_limit": 100}),
        )
        .await;
    let id = node["id"].as_u64().unwrap();
    let token = node["token"].as_str().unwrap();
    let mut request = format!("{}/ws/agent", dash.base.replace("http:", "ws:"))
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("x-trojan-node-traffic", "1".parse().unwrap());
    let (mut supported, response) = tokio_tungstenite::connect_async(request).await.unwrap();
    assert_eq!(response.headers()["x-trojan-node-traffic"], "1");
    send(
        &mut supported,
        v1::AgentMessage::Register {
            protocol_version: 1,
            token: token.into(),
            version: "negotiated-test".into(),
            hostname: "test".into(),
            os: "test".into(),
            arch: "test".into(),
        },
    )
    .await;
    let Message::Binary(bytes) = frame(&mut supported).await else {
        panic!("expected Registered");
    };
    assert!(matches!(
        bincode::deserialize::<v1::PanelMessage>(&bytes).unwrap(),
        v1::PanelMessage::Registered { .. }
    ));
    let observed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let report = AgentMessage::NodeTraffic {
        report: NodeTrafficReport {
            stream_id: "mixed-stream".into(),
            sequence: 1,
            observed_at,
            bytes_in: 30,
            bytes_out: 10,
        },
    };
    supported
        .send(Message::Binary(bincode::serialize(&report).unwrap().into()))
        .await
        .unwrap();
    loop {
        let Message::Binary(bytes) = frame(&mut supported).await else {
            panic!("expected accounting ACK");
        };
        match bincode::deserialize::<PanelMessage>(&bytes).unwrap() {
            PanelMessage::NodeTrafficAck { sequence: 1, .. } => break,
            PanelMessage::NodeStates { .. } => {}
            other => panic!("unexpected message: {other:?}"),
        }
    }
    let status = dash.admin_get(&format!("/admin/nodes/{id}")).await;
    assert_eq!(status["traffic_supported"], true);
    assert_eq!(status["traffic_remaining"], 60);
    let mut legacy = connect(&dash, token).await;
    original_frames_through_pong(&mut legacy).await;
    let status = dash.admin_get(&format!("/admin/nodes/{id}")).await;
    assert_eq!(status["traffic_used"], 40);
    assert_eq!(status["period_bytes_in"], 30);
    assert_eq!(status["period_bytes_out"], 10);
    assert_eq!(status["traffic_supported"], false);
    assert!(status["traffic_remaining"].is_null());
    assert_eq!(status["unavailable_reason"], "traffic_unsupported");
    loop {
        let Message::Binary(bytes) = frame(&mut supported).await else {
            panic!("expected mixed session state");
        };
        let PanelMessage::NodeStates { snapshot } =
            bincode::deserialize::<PanelMessage>(&bytes).unwrap()
        else {
            panic!("expected NodeStates");
        };
        if snapshot.nodes.iter().any(|node| {
            node.node_id == id.to_string() && !node.traffic_supported && node.used_bytes == 40
        }) {
            break;
        }
    }
    legacy.close(None).await.unwrap();
    loop {
        let Message::Binary(bytes) = frame(&mut supported).await else {
            panic!("expected restored accounting state");
        };
        let PanelMessage::NodeStates { snapshot } =
            bincode::deserialize::<PanelMessage>(&bytes).unwrap()
        else {
            panic!("expected NodeStates");
        };
        if snapshot
            .nodes
            .iter()
            .any(|node| node.node_id == id.to_string() && node.traffic_supported)
        {
            break;
        }
    }
    let status = dash.admin_get(&format!("/admin/nodes/{id}")).await;
    assert_eq!(status["traffic_supported"], true);
    assert_eq!(status["traffic_remaining"], 60);
    supported.close(None).await.unwrap();
}
