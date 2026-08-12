//! The agent-facing socket, driven with the same message types an agent
//! compiles against.
//!
//! What a node reports over this socket is the only place the panel learns
//! what an entry or relay carried, so the assertions are on what ends up
//! stored, not on the frames themselves.

#![expect(
    clippy::tests_outside_test_module,
    reason = "integration tests are their own crate, where every #[test] is \
              necessarily a free item; the lint targets unit tests that \
              escaped a #[cfg(test)] mod"
)]

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use trojan_protocol::{
    AgentMessage, ErrorCode, NodeType, PROTOCOL_VERSION, PanelMessage, ServiceState, TrafficRecord,
};

mod common;

use common::Dash;

/// A connected agent socket, framed the way the agent frames it.
struct Agent {
    socket: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
}

impl Agent {
    async fn connect(dash: &Dash) -> Self {
        let url = format!("{}/ws/agent", dash.base.replace("http://", "ws://"));
        let (socket, _) = tokio_tungstenite::connect_async(url).await.unwrap();
        Self { socket }
    }

    async fn send(&mut self, message: AgentMessage) {
        let bytes = bincode::serialize(&message).unwrap();
        self.socket
            .send(Message::Binary(bytes.into()))
            .await
            .unwrap();
    }

    /// The next panel message, or `None` if the socket closed first.
    async fn recv(&mut self) -> Option<PanelMessage> {
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(3), self.socket.next())
                .await
                .expect("panel did not answer")?;
            match frame.ok()? {
                Message::Binary(bytes) => return bincode::deserialize(&bytes).ok(),
                Message::Close(_) => return None,
                _ => continue,
            }
        }
    }

    async fn register(&mut self, token: &str) -> Option<PanelMessage> {
        self.send(AgentMessage::Register {
            protocol_version: PROTOCOL_VERSION,
            token: token.to_owned(),
            version: "0.0.0-test".to_owned(),
            hostname: "test-host".to_owned(),
            os: "linux".to_owned(),
            arch: "x86_64".to_owned(),
        })
        .await;
        self.recv().await
    }
}

/// Registration hands back the service the operator configured, so the agent
/// knows what to boot without any local config of its own.
#[tokio::test]
async fn registration_hands_the_agent_its_configured_service() {
    let dash = Dash::start().await;
    let node = dash
        .admin_post(
            "/admin/nodes",
            serde_json::json!({
                "name": "entry-sh",
                "node_type": "entry",
                "config": { "node_id": "7", "rules": [] },
            }),
        )
        .await;
    let token = node["token"].as_str().unwrap().to_owned();
    let node_id = node["id"].as_u64().unwrap();

    let mut agent = Agent::connect(&dash).await;
    let reply = agent.register(&token).await.expect("no reply to Register");

    let PanelMessage::Registered {
        node_id: reported,
        node_type,
        config,
        ..
    } = reply
    else {
        panic!("expected Registered, got {reply:?}");
    };
    assert_eq!(reported, node_id.to_string());
    assert_eq!(node_type, NodeType::Entry);

    let config: serde_json::Value = serde_json::from_slice(&config).unwrap();
    assert_eq!(config["node_id"], "7");
}

/// Heartbeats are how a relay's traffic becomes visible at all: it carries
/// bytes for users it cannot name, so the node totals are the whole story.
#[tokio::test]
async fn a_heartbeat_becomes_the_nodes_reported_state() {
    let dash = Dash::start().await;
    let node = dash
        .admin_post(
            "/admin/nodes",
            serde_json::json!({ "name": "relay-hk", "node_type": "relay" }),
        )
        .await;
    let token = node["token"].as_str().unwrap().to_owned();
    let node_id = node["id"].as_u64().unwrap();

    let mut agent = Agent::connect(&dash).await;
    agent.register(&token).await.expect("registration failed");

    agent
        .send(AgentMessage::Heartbeat {
            connections_active: 12,
            bytes_in: 900_000,
            bytes_out: 4_500_000,
            uptime_secs: 3600,
            memory_rss_bytes: Some(52_428_800),
            cpu_usage_percent: Some(3.5),
        })
        .await;
    agent
        .send(AgentMessage::ServiceStatus {
            status: ServiceState::Running,
            started_at: 1_700_000_000,
            config_version: 1,
        })
        .await;

    let stored = await_node(&dash, node_id, |node| {
        node["bytes_in"].as_u64() == Some(900_000)
    })
    .await;
    assert_eq!(stored["bytes_out"].as_u64(), Some(4_500_000));
    assert_eq!(stored["connections_active"].as_u64(), Some(12));
    assert_eq!(stored["uptime_secs"].as_u64(), Some(3600));
    assert_eq!(stored["agent_version"].as_str(), Some("0.0.0-test"));
    assert!(stored["last_seen"].as_u64().unwrap_or(0) > 0);
}

/// Per-user traffic over the socket lands where the HTTP endpoint puts it —
/// same accounting, different transport.
#[tokio::test]
async fn reported_traffic_lands_on_the_user_and_the_node() {
    let dash = Dash::start().await;
    let node = dash
        .admin_post("/admin/nodes", serde_json::json!({ "name": "exit-jp" }))
        .await;
    let token = node["token"].as_str().unwrap().to_owned();
    let (user_id, _password) = dash.add_user("frank").await;

    let mut agent = Agent::connect(&dash).await;
    agent.register(&token).await.expect("registration failed");

    agent
        .send(AgentMessage::Traffic {
            records: vec![
                TrafficRecord {
                    user_id: user_id.to_string(),
                    bytes: 1024,
                },
                // A user removed while the node still held bytes for them must
                // not cost the rest of the batch.
                TrafficRecord {
                    user_id: "4242".to_owned(),
                    bytes: 512,
                },
            ],
        })
        .await;

    // The socket answers a report with nothing, so wait for the write itself.
    for _ in 0..100 {
        let user = dash.admin_get(&format!("/admin/users/{user_id}")).await;
        if user["traffic_used"].as_u64() == Some(1024) {
            let logs = dash
                .admin_get(&format!("/admin/traffic?user_id={user_id}"))
                .await;
            let logs = logs.as_array().unwrap();
            assert_eq!(logs.len(), 1, "one user, node and day: {logs:?}");
            assert_eq!(logs[0]["bytes"].as_u64(), Some(1024));
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("traffic never reached the user");
}

/// A token that names no node gets a reason, not a silent drop.
#[tokio::test]
async fn an_unknown_token_is_refused() {
    let dash = Dash::start().await;
    let mut agent = Agent::connect(&dash).await;

    let reply = agent.register("not-a-real-token").await;

    match reply {
        Some(PanelMessage::Error { code, .. }) => assert_eq!(code, ErrorCode::InvalidToken),
        other => panic!("expected an InvalidToken error, got {other:?}"),
    }
}

/// A disabled node is turned away too — the token still exists, the node is
/// just not supposed to be serving.
#[tokio::test]
async fn a_disabled_node_is_refused() {
    let dash = Dash::start().await;
    let node = dash
        .admin_post("/admin/nodes", serde_json::json!({ "name": "retired" }))
        .await;
    let token = node["token"].as_str().unwrap().to_owned();
    let node_id = node["id"].as_u64().unwrap();

    let resp = dash
        .client
        .patch(format!("{}/admin/nodes/{node_id}", dash.base))
        .bearer_auth(common::ADMIN_TOKEN)
        .json(&serde_json::json!({ "enabled": false }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let mut agent = Agent::connect(&dash).await;

    match agent.register(&token).await {
        Some(PanelMessage::Error { code, .. }) => assert_eq!(code, ErrorCode::NodeDisabled),
        other => panic!("expected a NodeDisabled error, got {other:?}"),
    }
}

/// Poll the node until `ready` accepts it, since the socket is one-way: the
/// panel answers a report with nothing at all.
async fn await_node(
    dash: &Dash,
    node_id: u64,
    ready: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    for _ in 0..100 {
        let node = dash.admin_get(&format!("/admin/nodes/{node_id}")).await;
        if ready(&node) {
            return node;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("node {node_id} never reached the expected state");
}
