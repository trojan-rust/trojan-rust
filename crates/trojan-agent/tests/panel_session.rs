//! End-to-end tests for the agent↔panel session.
//!
//! The agent is how a node is driven from a control plane, and none of it had
//! coverage beyond config parsing: registration, the bincode wire format, and
//! error handling were only ever exercised against a real panel. `panel_url`
//! is configurable, so a stand-in panel over plain WebSocket covers the whole
//! handshake.
#![expect(
    clippy::tests_outside_test_module,
    reason = "integration tests are their own crate, where every #[test] is \
              necessarily a free item; the lint targets unit tests that \
              escaped a #[cfg(test)] mod"
)]

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use trojan_agent::{client::connect_and_register, config::AgentConfig, error::AgentError};
use trojan_protocol::{AgentMessage, ErrorCode, NodeType, PROTOCOL_VERSION, PanelMessage};

/// How the stand-in panel should answer a registration.
#[derive(Clone)]
enum PanelBehaviour {
    /// Accept, handing back this node id and service config.
    Accept { node_id: String, config: String },
    /// Refuse with an error.
    Reject { code: ErrorCode, message: String },
}

/// A stand-in panel. Returns its address and a receiver for what the agent
/// sent, so tests can assert on the registration rather than just its effect.
async fn spawn_panel(
    behaviour: PanelBehaviour,
) -> (SocketAddr, tokio::sync::oneshot::Receiver<AgentMessage>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (registered_tx, registered_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
            return;
        };
        let (mut sink, mut source) = ws.split();

        // First binary frame must be the registration.
        let Some(Ok(Message::Binary(data))) = source.next().await else {
            return;
        };
        let Ok(message) = bincode::deserialize::<AgentMessage>(&data) else {
            return;
        };
        let _ = registered_tx.send(message);

        let reply = match behaviour {
            PanelBehaviour::Accept { node_id, config } => PanelMessage::Registered {
                node_id,
                node_type: NodeType::Server,
                config_version: 7,
                report_interval_secs: 30,
                config: config.into_bytes(),
            },
            PanelBehaviour::Reject { code, message } => PanelMessage::Error { code, message },
        };

        let bytes = bincode::serialize(&reply).expect("encode panel reply");
        let _ = sink.send(Message::Binary(bytes.into())).await;
        // Keep the connection open so the agent does not see a close first.
        tokio::time::sleep(Duration::from_secs(30)).await;
    });

    (addr, registered_rx)
}

fn agent_config(addr: SocketAddr, token: &str) -> AgentConfig {
    AgentConfig {
        panel_url: format!("ws://{addr}/ws/agent"),
        token: token.to_string(),
        cache_dir: None,
        report_interval_secs: None,
        log_level: None,
        reconnect: Default::default(),
    }
}

/// A successful registration hands back what the panel sent, and the panel
/// sees a well-formed `Register` carrying the configured token.
///
/// Asserting both directions matters: checking only the returned node id would
/// pass even if the agent never sent its token.
#[tokio::test]
async fn agent_registers_and_receives_config() {
    let (addr, registered) = spawn_panel(PanelBehaviour::Accept {
        node_id: "node-42".to_string(),
        config: r#"{"server":{"listen":"0.0.0.0:443"}}"#.to_string(),
    })
    .await;

    let config = agent_config(addr, "secret-node-token");
    let (result, _tx, _rx) = tokio::time::timeout(
        Duration::from_secs(10),
        connect_and_register(&config, CancellationToken::new()),
    )
    .await
    .expect("registration timed out")
    .expect("registration should succeed");

    assert_eq!(result.node_id, "node-42");
    assert_eq!(result.node_type, NodeType::Server);
    assert_eq!(result.config_version, 7);
    assert_eq!(result.report_interval_secs, 30);
    assert_eq!(
        result.config["server"]["listen"], "0.0.0.0:443",
        "the panel's service config should be parsed and handed back"
    );

    let sent = registered.await.expect("panel never saw a registration");
    match sent {
        AgentMessage::Register {
            protocol_version,
            token,
            os,
            arch,
            ..
        } => {
            assert_eq!(protocol_version, PROTOCOL_VERSION);
            assert_eq!(token, "secret-node-token");
            assert_eq!(os, std::env::consts::OS);
            assert_eq!(arch, std::env::consts::ARCH);
        }
        other => panic!("expected a Register message, got {other:?}"),
    }
}

/// A panel that refuses registration surfaces as a typed error, not a hang or
/// a success with empty fields.
#[tokio::test]
async fn agent_surfaces_panel_rejection() {
    let (addr, _registered) = spawn_panel(PanelBehaviour::Reject {
        code: ErrorCode::InvalidToken,
        message: "token revoked".to_string(),
    })
    .await;

    let config = agent_config(addr, "stale-token");
    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        connect_and_register(&config, CancellationToken::new()),
    )
    .await
    .expect("the client should fail fast, not hang");

    match outcome {
        Err(AgentError::Panel { code, message }) => {
            assert_eq!(code, ErrorCode::InvalidToken);
            assert_eq!(message, "token revoked");
        }
        Err(other) => panic!("expected a panel error, got {other:?}"),
        Ok(_) => panic!("a revoked token must not register successfully"),
    }
}

/// An unreachable panel fails rather than blocking forever.
#[tokio::test]
async fn agent_fails_when_panel_is_unreachable() {
    // Bind and release, so nothing is listening.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let config = agent_config(addr, "any-token");
    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        connect_and_register(&config, CancellationToken::new()),
    )
    .await
    .expect("connecting to a dead panel should fail, not hang");

    outcome.expect_err("registration against a dead panel must not succeed");
}
