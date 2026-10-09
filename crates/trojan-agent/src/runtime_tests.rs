use super::*;
use crate::protocol::NodeType;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

pub(super) const WAIT: Duration = Duration::from_secs(5);

pub(super) fn init_crypto() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .unwrap();
    });
}

pub(super) async fn free_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

pub(super) fn entry_config(listen: SocketAddr, target: SocketAddr) -> serde_json::Value {
    json!({
        "chains": {"direct": {"nodes": []}},
        "rules": [{"name": "test", "listen": listen, "chain": "direct", "dest": target.to_string()}]
    })
}

pub(super) fn agent_config(panel: SocketAddr, cache: &std::path::Path) -> AgentConfig {
    AgentConfig {
        panel_url: format!("ws://{panel}/ws/agent"),
        token: "token".into(),
        cache_dir: Some(cache.into()),
        report_interval_secs: Some(1),
        log_level: None,
        reconnect: crate::config::ReconnectConfig {
            initial_delay_ms: 20,
            max_delay_ms: 20,
            multiplier: 1.0,
            jitter: 0.0,
        },
    }
}

#[expect(
    clippy::unnecessary_wraps,
    clippy::result_large_err,
    reason = "the WebSocket handshake callback requires an HTTP response Result"
)]
pub(super) fn accept_node_traffic(
    request: &tokio_tungstenite::tungstenite::handshake::server::Request,
    mut response: tokio_tungstenite::tungstenite::handshake::server::Response,
) -> Result<
    tokio_tungstenite::tungstenite::handshake::server::Response,
    tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
> {
    assert_eq!(request.headers()[crate::protocol::NODE_TRAFFIC_HEADER], "1");
    response
        .headers_mut()
        .insert(crate::protocol::NODE_TRAFFIC_HEADER, "1".parse().unwrap());
    Ok(response)
}

pub(super) async fn register(
    panel: &TcpListener,
    config: &serde_json::Value,
) -> WebSocketStream<TcpStream> {
    register_node(panel, NodeType::Entry, config).await
}

pub(super) async fn register_node(
    panel: &TcpListener,
    node_type: NodeType,
    config: &serde_json::Value,
) -> WebSocketStream<TcpStream> {
    let (tcp, _) = timeout(WAIT, panel.accept()).await.unwrap().unwrap();
    let mut ws = timeout(
        WAIT,
        tokio_tungstenite::accept_hdr_async(tcp, super::tests::accept_node_traffic),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(
        receive(&mut ws).await,
        AgentMessage::Register { .. }
    ));
    send(
        &mut ws,
        PanelMessage::Registered {
            node_id: "entry".into(),
            node_type,
            config_version: 1,
            report_interval_secs: 1,
            config: serde_json::to_vec(config).unwrap(),
        },
    )
    .await;
    send_states(&mut ws, true).await;
    ws
}

pub(super) async fn send_states(ws: &mut WebSocketStream<TcpStream>, enabled: bool) {
    send(
        ws,
        PanelMessage::NodeStates {
            snapshot: crate::protocol::NodeStateSnapshot {
                generated_at: unix_now(),
                valid_until: unix_now() + 90,
                nodes: vec![crate::protocol::NodeState {
                    node_id: "entry".into(),
                    enabled,
                    online: true,
                    traffic_supported: true,
                    traffic_limit: 0,
                    used_bytes: 0,
                    period_start: 0,
                    reset_at: unix_now() + 3600,
                }],
            },
        },
    )
    .await;
}

pub(super) async fn ready(ws: &mut WebSocketStream<TcpStream>, config: &serde_json::Value) -> u64 {
    // The acknowledgement confirms all preceding state snapshots reached the runtime.
    send(
        ws,
        PanelMessage::ConfigPush {
            version: 1,
            restart_required: false,
            drain_timeout_secs: None,
            config: serde_json::to_vec(config).unwrap(),
        },
    )
    .await;
    let mut started = None;
    loop {
        match receive(ws).await {
            AgentMessage::ServiceStatus { started_at, .. } => started = Some(started_at),
            AgentMessage::ConfigAck { ok: true, .. } => return started.unwrap_or(0),
            _ => {}
        }
    }
}

pub(super) async fn receive(ws: &mut WebSocketStream<TcpStream>) -> AgentMessage {
    let message = timeout(WAIT, ws.next()).await.unwrap().unwrap().unwrap();
    let Message::Binary(bytes) = message else {
        panic!("expected binary message, got {message:?}")
    };
    bincode::deserialize(&bytes).unwrap()
}

pub(super) async fn send(ws: &mut WebSocketStream<TcpStream>, message: PanelMessage) {
    ws.send(Message::Binary(
        bincode::serialize(&message).unwrap().into(),
    ))
    .await
    .unwrap();
}

pub(super) async fn connect_service(address: SocketAddr) -> TcpStream {
    timeout(WAIT, async {
        loop {
            match TcpStream::connect(address).await {
                Ok(stream) => return stream,
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    sleep(Duration::from_millis(10)).await
                }
                Err(e) => panic!("service connection failed: {e}"),
            }
        }
    })
    .await
    .unwrap()
}

pub(super) async fn round_trip(client: &mut TcpStream, target: &mut TcpStream) {
    client.write_all(b"payload").await.unwrap();
    let mut bytes = [0; 7];
    timeout(WAIT, target.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"payload");
    target.write_all(&bytes).await.unwrap();
    timeout(WAIT, client.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"payload");
}

async fn heartbeat_with_traffic(ws: &mut WebSocketStream<TcpStream>, bytes: u64) {
    timeout(WAIT, async {
        loop {
            if let AgentMessage::Heartbeat {
                bytes_in,
                bytes_out,
                ..
            } = receive(ws).await
                && bytes_in >= bytes
                && bytes_out >= bytes
            {
                return;
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn reconnect_preserves_listener_connections_and_statistics() {
    init_crypto();
    let cache = tempfile::tempdir().unwrap();
    let panel = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = free_address().await;
    let service_config = entry_config(listen, target.local_addr().unwrap());
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(run(
        agent_config(panel.local_addr().unwrap(), cache.path()),
        shutdown.clone(),
    ));
    let mut first = register(&panel, &service_config).await;
    let started_at = ready(&mut first, &service_config).await;
    let mut client = connect_service(listen).await;
    let (mut remote, _) = timeout(WAIT, target.accept()).await.unwrap().unwrap();
    round_trip(&mut client, &mut remote).await;
    heartbeat_with_traffic(&mut first, 7).await;
    first.close(None).await.unwrap();
    drop(first);

    let mut second = register(&panel, &service_config).await;
    let after = ready(&mut second, &service_config).await;
    assert_eq!(started_at, after);
    round_trip(&mut client, &mut remote).await;
    heartbeat_with_traffic(&mut second, 14).await;
    let mut next_client = connect_service(listen).await;
    let (mut next_remote, _) = timeout(WAIT, target.accept()).await.unwrap().unwrap();
    round_trip(&mut next_client, &mut next_remote).await;
    assert!(!task.is_finished());
    drop((client, remote, next_client, next_remote));
    shutdown.cancel();
    timeout(WAIT, task).await.unwrap().unwrap().unwrap();
    TcpListener::bind(listen)
        .await
        .expect("agent shutdown must release the service listener");
}

#[tokio::test]
async fn cached_service_recovers_when_panel_returns() {
    init_crypto();
    let cache = tempfile::tempdir().unwrap();
    let panel_addr = free_address().await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = free_address().await;
    let service_config = entry_config(listen, target.local_addr().unwrap());
    cache::write_cache(
        cache.path(),
        &CachedConfig {
            node_id: Some("entry".into()),
            node_traffic: true,
            version: 1,
            node_type: NodeType::Entry,
            report_interval_secs: 1,
            config: service_config.clone(),
            cached_at: unix_now(),
        },
    )
    .await
    .unwrap();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(run(
        agent_config(panel_addr, cache.path()),
        shutdown.clone(),
    ));
    drop(connect_service(listen).await);
    let panel = TcpListener::bind(panel_addr).await.unwrap();
    let mut ws = register(&panel, &service_config).await;
    ready(&mut ws, &service_config).await;
    let mut client = connect_service(listen).await;
    let (mut remote, _) = timeout(WAIT, target.accept()).await.unwrap().unwrap();
    round_trip(&mut client, &mut remote).await;
    heartbeat_with_traffic(&mut ws, 7).await;
    round_trip(&mut client, &mut remote).await;
    heartbeat_with_traffic(&mut ws, 14).await;
    drop((client, remote));
    shutdown.cancel();
    timeout(WAIT, task).await.unwrap().unwrap().unwrap();
    TcpListener::bind(listen).await.unwrap();
}

#[tokio::test]
async fn shutdown_during_registration_releases_cached_listener() {
    init_crypto();
    let cache = tempfile::tempdir().unwrap();
    let panel = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = free_address().await;
    cache::write_cache(
        cache.path(),
        &CachedConfig {
            node_id: Some("entry".into()),
            node_traffic: true,
            version: 1,
            node_type: NodeType::Entry,
            report_interval_secs: 1,
            config: entry_config(listen, target.local_addr().unwrap()),
            cached_at: unix_now(),
        },
    )
    .await
    .unwrap();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(run(
        agent_config(panel.local_addr().unwrap(), cache.path()),
        shutdown.clone(),
    ));
    let (_pending_registration, _) = timeout(WAIT, panel.accept()).await.unwrap().unwrap();
    let client = connect_service(listen).await;
    drop(client);
    shutdown.cancel();
    timeout(WAIT, task).await.unwrap().unwrap().unwrap();
    TcpListener::bind(listen).await.unwrap();
}

#[tokio::test]
async fn config_push_requires_restart_and_replaces_the_listener() {
    init_crypto();
    let cache = tempfile::tempdir().unwrap();
    let panel = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let old = free_address().await;
    let new = free_address().await;
    let config = entry_config(old, target.local_addr().unwrap());
    let replacement = entry_config(new, target.local_addr().unwrap());
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(run(
        agent_config(panel.local_addr().unwrap(), cache.path()),
        shutdown.clone(),
    ));
    let mut ws = register(&panel, &config).await;
    ready(&mut ws, &config).await;
    drop(connect_service(old).await);
    for restart in [false, true] {
        send(
            &mut ws,
            PanelMessage::ConfigPush {
                version: 2,
                restart_required: restart,
                drain_timeout_secs: Some(1),
                config: serde_json::to_vec(&replacement).unwrap(),
            },
        )
        .await;
        loop {
            if let AgentMessage::ConfigAck { version, ok, .. } = receive(&mut ws).await {
                assert_eq!(version, 2);
                assert_eq!(ok, restart);
                break;
            }
        }
        if !restart {
            assert_eq!(
                cache::read_cache(cache.path()).await.unwrap().config,
                config
            );
            drop(connect_service(old).await);
        }
    }
    drop(connect_service(new).await);
    assert_eq!(
        cache::read_cache(cache.path()).await.unwrap().config,
        replacement
    );
    TcpListener::bind(old).await.unwrap();
    shutdown.cancel();
    timeout(WAIT, task).await.unwrap().unwrap().unwrap();
    TcpListener::bind(new).await.unwrap();
}

#[tokio::test]
async fn node_state_push_changes_admission_without_restarting_existing_connections() {
    init_crypto();
    let cache = tempfile::tempdir().unwrap();
    let panel = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = free_address().await;
    let config = entry_config(listen, target.local_addr().unwrap());
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(run(
        agent_config(panel.local_addr().unwrap(), cache.path()),
        shutdown.clone(),
    ));
    let mut ws = register(&panel, &config).await;
    ready(&mut ws, &config).await;
    let mut client = connect_service(listen).await;
    let (mut remote, _) = timeout(WAIT, target.accept()).await.unwrap().unwrap();
    round_trip(&mut client, &mut remote).await;

    send_states(&mut ws, false).await;
    ready(&mut ws, &config).await;
    let mut denied = connect_service(listen).await;
    assert_eq!(
        timeout(WAIT, denied.read(&mut [0u8]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    round_trip(&mut client, &mut remote).await;

    send_states(&mut ws, true).await;
    ready(&mut ws, &config).await;
    let mut next_client = connect_service(listen).await;
    let (mut next_remote, _) = timeout(WAIT, target.accept()).await.unwrap().unwrap();
    round_trip(&mut next_client, &mut next_remote).await;
    round_trip(&mut client, &mut remote).await;
    drop((client, remote, denied, next_client, next_remote));
    shutdown.cancel();
    timeout(WAIT, task).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn panel_disconnect_closes_both_client_channels() {
    let cache = tempfile::tempdir().unwrap();
    let panel = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = agent_config(panel.local_addr().unwrap(), cache.path());
    let client = tokio::spawn(async move {
        client::connect_and_register(&config, CancellationToken::new())
            .await
            .unwrap()
    });
    let mut ws = register(&panel, &json!({})).await;
    let (_, tx, mut rx) = client.await.unwrap();
    assert!(matches!(
        timeout(WAIT, rx.recv()).await.unwrap(),
        Some(PanelMessage::NodeStates { .. })
    ));
    ws.close(None).await.unwrap();
    drop(ws);
    timeout(WAIT, tx.closed())
        .await
        .expect("send task must stop when receive task stops");
    assert!(timeout(WAIT, rx.recv()).await.unwrap().is_none());
}
