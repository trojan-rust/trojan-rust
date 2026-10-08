use super::tests::*;
use super::*;
use crate::protocol::{NodeType, PROTOCOL_VERSION};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_tungstenite::WebSocketStream;

async fn register_capability(
    panel: &TcpListener,
    config: &serde_json::Value,
    supported: bool,
) -> WebSocketStream<TcpStream> {
    let (tcp, _) = timeout(WAIT, panel.accept()).await.unwrap().unwrap();
    let mut ws = if supported {
        tokio_tungstenite::accept_hdr_async(tcp, accept_node_traffic)
            .await
            .unwrap()
    } else {
        tokio_tungstenite::accept_async(tcp).await.unwrap()
    };
    assert!(matches!(
        receive(&mut ws).await,
        AgentMessage::Register {
            protocol_version: PROTOCOL_VERSION,
            ..
        }
    ));
    send(
        &mut ws,
        PanelMessage::Registered {
            node_id: "entry".into(),
            node_type: NodeType::Entry,
            config_version: 1,
            report_interval_secs: 1,
            config: serde_json::to_vec(config).unwrap(),
        },
    )
    .await;
    ws
}

async fn legacy_heartbeat(ws: &mut WebSocketStream<TcpStream>, minimum: u64) {
    timeout(WAIT, async {
        loop {
            match receive(ws).await {
                AgentMessage::NodeTraffic { .. } => {
                    panic!("legacy panel received an extension frame")
                }
                AgentMessage::Heartbeat {
                    bytes_in,
                    bytes_out,
                    ..
                } if bytes_in >= minimum && bytes_out >= minimum => return,
                _ => {}
            }
        }
    })
    .await
    .unwrap();
}

fn journal(cache: &std::path::Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(cache.join("node-traffic.json")).unwrap()).unwrap()
}

#[tokio::test]
async fn legacy_panel_keeps_forwarding_and_reconnects_without_node_reports() {
    init_crypto();
    let cache = tempfile::tempdir().unwrap();
    let panel = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = free_address().await;
    let config = entry_config(listen, target.local_addr().unwrap());
    let shutdown = CancellationToken::new();
    let _guard = shutdown.clone().drop_guard();
    let agent = tokio::spawn(run(
        agent_config(panel.local_addr().unwrap(), cache.path()),
        shutdown.clone(),
    ));
    let mut ws = register_capability(&panel, &config, false).await;
    ready(&mut ws, &config).await;
    let mut client = connect_service(listen).await;
    let (mut remote, _) = timeout(WAIT, target.accept()).await.unwrap().unwrap();
    round_trip(&mut client, &mut remote).await;
    legacy_heartbeat(&mut ws, 7).await;
    ws.close(None).await.unwrap();
    drop(ws);
    let mut ws = register_capability(&panel, &config, false).await;
    ready(&mut ws, &config).await;
    round_trip(&mut client, &mut remote).await;
    legacy_heartbeat(&mut ws, 14).await;
    assert!(!cache::read_cache(cache.path()).await.unwrap().node_traffic);
    shutdown.cancel();
    timeout(WAIT, agent).await.unwrap().unwrap().unwrap();
    assert!(
        journal(cache.path())["pending"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(journal(cache.path())["node_traffic"], false);
}

#[tokio::test]
async fn enabling_accounting_excludes_legacy_bytes_and_requires_new_states() {
    init_crypto();
    let cache = tempfile::tempdir().unwrap();
    let panel = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = free_address().await;
    let config = entry_config(listen, target.local_addr().unwrap());
    let agent_config = agent_config(panel.local_addr().unwrap(), cache.path());
    let shutdown = CancellationToken::new();
    let _guard = shutdown.clone().drop_guard();
    let agent = tokio::spawn(run(agent_config.clone(), shutdown.clone()));
    let mut ws = register_capability(&panel, &config, false).await;
    ready(&mut ws, &config).await;
    let mut client = connect_service(listen).await;
    let (mut remote, _) = timeout(WAIT, target.accept()).await.unwrap().unwrap();
    round_trip(&mut client, &mut remote).await;
    legacy_heartbeat(&mut ws, 7).await;
    round_trip(&mut client, &mut remote).await;
    ws.close(None).await.unwrap();
    drop(ws);

    let mut ws = register_capability(&panel, &config, true).await;
    ready(&mut ws, &config).await;
    assert_eq!(
        timeout(WAIT, remote.read(&mut [0])).await.unwrap().unwrap(),
        0
    );
    let mut denied = connect_service(listen).await;
    assert_eq!(
        timeout(WAIT, denied.read(&mut [0])).await.unwrap().unwrap(),
        0
    );
    send_states(&mut ws, true).await;
    ready(&mut ws, &config).await;
    let mut client = connect_service(listen).await;
    let (mut remote, _) = timeout(WAIT, target.accept()).await.unwrap().unwrap();
    round_trip(&mut client, &mut remote).await;
    shutdown.cancel();
    timeout(WAIT, agent).await.unwrap().unwrap().unwrap();
    let saved = journal(cache.path());
    let pending = saved["pending"].as_array().unwrap();
    assert_eq!(
        pending
            .iter()
            .map(|report| report["bytes_in"].as_u64().unwrap())
            .sum::<u64>(),
        7
    );
    assert_eq!(
        pending
            .iter()
            .map(|report| report["bytes_out"].as_u64().unwrap())
            .sum::<u64>(),
        7
    );
    assert!(cache::read_cache(cache.path()).await.unwrap().node_traffic);

    // A lost config cache must not erase the journal's proven capability or pending reports.
    std::fs::remove_file(cache.path().join("config.json")).unwrap();
    let restarted_shutdown = CancellationToken::new();
    let _guard = restarted_shutdown.clone().drop_guard();
    let restarted = tokio::spawn(run(agent_config, restarted_shutdown));
    let _legacy = register_capability(&panel, &config, false).await;
    assert!(matches!(
        timeout(WAIT, restarted).await.unwrap().unwrap(),
        Err(AgentError::Accounting(_))
    ));
    assert_eq!(journal(cache.path())["pending"], saved["pending"]);
    TcpListener::bind(listen).await.unwrap();
}

#[tokio::test]
async fn losing_accounting_support_closes_existing_connections() {
    init_crypto();
    let cache = tempfile::tempdir().unwrap();
    let panel = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = free_address().await;
    let config = entry_config(listen, target.local_addr().unwrap());
    let shutdown = CancellationToken::new();
    let _guard = shutdown.clone().drop_guard();
    let agent = tokio::spawn(run(
        agent_config(panel.local_addr().unwrap(), cache.path()),
        shutdown,
    ));
    let mut ws = register(&panel, &config).await;
    ready(&mut ws, &config).await;
    let mut client = connect_service(listen).await;
    let (mut remote, _) = timeout(WAIT, target.accept()).await.unwrap().unwrap();
    round_trip(&mut client, &mut remote).await;
    ws.close(None).await.unwrap();
    drop(ws);
    let _legacy = register_capability(&panel, &config, false).await;
    assert!(matches!(
        timeout(WAIT, agent).await.unwrap().unwrap(),
        Err(AgentError::Accounting(_))
    ));
    assert_eq!(
        timeout(WAIT, remote.read(&mut [0])).await.unwrap().unwrap(),
        0
    );
    let saved = journal(cache.path());
    assert_eq!(saved["node_traffic"], true);
    assert_eq!(
        saved["pending"]
            .as_array()
            .unwrap()
            .iter()
            .map(|report| report["bytes_in"].as_u64().unwrap()
                + report["bytes_out"].as_u64().unwrap())
            .sum::<u64>(),
        14
    );
    TcpListener::bind(listen).await.unwrap();
}

#[tokio::test]
async fn unnegotiated_extension_messages_stop_the_agent() {
    init_crypto();
    let cache = tempfile::tempdir().unwrap();
    let panel = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = free_address().await;
    let config = entry_config(listen, target.local_addr().unwrap());
    let shutdown = CancellationToken::new();
    let _guard = shutdown.clone().drop_guard();
    let agent = tokio::spawn(run(
        agent_config(panel.local_addr().unwrap(), cache.path()),
        shutdown,
    ));
    let mut ws = register_capability(&panel, &config, false).await;
    ready(&mut ws, &config).await;
    send_states(&mut ws, true).await;
    assert!(matches!(
        timeout(WAIT, agent).await.unwrap().unwrap(),
        Err(AgentError::Accounting(_))
    ));
    assert!(
        journal(cache.path())["pending"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}
