//! Exercise persisted routing across an agent restart without a panel.

use super::tests::*;
use super::*;
use crate::protocol::{NodeState, NodeStateSnapshot, NodeType};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::time::timeout;

async fn assert_admission(listen: std::net::SocketAddr, target: &TcpListener, allowed: bool) {
    let mut client = connect_service(listen).await;
    if allowed {
        let (mut remote, _) = timeout(WAIT, target.accept()).await.unwrap().unwrap();
        round_trip(&mut client, &mut remote).await;
    } else {
        assert_eq!(
            timeout(WAIT, client.read(&mut [0])).await.unwrap().unwrap(),
            0
        );
    }
}

#[tokio::test]
async fn cached_snapshot_restores_offline_routing_after_restart_and_respects_local_grace() {
    init_crypto();
    for (grace, allowed) in [(172_800, true), (0, false), (60, false)] {
        let directory = tempfile::tempdir().unwrap();
        let panel = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = free_address().await;
        let service_config = entry_config(listen, target.local_addr().unwrap());
        let mut settings = agent_config(panel.local_addr().unwrap(), directory.path());
        settings.node_state_grace_secs = grace;
        let shutdown = CancellationToken::new();
        let _guard = shutdown.clone().drop_guard();
        let agent = tokio::spawn(run(settings.clone(), shutdown.clone()));
        let (tcp, _) = timeout(WAIT, panel.accept()).await.unwrap().unwrap();
        let mut ws = tokio_tungstenite::accept_hdr_async(tcp, accept_node_traffic)
            .await
            .unwrap();
        assert!(matches!(
            receive(&mut ws).await,
            AgentMessage::Register { .. }
        ));
        send(
            &mut ws,
            PanelMessage::Registered {
                node_id: "entry".into(),
                node_type: NodeType::Entry,
                config_version: 1,
                report_interval_secs: 1,
                config: serde_json::to_vec(&service_config).unwrap(),
            },
        )
        .await;
        let now = unix_now();
        let snapshot = NodeStateSnapshot {
            generated_at: now - 120,
            valid_until: now - 30,
            nodes: vec![NodeState {
                node_id: "entry".into(),
                enabled: true,
                online: true,
                traffic_supported: true,
                traffic_limit: 100,
                used_bytes: 80,
                period_start: 0,
                reset_at: now - 60,
            }],
        };
        send(
            &mut ws,
            PanelMessage::NodeStates {
                snapshot: snapshot.clone(),
            },
        )
        .await;
        ready(&mut ws, &service_config).await;
        let persisted: NodeStateSnapshot = serde_json::from_slice(
            &tokio::fs::read(directory.path().join("node-states.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(persisted, snapshot);
        assert_admission(listen, &target, allowed).await;
        shutdown.cancel();
        timeout(WAIT, agent).await.unwrap().unwrap().unwrap();
        drop((ws, panel));

        let offline_shutdown = CancellationToken::new();
        let _offline_guard = offline_shutdown.clone().drop_guard();
        let offline = tokio::spawn(run(settings, offline_shutdown.clone()));
        assert_admission(listen, &target, allowed).await;
        offline_shutdown.cancel();
        timeout(WAIT, offline).await.unwrap().unwrap().unwrap();
        let after: NodeStateSnapshot = serde_json::from_slice(
            &tokio::fs::read(directory.path().join("node-states.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(after, snapshot);
    }
}

#[tokio::test]
async fn snapshot_write_failure_stops_the_agent() {
    init_crypto();
    let directory = tempfile::tempdir().unwrap();
    tokio::fs::create_dir(directory.path().join("node-states.json.tmp"))
        .await
        .unwrap();
    let panel = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = free_address().await;
    let service_config = entry_config(listen, "127.0.0.1:1".parse().unwrap());
    let shutdown = CancellationToken::new();
    let _guard = shutdown.clone().drop_guard();
    let agent = tokio::spawn(run(
        agent_config(panel.local_addr().unwrap(), directory.path()),
        shutdown,
    ));
    let _ws = register(&panel, &service_config).await;
    assert!(matches!(
        timeout(WAIT, agent).await.unwrap().unwrap(),
        Err(AgentError::Cache(_))
    ));
    TcpListener::bind(listen).await.unwrap();
}
