//! Verify the accounting and routing contract across the real panel and agent.

use std::net::SocketAddr;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use super::run;
use crate::config::AgentConfig;

const ADMIN_TOKEN: &str = "node-budget-test-admin";
const PAYLOAD: [u8; 64] = [0x5a; 64];

async fn echo(stream: &mut TcpStream) -> std::io::Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        stream.write_all(&PAYLOAD).await?;
        let mut received = [0; PAYLOAD.len()];
        stream.read_exact(&mut received).await?;
        assert_eq!(received, PAYLOAD);
        Ok(())
    })
    .await
    .map_err(std::io::Error::other)?
}

async fn connect_when_available(addr: SocketAddr) -> TcpStream {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(mut stream) = TcpStream::connect(addr).await
                && echo(&mut stream).await.is_ok()
            {
                return stream;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("managed entry did not become available")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_usage_closes_new_routes_and_live_budget_update_reopens_them() {
    let dir = tempfile::tempdir().unwrap();
    let panel_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let panel_addr = panel_listener.local_addr().unwrap();
    let base = format!("http://{panel_addr}");
    let database = toml::Value::from(dir.path().join("panel.db").display().to_string());
    let panel_config = toml::from_str(&format!(
        "database = {database}\nadmin_token = \"{ADMIN_TOKEN}\""
    ))
    .unwrap();
    let panel_shutdown = CancellationToken::new();
    let _panel_guard = panel_shutdown.clone().drop_guard();
    let token = panel_shutdown.clone();
    let panel = tokio::spawn(trojan_dash::run_with_listener(
        panel_config,
        panel_listener,
        token,
    ));

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                tokio::io::copy(&mut read, &mut write).await.unwrap();
            });
        }
    });
    let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let entry_addr = reserved.local_addr().unwrap();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let node: Value = client
        .post(format!("{base}/admin/nodes"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&json!({
            "name": "managed-entry",
            "node_type": "entry",
            "traffic_limit": 32,
            "config": {
                "chains": {"direct": {"nodes": []}},
                "rules": [{
                    "name": "echo",
                    "listen": entry_addr,
                    "chain": "direct",
                    "dest": echo_addr.to_string()
                }]
            }
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let node_url = format!("{base}/admin/nodes/{}", node["id"]);
    let agent_config = AgentConfig {
        panel_url: format!("ws://{panel_addr}/ws/agent"),
        token: node["token"].as_str().unwrap().to_owned(),
        cache_dir: Some(dir.path().join("agent")),
        report_interval_secs: Some(1),
        log_level: None,
        reconnect: Default::default(),
    };
    drop(reserved);
    let shutdown = CancellationToken::new();
    let _agent_guard = shutdown.clone().drop_guard();
    let agent = tokio::spawn(run(agent_config, shutdown.clone()));
    let mut existing = connect_when_available(entry_addr).await;

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let node: Value = client
                .get(&node_url)
                .bearer_auth(ADMIN_TOKEN)
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();
            if node["unavailable_reason"] == "traffic_exhausted" {
                assert!(node["period_bytes_in"].as_u64().unwrap() >= 64);
                assert!(node["period_bytes_out"].as_u64().unwrap() >= 64);
                assert_eq!(node["traffic_remaining"], 0);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("real forwarded traffic did not exhaust the node budget");

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut fresh = TcpStream::connect(entry_addr).await.unwrap();
            if echo(&mut fresh).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("exhausted node still accepts new routes");
    echo(&mut existing).await.unwrap();

    client
        .patch(&node_url)
        .bearer_auth(ADMIN_TOKEN)
        .json(&json!({"traffic_limit": 1_000_000}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let mut resumed = connect_when_available(entry_addr).await;
    // The original stream must survive both quota changes without a service restart.
    echo(&mut existing).await.unwrap();
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(10), agent)
        .await
        .expect("agent shutdown timed out")
        .unwrap()
        .unwrap();
    assert!(echo(&mut existing).await.is_err());
    assert!(echo(&mut resumed).await.is_err());
    panel_shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(10), panel)
        .await
        .expect("panel shutdown timed out")
        .unwrap()
        .unwrap();
    echo_server.abort();
}
