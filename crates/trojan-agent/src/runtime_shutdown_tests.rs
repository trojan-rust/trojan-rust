use super::*;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore},
};
use tokio_tungstenite::tungstenite::Message;
use trojan_metrics::NodeStats;
use trojan_proto::{AddressRef, CMD_CONNECT, HostRef, write_request_header};

const WAIT: Duration = Duration::from_secs(5);

struct Fixture {
    directory: tempfile::TempDir,
    listen: std::net::SocketAddr,
    target: TcpListener,
    connector: TlsConnector,
    config: CachedConfig,
}

async fn fixture() -> Fixture {
    super::tests::init_crypto();
    let directory = tempfile::tempdir().unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_path = directory.path().join("cert.pem");
    let key_path = directory.path().join("key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = reservation.local_addr().unwrap();
    drop(reservation);
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = CachedConfig {
        node_id: Some("server".into()),
        node_traffic: true,
        version: 1,
        node_type: crate::protocol::NodeType::Server,
        report_interval_secs: 120,
        config: json!({
            "server": {"listen": listen.to_string(), "fallback": "127.0.0.1:1", "tcp_idle_timeout_secs": 120},
            "tls": {"cert": cert_path, "key": key_path},
            "auth": {"passwords": ["secret"]}
        }),
        cached_at: unix_now(),
    };
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    Fixture {
        directory,
        listen,
        target,
        connector,
        config,
    }
}

async fn live_connection(
    fixture: &Fixture,
) -> (tokio_rustls::client::TlsStream<TcpStream>, TcpStream) {
    let tcp = tokio::time::timeout(WAIT, async {
        loop {
            match TcpStream::connect(fixture.listen).await {
                Ok(stream) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => panic!("service connection failed: {error}"),
            }
        }
    })
    .await
    .unwrap();
    let mut client = fixture
        .connector
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .unwrap();
    let mut request = BytesMut::new();
    write_request_header(
        &mut request,
        trojan_auth::sha224_hex("secret").as_bytes(),
        CMD_CONNECT,
        &AddressRef {
            host: HostRef::Ipv4([127, 0, 0, 1]),
            port: fixture.target.local_addr().unwrap().port(),
        },
    )
    .unwrap();
    request.extend_from_slice(b"hello");
    client.write_all(&request).await.unwrap();
    let (mut remote, _) = tokio::time::timeout(WAIT, fixture.target.accept())
        .await
        .unwrap()
        .unwrap();
    let mut bytes = [0; 5];
    remote.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"hello");
    remote.write_all(b"world").await.unwrap();
    client.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"world");
    (client, remote)
}

async fn wait_for_listener_close(listen: std::net::SocketAddr) {
    tokio::time::timeout(WAIT, async {
        loop {
            if let Ok(listener) = TcpListener::bind(listen).await {
                drop(listener);
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

async fn assert_server_shutdown(drain_timeout: Duration) {
    let fixture = fixture().await;
    let stats = NodeStats::new();
    let service = Service::start(
        fixture.config.clone(),
        runner::ServiceSinks {
            stats: stats.clone(),
            ..Default::default()
        },
    );
    let (_client, mut remote) = live_connection(&fixture).await;
    assert_eq!(stats.snapshot().connections_active, 1);

    service.shutdown.cancel();
    if !drain_timeout.is_zero() {
        wait_for_listener_close(fixture.listen).await;
        assert!(
            !service.task.is_finished(),
            "live sessions must receive a drain period"
        );
        tokio::time::pause();
        tokio::time::advance(trojan_server::DEFAULT_SHUTDOWN_TIMEOUT).await;
    }
    tokio::time::timeout(WAIT, service.stop(drain_timeout))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stats.snapshot().connections_active, 0);
    assert_eq!(
        tokio::time::timeout(WAIT, remote.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0,
        "the target stream must close before the final checkpoint"
    );
    let final_snapshot = stats.snapshot();
    assert_eq!((final_snapshot.bytes_in, final_snapshot.bytes_out), (5, 5));
    let agent_config = serde_json::from_value(json!({
        "panel_url": "ws://localhost:8080/ws/agent", "token": "token"
    }))
    .unwrap();
    let traffic = NodeTraffic::open(fixture.directory.path(), &agent_config, 120)
        .await
        .unwrap();
    traffic.enable(NodeStats::new()).await.unwrap();
    let sampler_shutdown = CancellationToken::new();
    sampler_shutdown.cancel();
    traffic
        .run_sampler(stats.clone(), sampler_shutdown)
        .await
        .unwrap();
    let saved: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fixture.directory.path().join("node-traffic.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(saved["pending"][0]["bytes_in"], 5);
    assert_eq!(saved["pending"][0]["bytes_out"], 5);
    tokio::task::yield_now().await;
    assert_eq!(stats.snapshot(), final_snapshot);
}

#[tokio::test]
async fn forced_service_stop_closes_sessions_before_final_checkpoint() {
    assert_server_shutdown(Duration::ZERO).await;
}

#[tokio::test]
async fn server_drain_deadline_closes_sessions_before_final_checkpoint() {
    assert_server_shutdown(Duration::from_secs(60)).await;
}

async fn assert_sampler_failure(during_drain: bool) {
    let fixture = fixture().await;
    cache::write_cache(fixture.directory.path(), &fixture.config)
        .await
        .unwrap();
    let panel = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = serde_json::from_value(json!({
        "panel_url": format!("ws://{}/ws/agent", panel.local_addr().unwrap()),
        "token": "token",
        "cache_dir": fixture.directory.path(),
        "report_interval_secs": 10,
    }))
    .unwrap();
    let shutdown = CancellationToken::new();
    let _guard = shutdown.clone().drop_guard();
    let agent = tokio::spawn(run(config, shutdown.clone()));
    let (_client, mut remote) = live_connection(&fixture).await;
    if during_drain {
        shutdown.cancel();
        wait_for_listener_close(fixture.listen).await;
        assert!(
            !agent.is_finished(),
            "the live connection must still be draining"
        );
    }
    std::fs::create_dir(fixture.directory.path().join("node-traffic.json.tmp")).unwrap();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::time::resume();
    let result = tokio::time::timeout(WAIT, agent)
        .await
        .expect("accounting failure must not wait for the 30-second drain")
        .unwrap();
    assert!(matches!(result, Err(AgentError::AccountingStorage(_))));
    assert_eq!(
        tokio::time::timeout(WAIT, remote.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0,
        "accounting failure must close the live target connection"
    );
}

#[tokio::test]
async fn sampler_failure_closes_live_server_without_a_drain_period() {
    assert_sampler_failure(false).await;
}

#[tokio::test]
async fn sampler_failure_interrupts_an_existing_graceful_drain() {
    assert_sampler_failure(true).await;
}

#[tokio::test]
async fn accounting_protocol_error_closes_live_server_without_a_drain_period() {
    let fixture = fixture().await;
    let panel = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = serde_json::from_value(json!({
        "panel_url": format!("ws://{}/ws/agent", panel.local_addr().unwrap()),
        "token": "token",
        "cache_dir": fixture.directory.path(),
    }))
    .unwrap();
    let shutdown = CancellationToken::new();
    let _guard = shutdown.clone().drop_guard();
    let agent = tokio::spawn(run(config, shutdown));
    let (tcp, _) = tokio::time::timeout(WAIT, panel.accept())
        .await
        .unwrap()
        .unwrap();
    let mut ws = tokio_tungstenite::accept_hdr_async(tcp, super::tests::accept_node_traffic)
        .await
        .unwrap();
    let Message::Binary(bytes) = ws.next().await.unwrap().unwrap() else {
        panic!("expected registration")
    };
    assert!(matches!(
        bincode::deserialize::<AgentMessage>(&bytes).unwrap(),
        AgentMessage::Register { .. }
    ));
    ws.send(Message::Binary(
        bincode::serialize(&PanelMessage::Registered {
            node_id: "server".into(),
            node_type: crate::protocol::NodeType::Server,
            config_version: 1,
            report_interval_secs: 60,
            config: serde_json::to_vec(&fixture.config.config).unwrap(),
        })
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();
    let (_client, mut remote) = live_connection(&fixture).await;
    ws.send(Message::Binary(
        bincode::serialize(&PanelMessage::NodeTrafficAck {
            stream_id: "another-stream".into(),
            sequence: 1,
        })
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();
    let result = tokio::time::timeout(WAIT, agent)
        .await
        .expect("accounting protocol failure must not wait for the 30-second drain")
        .unwrap();
    assert!(matches!(result, Err(AgentError::Accounting(_))));
    assert_eq!(
        tokio::time::timeout(WAIT, remote.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0,
        "accounting protocol failure must close the live target connection"
    );
}
