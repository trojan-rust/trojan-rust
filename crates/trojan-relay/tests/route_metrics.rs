//! Verify exported route outcomes at real tunnel setup and cancellation boundaries.

#![expect(
    clippy::tests_outside_test_module,
    reason = "integration tests are independent test crates"
)]

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use trojan_metrics::NodeStats;
use trojan_relay::config::{ChainConfig, ChainNodeConfig, EntryConfig, RouteConfig, TransportType};
use trojan_relay::handshake;

async fn available_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

fn config(name: &str, listen: SocketAddr, destinations: Vec<String>) -> EntryConfig {
    let mut config: EntryConfig = toml::from_str(
        "[chains.direct]\nnodes = []\n[[rules]]\nname = 'test'\nlisten = '127.0.0.1:1'\nchain = 'direct'\ndest = 'unused:1'\nstrategy = 'failover'",
    ).unwrap();
    config.rules[0].name = name.into();
    config.rules[0].listen = listen;
    config.rules[0].dest = destinations;
    config
}

fn relay_chain(address: SocketAddr) -> ChainConfig {
    ChainConfig {
        nodes: vec![ChainNodeConfig {
            addr: address.to_string(),
            node_id: None,
            password: Some("secret".into()),
            transport: TransportType::Plain,
            sni: "test.local".into(),
        }],
    }
}

async fn connect_when_ready(address: SocketAddr) -> TcpStream {
    loop {
        match TcpStream::connect(address).await {
            Ok(stream) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                tokio::task::yield_now().await;
            }
            Err(error) => panic!("cannot connect to listener: {error}"),
        }
    }
}

async fn scrape(address: SocketAddr) -> String {
    let mut stream = connect_when_ready(address).await;
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut body = String::new();
    stream.read_to_string(&mut body).await.unwrap();
    assert!(body.starts_with("HTTP/1.1 200"), "{body}");
    body
}

fn assert_sample(body: &str, name: &str, labels: &[(&str, &str)], expected: u64) {
    let line = body
        .lines()
        .find(|line| {
            (line.starts_with(&format!("{name}{{")) || line.starts_with(&format!("{name} ")))
                && labels
                    .iter()
                    .all(|(key, value)| line.contains(&format!("{key}=\"{value}\"")))
        })
        .unwrap_or_else(|| panic!("missing {name} {labels:?}: {body}"));
    assert_eq!(line.rsplit_once(' ').unwrap().1, expected.to_string());
}

async fn destination_failover(metrics: SocketAddr) {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let dead = available_addr().await;
    let listen = available_addr().await;
    let config = config(
        "destination",
        listen,
        vec![dead.to_string(), target_addr.to_string()],
    );
    let shutdown = CancellationToken::new();
    let service = tokio::spawn(trojan_relay::entry::run(config, shutdown.clone()));
    let mut client = connect_when_ready(listen).await;
    let (mut connected, _) = target.accept().await.unwrap();
    client.write_all(b"payload").await.unwrap();
    let mut payload = [0; 7];
    connected.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"payload");
    shutdown.cancel();
    service.await.unwrap().unwrap();
    let body = scrape(metrics).await;
    assert_sample(
        &body,
        "trojan_route_selections_total",
        &[("rule", "destination"), ("outcome", "selected")],
        2,
    );
    assert_sample(
        &body,
        "trojan_route_setup_total",
        &[("rule", "destination"), ("outcome", "destination_error")],
        1,
    );
    assert_sample(
        &body,
        "trojan_route_setup_total",
        &[("rule", "destination"), ("outcome", "connected")],
        1,
    );
    assert_sample(
        &body,
        "trojan_route_failovers_total",
        &[("rule", "destination"), ("reason", "destination")],
        1,
    );
    assert_sample(
        &body,
        "trojan_route_setup_duration_seconds_count",
        &[("rule", "destination"), ("outcome", "connected")],
        1,
    );
}

async fn relay_failover(metrics: SocketAddr) {
    let rejected = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = target.local_addr().unwrap().to_string();
    let listen = available_addr().await;
    let mut config = config("relay", listen, vec![]);
    config
        .chains
        .insert("bad".into(), relay_chain(rejected.local_addr().unwrap()));
    config.rules[0].chain.clear();
    config.rules[0].routes = vec![
        RouteConfig {
            chain: "bad".into(),
            dest: destination.clone(),
            node_id: None,
        },
        RouteConfig {
            chain: "direct".into(),
            dest: destination,
            node_id: None,
        },
    ];
    let shutdown = CancellationToken::new();
    let service = tokio::spawn(trojan_relay::entry::run(config, shutdown.clone()));
    let mut client = connect_when_ready(listen).await;
    let (mut relay, _) = rejected.accept().await.unwrap();
    handshake::read_handshake(&mut relay).await.unwrap();
    relay.write_all(b"TR\x01\x02").await.unwrap();
    let (mut connected, _) = target.accept().await.unwrap();
    // Receiving payload proves tunnel setup has completed before shutdown.
    client.write_all(b"x").await.unwrap();
    let mut byte = [0];
    connected.read_exact(&mut byte).await.unwrap();
    shutdown.cancel();
    service.await.unwrap().unwrap();
    let body = scrape(metrics).await;
    assert_sample(
        &body,
        "trojan_route_setup_total",
        &[("rule", "relay"), ("outcome", "relay_error")],
        1,
    );
    assert_sample(
        &body,
        "trojan_route_setup_total",
        &[("rule", "relay"), ("outcome", "connected")],
        1,
    );
    assert_sample(
        &body,
        "trojan_route_failovers_total",
        &[("rule", "relay"), ("reason", "relay")],
        1,
    );
}

async fn exhausted_candidates(metrics: SocketAddr) {
    let dead = available_addr().await;
    let listen = available_addr().await;
    let config = config("exhausted", listen, vec![dead.to_string()]);
    let shutdown = CancellationToken::new();
    let service = tokio::spawn(trojan_relay::entry::run(config, shutdown.clone()));
    let mut client = connect_when_ready(listen).await;
    let mut byte = [0];
    assert_eq!(client.read(&mut byte).await.unwrap(), 0);
    shutdown.cancel();
    service.await.unwrap().unwrap();
    let body = scrape(metrics).await;
    assert_sample(
        &body,
        "trojan_route_selections_total",
        &[("rule", "exhausted"), ("outcome", "unavailable")],
        1,
    );
    assert_sample(
        &body,
        "trojan_route_failovers_total",
        &[("rule", "exhausted"), ("reason", "destination")],
        0,
    );
}

async fn cancelled_setup(metrics: SocketAddr) {
    let stalled = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = available_addr().await;
    let mut config = config("cancelled", listen, vec!["127.0.0.1:1".into()]);
    config
        .chains
        .insert("direct".into(), relay_chain(stalled.local_addr().unwrap()));
    let shutdown = CancellationToken::new();
    let stats = NodeStats::new();
    let service = tokio::spawn(trojan_relay::entry::run_with_stats(
        config,
        stats.clone(),
        shutdown,
    ));
    let _client = connect_when_ready(listen).await;
    let (mut relay, _) = stalled.accept().await.unwrap();
    handshake::read_handshake(&mut relay).await.unwrap();
    service.abort();
    assert!(service.await.unwrap_err().is_cancelled());
    while stats.snapshot().connections_active != 0 {
        tokio::task::yield_now().await;
    }
    let body = scrape(metrics).await;
    assert_sample(
        &body,
        "trojan_route_setup_total",
        &[("rule", "cancelled"), ("outcome", "cancelled")],
        1,
    );
    assert_sample(
        &body,
        "trojan_route_setup_duration_seconds_count",
        &[("rule", "cancelled"), ("outcome", "cancelled")],
        1,
    );
    assert_sample(&body, "trojan_connections_active", &[], 0);
    assert_sample(&body, "trojan_connections_total", &[], 4);
    assert_sample(&body, "trojan_connection_duration_seconds_count", &[], 4);
}

#[tokio::test]
async fn exported_metrics_follow_setup_failover_exhaustion_and_abort() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    tokio::time::timeout(Duration::from_secs(5), async {
        let metrics = available_addr().await;
        let exporter = trojan_metrics::init_metrics_server(&metrics.to_string(), None).unwrap();
        destination_failover(metrics).await;
        relay_failover(metrics).await;
        exhausted_candidates(metrics).await;
        cancelled_setup(metrics).await;
        exporter.abort();
        assert!(exporter.await.unwrap_err().is_cancelled());
    })
    .await
    .expect("route metrics scenarios did not complete");
}
