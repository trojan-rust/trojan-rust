//! Service shutdown must close open tunnels before callers checkpoint node traffic.

#![expect(
    clippy::tests_outside_test_module,
    reason = "integration tests are independent test crates"
)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Once;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use trojan_metrics::NodeStats;
use trojan_relay::config::{
    ChainConfig, EntryConfig, RelayAuthConfig, RelayListenerConfig, RelayNodeConfig, RuleConfig,
    TransportType,
};
use trojan_relay::handshake::{self, HandshakeMetadata};

const DEADLINE: Duration = Duration::from_secs(3);

#[derive(Clone, Copy)]
enum Role {
    Entry,
    Relay,
}

enum Stop {
    Cancel,
    Abort,
}

fn init_crypto() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

async fn available_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

fn entry_config(listen: SocketAddr, target: SocketAddr) -> EntryConfig {
    EntryConfig {
        node_id: None,
        chains: HashMap::from([("direct".into(), ChainConfig { nodes: vec![] })]),
        rules: vec![RuleConfig {
            name: "shutdown".into(),
            listen,
            chain: "direct".into(),
            dest: vec![target.to_string()],
            routes: vec![],
            strategy: Default::default(),
            failover_cooldown_secs: 30,
            proxy_protocol: false,
        }],
        timeouts: Default::default(),
        dns: Default::default(),
        metrics: Default::default(),
    }
}

fn relay_config(listen: SocketAddr) -> RelayNodeConfig {
    RelayNodeConfig {
        relay: RelayListenerConfig {
            listen,
            transport: TransportType::Plain,
            tls: None,
            auth: RelayAuthConfig {
                password: "shutdown-test".into(),
            },
            outbound: Default::default(),
            timeouts: Default::default(),
            dns: Default::default(),
        },
        metrics: Default::default(),
    }
}

async fn connect_when_ready(addr: SocketAddr) -> TcpStream {
    tokio::time::timeout(DEADLINE, async {
        loop {
            match TcpStream::connect(addr).await {
                Ok(client) => return client,
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => panic!("cannot connect to service: {error}"),
            }
        }
    })
    .await
    .expect("service did not start")
}

async fn open_tunnel_shutdown(role: Role, stop: Stop) {
    init_crypto();
    tokio::time::timeout(DEADLINE, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = listener.local_addr().unwrap();
        let listen = available_addr().await;
        let stats = NodeStats::new();
        let shutdown = CancellationToken::new();
        let task_stats = stats.clone();
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            match role {
                Role::Entry => {
                    trojan_relay::entry::run_with_stats(
                        entry_config(listen, target_addr),
                        task_stats,
                        task_shutdown,
                    )
                    .await
                }
                Role::Relay => {
                    trojan_relay::relay::run_with_stats(
                        relay_config(listen),
                        task_stats,
                        task_shutdown,
                    )
                    .await
                }
            }
        });
        let mut client = connect_when_ready(listen).await;
        if matches!(role, Role::Relay) {
            handshake::write_handshake(
                &mut client,
                "shutdown-test",
                &target_addr.to_string(),
                &HandshakeMetadata {
                    transport: Some(TransportType::Plain),
                    sni: None,
                    ack: true,
                },
            )
            .await
            .unwrap();
            let mut response = [0; 4];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"TR\x01\x00");
        }
        let (mut target, _) = listener.accept().await.unwrap();
        client.write_all(b"upload").await.unwrap();
        let mut upload = [0; 6];
        target.read_exact(&mut upload).await.unwrap();
        assert_eq!(&upload, b"upload");
        target.write_all(b"download").await.unwrap();
        let mut download = [0; 8];
        client.read_exact(&mut download).await.unwrap();
        assert_eq!(&download, b"download");
        assert_eq!(stats.snapshot().connections_active, 1);

        match stop {
            Stop::Cancel => {
                shutdown.cancel();
                task.await.unwrap().unwrap();
                assert_eq!(stats.snapshot().connections_active, 0);
            }
            Stop::Abort => {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
                while stats.snapshot().connections_active != 0 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        }

        let settled = stats.snapshot();
        assert_eq!(settled.bytes_in, 6);
        assert_eq!(settled.bytes_out, 8);
        assert_eq!(settled.connections_total, 1);
        let mut byte = [0; 1];
        assert_eq!(client.read(&mut byte).await.unwrap(), 0);
        assert_eq!(target.read(&mut byte).await.unwrap(), 0);
        assert_eq!(stats.snapshot(), settled);
        let _rebound = TcpListener::bind(listen).await.unwrap();
    })
    .await
    .expect("service left a live listener or tunnel after shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entry_shutdown_joins_open_tunnels() {
    open_tunnel_shutdown(Role::Entry, Stop::Cancel).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_shutdown_joins_open_tunnels() {
    open_tunnel_shutdown(Role::Relay, Stop::Cancel).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aborting_entry_cancels_owned_tunnels() {
    open_tunnel_shutdown(Role::Entry, Stop::Abort).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aborting_relay_cancels_owned_tunnels() {
    open_tunnel_shutdown(Role::Relay, Stop::Abort).await;
}

#[tokio::test]
async fn entry_bind_failure_releases_previously_bound_listeners() {
    init_crypto();
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let available = available_addr().await;
    let stats = NodeStats::new();
    let mut config = entry_config(available, occupied.local_addr().unwrap());
    let mut second = config.rules[0].clone();
    second.name = "occupied".into();
    second.listen = occupied.local_addr().unwrap();
    config.rules.push(second);

    let result =
        trojan_relay::entry::run_with_stats(config, stats.clone(), CancellationToken::new()).await;
    let trojan_relay::error::RelayError::Io(error) = result.unwrap_err() else {
        panic!("expected a listener bind error");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
    let _rebound = TcpListener::bind(available).await.unwrap();
    assert_eq!(stats.snapshot().connections_total, 0);
}
