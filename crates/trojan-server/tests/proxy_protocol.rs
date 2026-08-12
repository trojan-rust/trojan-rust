//! The exit server's side of the chain header.
//!
//! Covers what a relay chain in front of the server changes: the client it
//! attributes a connection to, and therefore what its rate limiter counts.
//! Without the header every connection through a chain shares the last hop's
//! address, which reads as one very busy client.

#![expect(
    clippy::tests_outside_test_module,
    reason = "integration tests are their own crate, where every #[test] is \
              necessarily a free item; the lint targets unit tests that \
              escaped a #[cfg(test)] mod"
)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use bytes::BytesMut;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use trojan_auth::{
    AuthBackend, AuthError, AuthMetadata, AuthResult, MemoryAuth, NodeQuota, sha224_hex,
};
use trojan_config::{
    AuthConfig, Config, LoggingConfig, MetricsConfig, ProxyProtocolConfig, RateLimitConfig,
    ServerConfig, TcpConfig, TlsConfig, TlsVersion, WebSocketConfig,
};
use trojan_core::proxy_protocol::{ChainInfo, ProxyHeader};
use trojan_proto::{AddressRef, CMD_CONNECT, HostRef, write_request_header};

#[ctor::ctor]
fn init_crypto() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install aws-lc-rs crypto provider");
}

const PASSWORD: &str = "proxy-protocol-test-password";

/// Echoes whatever it receives, so a relayed round trip is observable.
fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 || stream.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

struct TestServer {
    addr: SocketAddr,
    connector: TlsConnector,
    _temp_dir: tempfile::TempDir,
}

/// What a test varies about the server it starts.
struct Options<A> {
    /// Per-client connection limit, or none.
    rate_limit: Option<RateLimitConfig>,
    /// The backend that answers `verify`.
    auth: A,
    /// Where refused connections are sent, so a test can tell "served" from
    /// "turned away" by who answered.
    fallback: SocketAddr,
}

impl Options<MemoryAuth> {
    /// The plain setup: one known password, an echo as the fallback.
    fn new(rate_limit: Option<RateLimitConfig>) -> Self {
        Self {
            rate_limit,
            auth: MemoryAuth::from_passwords(&[PASSWORD.to_string()]),
            fallback: spawn_echo(),
        }
    }
}

impl TestServer {
    /// Start a server that trusts loopback senders.
    async fn start<A: AuthBackend + 'static>(options: Options<A>) -> Self {
        let Options {
            rate_limit,
            auth,
            fallback,
        } = options;
        use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![rcgen::SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        ))];
        let cert = params.self_signed(&key_pair).unwrap();
        let (cert_pem, key_pem) = (cert.pem(), key_pair.serialize_pem());

        let temp_dir = tempfile::Builder::new()
            .prefix("trojan-proxy-protocol-")
            .tempdir()
            .unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();

        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap()
            .to_vec();
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(cert_der)).unwrap();
        let connector = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let config = Config {
            server: ServerConfig {
                listen: addr.to_string(),
                fallback: fallback.to_string(),
                tcp_idle_timeout_secs: 30,
                udp_timeout_secs: 30,
                max_udp_payload: 8192,
                max_udp_buffer_bytes: 65536,
                max_header_bytes: 8192,
                max_connections: None,
                rate_limit,
                fallback_pool: None,
                resource_limits: None,
                tcp: TcpConfig::default(),
                outbounds: Default::default(),
                rule_providers: Default::default(),
                rules: Default::default(),
                geoip: None,
                proxy_protocol: toml::from_str::<ProxyProtocolConfig>(r#"trusted = ["127.0.0.1"]"#)
                    .unwrap(),
            },
            tls: TlsConfig {
                cert: cert_path.to_string_lossy().to_string(),
                key: key_path.to_string_lossy().to_string(),
                alpn: vec![],
                min_version: TlsVersion::Tls12,
                max_version: TlsVersion::Tls13,
                client_ca: None,
                cipher_suites: vec![],
            },
            auth: AuthConfig {
                passwords: vec![PASSWORD.to_string()],
                users: vec![],
                ..Default::default()
            },
            websocket: WebSocketConfig::default(),
            metrics: MetricsConfig {
                listen: None,
                ..Default::default()
            },
            analytics: Default::default(),
            logging: LoggingConfig {
                level: Some("warn".to_string()),
                ..Default::default()
            },
            dns: Default::default(),
            ddns: Default::default(),
        };

        tokio::spawn(async move {
            if let Err(e) = trojan_server::run(config, auth).await {
                eprintln!("server exited: {e}");
            }
        });

        // The probe below opens a real connection, which counts against the
        // limiter like any other from this address — tests that exercise a
        // direct client therefore run without a limit.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(50)) {
                Ok(probe) => {
                    drop(probe);
                    break;
                }
                Err(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => panic!("server never listened on {addr}: {e}"),
            }
        }

        Self {
            addr,
            connector,
            _temp_dir: temp_dir,
        }
    }

    /// Relay one payload to `target`, optionally introducing the connection
    /// with a PROXY header first. Returns what came back.
    async fn round_trip(
        &self,
        header: Option<ProxyHeader>,
        target: SocketAddr,
        payload: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        let mut tcp = TcpStream::connect(self.addr).await?;

        if let Some(header) = header {
            // Written on its own, as a relay would: the server has to read the
            // header before the ClientHello it precedes.
            tcp.write_all(&header.encode().unwrap()).await?;
            tcp.flush().await?;
        }

        let name = ServerName::try_from("127.0.0.1").unwrap();
        let mut tls = self.connector.connect(name, tcp).await?;

        let mut request = connect_header(&sha224_hex(PASSWORD), target);
        request.extend_from_slice(payload);
        tls.write_all(&request).await?;
        tls.flush().await?;

        let mut buf = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(3), tls.read_exact(&mut buf))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "no reply"))??;
        Ok(buf)
    }
}

fn connect_header(hash: &str, target: SocketAddr) -> BytesMut {
    let std::net::IpAddr::V4(ip) = target.ip() else {
        panic!("test targets are IPv4");
    };
    let address = AddressRef {
        host: HostRef::Ipv4(ip.octets()),
        port: target.port(),
    };
    let mut header = BytesMut::new();
    write_request_header(&mut header, hash.as_bytes(), CMD_CONNECT, &address).unwrap();
    header
}

/// One connection per client address, so a second from the same one is
/// rejected — which is what makes the attribution observable.
fn one_per_client() -> RateLimitConfig {
    RateLimitConfig {
        max_connections_per_ip: 1,
        window_secs: 60,
        cleanup_interval_secs: 60,
    }
}

fn header_from(client: &str) -> ProxyHeader {
    ProxyHeader::new(client.parse().unwrap(), "127.0.0.1:443".parse().unwrap())
        .with_chain(ChainInfo::new(vec!["entry-1".into(), "relay-2".into()]))
}

/// Two clients behind one relay are two clients, not one very busy one.
///
/// Both connections arrive from 127.0.0.1, and the limiter allows a single
/// connection per address — so the second only survives if the server counted
/// the client the header named instead of the hop it came from.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clients_behind_a_trusted_proxy_are_counted_separately() {
    let echo = spawn_echo();
    let server = TestServer::start(Options::new(Some(one_per_client()))).await;

    let first = server
        .round_trip(Some(header_from("203.0.113.1:40001")), echo, b"first")
        .await
        .expect("first proxied client rejected");
    assert_eq!(first, b"first");

    let second = server
        .round_trip(Some(header_from("203.0.113.2:40002")), echo, b"second")
        .await
        .expect("second proxied client rejected — limiter counted the relay");
    assert_eq!(second, b"second");
}

/// The limit still applies, just to the address that earned it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeat_client_behind_the_proxy_still_hits_the_limit() {
    let echo = spawn_echo();
    let server = TestServer::start(Options::new(Some(one_per_client()))).await;

    let first = server
        .round_trip(Some(header_from("198.51.100.9:40001")), echo, b"first")
        .await
        .expect("first proxied client rejected");
    assert_eq!(first, b"first");

    let repeat = server
        .round_trip(Some(header_from("198.51.100.9:40002")), echo, b"repeat")
        .await;

    assert!(
        repeat.is_err(),
        "the same client twice should hit the per-IP limit, got {repeat:?}"
    );
}

/// Trust is permission to be believed, not a requirement to speak: a direct
/// client from a trusted address still works, and its ClientHello — read while
/// checking for a header — must be replayed intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_trusted_sender_without_a_header_is_served_normally() {
    let echo = spawn_echo();
    let server = TestServer::start(Options::new(None)).await;

    let reply = server
        .round_trip(None, echo, b"direct")
        .await
        .expect("direct client rejected");

    assert_eq!(reply, b"direct");
}

// ── Per-node allowances ──

/// A backend that knows one user and caps them on one node.
///
/// Stands in for the panel: only a panel-backed backend ever publishes
/// allowances, and what the exit does with them is what these tests are about.
#[derive(Debug)]
struct CappedAuth {
    inner: MemoryAuth,
    quota: NodeQuota,
}

impl CappedAuth {
    fn new(node_id: &str, limit: u64, used: u64) -> Self {
        let mut inner = MemoryAuth::new();
        inner.add_password(PASSWORD, Some("u-1".to_string()));
        Self {
            inner,
            quota: NodeQuota {
                node_id: node_id.to_owned(),
                limit,
                used,
            },
        }
    }
}

#[async_trait::async_trait]
impl AuthBackend for CappedAuth {
    async fn verify(&self, hash: &str) -> Result<AuthResult, AuthError> {
        let result = self.inner.verify(hash).await?;
        Ok(AuthResult {
            metadata: Some(AuthMetadata {
                node_quotas: vec![self.quota.clone()],
                ..AuthMetadata::new()
            }),
            ..result
        })
    }
}

/// Replies with a marker instead of echoing, so a test can tell which side
/// answered: the target, or the fallback a refused connection is sent to.
fn spawn_marker(marker: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                if stream.read(&mut buf).is_ok() {
                    let _ = stream.write_all(marker);
                }
            });
        }
    });
    addr
}

/// A connection through a hop whose allowance is spent is turned away — and
/// turned away the same way an unauthenticated one is, so a prober learns
/// nothing from the difference.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chain_through_a_spent_hop_is_refused() {
    let echo = spawn_echo();
    let server = TestServer::start(Options {
        rate_limit: None,
        auth: CappedAuth::new("entry-1", 1024, 1024),
        fallback: spawn_marker(b"FALLBACK"),
    })
    .await;

    let reply = server
        .round_trip(Some(header_from("203.0.113.1:40001")), echo, b"blocked!")
        .await
        .expect("the connection should be served, just not by the target");

    assert_eq!(
        reply, b"FALLBACK",
        "a spent allowance must send the connection to the fallback"
    );
}

/// The same user on the same node, under the limit, is served normally.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chain_within_its_allowance_is_served() {
    let echo = spawn_echo();
    let server = TestServer::start(Options {
        rate_limit: None,
        auth: CappedAuth::new("entry-1", 1024, 512),
        fallback: spawn_marker(b"FALLBACK"),
    })
    .await;

    let reply = server
        .round_trip(Some(header_from("203.0.113.2:40002")), echo, b"allowed!")
        .await
        .expect("an allowance with room left must not block");

    assert_eq!(reply, b"allowed!");
}

/// A direct connection crosses no hops, so a spent allowance on one cannot
/// touch it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_direct_connection_ignores_hop_allowances() {
    let echo = spawn_echo();
    let server = TestServer::start(Options {
        rate_limit: None,
        auth: CappedAuth::new("entry-1", 1024, 1024),
        fallback: spawn_marker(b"FALLBACK"),
    })
    .await;

    let reply = server
        .round_trip(None, echo, b"direct!!")
        .await
        .expect("a direct client should be unaffected");

    assert_eq!(reply, b"direct!!");
}
