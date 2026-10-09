//! End-to-end tests for the Prometheus metrics endpoint.
//!
//! Lives in its own test binary on purpose: the metrics recorder is installed
//! globally and only once per process, so a server started here must be the
//! first to install it. Sharing a process with the main integration tests
//! would make what `/metrics` reports depend on test ordering.
#![expect(
    clippy::tests_outside_test_module,
    reason = "integration tests are their own crate, where every #[test] is \
              necessarily a free item; the lint targets unit tests that \
              escaped a #[cfg(test)] mod"
)]

use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    sync::Arc,
    thread,
    time::Duration,
};

use bytes::BytesMut;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio_rustls::TlsConnector;
use trojan_auth::{MemoryAuth, sha224_hex};
use trojan_config::{
    AuthConfig, Config, LoggingConfig, MetricsConfig, ServerConfig, TcpConfig, TlsConfig,
    TlsVersion, WebSocketConfig,
};
use trojan_proto::{AddressRef, CMD_CONNECT, HostRef, write_request_header};
use trojan_server::{CancellationToken, run_with_shutdown};

const PASSWORD: &str = "test_password_123";

/// Install the aws-lc-rs crypto provider once at process startup, for the same
/// reason as the main integration tests: with the `rules` feature, `reqwest`
/// pulls in `ring` alongside it and rustls cannot pick on its own.
#[ctor::ctor]
fn init_crypto() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install aws-lc-rs crypto provider");
}

fn generate_test_certs() -> (String, String) {
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".try_into().unwrap()),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
    ];
    let cert = params.self_signed(&key_pair).unwrap();
    (cert.pem(), key_pair.serialize_pem())
}

fn metrics_identity(
    config: &Config,
    directory: &std::path::Path,
) -> (trojan_core::metrics::MetricsTlsConfig, TlsConnector) {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
    };
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    let client_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client = params.signed_by(&client_key, &ca).unwrap();
    let ca_path = directory.join("metrics-clients-ca.crt");
    fs::write(&ca_path, ca.pem()).unwrap();
    let mut roots = RootCertStore::empty();
    for cert in trojan_core::tls::load_certs(&config.tls.cert).unwrap() {
        roots.add(cert).unwrap();
    }
    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![client.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(client_key.serialize_der()).into(),
            )
            .unwrap(),
    ));
    (
        trojan_core::metrics::MetricsTlsConfig {
            cert: config.tls.cert.clone(),
            key: config.tls.key.clone(),
            client_ca: ca_path.to_string_lossy().into_owned(),
        },
        connector,
    )
}

/// TCP server that echoes whatever it receives.
struct MockEchoServer {
    addr: SocketAddr,
    _handle: thread::JoinHandle<()>,
}

impl MockEchoServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
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
        Self {
            addr,
            _handle: handle,
        }
    }
}

struct TestServer {
    addr: SocketAddr,
    config: Config,
    tls_connector: TlsConnector,
    shutdown: CancellationToken,
    handle: tokio::task::JoinHandle<Result<(), trojan_server::ServerError>>,
    _temp_dir: tempfile::TempDir,
}

impl TestServer {
    /// `metrics_listen` is `Some` only for the server that should own the
    /// exporter; later servers still record into the same global registry.
    async fn start(metrics_listen: Option<SocketAddr>, per_target: bool) -> Self {
        let (cert_pem, key_pem) = generate_test_certs();
        let temp_dir = tempfile::Builder::new()
            .prefix("trojan-metrics-test-")
            .tempdir()
            .unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");
        fs::write(&cert_path, &cert_pem).unwrap();
        fs::write(&key_path, &key_pem).unwrap();

        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap()
            .to_vec();
        let mut root_store = RootCertStore::empty();
        root_store.add(CertificateDer::from(cert_der)).unwrap();
        let tls_connector = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        ));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        // Unused by these tests, but the server requires a fallback target.
        let fallback = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fallback_addr = fallback.local_addr().unwrap();
        drop(fallback);

        let config = Config {
            server: ServerConfig {
                listen: addr.to_string(),
                fallback: fallback_addr.to_string(),
                tcp_idle_timeout_secs: 30,
                udp_timeout_secs: 30,
                max_udp_payload: 8192,
                max_udp_buffer_bytes: 65536,
                max_header_bytes: 8192,
                max_connections: None,
                rate_limit: None,
                fallback_pool: None,
                resource_limits: None,
                tcp: TcpConfig::default(),
                outbounds: Default::default(),
                rule_providers: Default::default(),
                rules: Default::default(),
                geoip: None,
                proxy_protocol: Default::default(),
            },
            tls: TlsConfig {
                cert: cert_path.to_string_lossy().into_owned(),
                key: key_path.to_string_lossy().into_owned(),
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
                listen: metrics_listen.map(|a| a.to_string()),
                tls: None,
                geoip: None,
                per_target,
            },
            analytics: Default::default(),
            logging: LoggingConfig {
                level: Some("warn".to_string()),
                ..Default::default()
            },
            dns: Default::default(),
            ddns: Default::default(),
        };

        let auth = MemoryAuth::from_passwords(&config.auth.passwords);
        let shutdown = CancellationToken::new();
        let token = shutdown.clone();
        let handle = tokio::spawn(run_with_shutdown(config.clone(), auth, token));
        tokio::time::sleep(Duration::from_millis(500)).await;

        Self {
            addr,
            config,
            tls_connector,
            shutdown,
            handle,
            _temp_dir: temp_dir,
        }
    }

    async fn stop(&mut self) {
        self.shutdown.cancel();
        (&mut self.handle).await.unwrap().unwrap();
    }

    /// Relay a payload through to `target`, so the byte counters move.
    async fn relay(&self, target: SocketAddr) {
        let tcp = tokio::net::TcpStream::connect(self.addr).await.unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        let mut tls = self.tls_connector.connect(name, tcp).await.unwrap();

        let ip = match target.ip() {
            std::net::IpAddr::V4(v4) => v4,
            other => panic!("expected IPv4 target, got {other}"),
        };
        let address = AddressRef {
            host: HostRef::Ipv4(ip.octets()),
            port: target.port(),
        };
        let mut header = BytesMut::new();
        write_request_header(
            &mut header,
            sha224_hex(PASSWORD).as_bytes(),
            CMD_CONNECT,
            &address,
        )
        .unwrap();
        let payload = b"metrics-probe-payload";
        header.extend_from_slice(payload);

        tls.write_all(&header).await.unwrap();
        tls.flush().await.unwrap();

        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(10), tls.read_exact(&mut echoed))
            .await
            .expect("relay timeout")
            .unwrap();
        assert_eq!(&echoed[..], payload);
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Minimal HTTP/1.1 GET, returning (status line, body).
async fn http_get(addr: SocketAddr, path: &str) -> (String, String) {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    http_get_stream(stream, path).await
}

async fn http_get_stream(
    mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    path: &str,
) -> (String, String) {
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();

    tokio::time::timeout(Duration::from_secs(10), async {
        let mut reader = BufReader::new(stream);
        let mut head = String::new();
        while !head.ends_with("\r\n\r\n") {
            assert!(reader.read_line(&mut head).await.unwrap() > 0);
        }
        let length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap();
        let mut body = vec![0; length];
        reader.read_exact(&mut body).await.unwrap();
        (
            head.lines().next().unwrap().to_string(),
            String::from_utf8(body).unwrap(),
        )
    })
    .await
    .unwrap_or_else(|_| panic!("timed out reading {path}"))
}

async fn free_addr() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

/// The exporter serves its three endpoints, and `metrics.per_target` decides
/// whether destination-labelled byte and connection counters exist.
///
/// Both phases run in one test, in order, because the recorder is global: the
/// absence assertion is only meaningful before any server that emits the
/// metric has run.
#[tokio::test]
async fn metrics_endpoint_reports_traffic_and_honours_per_target() {
    let echo = MockEchoServer::start();
    let metrics_addr = free_addr().await;

    // ── Phase 1: per_target off ──
    let mut server = TestServer::start(Some(metrics_addr), false).await;
    server.relay(echo.addr).await;

    let (status, _) = http_get(metrics_addr, "/health").await;
    assert!(status.contains("200"), "/health returned {status:?}");

    let (status, body) = http_get(metrics_addr, "/ready").await;
    assert!(status.contains("200"), "/ready returned {status:?}");
    assert!(body.contains("READY"), "/ready body was {body:?}");

    let (status, body) = http_get(metrics_addr, "/metrics").await;
    assert!(status.contains("200"), "/metrics returned {status:?}");

    // Traffic actually reached the counters.
    for metric in [
        "trojan_connections_total",
        "trojan_bytes_received_total",
        "trojan_bytes_sent_total",
        "trojan_auth_success_total",
    ] {
        assert!(body.contains(metric), "/metrics is missing {metric}");
    }

    assert!(
        !body.contains("trojan_target_bytes_total"),
        "per_target = false must not emit the destination-labelled byte counter"
    );
    assert!(
        !body.contains("trojan_target_connections_total{"),
        "per_target = false must not emit destination-labelled connection series"
    );

    // ── Phase 2: per_target on ──
    // No exporter of its own — the recorder is already installed globally, so
    // this server's counters land in the same registry.
    let mut per_target_server = TestServer::start(None, true).await;
    per_target_server.relay(echo.addr).await;

    let (_, body) = http_get(metrics_addr, "/metrics").await;
    assert!(
        body.contains("trojan_target_bytes_total"),
        "per_target = true must emit the destination-labelled byte counter"
    );
    assert!(body.contains("trojan_target_connections_total{target=\"127.0.0.1\"} 1"));
    assert!(
        body.contains("direction=\"sent\""),
        "expected a direction label on the per-target counter, got:\n{body}"
    );

    let mut config = server.config.clone();
    config.server.listen = "127.0.0.1:0".into();
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        run_with_shutdown(
            config.clone(),
            MemoryAuth::from_passwords(&config.auth.passwords),
            CancellationToken::new(),
        ),
    )
    .await
    .expect("invalid startup must fail promptly")
    .unwrap_err();
    assert!(matches!(error, trojan_server::ServerError::Metrics(_)));

    let available_metrics = free_addr().await;
    config.metrics.listen = Some(available_metrics.to_string());
    config.server.listen = server.addr.to_string();
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        run_with_shutdown(
            config.clone(),
            MemoryAuth::from_passwords(&config.auth.passwords),
            CancellationToken::new(),
        ),
    )
    .await
    .expect("invalid startup must fail promptly")
    .unwrap_err();
    assert!(matches!(error, trojan_server::ServerError::Io(_)));
    let _rebound_after_failure = tokio::net::TcpListener::bind(available_metrics)
        .await
        .unwrap();

    config.server.listen = "127.0.0.1:0".into();
    config.metrics.listen = Some("127.0.0.1:0".into());
    config.metrics.tls = Some(trojan_core::metrics::MetricsTlsConfig {
        cert: "/nonexistent/server.crt".into(),
        key: "/nonexistent/server.key".into(),
        client_ca: "/nonexistent/clients-ca.crt".into(),
    });
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        run_with_shutdown(
            config.clone(),
            MemoryAuth::from_passwords(&config.auth.passwords),
            CancellationToken::new(),
        ),
    )
    .await
    .expect("invalid startup must fail promptly")
    .unwrap_err();
    assert!(matches!(error, trojan_server::ServerError::Metrics(_)));

    let mut old_connection = tokio::net::TcpStream::connect(metrics_addr).await.unwrap();
    old_connection
        .write_all(b"GET /ready HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    while !response.ends_with(b"READY") {
        let mut buffer = [0; 512];
        let count = old_connection.read(&mut buffer).await.unwrap();
        assert!(count > 0);
        response.extend_from_slice(&buffer[..count]);
    }
    assert!(response.starts_with(b"HTTP/1.1 200"));
    per_target_server.stop().await;
    server.stop().await;
    let rebound = tokio::net::TcpListener::bind(metrics_addr).await.unwrap();
    assert_eq!(old_connection.read(&mut [0; 1]).await.unwrap(), 0);
    drop(rebound);

    let (tls, connector) = metrics_identity(&server.config, server._temp_dir.path());
    server.config.metrics.tls = Some(tls);
    server.shutdown = CancellationToken::new();
    server.handle = tokio::spawn(run_with_shutdown(
        server.config.clone(),
        MemoryAuth::from_passwords(&server.config.auth.passwords),
        server.shutdown.clone(),
    ));
    let stream = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match tokio::net::TcpStream::connect(metrics_addr).await {
                Ok(stream) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    tokio::task::yield_now().await
                }
                Err(error) => panic!("cannot connect to metrics: {error}"),
            }
        }
    })
    .await
    .unwrap();
    let stream = connector
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .unwrap();
    let (status, body) = http_get_stream(stream, "/metrics").await;
    assert!(status.contains("200"));
    assert!(body.contains("trojan_bytes_received_total"));
    server.relay(echo.addr).await;
    server.stop().await;
}
