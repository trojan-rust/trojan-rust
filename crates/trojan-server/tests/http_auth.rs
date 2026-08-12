//! End-to-end tests for the HTTP authentication backend.
//!
//! `HttpAuth` delegates verification to a remote dashboard, and is the path
//! this project's own `trojan-dash` exists to serve, yet nothing exercised it
//! end to end: the server tests all use `MemoryAuth`. These drive a real
//! server whose auth backend talks to a stand-in dashboard over HTTP, so the
//! wire format, the caching layer, and the traffic-reporting call are all
//! covered against the actual `HttpAuth` implementation.
//!
//! The other half of the contract — that `trojan-dash` answers what `HttpAuth`
//! expects — is covered by `trojan-dash`'s own `node_protocol` tests.
#![expect(
    clippy::tests_outside_test_module,
    reason = "integration tests are their own crate, where every #[test] is \
              necessarily a free item; the lint targets unit tests that \
              escaped a #[cfg(test)] mod"
)]

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use bytes::BytesMut;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use trojan_auth::{
    http::{Codec, HttpAuth, HttpAuthConfig},
    sha224_hex,
};
use trojan_config::{
    AnalyticsConfig, AuthConfig, Config, LoggingConfig, MetricsConfig, ServerConfig, TcpConfig,
    TlsConfig, WebSocketConfig,
};
use trojan_proto::{AddressRef, CMD_CONNECT, HostRef, write_request_header};
use trojan_server::{CancellationToken, run_with_shutdown};

const GOOD_PASSWORD: &str = "http-auth-good";
const BAD_PASSWORD: &str = "http-auth-unknown";

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

/// Counts of what the worker was asked to do, so a test can assert that the
/// server really called out rather than deciding locally.
#[derive(Default)]
struct WorkerCalls {
    verify: AtomicUsize,
    traffic: AtomicUsize,
}

/// A stand-in dashboard worker speaking the JSON codec.
///
/// Serde encodes the wire `Result` as `{"Ok": ...}` / `{"Err": ...}`, which is
/// what `HttpAuth` expects to decode.
struct MockAuthWorker {
    addr: SocketAddr,
    calls: Arc<WorkerCalls>,
    _handle: thread::JoinHandle<()>,
}

impl MockAuthWorker {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let calls = Arc::new(WorkerCalls::default());
        let good_hash = sha224_hex(GOOD_PASSWORD);

        let worker_calls = Arc::clone(&calls);
        let handle = thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let calls = Arc::clone(&worker_calls);
                let good_hash = good_hash.clone();
                thread::spawn(move || {
                    let _ = Self::serve(stream, &calls, &good_hash);
                });
            }
        });

        Self {
            addr,
            calls,
            _handle: handle,
        }
    }

    fn serve(
        mut stream: std::net::TcpStream,
        calls: &WorkerCalls,
        good_hash: &str,
    ) -> std::io::Result<()> {
        let mut reader = BufReader::new(stream.try_clone()?);

        // Request line, then headers up to the blank line.
        let mut request_line = String::new();
        if reader.read_line(&mut request_line)? == 0 {
            return Ok(());
        }
        let path = request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("")
            .to_string();

        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                return Ok(());
            }
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                break;
            }
            // Header names are case-insensitive on the wire, and hyper emits
            // them lowercase — matching "Content-Length:" exactly silently
            // yields an empty body and makes every lookup miss.
            if let Some((name, value)) = trimmed.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }

        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body)?;
        let body = String::from_utf8_lossy(&body).into_owned();

        let payload = if path.ends_with("/verify") {
            calls.verify.fetch_add(1, Ordering::SeqCst);
            if body.contains(good_hash) {
                r#"{"Ok":{"user_id":"alice","metadata":{"traffic_limit":0,"traffic_used":0,"expires_at":0,"enabled":true}}}"#
                    .to_string()
            } else {
                r#"{"Err":"NotFound"}"#.to_string()
            }
        } else if path.ends_with("/traffic") {
            calls.traffic.fetch_add(1, Ordering::SeqCst);
            r#"{"Ok":null}"#.to_string()
        } else {
            String::new()
        };

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            payload.len(),
            payload
        );
        stream.write_all(response.as_bytes())?;
        stream.flush()?;
        Ok(())
    }
}

struct TestServer {
    addr: SocketAddr,
    tls_connector: TlsConnector,
    shutdown: CancellationToken,
    _handle: tokio::task::JoinHandle<()>,
    _temp_dir: tempfile::TempDir,
}

impl TestServer {
    async fn start(worker_addr: SocketAddr) -> Self {
        let (cert_pem, key_pem) = generate_test_certs();
        let temp_dir = tempfile::Builder::new()
            .prefix("trojan-http-auth-")
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
                min_version: "tls12".to_string(),
                max_version: "tls13".to_string(),
                client_ca: None,
                cipher_suites: vec![],
            },
            // Local passwords are deliberately empty: every decision here has
            // to come from the worker.
            auth: AuthConfig::default(),
            websocket: WebSocketConfig::default(),
            metrics: MetricsConfig {
                listen: None,
                ..Default::default()
            },
            analytics: AnalyticsConfig::default(),
            logging: LoggingConfig {
                level: Some("warn".to_string()),
                ..Default::default()
            },
            dns: Default::default(),
            ddns: Default::default(),
        };

        let auth = HttpAuth::new(HttpAuthConfig {
            base_url: format!("http://{worker_addr}"),
            codec: Codec::Json,
            node_token: Some("test-node-token".to_string()),
            // Short flush so the traffic report lands within the test.
            batch_flush_interval: Duration::from_millis(200),
            ..Default::default()
        });

        let shutdown = CancellationToken::new();
        let token = shutdown.clone();
        let handle = tokio::spawn(async move {
            let _ = run_with_shutdown(config, auth, token).await;
        });
        tokio::time::sleep(Duration::from_millis(500)).await;

        Self {
            addr,
            tls_connector,
            shutdown,
            _handle: handle,
            _temp_dir: temp_dir,
        }
    }

    async fn connect(&self) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
        let tcp = tokio::net::TcpStream::connect(self.addr).await.unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        self.tls_connector.connect(name, tcp).await.unwrap()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

fn connect_header(password: &str, target: SocketAddr) -> BytesMut {
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
        sha224_hex(password).as_bytes(),
        CMD_CONNECT,
        &address,
    )
    .unwrap();
    header
}

/// A password the worker recognises is relayed; one it does not is not.
///
/// Both halves matter: without the rejection case, a backend that blindly
/// accepted everything would pass.
#[tokio::test]
async fn http_auth_admits_known_password_and_refuses_unknown() {
    let echo = MockEchoServer::start();
    let worker = MockAuthWorker::start();
    let server = TestServer::start(worker.addr).await;

    // Known password: relayed.
    let mut tls = server.connect().await;
    let payload = b"http-auth-payload";
    let mut header = connect_header(GOOD_PASSWORD, echo.addr);
    header.extend_from_slice(payload);
    tls.write_all(&header).await.unwrap();
    tls.flush().await.unwrap();

    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), tls.read_exact(&mut echoed))
        .await
        .expect("relay timeout for a password the worker accepted")
        .unwrap();
    assert_eq!(&echoed[..], payload);

    assert!(
        worker.calls.verify.load(Ordering::SeqCst) > 0,
        "the server never called the worker — it decided locally"
    );

    // Unknown password: falls back instead of relaying. The fallback target
    // is not listening, so the connection ends without echoing.
    let mut tls = server.connect().await;
    let mut header = connect_header(BAD_PASSWORD, echo.addr);
    header.extend_from_slice(payload);
    tls.write_all(&header).await.unwrap();
    tls.flush().await.unwrap();

    let mut buf = vec![0u8; payload.len()];
    let result = tokio::time::timeout(Duration::from_secs(10), tls.read_exact(&mut buf))
        .await
        .expect("timed out on a password the worker rejected");
    assert!(
        result.is_err(),
        "a password the worker rejected must not be relayed"
    );
}

/// Traffic is accounted even when a client vanishes mid-session.
///
/// A client that disappears without a TLS close_notify — a killed app, a
/// dropped mobile link, an RST — ends the relay in error. Billing only the
/// success path let that traffic through free on a server enforcing
/// `traffic_limit`, and an aborted connection is the common case rather than
/// the exception. `RelayCounters` carries a running total so the handler can
/// settle up however the relay ended.
#[tokio::test]
async fn http_auth_reports_traffic_after_abrupt_disconnect() {
    let echo = MockEchoServer::start();
    let worker = MockAuthWorker::start();
    let server = TestServer::start(worker.addr).await;

    {
        let mut tls = server.connect().await;
        let payload = b"aborted-session-payload";
        let mut header = connect_header(GOOD_PASSWORD, echo.addr);
        header.extend_from_slice(payload);
        tls.write_all(&header).await.unwrap();
        tls.flush().await.unwrap();

        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(10), tls.read_exact(&mut echoed))
            .await
            .expect("relay timeout")
            .unwrap();

        // Dropped, not shut down: no close_notify, so the relay ends in error.
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while worker.calls.traffic.load(Ordering::SeqCst) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "bytes relayed before an abrupt disconnect were never accounted"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Relayed bytes are reported back to the worker.
///
/// Traffic is batched, so this waits for the flush interval rather than
/// expecting the call during the connection.
#[tokio::test]
async fn http_auth_reports_traffic_to_the_worker() {
    let echo = MockEchoServer::start();
    let worker = MockAuthWorker::start();
    let server = TestServer::start(worker.addr).await;

    {
        let mut tls = server.connect().await;
        let payload = b"traffic-accounting-payload";
        let mut header = connect_header(GOOD_PASSWORD, echo.addr);
        header.extend_from_slice(payload);
        tls.write_all(&header).await.unwrap();
        tls.flush().await.unwrap();

        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(10), tls.read_exact(&mut echoed))
            .await
            .expect("relay timeout")
            .unwrap();

        // Close cleanly. Dropping the stream instead would abort the TLS
        // session, and the relay's error path skips traffic accounting
        // entirely — see `handle_connect`.
        tls.shutdown().await.unwrap();
    }

    // Traffic is recorded when the connection ends, then flushed on a timer.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while worker.calls.traffic.load(Ordering::SeqCst) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the worker was never told about the relayed bytes"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
