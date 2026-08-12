//! End-to-end tests for analytics event delivery.
//!
//! The analytics pipeline batches connection events and writes them to
//! ClickHouse over its HTTP interface. `analytics` is a non-default feature,
//! so none of this was built — let alone run — by `cargo test --workspace`.
//! ClickHouse's endpoint is just a URL, so a mock HTTP server standing in for
//! it exercises the whole path: sampling, the bounded channel, the batching
//! writer, and the insert itself.
#![cfg(feature = "analytics")]
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
        Arc, Mutex,
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
use trojan_auth::{MemoryAuth, sha224_hex};
use trojan_config::{
    AnalyticsBufferConfig, AnalyticsConfig, AnalyticsSamplingConfig, AuthConfig, ClickHouseConfig,
    Config, LoggingConfig, MetricsConfig, ServerConfig, TcpConfig, TlsConfig, WebSocketConfig,
};
use trojan_proto::{AddressRef, CMD_CONNECT, HostRef, write_request_header};
use trojan_server::{CancellationToken, run_with_shutdown};

const PASSWORD: &str = "analytics-test-password";

/// Set to a running ClickHouse (e.g. `http://127.0.0.1:8123`) to run the
/// tests that write real rows.
const CLICKHOUSE_URL_ENV: &str = "TROJAN_TEST_CLICKHOUSE_URL";

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

/// Stands in for ClickHouse's HTTP interface.
///
/// An insert arrives as a POST whose query string carries the statement, so
/// recording the request targets is enough to prove the writer reached the
/// configured table rather than merely opening a socket.
struct MockClickHouse {
    addr: SocketAddr,
    inserts: Arc<AtomicUsize>,
    targets: Arc<Mutex<Vec<String>>>,
    _handle: thread::JoinHandle<()>,
}

impl MockClickHouse {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let inserts = Arc::new(AtomicUsize::new(0));
        let targets = Arc::new(Mutex::new(Vec::new()));

        let counter = Arc::clone(&inserts);
        let seen = Arc::clone(&targets);
        let handle = thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let counter = Arc::clone(&counter);
                let seen = Arc::clone(&seen);
                thread::spawn(move || {
                    let _ = Self::serve(stream, &counter, &seen);
                });
            }
        });

        Self {
            addr,
            inserts,
            targets,
            _handle: handle,
        }
    }

    fn serve(
        mut stream: std::net::TcpStream,
        counter: &AtomicUsize,
        seen: &Mutex<Vec<String>>,
    ) -> std::io::Result<()> {
        let mut reader = BufReader::new(stream.try_clone()?);

        let mut request_line = String::new();
        if reader.read_line(&mut request_line)? == 0 {
            return Ok(());
        }

        let mut content_length = 0usize;
        let mut chunked = false;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                return Ok(());
            }
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap_or(0);
                } else if name.eq_ignore_ascii_case("transfer-encoding")
                    && value.to_ascii_lowercase().contains("chunked")
                {
                    chunked = true;
                }
            }
        }

        // The body is RowBinary and not worth decoding; it only has to be
        // drained so the client sees its request accepted.
        let mut body = Vec::new();
        if chunked {
            loop {
                let mut size_line = String::new();
                if reader.read_line(&mut size_line)? == 0 {
                    break;
                }
                let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
                if size == 0 {
                    let mut trailer = String::new();
                    let _ = reader.read_line(&mut trailer);
                    break;
                }
                let mut chunk = vec![0u8; size + 2]; // payload + CRLF
                reader.read_exact(&mut chunk)?;
                chunk.truncate(size);
                body.extend_from_slice(&chunk);
            }
        } else if content_length > 0 {
            body = vec![0u8; content_length];
            reader.read_exact(&mut body)?;
        }

        if request_line.starts_with("POST") {
            counter.fetch_add(1, Ordering::SeqCst);
            let target = request_line.split_whitespace().nth(1).unwrap_or("");
            // The statement travels in the body; the query string only carries
            // settings. Keep both so assertions can look at either.
            let body_text: String = String::from_utf8_lossy(&body)
                .chars()
                .filter(|c| c.is_ascii_graphic() || *c == ' ')
                .collect();
            seen.lock().unwrap().push(format!("{target} {body_text}"));
        }

        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
        stream.flush()?;
        Ok(())
    }
}

struct TestServer {
    addr: SocketAddr,
    /// Unique per instance, so concurrent runs do not read each other's rows.
    server_id: String,
    tls_connector: TlsConnector,
    shutdown: CancellationToken,
    _handle: tokio::task::JoinHandle<()>,
    _temp_dir: tempfile::TempDir,
}

impl TestServer {
    async fn start(clickhouse_addr: SocketAddr, sample_rate: f64) -> Self {
        Self::start_with_url(&format!("http://{clickhouse_addr}"), sample_rate).await
    }

    async fn start_with_url(clickhouse_url: &str, sample_rate: f64) -> Self {
        let (cert_pem, key_pem) = generate_test_certs();
        let temp_dir = tempfile::Builder::new()
            .prefix("trojan-analytics-")
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
        // Derived from the listen port, which is unique while this test runs.
        let server_id = format!("test-node-{}", addr.port());
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
            analytics: AnalyticsConfig {
                enabled: true,
                clickhouse: Some(ClickHouseConfig {
                    url: clickhouse_url.to_string(),
                    database: "trojan".to_string(),
                    table: "connections".to_string(),
                    username: None,
                    password: None,
                    connect_timeout_secs: 5,
                    write_timeout_secs: 5,
                }),
                buffer: AnalyticsBufferConfig {
                    size: 64,
                    // Flush as soon as one event lands, so the test does not
                    // depend on a timer.
                    batch_size: 1,
                    flush_interval_secs: 1,
                    fallback_path: None,
                },
                sampling: AnalyticsSamplingConfig {
                    rate: sample_rate,
                    always_record_users: vec![],
                },
                privacy: Default::default(),
                server_id: Some(server_id.clone()),
                geoip: None,
            },
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
        let handle = tokio::spawn(async move {
            let _ = run_with_shutdown(config, auth, token).await;
        });
        tokio::time::sleep(Duration::from_millis(500)).await;

        Self {
            addr,
            server_id,
            tls_connector,
            shutdown,
            _handle: handle,
            _temp_dir: temp_dir,
        }
    }

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
        let payload = b"analytics-probe";
        header.extend_from_slice(payload);

        tls.write_all(&header).await.unwrap();
        tls.flush().await.unwrap();

        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(10), tls.read_exact(&mut echoed))
            .await
            .expect("relay timeout")
            .unwrap();
        tls.shutdown().await.unwrap();
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// A relayed connection produces an analytics event that reaches ClickHouse.
///
/// Covers everything this repo owns: sampling, the bounded channel, the
/// batching writer, and the HTTP request naming the configured database and
/// table. Verified by pointing `table` elsewhere, which fails the assertion.
///
/// It stops at the first request. The `clickhouse` crate opens an insert with
/// `DESCRIBE TABLE` to learn the schema for RowBinaryWithNamesAndTypes, and
/// the mock cannot answer that in ClickHouse's binary format, so the row write
/// itself is not exercised — that needs a real server.
#[tokio::test]
async fn analytics_events_reach_clickhouse() {
    let echo = MockEchoServer::start();
    let clickhouse = MockClickHouse::start();
    let server = TestServer::start(clickhouse.addr, 1.0).await;

    server.relay(echo.addr).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while clickhouse.inserts.load(Ordering::SeqCst) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no analytics insert reached ClickHouse"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let targets = clickhouse.targets.lock().unwrap().clone();
    let joined = targets.join(" ");
    assert!(
        joined.contains("connections"),
        "insert did not name the configured table: {targets:?}"
    );
    assert!(
        joined.contains("trojan"),
        "insert did not name the configured database: {targets:?}"
    );
}

/// Sampling at 0.0 records nothing.
///
/// The counterpart to the test above: without it, a pipeline that ignored the
/// sampling rate entirely would look just as correct. Uses its own mock so the
/// two tests cannot contaminate each other's counters.
#[tokio::test]
async fn analytics_sampling_rate_zero_records_nothing() {
    let echo = MockEchoServer::start();
    let clickhouse = MockClickHouse::start();
    let server = TestServer::start(clickhouse.addr, 0.0).await;

    server.relay(echo.addr).await;

    // Comfortably longer than the one-second flush interval.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        clickhouse.inserts.load(Ordering::SeqCst),
        0,
        "events were written despite a 0.0 sampling rate"
    );
}

// ── Against a real ClickHouse ──
//
// The mock above stops at the first request: the `clickhouse` crate opens an
// insert with `DESCRIBE TABLE` to learn the schema, and answers are LZ4-framed
// with a CityHash checksum, so faking one would mean reimplementing the wire
// protocol and then testing that reimplementation. A real server is both less
// work and worth more. CI provides one as a service container; locally, set
// TROJAN_TEST_CLICKHOUSE_URL.

fn clickhouse_url() -> String {
    std::env::var(CLICKHOUSE_URL_ENV).unwrap_or_else(|_| {
        panic!(
            "{CLICKHOUSE_URL_ENV} is not set. These tests are #[ignore]d for that reason; \
             they fail rather than skip so a CI job cannot pass without a server."
        )
    })
}

/// Issue a statement over ClickHouse's HTTP interface.
async fn clickhouse_exec(url: &str, sql: &str) -> String {
    let response = reqwest::Client::new()
        .post(url)
        .body(sql.to_string())
        .send()
        .await
        .expect("clickhouse request");
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    assert!(status.is_success(), "clickhouse rejected {sql:?}: {body}");
    body
}

/// A relayed connection lands as a row in ClickHouse.
///
/// This is the half the mock cannot reach: the schema handshake, the
/// RowBinary encoding of `ConnectionEvent`, and the insert itself all run
/// against a real server.
#[tokio::test]
#[ignore = "needs a ClickHouse server; run via the analytics CI job or set TROJAN_TEST_CLICKHOUSE_URL"]
async fn analytics_rows_land_in_clickhouse() {
    // The writer reports insert failures through `tracing`; without a
    // subscriber they vanish and this test can only say "no row arrived".
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let url = clickhouse_url();
    let echo = MockEchoServer::start();

    // Isolate from other runs: a table of our own, dropped and recreated.
    clickhouse_exec(&url, "CREATE DATABASE IF NOT EXISTS trojan").await;
    clickhouse_exec(&url, "DROP TABLE IF EXISTS trojan.connections").await;
    clickhouse_exec(&url, trojan_analytics::writer::clickhouse::CREATE_TABLE_SQL).await;

    let server = TestServer::start_with_url(&url, 1.0).await;
    let server_id = server.server_id.clone();
    server.relay(echo.addr).await;

    // The writer batches; poll until the row appears.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let count = clickhouse_exec(
            &url,
            &format!("SELECT count() FROM trojan.connections WHERE server_id = '{server_id}'"),
        )
        .await;
        if count.trim() != "0" {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no analytics row reached ClickHouse"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // The row must carry the connection's own fields, not defaults.
    let row = clickhouse_exec(
        &url,
        &format!(
            "SELECT peer_ip, protocol, target_host, target_port, conn_id > 0, \
             bytes_sent > 0, bytes_recv > 0, close_reason \
             FROM trojan.connections WHERE server_id = '{server_id}' LIMIT 1 FORMAT TSV"
        ),
    )
    .await;
    let f: Vec<&str> = row.trim().split('\t').collect();

    // Proves the IpAddr-as-IPv6 mapping: loopback arrives IPv4-mapped rather
    // than as a serde enum variant, which the column would have rejected.
    assert_eq!(
        f.first().copied(),
        Some("::ffff:127.0.0.1"),
        "peer_ip did not survive as an IPv4-mapped address: {row:?}"
    );
    assert_eq!(
        f.get(1).copied(),
        Some("tcp"),
        "protocol enum did not round-trip through Enum8: {row:?}"
    );

    // The event used to ship with these at their defaults because the
    // connection handler never populated the builder.
    assert_eq!(
        f.get(2).copied(),
        Some("127.0.0.1"),
        "target_host was not recorded: {row:?}"
    );
    assert_eq!(
        f.get(3).copied(),
        Some(echo.addr.port().to_string().as_str()),
        "target_port was not recorded: {row:?}"
    );
    assert_eq!(
        f.get(4).copied(),
        Some("1"),
        "conn_id was left at 0: {row:?}"
    );
    assert_eq!(
        f.get(5).copied(),
        Some("1"),
        "bytes_sent was not recorded: {row:?}"
    );
    assert_eq!(
        f.get(6).copied(),
        Some("1"),
        "bytes_recv was not recorded: {row:?}"
    );
    assert_eq!(
        f.get(7).copied(),
        Some("normal"),
        "close_reason should be normal for a cleanly closed session: {row:?}"
    );
}
