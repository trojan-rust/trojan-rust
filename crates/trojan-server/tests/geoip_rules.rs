//! End-to-end tests for GeoIP-based routing.
//!
//! `geoip` is a non-default feature and had no coverage: exercising it needs a
//! MaxMind database, and neither committing a binary fixture nor downloading
//! one at test time is acceptable. `maxminddb-writer` sidesteps both by
//! building a real `.mmdb` in a temp directory, so the rule engine, the
//! database loader, and the reader all run against genuine data.
#![cfg(feature = "geoip")]
#![expect(
    clippy::tests_outside_test_module,
    reason = "integration tests are their own crate, where every #[test] is \
              necessarily a free item; the lint targets unit tests that \
              escaped a #[cfg(test)] mod"
)]

use std::{
    fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    sync::Arc,
    thread,
    time::Duration,
};

use bytes::BytesMut;
use maxminddb_writer::paths::IpAddrWithMask;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use trojan_auth::{MemoryAuth, sha224_hex};
use trojan_config::{
    AuthConfig, Config, LoggingConfig, MetricsConfig, RouteRuleConfig, ServerConfig, TcpConfig,
    TlsConfig, WebSocketConfig,
};
use trojan_proto::{AddressRef, CMD_CONNECT, HostRef, write_request_header};
use trojan_server::{CancellationToken, run_with_shutdown};

const PASSWORD: &str = "geoip-test-password";

#[ctor::ctor]
fn init_crypto() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install aws-lc-rs crypto provider");
}

// ── Database construction ──

/// Shaped to match what `maxminddb::geoip2::Country` decodes.
#[derive(Serialize)]
struct CountryRecord {
    country: CountryIsoCode,
}

#[derive(Serialize)]
struct CountryIsoCode {
    iso_code: String,
}

/// Write a database mapping each `(network, mask)` to a country code.
fn write_geoip_db(path: &std::path::Path, entries: &[(Ipv4Addr, u8, &str)]) {
    let mut db = maxminddb_writer::Database::default();

    for (network, mask, code) in entries {
        let data = db
            .insert_value(CountryRecord {
                country: CountryIsoCode {
                    iso_code: (*code).to_string(),
                },
            })
            .expect("encode country record");
        db.insert_node(IpAddrWithMask::new(IpAddr::V4(*network), *mask), data);
    }

    let file = fs::File::create(path).expect("create mmdb");
    db.write_to(file).expect("write mmdb");
}

// ── Fixtures ──

fn generate_test_certs() -> (String, String) {
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".try_into().unwrap()),
        rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
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

struct TestServer {
    addr: SocketAddr,
    tls_connector: TlsConnector,
    shutdown: CancellationToken,
    _handle: tokio::task::JoinHandle<()>,
    _temp_dir: tempfile::TempDir,
}

impl TestServer {
    async fn start(rules: Vec<RouteRuleConfig>, db_entries: &[(Ipv4Addr, u8, &str)]) -> Self {
        let (cert_pem, key_pem) = generate_test_certs();
        let temp_dir = tempfile::Builder::new()
            .prefix("trojan-geoip-")
            .tempdir()
            .unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");
        fs::write(&cert_path, &cert_pem).unwrap();
        fs::write(&key_path, &key_pem).unwrap();

        let db_path = temp_dir.path().join("country.mmdb");
        write_geoip_db(&db_path, db_entries);

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
                rules,
                geoip: Some(trojan_rules::config::GeoipConfig {
                    source: "test-local".to_string(),
                    path: Some(db_path.to_string_lossy().into_owned()),
                    url: None,
                    auto_update: false,
                    interval: 0,
                    cache_path: None,
                }),
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

        let auth = MemoryAuth::from_passwords(&config.auth.passwords);
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

    /// CONNECT to `target`; `Ok` means the payload round-tripped.
    async fn try_relay(&self, target: SocketAddr) -> std::io::Result<()> {
        let tcp = tokio::net::TcpStream::connect(self.addr).await?;
        let name = ServerName::try_from("localhost").unwrap();
        let mut tls = self.tls_connector.connect(name, tcp).await?;

        let ip = match target.ip() {
            IpAddr::V4(v4) => v4,
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
        let payload = b"geoip-probe";
        header.extend_from_slice(payload);

        tls.write_all(&header).await?;
        tls.flush().await?;

        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(10), tls.read_exact(&mut echoed))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "relay timeout"))??;
        assert_eq!(&echoed[..], payload);
        Ok(())
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

fn rule(rule_type: &str, value: Option<&str>, outbound: &str) -> RouteRuleConfig {
    RouteRuleConfig {
        rule_set: None,
        rule_type: Some(rule_type.to_string()),
        value: value.map(str::to_string),
        outbound: outbound.to_string(),
    }
}

// ── Tests ──

/// A GEOIP rule matching the destination's country rejects the connection.
#[tokio::test]
async fn geoip_rule_rejects_matching_country() {
    let echo = MockEchoServer::start();
    let server = TestServer::start(
        vec![
            rule("GEOIP", Some("TC"), "REJECT"),
            rule("FINAL", None, "DIRECT"),
        ],
        // Loopback tagged with a country code that exists nowhere real, so a
        // rule matching it can only be coming from this database.
        &[(Ipv4Addr::new(127, 0, 0, 0), 8, "TC")],
    )
    .await;

    server
        .try_relay(echo.addr)
        .await
        .expect_err("a destination in the rejected country must not be relayed");
}

/// The same rule leaves other countries alone.
///
/// Without this, a rule engine that rejected everything — or one that failed
/// to load the database and fell through — would look identical.
#[tokio::test]
async fn geoip_rule_allows_other_countries() {
    let echo = MockEchoServer::start();
    let server = TestServer::start(
        vec![
            rule("GEOIP", Some("XX"), "REJECT"),
            rule("FINAL", None, "DIRECT"),
        ],
        // Loopback is TC; the rule rejects XX, so this must pass through.
        &[(Ipv4Addr::new(127, 0, 0, 0), 8, "TC")],
    )
    .await;

    server
        .try_relay(echo.addr)
        .await
        .expect("a destination outside the rejected country should be relayed");
}

/// The generated database is a real MaxMind file the reader agrees with.
///
/// Guards the fixture itself: if `maxminddb-writer` and the `maxminddb`
/// reader ever disagree on format, the routing tests above would silently
/// become vacuous — every lookup would miss and every rule would fall through
/// to FINAL.
#[test]
fn generated_database_is_readable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("country.mmdb");
    write_geoip_db(
        &path,
        &[
            (Ipv4Addr::new(127, 0, 0, 0), 8, "TC"),
            (Ipv4Addr::new(10, 0, 0, 0), 8, "XX"),
        ],
    );

    let db = trojan_rules::geoip_db::GeoipDb::from_file(&path).expect("open generated database");

    assert_eq!(
        db.country_code(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .as_deref(),
        Some("TC")
    );
    assert_eq!(
        db.country_code(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)))
            .as_deref(),
        Some("XX")
    );
    assert_eq!(db.country_code(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))), None);
}
