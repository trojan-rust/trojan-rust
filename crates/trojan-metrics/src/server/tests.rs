use super::*;
use std::{io, path::Path};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose,
    IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::{
    ClientConfig,
    pki_types::{PrivatePkcs8KeyDer, ServerName},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    sync::oneshot,
    task::JoinHandle,
};
use tokio_rustls::TlsConnector;

struct Identity {
    certificate: Certificate,
    key: KeyPair,
}

struct Pki {
    _dir: tempfile::TempDir,
    config: MetricsTlsConfig,
    server_ca: CertifiedIssuer<'static, KeyPair>,
    client_ca: CertifiedIssuer<'static, KeyPair>,
    client: Identity,
}

fn ca(name: &str) -> CertifiedIssuer<'static, KeyPair> {
    let mut params = CertificateParams::new(vec![name.into()]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
}

fn identity(
    ca: &CertifiedIssuer<'static, KeyPair>,
    usage: ExtendedKeyUsagePurpose,
    expired: bool,
) -> Identity {
    let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.extended_key_usages = vec![usage];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    if expired {
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(2001, 1, 1);
    }
    let key = KeyPair::generate().unwrap();
    let certificate = params.signed_by(&key, ca).unwrap();
    Identity { certificate, key }
}

impl Pki {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let server_ca = ca("servers");
        let client_ca = ca("clients");
        let server = identity(&server_ca, ExtendedKeyUsagePurpose::ServerAuth, false);
        let client = identity(&client_ca, ExtendedKeyUsagePurpose::ClientAuth, false);
        let config = MetricsTlsConfig {
            cert: write(dir.path(), "server.pem", &server.certificate.pem()),
            key: write(dir.path(), "server-key.pem", &server.key.serialize_pem()),
            client_ca: write(dir.path(), "clients.pem", &client_ca.pem()),
        };
        Self {
            _dir: dir,
            config,
            server_ca,
            client_ca,
            client,
        }
    }

    fn client_config(&self, identity: Option<&Identity>) -> Arc<ClientConfig> {
        client_config(&self.server_ca, identity)
    }
}

fn write(dir: &Path, name: &str, contents: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path.to_str().unwrap().into()
}

fn client_config(
    ca: &CertifiedIssuer<'static, KeyPair>,
    identity: Option<&Identity>,
) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots);
    Arc::new(match identity {
        Some(identity) => config
            .with_client_auth_cert(
                vec![identity.certificate.der().clone()],
                PrivatePkcs8KeyDer::from(identity.key.serialize_der()).into(),
            )
            .unwrap(),
        None => config.with_no_client_auth(),
    })
}

type ServerTask = JoinHandle<Result<Result<(), oneshot::error::RecvError>, MetricsError>>;

fn spawn(server: MetricsServer) -> (oneshot::Sender<()>, ServerTask) {
    let (stop, stopped) = oneshot::channel();
    (stop, tokio::spawn(server.run_until(stopped)))
}

async fn exchange<I: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut I,
    path: &str,
) -> io::Result<String> {
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
        .await?;
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    let mut length = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = Some(value.trim().parse::<usize>().unwrap());
        }
        response.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }
    let mut body = vec![0; length.expect("Axum responses have a content length")];
    reader.read_exact(&mut body).await?;
    response.push_str(std::str::from_utf8(&body).unwrap());
    Ok(response)
}

async fn https(
    address: SocketAddr,
    config: Arc<ClientConfig>,
    name: &'static str,
    path: &str,
) -> io::Result<String> {
    let stream = TcpStream::connect(address).await?;
    let mut tls = TlsConnector::from(config)
        .connect(ServerName::try_from(name).unwrap(), stream)
        .await?;
    exchange(&mut tls, path).await
}

async fn assert_closed(stream: &mut TcpStream) {
    let result = timeout(Duration::from_secs(1), stream.read(&mut [0; 1]))
        .await
        .expect("old connection must close");
    match result {
        Ok(size) => assert_eq!(size, 0),
        Err(error) => assert!(
            matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
            ),
            "{error}"
        ),
    }
}

#[tokio::test]
async fn http_reuses_recorder_and_closes_keepalive_connections_before_restart() {
    let server = init_metrics_server("127.0.0.1:0", None, None)
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    metrics::counter!("metrics_restart_test_total").increment(7);
    let (stop, task) = spawn(server);
    let mut stream = TcpStream::connect(address).await.unwrap();
    let response = exchange(&mut stream, "/metrics").await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains("metrics_restart_test_total 7"));
    stop.send(()).unwrap();
    task.await.unwrap().unwrap().unwrap();
    assert_closed(&mut stream).await;

    let replacement = init_metrics_server(&address.to_string(), None, None)
        .await
        .unwrap();
    let (stop, task) = spawn(replacement);
    let mut stream = TcpStream::connect(address).await.unwrap();
    let response = exchange(&mut stream, "/metrics").await.unwrap();
    assert!(response.contains("metrics_restart_test_total 7"));
    stop.send(()).unwrap();
    task.await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn mtls_enforces_certificates_on_all_routes_and_verifies_server_identity() {
    let pki = Pki::new();
    let extra = Router::new().route(
        "/extra",
        get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.ip().to_string() }),
    );
    let server = init_metrics_server("127.0.0.1:0", Some(&pki.config), Some(extra))
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    metrics::counter!("metrics_mtls_test_total").increment(9);
    let (stop, task) = spawn(server);
    let valid = pki.client_config(Some(&pki.client));
    for (path, expected) in [
        ("/metrics", "metrics_mtls_test_total 9"),
        ("/health", "OK"),
        ("/ready", "READY"),
        ("/extra", "127.0.0.1"),
    ] {
        let response = https(address, valid.clone(), "localhost", path)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.contains(expected), "{response}");
        https(address, pki.client_config(None), "localhost", path)
            .await
            .expect_err("anonymous clients must be rejected at TLS");
    }

    let rogue_ca = ca("rogue");
    for client in [
        identity(&rogue_ca, ExtendedKeyUsagePurpose::ClientAuth, false),
        identity(&pki.client_ca, ExtendedKeyUsagePurpose::ClientAuth, true),
        identity(&pki.client_ca, ExtendedKeyUsagePurpose::ServerAuth, false),
    ] {
        https(
            address,
            pki.client_config(Some(&client)),
            "localhost",
            "/metrics",
        )
        .await
        .expect_err("invalid client certificate must fail");
        assert!(
            https(address, valid.clone(), "localhost", "/metrics")
                .await
                .unwrap()
                .contains("metrics_mtls_test_total 9")
        );
    }
    https(
        address,
        client_config(&rogue_ca, Some(&pki.client)),
        "localhost",
        "/metrics",
    )
    .await
    .expect_err("untrusted server CA must fail");
    https(address, valid.clone(), "wrong.example", "/metrics")
        .await
        .expect_err("incorrect server SAN must fail");
    let mut plain = TcpStream::connect(address).await.unwrap();
    exchange(&mut plain, "/metrics")
        .await
        .expect_err("plaintext must fail on the TLS listener");

    let _stalled = TcpStream::connect(address).await.unwrap();
    let response = timeout(
        Duration::from_secs(1),
        https(address, valid, "localhost", "/metrics"),
    )
    .await
    .expect("a stalled handshake must not block another client")
    .unwrap();
    assert!(response.contains("metrics_mtls_test_total 9"));
    stop.send(()).unwrap();
    task.await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn startup_propagates_certificate_key_ca_and_bind_failures() {
    let pki = Pki::new();
    for field in ["cert", "key", "client_ca"] {
        let mut config = pki.config.clone();
        let path = match field {
            "cert" => &mut config.cert,
            "key" => &mut config.key,
            _ => &mut config.client_ca,
        };
        path.push_str(".missing");
        let expected = path.clone();
        let error = init_metrics_server("127.0.0.1:0", Some(&config), None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains(&expected), "{error}");
    }
    let rogue = KeyPair::generate().unwrap();
    let mut config = pki.config.clone();
    config.key = write(
        pki._dir.path(),
        "mismatched-key.pem",
        &rogue.serialize_pem(),
    );
    let error = init_metrics_server("127.0.0.1:0", Some(&config), None)
        .await
        .unwrap_err();
    assert!(matches!(error, MetricsError::Tls(_)), "{error}");
    assert!(error.to_string().contains("key"));

    for contents in [
        "not a certificate".to_owned(),
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_owned(),
        format!(
            "{}\n-----BEGIN CERTIFICATE-----\ninvalid-base64!\n-----END CERTIFICATE-----\n",
            pki.client_ca.pem()
        ),
    ] {
        let mut config = pki.config.clone();
        config.client_ca = write(pki._dir.path(), "invalid-ca.pem", &contents);
        let error = init_metrics_server("127.0.0.1:0", Some(&config), None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("invalid-ca.pem"), "{error}");
    }
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    for tls in [None, Some(&pki.config)] {
        let error = init_metrics_server(&occupied.local_addr().unwrap().to_string(), tls, None)
            .await
            .unwrap_err();
        assert!(
            matches!(error, MetricsError::Bind { source, .. } if source.kind() == io::ErrorKind::AddrInUse)
        );
    }
}

#[tokio::test]
async fn abort_releases_listener_and_accepted_sockets_synchronously() {
    let server = init_metrics_server("127.0.0.1:0", None, None)
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let (_stop, task) = spawn(server);
    let mut stream = TcpStream::connect(address).await.unwrap();
    assert!(
        exchange(&mut stream, "/ready")
            .await
            .unwrap()
            .contains("READY")
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_closed(&mut stream).await;
    let replacement = init_metrics_server(&address.to_string(), None, None)
        .await
        .unwrap();
    drop(replacement);
    TcpListener::bind(address)
        .await
        .expect("dropping an unpolled server releases the port");
}

#[tokio::test]
async fn restart_applies_http_to_tls_certificate_ca_and_port_changes() {
    let old_pki = Pki::new();
    let server = init_metrics_server("127.0.0.1:0", None, None)
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let (stop, task) = spawn(server);
    let mut old_plain = TcpStream::connect(address).await.unwrap();
    assert!(
        exchange(&mut old_plain, "/health")
            .await
            .unwrap()
            .contains("OK")
    );
    stop.send(()).unwrap();
    task.await.unwrap().unwrap().unwrap();

    let server = init_metrics_server(&address.to_string(), Some(&old_pki.config), None)
        .await
        .unwrap();
    let (stop, task) = spawn(server);
    assert_closed(&mut old_plain).await;
    let mut plain = TcpStream::connect(address).await.unwrap();
    exchange(&mut plain, "/metrics")
        .await
        .expect_err("HTTP must stop after mTLS activation");
    assert!(
        https(
            address,
            old_pki.client_config(Some(&old_pki.client)),
            "localhost",
            "/metrics"
        )
        .await
        .unwrap()
        .starts_with("HTTP/1.1 200")
    );
    stop.send(()).unwrap();
    task.await.unwrap().unwrap().unwrap();

    let new_pki = Pki::new();
    std::fs::copy(&new_pki.config.cert, &old_pki.config.cert).unwrap();
    std::fs::copy(&new_pki.config.key, &old_pki.config.key).unwrap();
    std::fs::copy(&new_pki.config.client_ca, &old_pki.config.client_ca).unwrap();
    let server = init_metrics_server(&address.to_string(), Some(&old_pki.config), None)
        .await
        .unwrap();
    let (stop, task) = spawn(server);
    https(
        address,
        old_pki.client_config(Some(&old_pki.client)),
        "localhost",
        "/metrics",
    )
    .await
    .expect_err("old server trust must fail after certificate replacement");
    https(
        address,
        new_pki.client_config(Some(&old_pki.client)),
        "localhost",
        "/metrics",
    )
    .await
    .expect_err("old client CA must fail after CA replacement");
    assert!(
        https(
            address,
            new_pki.client_config(Some(&new_pki.client)),
            "localhost",
            "/metrics"
        )
        .await
        .unwrap()
        .starts_with("HTTP/1.1 200")
    );
    stop.send(()).unwrap();
    task.await.unwrap().unwrap().unwrap();

    let reserved_old_port = TcpListener::bind(address).await.unwrap();
    let server = init_metrics_server("127.0.0.1:0", Some(&old_pki.config), None)
        .await
        .unwrap();
    let new_address = server.local_addr().unwrap();
    assert_ne!(address, new_address);
    drop(reserved_old_port);
    let (stop, task) = spawn(server);
    TcpStream::connect(address)
        .await
        .expect_err("the previous listen address must be closed");
    assert!(
        https(
            new_address,
            new_pki.client_config(Some(&new_pki.client)),
            "localhost",
            "/metrics"
        )
        .await
        .unwrap()
        .starts_with("HTTP/1.1 200")
    );
    stop.send(()).unwrap();
    task.await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn stalled_handshakes_have_a_timeout_and_connection_limit() {
    let pki = Pki::new();
    let server = init_metrics_server("127.0.0.1:0", Some(&pki.config), None)
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let (stop, task) = spawn(server);
    let mut stalled = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        stalled.push(TcpStream::connect(address).await.unwrap());
    }
    let request = https(
        address,
        pki.client_config(Some(&pki.client)),
        "localhost",
        "/metrics",
    );
    tokio::pin!(request);
    timeout(Duration::from_millis(100), &mut request)
        .await
        .expect_err("connections beyond the limit must wait");
    let response = timeout(HANDSHAKE_TIMEOUT + Duration::from_secs(2), request)
        .await
        .expect("stalled handshakes must release capacity")
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    assert_closed(&mut stalled[0]).await;
    stop.send(()).unwrap();
    task.await.unwrap().unwrap().unwrap();
}
