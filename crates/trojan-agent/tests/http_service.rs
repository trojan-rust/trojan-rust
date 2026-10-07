#![expect(
    clippy::tests_outside_test_module,
    reason = "integration tests are standalone crates"
)]

use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use bytes::BytesMut;
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};
use tokio_rustls::{
    TlsConnector,
    rustls::{self, ClientConfig, RootCertStore},
};
use tokio_util::sync::CancellationToken;
use trojan_agent::{
    protocol::NodeType,
    runner::{ServiceSinks, run_service},
};
use trojan_auth::{protocol, sha224_hex};
use trojan_proto::{AddressRef, CMD_CONNECT, HostRef, write_request_header};

#[derive(Default)]
struct Calls {
    hashes: Vec<String>,
    traffic: Vec<protocol::TrafficRequest>,
}

async fn verify(
    State(calls): State<Arc<Mutex<Calls>>>,
    headers: HeaderMap,
    Json(request): Json<protocol::VerifyRequest>,
) -> Json<Result<protocol::AuthResult, protocol::AuthError>> {
    assert_eq!(headers["authorization"], "Bearer node-token");
    let valid = request.hash == sha224_hex("remote-password");
    calls.lock().unwrap().hashes.push(request.hash);
    Json(if valid {
        Ok(protocol::AuthResult {
            user_id: Some("alice".into()),
            metadata: None,
        })
    } else {
        Err(protocol::AuthError::Invalid)
    })
}

async fn traffic(
    State(calls): State<Arc<Mutex<Calls>>>,
    headers: HeaderMap,
    Json(request): Json<protocol::TrafficRequest>,
) -> Json<Result<(), protocol::AuthError>> {
    assert_eq!(headers["authorization"], "Bearer node-token");
    calls.lock().unwrap().traffic.push(request);
    Json(Ok(()))
}

#[tokio::test]
async fn managed_server_uses_http_auth_and_flushes_traffic_once_on_shutdown() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();
    let calls = Arc::new(Mutex::new(Calls::default()));
    let panel = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let panel_addr = panel.local_addr().unwrap();
    let router = Router::new()
        .route("/verify", post(verify))
        .route("/traffic", post(traffic))
        .with_state(calls.clone());
    let panel_task = tokio::spawn(async move { axum::serve(panel, router).await.unwrap() });
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = reservation.local_addr().unwrap();
    drop(reservation);

    let dir = tempfile::tempdir().unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    let config = json!({
        "server": {"listen": listen.to_string(), "fallback": "127.0.0.1:1"},
        "tls": {"cert": cert_path, "key": key_path},
        "auth": {
            "http_url": format!("http://{panel_addr}"),
            "http_node_token": "node-token",
            "http_codec": "json",
            "http_cache_ttl_secs": 0,
            "http_batch_flush_interval_secs": 3600
        }
    });
    let sinks = ServiceSinks::default();
    let observer = sinks.clone();
    let shutdown = CancellationToken::new();
    let token = shutdown.clone();
    let service =
        tokio::spawn(async move { run_service(NodeType::Server, &config, sinks, token).await });
    let tcp = timeout(Duration::from_secs(5), async {
        loop {
            match TcpStream::connect(listen).await {
                Ok(tcp) => return tcp,
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    sleep(Duration::from_millis(10)).await
                }
                Err(e) => panic!("connection failed: {e}"),
            }
        }
    })
    .await
    .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let mut tls = connector
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .unwrap();
    let mut request = BytesMut::new();
    write_request_header(
        &mut request,
        sha224_hex("remote-password").as_bytes(),
        CMD_CONNECT,
        &AddressRef {
            host: HostRef::Ipv4([127, 0, 0, 1]),
            port: target_addr.port(),
        },
    )
    .unwrap();
    request.extend_from_slice(b"hello");
    tls.write_all(&request).await.unwrap();
    let (mut remote, _) = timeout(Duration::from_secs(5), target.accept())
        .await
        .unwrap()
        .unwrap();
    let mut bytes = [0; 5];
    remote.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"hello");
    remote.write_all(b"world").await.unwrap();
    tls.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"world");
    tls.shutdown().await.unwrap();
    remote.shutdown().await.unwrap();
    assert!(
        calls.lock().unwrap().traffic.is_empty(),
        "the long batch interval must defer reporting"
    );
    shutdown.cancel();
    timeout(Duration::from_secs(5), service)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let calls = calls.lock().unwrap();
    assert_eq!(calls.hashes, [sha224_hex("remote-password")]);
    assert_eq!(calls.traffic.len(), 1);
    assert_eq!(calls.traffic[0].user_id, "alice");
    assert_eq!(calls.traffic[0].bytes, 10);
    assert!(
        observer.traffic.drain().is_empty(),
        "HTTP accounting must not also queue socket accounting"
    );
    panel_task.abort();
}
