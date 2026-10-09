use super::tests::{
    WAIT, agent_config, connect_service, entry_config, free_address, init_crypto, ready, receive,
    register_node, send,
};
use super::*;
use crate::protocol::NodeType;
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair};
use serde_json::{Value, json};
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::{TlsConnector, rustls};
use tokio_tungstenite::WebSocketStream;

struct Certificates {
    config: Value,
    client: Arc<rustls::ClientConfig>,
}

impl Certificates {
    fn write(directory: &Path) -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = params.self_signed(&key).unwrap();
        let issuer = Issuer::from_params(&params, &key);
        let server_key = KeyPair::generate().unwrap();
        let mut server_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server = server_params.signed_by(&server_key, &issuer).unwrap();
        let client_key = KeyPair::generate().unwrap();
        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client = client_params.signed_by(&client_key, &issuer).unwrap();
        let cert_path = directory.join("metrics.crt");
        let key_path = directory.join("metrics.key");
        let ca_path = directory.join("clients-ca.crt");
        std::fs::write(&cert_path, server.pem()).unwrap();
        std::fs::write(&key_path, server_key.serialize_pem()).unwrap();
        std::fs::write(&ca_path, ca.pem()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![client.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(client_key.serialize_der()).into(),
            )
            .unwrap();
        Self {
            config: json!({"cert": cert_path, "key": key_path, "client_ca": ca_path}),
            client: Arc::new(client_config),
        }
    }

    async fn connect(
        &self,
        address: SocketAddr,
    ) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        TlsConnector::from(self.client.clone())
            .connect(
                "localhost".try_into().unwrap(),
                TcpStream::connect(address).await?,
            )
            .await
    }

    async fn scrape(&self, address: SocketAddr) -> io::Result<String> {
        request(&mut self.connect(address).await?).await
    }
}

async fn configuration(node_type: NodeType, directory: &Path, tls: &Value) -> Value {
    let listen = free_address().await;
    match node_type {
        NodeType::Server => {
            let cert = directory.join("proxy.crt");
            let key = directory.join("proxy.key");
            std::fs::copy(tls["cert"].as_str().unwrap(), &cert).unwrap();
            std::fs::copy(tls["key"].as_str().unwrap(), &key).unwrap();
            json!({
                "server": {"listen": listen, "fallback": "127.0.0.1:1"},
                "tls": {"cert": cert, "key": key},
                "auth": {"passwords": ["secret"]}
            })
        }
        NodeType::Entry => entry_config(listen, "127.0.0.1:1".parse().unwrap()),
        NodeType::Relay => json!({
            "relay": {"listen": listen, "transport": "plain", "auth": {"password": "secret"}}
        }),
    }
}

async fn request<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> io::Result<String> {
    timeout(WAIT, async {
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut response = String::new();
        stream.read_to_string(&mut response).await?;
        Ok(response)
    })
    .await
    .map_err(io::Error::other)?
}

async fn health<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> io::Result<()> {
    timeout(WAIT, async {
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await?;
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\nOK") {
            response.push(stream.read_u8().await?);
        }
        assert!(response.starts_with(b"HTTP/1.1 200"));
        Ok(())
    })
    .await
    .map_err(io::Error::other)?
}

fn assert_metrics(response: &str) {
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response.contains("trojan_agent_metrics_restart_test_total"),
        "{response}"
    );
}

async fn assert_closed<S: AsyncRead + Unpin>(stream: &mut S) {
    match timeout(WAIT, stream.read(&mut [0]))
        .await
        .expect("old metrics connection remained open")
    {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
            ) => {}
        result => panic!("old metrics connection did not close: {result:?}"),
    }
}

async fn push(ws: &mut WebSocketStream<TcpStream>, config: &Value, version: u32) {
    send(
        ws,
        PanelMessage::ConfigPush {
            version,
            restart_required: true,
            drain_timeout_secs: Some(0),
            config: serde_json::to_vec(config).unwrap(),
        },
    )
    .await;
    loop {
        if let AgentMessage::ConfigAck {
            version: got,
            ok,
            message,
        } = receive(ws).await
        {
            assert_eq!(got, version);
            assert!(ok, "{message:?}");
            drop(
                connect_service(
                    config["metrics"]["listen"]
                        .as_str()
                        .unwrap()
                        .parse()
                        .unwrap(),
                )
                .await,
            );
            return;
        }
    }
}

async fn restart_metrics(node_type: NodeType) {
    let directory = tempfile::tempdir().unwrap();
    let certificates = Certificates::write(directory.path());
    let address = free_address().await;
    let mut config = configuration(node_type, directory.path(), &certificates.config).await;
    config["metrics"] = json!({"listen": address});
    cache::write_cache(
        directory.path(),
        &CachedConfig {
            node_id: Some("entry".into()),
            node_traffic: true,
            version: 1,
            node_type,
            report_interval_secs: 1,
            config: config.clone(),
            cached_at: unix_now(),
        },
    )
    .await
    .unwrap();
    let panel_address = free_address().await;
    let settings = agent_config(panel_address, directory.path());
    let shutdown = CancellationToken::new();
    let _guard = shutdown.clone().drop_guard();
    let agent = tokio::spawn(run(settings.clone(), shutdown.clone()));
    let mut existing_http = connect_service(address).await;
    health(&mut existing_http).await.unwrap();
    metrics::counter!("trojan_agent_metrics_restart_test_total").increment(1);
    assert_metrics(&request(&mut connect_service(address).await).await.unwrap());

    let panel = TcpListener::bind(panel_address).await.unwrap();
    let mut ws = register_node(&panel, node_type, &config).await;
    ready(&mut ws, &config).await;
    health(&mut existing_http).await.unwrap();
    ws.close(None).await.unwrap();
    drop(ws);
    let mut ws = register_node(&panel, node_type, &config).await;
    ready(&mut ws, &config).await;
    health(&mut existing_http).await.unwrap();

    config["metrics"]["tls"] = certificates.config.clone();
    push(&mut ws, &config, 2).await;
    assert_closed(&mut existing_http).await;
    assert_metrics(&certificates.scrape(address).await.unwrap());
    let plain = request(&mut TcpStream::connect(address).await.unwrap()).await;
    assert!(!plain.is_ok_and(|response| response.starts_with("HTTP/1.1 200")));
    let mut old_tls = certificates.connect(address).await.unwrap();
    health(&mut old_tls).await.unwrap();

    let rotated = Certificates::write(directory.path());
    assert_eq!(rotated.config, certificates.config);
    push(&mut ws, &config, 3).await;
    assert_closed(&mut old_tls).await;
    certificates
        .scrape(address)
        .await
        .expect_err("old server trust must fail after certificate replacement");
    assert_metrics(&rotated.scrape(address).await.unwrap());
    let mut old_identity = (*rotated.client).clone();
    old_identity.client_auth_cert_resolver = certificates.client.client_auth_cert_resolver.clone();
    let old_client = Certificates {
        config: rotated.config.clone(),
        client: Arc::new(old_identity),
    };
    old_client
        .scrape(address)
        .await
        .expect_err("old client CA must fail after CA replacement");

    let replacement = free_address().await;
    config["metrics"]["listen"] = json!(replacement);
    push(&mut ws, &config, 4).await;
    let _released = TcpListener::bind(address)
        .await
        .expect("old metrics port remains open");
    assert_metrics(&rotated.scrape(replacement).await.unwrap());
    let cached = cache::read_cache(directory.path()).await.unwrap();
    assert_eq!(cached.config, config);
    assert_eq!(cached.version, 4);
    assert!(directory.path().join("node-traffic.json").exists());
    shutdown.cancel();
    timeout(WAIT, agent).await.unwrap().unwrap().unwrap();
    drop(TcpListener::bind(replacement).await.unwrap());

    drop((ws, panel));
    let offline_shutdown = CancellationToken::new();
    let _offline_guard = offline_shutdown.clone().drop_guard();
    let offline = tokio::spawn(run(settings, offline_shutdown.clone()));
    drop(connect_service(replacement).await);
    assert_metrics(&rotated.scrape(replacement).await.unwrap());
    offline_shutdown.cancel();
    timeout(WAIT, offline).await.unwrap().unwrap().unwrap();
    TcpListener::bind(replacement).await.unwrap();
}

#[tokio::test]
async fn all_managed_roles_restart_metrics_and_reload_same_path_certificates() {
    init_crypto();
    for node_type in [NodeType::Server, NodeType::Relay, NodeType::Entry] {
        restart_metrics(node_type).await;
    }
}

#[tokio::test]
async fn all_managed_roles_report_metrics_startup_failure() {
    init_crypto();
    for node_type in [NodeType::Server, NodeType::Relay, NodeType::Entry] {
        for (occupied, pushed) in [(false, false), (true, false), (false, true)] {
            let directory = tempfile::tempdir().unwrap();
            let certificates = Certificates::write(directory.path());
            let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = reservation.local_addr().unwrap();
            let mut config = configuration(node_type, directory.path(), &certificates.config).await;
            config["metrics"] = json!({"listen": address, "tls": certificates.config});
            if !occupied {
                config["metrics"]["tls"]["cert"] = json!(directory.path().join("missing.crt"));
                drop(reservation);
            }
            let panel = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let shutdown = CancellationToken::new();
            let _guard = shutdown.clone().drop_guard();
            let settings = agent_config(panel.local_addr().unwrap(), directory.path());
            let agent = tokio::task::spawn_blocking(move || {
                // Drop the agent runtime immediately on failure, as the CLI does.
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(run(settings, shutdown))
            });
            let initial = if pushed {
                let mut initial = config.clone();
                initial["metrics"].as_object_mut().unwrap().remove("tls");
                initial
            } else {
                config.clone()
            };
            let mut ws = register_node(&panel, node_type, &initial).await;
            if pushed {
                health(&mut connect_service(address).await).await.unwrap();
                send(
                    &mut ws,
                    PanelMessage::ConfigPush {
                        version: 2,
                        restart_required: true,
                        drain_timeout_secs: Some(0),
                        config: serde_json::to_vec(&config).unwrap(),
                    },
                )
                .await;
            }
            loop {
                if let AgentMessage::ServiceStatus {
                    status: ServiceState::Error,
                    ..
                } = receive(&mut ws).await
                {
                    break;
                }
            }
            let result = timeout(WAIT, agent).await.unwrap().unwrap();
            assert!(matches!(result, Err(AgentError::Service(_))), "{result:?}");
            if !occupied {
                TcpListener::bind(address)
                    .await
                    .expect("failed startup left a metrics listener open");
            }
        }
    }
}
