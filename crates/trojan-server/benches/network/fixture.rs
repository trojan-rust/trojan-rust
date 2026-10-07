use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use trojan_auth::{MemoryAuth, sha224_hex};
use trojan_config::Config;
use trojan_core::io::relay_bidirectional;
use trojan_metrics::{NodeStats, RelayCounters};
use trojan_proto::{AddressRef, CMD_CONNECT, HostRef, write_request_header};

use super::load::{self, Connection};
use super::{Args, Result, Transport};

const PASSWORD: &str = "network-benchmark-only";

#[derive(Serialize, Deserialize)]
struct Setup {
    transport: Transport,
    config: Config,
}

pub struct Fixture {
    child: Child,
    echo: JoinHandle<()>,
    _files: tempfile::TempDir,
    pub endpoint: Endpoint,
}

#[derive(Clone)]
pub struct Endpoint {
    listen: SocketAddr,
    target: SocketAddr,
    tls: Option<TlsConnector>,
}

impl Endpoint {
    pub async fn connect(&self) -> Result<Connection> {
        let tcp = TcpStream::connect(self.listen).await?;
        tcp.set_nodelay(true)?;
        let Some(connector) = &self.tls else {
            return Ok(Box::new(tcp));
        };
        let mut tls = connector
            .connect(ServerName::try_from("localhost")?, tcp)
            .await?;
        let mut header = BytesMut::new();
        let SocketAddr::V4(target) = self.target else {
            unreachable!("loopback is IPv4")
        };
        write_request_header(
            &mut header,
            sha224_hex(PASSWORD).as_bytes(),
            CMD_CONNECT,
            &AddressRef {
                host: HostRef::Ipv4(target.ip().octets()),
                port: target.port(),
            },
        )
        .map_err(trojan_server::ServerError::ProtoWrite)?;
        tls.write_all(&header).await?;
        tls.flush().await?;
        Ok(Box::new(tls))
    }
}

impl Fixture {
    pub async fn start(args: &Args, transport: Transport) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let target = listener.local_addr()?;
        let echo = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.expect("accept echo client");
                socket.set_nodelay(true).expect("set echo TCP_NODELAY");
                tokio::spawn(async move {
                    let mut buffer = vec![0; 65536];
                    loop {
                        let n = socket.read(&mut buffer).await.expect("read echo request");
                        if n == 0 {
                            break;
                        }
                        socket
                            .write_all(&buffer[..n])
                            .await
                            .expect("write echo response");
                    }
                    socket.shutdown().await.expect("close echo connection");
                });
            }
        });
        let files = tempfile::tempdir()?;
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
        let cert_path = files.path().join("cert.pem");
        let key_path = files.path().join("key.pem");
        fs::write(&cert_path, cert.cert.pem())?;
        fs::write(&key_path, cert.signing_key.serialize_pem())?;
        let reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
        let listen = reservation.local_addr()?;
        let config: Config = serde_json::from_value(serde_json::json!({
            "server": {
                "listen": listen.to_string(), "fallback": target.to_string(),
                "resource_limits": { "relay_buffer_size": args.buffer_bytes },
            },
            "tls": { "cert": cert_path, "key": key_path },
            "auth": { "passwords": [PASSWORD] },
            "metrics": { "per_target": true },
        }))?;
        trojan_config::validate_config(&config)?;
        let setup_path = files.path().join("setup.json");
        fs::write(
            &setup_path,
            serde_json::to_vec(&Setup { transport, config })?,
        )?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone())?;
        let tls = matches!(transport, Transport::Tls).then(|| {
            TlsConnector::from(Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            ))
        });
        drop(reservation);
        let child = Command::new(std::env::current_exe()?)
            .arg("--serve")
            .arg(setup_path)
            .arg("--workers")
            .arg(args.workers.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        let mut fixture = Self {
            child,
            echo,
            _files: files,
            endpoint: Endpoint {
                listen,
                target,
                tls,
            },
        };
        // Readiness retries apply only to connection refusal during process startup.
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(status) = fixture.child.try_wait()? {
                    return Err(io::Error::other(format!(
                        "server exited during startup: {status}"
                    ))
                    .into());
                }
                match fixture.endpoint.connect().await {
                    Ok(mut stream) => {
                        load::warmup(&mut stream, args.buffer_bytes).await?;
                        stream.shutdown().await?;
                        break Ok::<_, super::Error>(());
                    }
                    Err(error)
                        if error
                            .downcast_ref::<io::Error>()
                            .is_some_and(|e| e.kind() == io::ErrorKind::ConnectionRefused) =>
                    {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        })
        .await??;
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(fixture)
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn stop(&mut self) -> Result<()> {
        self.child.kill()?;
        self.child.wait()?;
        self.echo.abort();
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Preserve the measurement error while releasing the benchmark's private process.
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.echo.abort();
    }
}

pub async fn serve(path: &Path) -> Result<()> {
    let Setup { transport, config } = serde_json::from_slice(&fs::read(path)?)?;
    metrics_exporter_prometheus::PrometheusBuilder::new().install_recorder()?;
    let stats = NodeStats::new();
    match transport {
        Transport::Tls => {
            trojan_server::run_with_stats(
                config,
                MemoryAuth::from_passwords([PASSWORD]),
                stats,
                trojan_server::CancellationToken::new(),
            )
            .await?;
        }
        Transport::Tcp => {
            let listener = TcpListener::bind(&config.server.listen).await?;
            let buffer = config
                .server
                .resource_limits
                .as_ref()
                .expect("benchmark buffer size")
                .relay_buffer_size;
            loop {
                let (inbound, _) = listener.accept().await?;
                inbound.set_nodelay(true)?;
                let target = config.server.fallback.clone();
                let stats = stats.clone();
                tokio::spawn(async move {
                    let _active = stats.connection_started();
                    let outbound = TcpStream::connect(target)
                        .await
                        .expect("connect echo target");
                    outbound
                        .set_nodelay(true)
                        .expect("set outbound TCP_NODELAY");
                    let counters = RelayCounters::with_target("127.0.0.1").with_node_stats(stats);
                    relay_bidirectional(
                        inbound,
                        outbound,
                        Duration::from_secs(60),
                        buffer,
                        &counters,
                    )
                    .await
                    .expect("relay benchmark bytes");
                });
            }
        }
    }
    Ok(())
}
