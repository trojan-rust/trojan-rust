//! Outbound connectors for rule-based routing.
//!
//! Each named outbound in the config becomes an `Outbound` instance that
//! knows how to establish a connection to the target address.

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::debug;
use trojan_config::{OutboundConfig, TcpConfig};
use trojan_proto::AddressRef;

use crate::error::ServerError;
use crate::resolve::resolve_address;
use crate::util::connect_with_buffers;

/// A configured outbound connector.
#[derive(Debug)]
pub enum Outbound {
    /// Direct connection, optionally bound to a local IP.
    Direct { bind: Option<IpAddr> },
    /// Trojan protocol proxy: connect to another trojan server.
    Trojan {
        addr: String,
        password_hash: String,
        sni: String,
    },
    /// Reject the connection (close immediately).
    Reject,
}

/// An established outbound connection, ready for relay.
#[allow(clippy::large_enum_variant)]
pub enum OutboundStream {
    /// Plain TCP stream (from direct connection).
    Tcp(TcpStream),
    /// TLS stream (from trojan outbound).
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl AsyncRead for OutboundStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            OutboundStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            OutboundStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for OutboundStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            OutboundStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            OutboundStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            OutboundStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            OutboundStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            OutboundStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            OutboundStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl Outbound {
    /// Build an Outbound from config.
    pub fn from_config(name: &str, cfg: &OutboundConfig) -> Result<Self, ServerError> {
        match cfg.outbound_type.as_str() {
            "direct" => {
                let bind = cfg
                    .bind
                    .as_deref()
                    .map(|s| {
                        s.parse::<IpAddr>().map_err(|e| {
                            ServerError::Config(format!(
                                "outbound '{name}': invalid bind address '{s}': {e}"
                            ))
                        })
                    })
                    .transpose()?;
                Ok(Outbound::Direct { bind })
            }
            "trojan" => {
                let addr = cfg.addr.as_deref().ok_or_else(|| {
                    ServerError::Config(format!("outbound '{name}': addr is required for trojan"))
                })?;
                let password = cfg.password.as_deref().ok_or_else(|| {
                    ServerError::Config(format!(
                        "outbound '{name}': password is required for trojan"
                    ))
                })?;
                let sni = match cfg.sni.clone() {
                    Some(s) => s,
                    None => {
                        // Try to extract hostname from addr (host:port).
                        // If the host portion is an IP address, require explicit sni.
                        let host = extract_host(addr);
                        if host.parse::<IpAddr>().is_ok() || host.starts_with('[')
                        // bracketed IPv6 like [::1]
                        {
                            return Err(ServerError::Config(format!(
                                "outbound '{name}': 'sni' is required when 'addr' is an IP address"
                            )));
                        }
                        host.to_string()
                    }
                };

                // Pre-compute SHA-224 hex hash of password
                use sha2::{Digest, Sha224};
                let hash = hex::encode(Sha224::digest(password.as_bytes()));

                Ok(Outbound::Trojan {
                    addr: addr.to_string(),
                    password_hash: hash,
                    sni,
                })
            }
            "reject" => Ok(Outbound::Reject),
            other => Err(ServerError::Config(format!(
                "outbound '{name}': unknown type '{other}'"
            ))),
        }
    }

    /// Connect to the target address through this outbound.
    ///
    /// Returns an `OutboundStream` ready for relay.
    /// For `Reject`, returns `None` (caller should drop the connection).
    pub async fn connect(
        &self,
        address: &AddressRef<'_>,
        tcp_config: &TcpConfig,
        send_buf: usize,
        recv_buf: usize,
    ) -> Result<Option<OutboundStream>, ServerError> {
        match self {
            Outbound::Direct { bind } => {
                let target = resolve_address(address, tcp_config.prefer_ipv4).await?;
                let stream = if let Some(bind_ip) = bind {
                    connect_with_bind(target, *bind_ip, send_buf, recv_buf, tcp_config).await?
                } else {
                    connect_with_buffers(target, send_buf, recv_buf, tcp_config).await?
                };
                Ok(Some(OutboundStream::Tcp(stream)))
            }
            Outbound::Trojan {
                addr,
                password_hash,
                sni,
            } => {
                let stream =
                    connect_trojan_outbound(addr, password_hash, sni, address, tcp_config).await?;
                Ok(Some(OutboundStream::Tls(stream)))
            }
            Outbound::Reject => Ok(None),
        }
    }
}

/// Connect to target with a specific local bind address.
#[allow(clippy::cast_possible_truncation)]
async fn connect_with_bind(
    target: SocketAddr,
    bind_ip: IpAddr,
    send_buf: usize,
    recv_buf: usize,
    tcp_cfg: &TcpConfig,
) -> Result<TcpStream, ServerError> {
    let socket = if target.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    if send_buf > 0 {
        socket.set_send_buffer_size(send_buf as u32)?;
    }
    if recv_buf > 0 {
        socket.set_recv_buffer_size(recv_buf as u32)?;
    }
    let bind_addr = SocketAddr::new(bind_ip, 0);
    socket.bind(bind_addr)?;
    let stream = socket.connect(target).await?;
    stream.set_nodelay(tcp_cfg.no_delay)?;
    Ok(stream)
}

/// Connect to a remote trojan server and send the trojan request header.
async fn connect_trojan_outbound(
    addr: &str,
    password_hash: &str,
    sni: &str,
    target: &AddressRef<'_>,
    tcp_config: &TcpConfig,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ServerError> {
    use rustls::pki_types::ServerName;
    use std::sync::Arc;
    use tokio_rustls::TlsConnector;

    // Resolve the trojan server address
    let server_addr = crate::resolve::resolve_sockaddr(addr, tcp_config.prefer_ipv4).await?;
    debug!(server = %addr, resolved = %server_addr, "connecting to trojan outbound");

    // Create TLS config for outbound (trust system roots)
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));

    let tcp = TcpStream::connect(server_addr).await?;
    tcp.set_nodelay(tcp_config.no_delay)?;

    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|e| ServerError::Config(format!("invalid SNI '{sni}': {e}")))?;
    let mut tls = connector.connect(server_name, tcp).await?;

    // Build trojan request header using trojan-proto
    let mut header = bytes::BytesMut::with_capacity(128);
    trojan_proto::write_request_header(
        &mut header,
        password_hash.as_bytes(),
        trojan_proto::CMD_CONNECT,
        target,
    )
    .map_err(ServerError::ProtoWrite)?;

    tls.write_all(&header).await?;

    Ok(tls)
}

/// Extract the host portion from an `addr` string.
///
/// Handles `host:port`, `[ipv6]:port`, and bare hostnames.
fn extract_host(addr: &str) -> &str {
    // Bracketed IPv6: [::1]:443
    if addr.starts_with('[')
        && let Some(end) = addr.find(']')
    {
        return &addr[..=end]; // include the brackets
    }
    // host:port — take everything before the last ':'
    if let Some((host, _port)) = addr.rsplit_once(':') {
        return host;
    }
    // Bare hostname without port
    addr
}

#[cfg(test)]
mod tests {
    use super::*;
    use trojan_config::OutboundConfig;

    #[test]
    fn parse_direct_outbound() {
        let cfg = OutboundConfig {
            outbound_type: "direct".to_string(),
            addr: None,
            password: None,
            sni: None,
            bind: None,
        };
        let outbound = Outbound::from_config("test", &cfg).unwrap();
        assert!(matches!(outbound, Outbound::Direct { bind: None }));
    }

    #[test]
    fn parse_direct_with_bind() {
        let cfg = OutboundConfig {
            outbound_type: "direct".to_string(),
            addr: None,
            password: None,
            sni: None,
            bind: Some("192.168.1.1".to_string()),
        };
        let outbound = Outbound::from_config("test", &cfg).unwrap();
        assert!(matches!(outbound, Outbound::Direct { bind: Some(_) }));
    }

    #[test]
    fn parse_reject_outbound() {
        let cfg = OutboundConfig {
            outbound_type: "reject".to_string(),
            addr: None,
            password: None,
            sni: None,
            bind: None,
        };
        let outbound = Outbound::from_config("test", &cfg).unwrap();
        assert!(matches!(outbound, Outbound::Reject));
    }

    #[test]
    fn parse_trojan_outbound() {
        let cfg = OutboundConfig {
            outbound_type: "trojan".to_string(),
            addr: Some("server.example.com:443".to_string()),
            password: Some("secret".to_string()),
            sni: Some("example.com".to_string()),
            bind: None,
        };
        let outbound = Outbound::from_config("test", &cfg).unwrap();
        assert!(matches!(outbound, Outbound::Trojan { .. }));
    }

    #[test]
    fn parse_trojan_missing_addr() {
        let cfg = OutboundConfig {
            outbound_type: "trojan".to_string(),
            addr: None,
            password: Some("secret".to_string()),
            sni: None,
            bind: None,
        };
        Outbound::from_config("test", &cfg).unwrap_err();
    }

    #[test]
    fn parse_unknown_type() {
        let cfg = OutboundConfig {
            outbound_type: "socks5".to_string(),
            addr: Some("proxy:1080".to_string()),
            password: None,
            sni: None,
            bind: None,
        };
        Outbound::from_config("test", &cfg).unwrap_err();
    }

    #[test]
    fn parse_trojan_sni_inferred_from_domain() {
        // When addr is a domain:port, sni should be inferred from the domain
        let cfg = OutboundConfig {
            outbound_type: "trojan".to_string(),
            addr: Some("server.example.com:443".to_string()),
            password: Some("secret".to_string()),
            sni: None,
            bind: None,
        };
        let outbound = Outbound::from_config("test", &cfg).unwrap();
        match outbound {
            Outbound::Trojan { sni, .. } => assert_eq!(sni, "server.example.com"),
            _ => panic!("expected Trojan"),
        }
    }

    #[test]
    fn parse_trojan_ip_addr_requires_sni() {
        // IPv4 addr without explicit sni should error
        let cfg = OutboundConfig {
            outbound_type: "trojan".to_string(),
            addr: Some("1.2.3.4:443".to_string()),
            password: Some("secret".to_string()),
            sni: None,
            bind: None,
        };
        Outbound::from_config("test", &cfg).unwrap_err();
    }

    #[test]
    fn parse_trojan_ipv6_addr_requires_sni() {
        // IPv6 addr without explicit sni should error
        let cfg = OutboundConfig {
            outbound_type: "trojan".to_string(),
            addr: Some("[::1]:443".to_string()),
            password: Some("secret".to_string()),
            sni: None,
            bind: None,
        };
        Outbound::from_config("test", &cfg).unwrap_err();
    }

    #[test]
    fn parse_trojan_ip_addr_with_explicit_sni() {
        // IPv4 addr with explicit sni should succeed
        let cfg = OutboundConfig {
            outbound_type: "trojan".to_string(),
            addr: Some("1.2.3.4:443".to_string()),
            password: Some("secret".to_string()),
            sni: Some("example.com".to_string()),
            bind: None,
        };
        let outbound = Outbound::from_config("test", &cfg).unwrap();
        match outbound {
            Outbound::Trojan { sni, .. } => assert_eq!(sni, "example.com"),
            _ => panic!("expected Trojan"),
        }
    }

    #[test]
    fn extract_host_from_domain_port() {
        assert_eq!(extract_host("server.example.com:443"), "server.example.com");
    }

    #[test]
    fn extract_host_from_ipv6_bracket() {
        assert_eq!(extract_host("[::1]:443"), "[::1]");
    }

    #[test]
    fn extract_host_bare() {
        assert_eq!(extract_host("example.com"), "example.com");
    }
}
