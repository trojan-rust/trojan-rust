//! TLS connection establishment to the remote trojan server.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tracing::debug;
use trojan_config::TcpConfig;
use trojan_dns::DnsResolver;

use crate::error::ClientError;

/// Shared client state for establishing outbound connections.
#[allow(missing_debug_implementations)]
pub struct ClientState {
    /// SHA-224 hex hash of the password (56 bytes).
    pub hash_hex: String,
    /// Remote trojan server address string (host:port).
    pub remote_addr: String,
    /// TLS connector.
    pub tls_connector: TlsConnector,
    /// TLS SNI server name.
    pub sni: ServerName<'static>,
    /// TCP socket options.
    pub tcp_config: TcpConfig,
    /// TLS handshake timeout.
    pub tls_handshake_timeout: Duration,
    /// DNS resolver.
    pub dns_resolver: DnsResolver,
}

impl ClientState {
    /// Establish a TLS connection to the remote trojan server.
    pub async fn connect(&self) -> Result<TlsStream<TcpStream>, ClientError> {
        // DNS resolve
        let addr: SocketAddr = self
            .dns_resolver
            .resolve(&self.remote_addr)
            .await
            .map_err(|_| ClientError::Resolve(self.remote_addr.clone()))?;

        debug!(remote = %addr, "connecting to trojan server");

        // TCP connect
        let tcp = TcpStream::connect(addr).await?;
        apply_tcp_options(&tcp, &self.tcp_config)?;

        // TLS handshake with timeout
        let tls = tokio::time::timeout(
            self.tls_handshake_timeout,
            self.tls_connector.connect(self.sni.clone(), tcp),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timed out")
        })??;

        Ok(tls)
    }
}

/// Build TLS client config from client TLS settings.
pub fn build_tls_config(
    tls: &crate::config::ClientTlsConfig,
) -> Result<rustls::ClientConfig, ClientError> {
    let mut root_store = rustls::RootCertStore::empty();

    if let Some(ca_path) = &tls.ca {
        let ca_data = std::fs::read(ca_path)
            .map_err(|e| ClientError::Config(format!("failed to read CA cert: {e}")))?;

        let certs = rustls_pemfile::certs(&mut std::io::Cursor::new(&ca_data))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ClientError::Config(format!("failed to parse CA cert: {e}")))?;

        for cert in certs {
            root_store
                .add(cert)
                .map_err(|e| ClientError::Config(format!("failed to add CA cert: {e}")))?;
        }
    } else {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let mut config = if tls.skip_verify {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    config.alpn_protocols = tls.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();

    Ok(config)
}

/// Extract the SNI hostname from config or the remote address.
pub fn resolve_sni(
    tls: &crate::config::ClientTlsConfig,
    remote: &str,
) -> Result<ServerName<'static>, ClientError> {
    let host = if let Some(sni) = &tls.sni {
        sni.clone()
    } else {
        extract_host(remote)
    };

    ServerName::try_from(host)
        .map_err(|e| ClientError::Config(format!("invalid SNI hostname: {e}")))
}

fn extract_host(remote: &str) -> String {
    if let Some(stripped) = remote.strip_prefix('[')
        && let Some(end) = stripped.find(']')
    {
        return stripped[..end].to_string();
    }

    if remote.chars().filter(|&c| c == ':').count() == 1 {
        return remote
            .rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| remote.to_string());
    }

    remote.to_string()
}

#[cfg(test)]
mod tests {
    use super::{extract_host, resolve_sni};

    #[test]
    fn extract_host_parses_bracketed_ipv6() {
        assert_eq!(extract_host("[::1]:443"), "::1");
        assert_eq!(extract_host("[2001:db8::1]:8443"), "2001:db8::1");
    }

    #[test]
    fn extract_host_parses_hostname_and_port() {
        assert_eq!(extract_host("example.com:443"), "example.com");
        assert_eq!(extract_host("example.com"), "example.com");
    }

    #[test]
    fn resolve_sni_accepts_ipv6_literal() {
        let tls = crate::config::ClientTlsConfig::default();
        let sni = resolve_sni(&tls, "[::1]:443");
        sni.unwrap();
    }
}

/// Apply TCP socket options.
fn apply_tcp_options(stream: &TcpStream, config: &TcpConfig) -> Result<(), ClientError> {
    stream.set_nodelay(config.no_delay)?;

    if config.keepalive_secs > 0 {
        let sock = socket2::SockRef::from(stream);
        let keepalive =
            socket2::TcpKeepalive::new().with_time(Duration::from_secs(config.keepalive_secs));
        sock.set_tcp_keepalive(&keepalive)?;
    }

    Ok(())
}

/// Certificate verifier that accepts any certificate (for skip_verify mode).
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::CryptoProvider::get_default()
            .map(|provider| {
                provider
                    .signature_verification_algorithms
                    .supported_schemes()
            })
            .unwrap_or_default()
    }
}
