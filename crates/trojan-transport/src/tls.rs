//! TLS transport implementation.
//!
//! - `TlsTransportAcceptor`: TLS server with auto-generated or file-based certs.
//! - `TlsTransportConnector`: TLS client that skips cert verification (for
//!   relay-to-relay self-signed certs) with configurable SNI.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpStream;
use tokio_rustls::rustls;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use trojan_core::tls::{SkipServerVerification, load_keypair};
use trojan_dns::DnsResolver;

use crate::error::TransportError;
use crate::tls_config::TlsConfig;
use crate::{TransportAcceptor, TransportConnector};

// ── TLS Acceptor ──

/// TLS transport acceptor that wraps incoming TCP connections in TLS.
#[expect(
    missing_debug_implementations,
    reason = "wraps a rustls TlsAcceptor, which has no Debug impl"
)]
#[derive(Clone)]
pub struct TlsTransportAcceptor {
    acceptor: TlsAcceptor,
}

impl TlsTransportAcceptor {
    /// Build from optional TLS config. Auto-generates self-signed cert if `None`.
    pub fn new(tls_config: Option<&TlsConfig>) -> Result<Self, TransportError> {
        let server_config = build_server_tls_config(tls_config)?;
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(server_config)),
        })
    }
}

impl TransportAcceptor for TlsTransportAcceptor {
    type Stream = tokio_rustls::server::TlsStream<TcpStream>;

    fn accept(
        &self,
        tcp: TcpStream,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Stream, TransportError>> + Send + '_>> {
        let acceptor = self.acceptor.clone();
        Box::pin(async move {
            acceptor.accept(tcp).await.map_err(|e| {
                TransportError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })
        })
    }
}

// ── TLS Connector ──

/// TLS transport connector for outbound connections.
///
/// When a [`DnsResolver`] is configured, domain names are resolved via
/// hickory-resolver before TCP connect. Without a resolver, falls back to
/// Tokio's built-in system DNS resolution.
#[derive(Debug, Clone)]
pub struct TlsTransportConnector {
    client_config: Arc<rustls::ClientConfig>,
    /// SNI value to send in the TLS ClientHello.
    sni: String,
    /// Optional DNS resolver for cached / custom resolution.
    resolver: Option<DnsResolver>,
}

impl TlsTransportConnector {
    /// Build an insecure (skip cert verification) TLS connector with the given SNI.
    pub fn new_insecure(sni: String) -> Self {
        Self {
            client_config: Arc::new(build_insecure_client_tls_config()),
            sni,
            resolver: None,
        }
    }

    /// Build an insecure TLS connector with a custom DNS resolver.
    pub fn new_insecure_with_resolver(sni: String, resolver: DnsResolver) -> Self {
        Self {
            client_config: Arc::new(build_insecure_client_tls_config()),
            sni,
            resolver: Some(resolver),
        }
    }

    /// Create a new connector sharing the same TLS config but with a different SNI.
    pub fn with_sni(&self, sni: String) -> Self {
        Self {
            client_config: self.client_config.clone(),
            sni,
            resolver: self.resolver.clone(),
        }
    }
}

impl TransportConnector for TlsTransportConnector {
    type Stream = tokio_rustls::client::TlsStream<TcpStream>;

    fn connect(
        &self,
        addr: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Stream, TransportError>> + Send + '_>> {
        let client_config = self.client_config.clone();
        let sni = self.sni.clone();
        let addr = addr.to_string();
        let resolver = self.resolver.clone();
        Box::pin(async move {
            let tcp = if let Some(resolver) = resolver {
                let socket_addr = resolver
                    .resolve(&addr)
                    .await
                    .map_err(|e| TransportError::Io(std::io::Error::other(e)))?;
                TcpStream::connect(socket_addr).await?
            } else {
                TcpStream::connect(&addr).await?
            };
            tcp.set_nodelay(true)?;

            let server_name = rustls::pki_types::ServerName::try_from(sni)
                .map_err(|e| TransportError::Config(format!("invalid SNI: {}", e)))?;

            let connector = TlsConnector::from(client_config);
            let tls_stream = connector.connect(server_name, tcp).await?;
            Ok(tls_stream)
        })
    }
}

// ── TLS Utility Functions ──

/// Generate a self-signed TLS server config.
///
/// If `tls_config` is provided, loads cert/key from files.
/// Otherwise, generates an ephemeral self-signed certificate in memory.
fn build_server_tls_config(
    tls_config: Option<&TlsConfig>,
) -> Result<rustls::ServerConfig, TransportError> {
    let (certs, key) = match tls_config {
        Some(cfg) => load_keypair(&cfg.cert, &cfg.key)?,
        None => generate_self_signed()?,
    };

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(TransportError::Tls)?;

    Ok(config)
}

/// Build a TLS client config that skips certificate verification.
fn build_insecure_client_tls_config() -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth()
}

/// Generate a self-signed certificate in memory using rcgen.
fn generate_self_signed()
-> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TransportError> {
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| TransportError::CertGeneration(e.to_string()))?;

    let params = CertificateParams::default();
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| TransportError::CertGeneration(e.to_string()))?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    Ok((vec![cert_der], key_der))
}
