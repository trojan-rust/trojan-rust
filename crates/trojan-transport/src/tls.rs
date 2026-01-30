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

use crate::error::TransportError;
use crate::tls_config::TlsConfig;
use crate::{TransportAcceptor, TransportConnector};

// ── TLS Acceptor ──

/// TLS transport acceptor that wraps incoming TCP connections in TLS.
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
            acceptor
                .accept(tcp)
                .await
                .map_err(|e| TransportError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
        })
    }
}

// ── TLS Connector ──

/// TLS transport connector for outbound connections.
#[derive(Clone)]
pub struct TlsTransportConnector {
    client_config: Arc<rustls::ClientConfig>,
    /// SNI value to send in the TLS ClientHello.
    sni: String,
}

impl TlsTransportConnector {
    /// Build an insecure (skip cert verification) TLS connector with the given SNI.
    pub fn new_insecure(sni: String) -> Self {
        Self {
            client_config: Arc::new(build_insecure_client_tls_config()),
            sni,
        }
    }

    /// Create a new connector sharing the same TLS config but with a different SNI.
    pub fn with_sni(&self, sni: String) -> Self {
        Self {
            client_config: self.client_config.clone(),
            sni,
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
        Box::pin(async move {
            let tcp = TcpStream::connect(&addr).await?;
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
        Some(cfg) => load_cert_files(&cfg.cert, &cfg.key)?,
        None => generate_self_signed()?,
    };

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TransportError::Tls(e))?;

    Ok(config)
}

/// Build a TLS client config that skips certificate verification.
fn build_insecure_client_tls_config() -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth()
}

/// Generate a self-signed certificate in memory using rcgen.
fn generate_self_signed() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TransportError>
{
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

/// Load certificate and private key from PEM files.
fn load_cert_files(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TransportError> {
    let mut reader = std::io::BufReader::new(std::fs::File::open(cert_path)?);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .filter_map(|c| c.ok().map(|v| v.into_owned()))
        .collect();

    if certs.is_empty() {
        return Err(TransportError::Config(format!(
            "no certificates found in {}",
            cert_path
        )));
    }

    let mut reader = std::io::BufReader::new(std::fs::File::open(key_path)?);
    let key = loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => {
                break PrivateKeyDer::Pkcs8(key);
            }
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => {
                break PrivateKeyDer::Pkcs1(key);
            }
            Some(_) => continue,
            None => {
                return Err(TransportError::Config(format!(
                    "no private key found in {}",
                    key_path
                )));
            }
        }
    };

    Ok((certs, key))
}

/// A TLS certificate verifier that accepts any certificate.
///
/// Used for relay-to-relay and relay-to-exit connections where
/// nodes use self-signed certificates.
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
