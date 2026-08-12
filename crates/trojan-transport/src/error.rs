//! Error types for the transport crate.

use thiserror::Error;

/// Errors that can occur in transport operations.
#[derive(Error, Debug)]
pub enum TransportError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("config error: {0}")]
    Config(String),

    #[error(transparent)]
    TlsMaterial(#[from] trojan_core::tls::TlsError),

    #[error("certificate generation failed: {0}")]
    CertGeneration(String),
}
