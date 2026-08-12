//! Error types for the relay crate.

use thiserror::Error;

/// Errors that can occur in the relay system.
#[derive(Error, Debug)]
pub enum RelayError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("config error: {0}")]
    Config(String),

    #[error("handshake failed: {0}")]
    Handshake(String),

    #[error("authentication failed")]
    AuthFailed,

    #[error("chain not found: {0}")]
    ChainNotFound(String),

    #[error("no rule matched for listener {0}")]
    NoRuleMatch(String),

    #[error("connect timeout to {0}")]
    ConnectTimeout(String),

    #[error("certificate generation failed: {0}")]
    CertGeneration(String),

    #[error("load balancer: {0}")]
    LoadBalancer(#[from] trojan_lb::LbError),

    #[error("proxy protocol: {0}")]
    ProxyProtocol(#[from] trojan_core::proxy_protocol::ProxyProtocolError),
}

impl From<trojan_transport::error::TransportError> for RelayError {
    fn from(err: trojan_transport::error::TransportError) -> Self {
        match err {
            trojan_transport::error::TransportError::Io(e) => RelayError::Io(e),
            trojan_transport::error::TransportError::Tls(e) => RelayError::Tls(e),
            trojan_transport::error::TransportError::Config(s) => RelayError::Config(s),
            // An unreadable cert or key is a config mistake like any other.
            trojan_transport::error::TransportError::TlsMaterial(e) => {
                RelayError::Config(e.to_string())
            }
            trojan_transport::error::TransportError::CertGeneration(s) => {
                RelayError::CertGeneration(s)
            }
        }
    }
}
