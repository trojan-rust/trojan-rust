//! Server error types.

use trojan_auth::AuthError;
use trojan_metrics::{ERROR_AUTH, ERROR_CONFIG, ERROR_IO, ERROR_PROTOCOL, ERROR_RESOLVE, ERROR_TLS_HANDSHAKE};
use trojan_proto::{ParseError, WriteError};

/// Server error type.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Tls(#[from] tokio_rustls::rustls::Error),
    #[error("auth: {0}")]
    Auth(#[from] AuthError),
    #[error("config: {0}")]
    Config(String),
    #[error("proto: {0:?}")]
    Proto(ParseError),
    #[error("proto write: {0:?}")]
    ProtoWrite(WriteError),
    #[error("resolve failed")]
    Resolve,
    #[error("udp payload too large")]
    UdpPayloadTooLarge,
}

impl ServerError {
    /// Get the error type string for metrics.
    pub fn error_type(&self) -> &'static str {
        match self {
            ServerError::Io(_) => ERROR_IO,
            ServerError::Tls(_) => ERROR_TLS_HANDSHAKE,
            ServerError::Auth(_) => ERROR_AUTH,
            ServerError::Config(_) => ERROR_CONFIG,
            ServerError::Proto(_) | ServerError::ProtoWrite(_) => ERROR_PROTOCOL,
            ServerError::Resolve => ERROR_RESOLVE,
            ServerError::UdpPayloadTooLarge => ERROR_PROTOCOL,
        }
    }
}
