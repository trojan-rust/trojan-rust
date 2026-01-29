//! Client error types.

use std::fmt;

/// Errors that can occur in the trojan client.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(#[from] tokio_rustls::rustls::Error),

    #[error("DNS resolution failed for {0}")]
    Resolve(String),

    #[error("SOCKS5 error: {0}")]
    Socks5(Socks5Error),

    #[error("Trojan protocol error: {0:?}")]
    Proto(trojan_proto::WriteError),

    #[error("config error: {0}")]
    Config(String),
}

/// SOCKS5 protocol errors.
#[derive(Debug)]
pub enum Socks5Error {
    InvalidVersion(u8),
    NoAcceptableMethods,
    UnsupportedCommand(u8),
    UnsupportedAddressType(u8),
    FragmentedUdp,
}

impl fmt::Display for Socks5Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion(v) => write!(f, "invalid SOCKS version: 0x{v:02x}"),
            Self::NoAcceptableMethods => write!(f, "no acceptable authentication methods"),
            Self::UnsupportedCommand(c) => write!(f, "unsupported command: 0x{c:02x}"),
            Self::UnsupportedAddressType(a) => write!(f, "unsupported address type: 0x{a:02x}"),
            Self::FragmentedUdp => write!(f, "fragmented UDP not supported"),
        }
    }
}

impl std::error::Error for Socks5Error {}

impl From<Socks5Error> for ClientError {
    fn from(e: Socks5Error) -> Self {
        Self::Socks5(e)
    }
}

impl From<trojan_proto::WriteError> for ClientError {
    fn from(e: trojan_proto::WriteError) -> Self {
        Self::Proto(e)
    }
}
