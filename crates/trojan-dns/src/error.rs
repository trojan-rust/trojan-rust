//! DNS resolver errors.

use std::net::AddrParseError;

/// Errors from DNS resolution.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    /// DNS lookup returned no results.
    #[error("dns lookup returned no results for {0}")]
    NoResults(String),

    /// DNS lookup failed.
    #[error("dns lookup failed: {0}")]
    Lookup(#[from] hickory_resolver::ResolveError),

    /// Invalid address format (missing port, bad IP, etc.).
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    /// Failed to parse IP address.
    #[error("invalid IP address: {0}")]
    AddrParse(#[from] AddrParseError),

    /// Invalid DNS server URL.
    #[error("invalid dns server url: {0}")]
    InvalidServer(String),
}
