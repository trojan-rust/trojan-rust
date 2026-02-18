//! Async DNS resolver for trojan-rs.
//!
//! Provides a shared, caching DNS resolver backed by
//! [`hickory-resolver`](https://crates.io/crates/hickory-resolver) with
//! support for custom nameservers (UDP/TCP), DNS-over-TLS, and
//! DNS-over-HTTPS.
//!
//! # Usage
//!
//! ```rust,no_run
//! use trojan_dns::{DnsConfig, DnsResolver};
//!
//! # async fn example() -> Result<(), trojan_dns::DnsError> {
//! let config = DnsConfig::default(); // system resolver with cache
//! let resolver = DnsResolver::new(&config)?;
//!
//! let addr = resolver.resolve("example.com:443").await?;
//! println!("resolved: {addr}");
//! # Ok(())
//! # }
//! ```

pub mod config;
pub mod error;
pub mod resolver;

pub use config::{DnsConfig, DnsStrategy};
pub use error::DnsError;
pub use resolver::DnsResolver;
