//! Dynamic DNS update service with Cloudflare support.
//!
//! The config types are always available; the updater itself sits behind the
//! default `updater` feature, so a crate that only needs to name [`DdnsConfig`]
//! does not compile an HTTP client and the Cloudflare API bindings.

#[cfg(feature = "updater")]
mod cloudflare;
pub mod config;
#[cfg(feature = "updater")]
mod error;
#[cfg(feature = "updater")]
mod ip;
#[cfg(feature = "updater")]
mod runner;

#[cfg(feature = "updater")]
pub use cloudflare::CloudflareUpdater;
pub use config::{CloudflareDdnsConfig, DdnsConfig};
#[cfg(feature = "updater")]
pub use error::DdnsError;
#[cfg(feature = "updater")]
pub use runner::ddns_loop;
