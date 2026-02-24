//! Dynamic DNS update service with Cloudflare support.

mod cloudflare;
mod error;
mod ip;
mod runner;

pub use error::DdnsError;
pub use runner::ddns_loop;
