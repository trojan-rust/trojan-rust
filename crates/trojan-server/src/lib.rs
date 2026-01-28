//! Trojan server library.
//!
//! This module exposes the server implementation for use by integration tests
//! and potential embedding scenarios.

pub mod cli;
mod error;
mod handler;
mod pool;
mod rate_limit;
mod relay;
mod resolve;
mod server;
mod state;
mod tls;
mod util;
#[cfg(feature = "ws")]
mod ws;

pub use cli::ServerArgs;
pub use error::ServerError;
pub use pool::ConnectionPool;
pub use rate_limit::RateLimiter;
pub use server::{DEFAULT_SHUTDOWN_TIMEOUT, run, run_with_shutdown};
pub use tokio_util::sync::CancellationToken;
