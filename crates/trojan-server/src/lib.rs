//! Trojan server library.
//!
//! This module exposes the server implementation for use by integration tests
//! and potential embedding scenarios.

pub mod cli;
#[cfg(feature = "rules")]
mod debug_api;
mod error;
mod handler;
#[cfg(feature = "rules")]
mod outbound;
mod pool;
mod rate_limit;
mod relay;
mod resolve;
#[cfg(feature = "rules")]
mod rules;
mod server;
mod state;
mod tls;
mod util;
#[cfg(feature = "ws")]
pub mod ws;

pub use cli::ServerArgs;
pub use error::ServerError;
pub use pool::ConnectionPool;
pub use rate_limit::RateLimiter;
pub use server::{DEFAULT_SHUTDOWN_TIMEOUT, run, run_with_shutdown};
pub use tokio_util::sync::CancellationToken;
