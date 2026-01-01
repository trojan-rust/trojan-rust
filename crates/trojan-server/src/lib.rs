//! Trojan server library.
//!
//! This module exposes the server implementation for use by integration tests
//! and potential embedding scenarios.

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

pub use error::ServerError;
pub use pool::ConnectionPool;
pub use rate_limit::RateLimiter;
pub use server::{run, run_with_shutdown, DEFAULT_SHUTDOWN_TIMEOUT};
pub use tokio_util::sync::CancellationToken;
