//! Dashboard service for trojan-rs.
//!
//! Serves three audiences from one process:
//!
//! - **nodes** — `/verify` and `/traffic`, the protocol defined in
//!   [`trojan_auth::protocol`], so a node's `HttpAuth` backend points straight
//!   at this service
//! - **operators** — `/admin/*`, guarded by a bearer token
//! - **users** — `/me` and `/sub/{name}`, for usage and subscription links
//!
//! Storage is SQLite. The built web panel, if configured, is served from the
//! same origin, so the browser needs no CORS exemption.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), trojan_dash::DashError> {
//! use tokio_util::sync::CancellationToken;
//! use trojan_dash::DashConfig;
//!
//! let config: DashConfig = toml::from_str(r#"
//!     listen = "127.0.0.1:8080"
//!     database = "dash.db"
//!     admin_token = "change-me"
//! "#).unwrap();
//!
//! trojan_dash::run(config, CancellationToken::new()).await
//! # }
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use trojan_auth::sha224_hex;

mod auth;
mod codec;
mod config;
mod db;
mod error;
mod handler;
mod routes;
mod state;
mod types;
mod util;

pub mod cli;

pub use cli::DashArgs;
pub use config::{ADMIN_TOKEN_ENV, DashConfig};
pub use error::DashError;

/// Run the service until `shutdown` is cancelled.
pub async fn run(config: DashConfig, shutdown: CancellationToken) -> Result<(), DashError> {
    let admin_token = config.resolve_admin_token()?;

    let pool = db::connect(&config.database_url()).await?;
    db::bootstrap(&pool).await?;

    let state = state::AppState {
        pool,
        admin_digest: Arc::new(sha224_hex(&admin_token)),
        node_last_seen_ttl: config.node_last_seen_ttl,
    };

    let app = routes::router(state.clone(), config.panel_dir.as_deref());
    let listener = TcpListener::bind(config.listen).await?;

    tracing::info!(
        listen = %config.listen,
        database = %config.database,
        panel = ?config.panel_dir,
        "trojan dash listening"
    );

    // ConnectInfo is what lets a node's source address reach the node list
    // when no reverse proxy is in front to set X-Forwarded-For.
    let serve = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    );

    serve
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await?;

    state.pool.close().await;
    Ok(())
}
