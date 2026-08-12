//! Dashboard service for trojan-rs.
//!
//! Serves three audiences from one process:
//!
//! - **nodes** — `/verify`, `/traffic` and `/traffic/chain`, the protocol
//!   defined in [`trojan_auth::protocol`], so a node's `HttpAuth` backend
//!   points straight at this service
//! - **agents** — `/ws/agent`, where a node registers with its token, is
//!   handed its service config, and reports heartbeats and per-user traffic
//! - **operators** — `/admin/*`, guarded by a bearer token
//! - **users** — `/me` and `/sub/{name}`, for usage and subscription links,
//!   plus `/surge/panel.js`, the script a Surge information panel runs
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
mod cache;
mod codec;
mod config;
mod db;
mod entity;
mod error;
mod handler;
mod migration;
mod retention;
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

    // Opening the database also brings its schema up to date.
    let db = db::connect(&config.database_url()).await?;

    let state = state::AppState {
        db,
        cache: cache::Caches::new(config.verify_cache_ttl(), config.sub_cache_ttl()),
        admin_digest: Arc::new(sha224_hex(&admin_token)),
        cfg: Arc::new(config.clone()),
    };

    let app = routes::router(state.clone(), config.static_dir.as_deref());
    let listener = TcpListener::bind(&config.listen).await?;

    tracing::info!(
        listen = %config.listen,
        database = %config.database_url,
        panel = ?config.static_dir,
        "trojan dash listening"
    );

    // A child token so the sweeper stops when the server does, without
    // cancelling the caller's token on the way out.
    let internal = shutdown.child_token();
    let sweeper = tokio::spawn(retention::sweep(
        state.db.clone(),
        config.hourly_retention_days,
        internal.clone(),
    ));

    // ConnectInfo is what lets a node's source address reach the node list
    // when no reverse proxy is in front to set X-Forwarded-For.
    let serve = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    );

    let served = serve
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await;

    internal.cancel();
    let _ = sweeper.await;

    state.db.close().await?;
    served?;
    Ok(())
}
