//! Router assembly.

use std::path::Path;

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use tower_http::services::{ServeDir, ServeFile};

use crate::auth::AdminAuth;
use crate::db;
use crate::error::DashError;
use crate::handler::{agent, me, node_api, nodes, sub, templates, traffic, users};
use crate::state::AppState;

/// Build the router. When `panel_dir` is set the built panel is served from
/// `/`, with unknown paths falling back to `index.html` so client-side routes
/// survive a reload.
pub fn router(state: AppState, panel_dir: Option<&Path>) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/admin/version", get(version))
        // Node-facing
        .route("/verify", post(node_api::verify))
        .route("/traffic", post(node_api::traffic))
        .route("/traffic/chain", post(node_api::chain_traffic))
        // Agents
        .route("/ws/agent", get(agent::ws))
        // Admin — users
        .route("/admin/users", get(users::list).post(users::add))
        .route(
            "/admin/users/{id}",
            get(users::get).patch(users::update).delete(users::remove),
        )
        // Admin — nodes
        .route("/admin/nodes", get(nodes::list).post(nodes::add))
        .route(
            "/admin/nodes/{id}",
            get(nodes::get).patch(nodes::update).delete(nodes::remove),
        )
        .route("/admin/nodes/{id}/rotate", post(nodes::rotate))
        // Admin — traffic
        .route("/admin/traffic", get(traffic::list))
        .route("/admin/traffic/daily", get(traffic::daily))
        // Admin — subscription templates
        .route(
            "/admin/sub-templates",
            get(templates::list).post(templates::add),
        )
        .route(
            "/admin/sub-templates/{id}",
            get(templates::get)
                .patch(templates::update)
                .delete(templates::remove),
        )
        .route("/admin/migrate", post(migrate))
        // Public
        .route("/sub/{name}", get(sub::sub))
        .route("/me", get(me::me))
        .with_state(state);

    match panel_dir {
        Some(dir) => api
            .fallback_service(ServeDir::new(dir).fallback(ServeFile::new(dir.join("index.html")))),
        None => api,
    }
}

/// `GET /health`
async fn health() -> &'static str {
    "ok"
}

/// `GET /admin/version` — unauthenticated, as it was on Workers.
async fn version() -> &'static str {
    trojan_core::VERSION
}

/// `POST /admin/migrate` — re-apply the schema.
///
/// Startup already does this; the route stays so an operator can repair a
/// database without restarting.
async fn migrate(
    State(state): State<AppState>,
    _admin: AdminAuth,
) -> Result<&'static str, DashError> {
    db::bootstrap(&state.pool).await?;
    Ok("migrated")
}
