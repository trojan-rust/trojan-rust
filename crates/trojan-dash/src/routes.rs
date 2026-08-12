//! Router assembly.

use std::path::Path;

use axum::Router;
use axum::middleware;
use axum::routing::{get, post, put};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

use crate::auth::require_admin;
use crate::handler::{agent, limits, me, node_api, nodes, sub, surge, templates, traffic, users};
use crate::state::AppState;

/// Build the router. When the panel directory exists its contents are served
/// from `/`, with unknown paths falling back to `index.html` so client-side
/// routes survive a reload.
pub fn router(state: AppState, panel_dir: Option<&Path>) -> Router {
    let public = Router::new()
        .route("/health", get(health))
        .route("/admin/version", get(version))
        // Node-facing
        .route("/verify", post(node_api::verify))
        .route("/traffic", post(node_api::traffic))
        .route("/traffic/chain", post(node_api::chain_traffic))
        .route("/ws/agent", get(agent::ws))
        // User-facing
        .route("/sub/{name}", get(sub::sub))
        .route("/me", get(me::me))
        .route("/me/traffic", get(me::traffic))
        // Client-facing: the script a Surge panel runs against /me.
        .route("/surge/panel.js", get(surge::panel_js));

    // One guard for the whole admin surface: a route added here cannot forget
    // to authenticate.
    let admin = Router::new()
        .route("/admin/users", get(users::list).post(users::add))
        .route(
            "/admin/users/{id}",
            get(users::get).patch(users::update).delete(users::remove),
        )
        .route("/admin/users/{id}/limits", get(limits::list))
        .route(
            "/admin/users/{id}/limits/{node_id}",
            put(limits::set).delete(limits::remove),
        )
        .route("/admin/nodes", get(nodes::list).post(nodes::add))
        .route(
            "/admin/nodes/{id}",
            get(nodes::get).patch(nodes::update).delete(nodes::remove),
        )
        .route("/admin/nodes/{id}/rotate", post(nodes::rotate))
        .route("/admin/traffic", get(traffic::list))
        .route("/admin/traffic/series", get(traffic::series))
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
        .route_layer(middleware::from_fn_with_state(state.clone(), require_admin));

    let mut app = Router::new().merge(public).merge(admin);

    // Migrations run at startup, so there is no /admin/migrate: a schema this
    // binary can serve is a schema it already applied.
    match panel_dir {
        Some(dir) if dir.is_dir() => {
            tracing::info!(path = %dir.display(), "serving the panel");
            app = app.fallback_service(
                ServeDir::new(dir).fallback(ServeFile::new(dir.join("index.html"))),
            );
        }
        Some(dir) => {
            tracing::warn!(path = %dir.display(), "panel directory not found — serving the API alone");
        }
        None => {}
    }

    app.layer(TraceLayer::new_for_http()).with_state(state)
}

/// `GET /health`
async fn health() -> &'static str {
    "ok"
}

/// `GET /admin/version` — unauthenticated, as the previous panel had it.
async fn version() -> &'static str {
    trojan_core::VERSION
}
