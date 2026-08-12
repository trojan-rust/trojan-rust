//! The Surge information panel script.
//!
//! Surge downloads `script-path` itself and caches it, so the script it runs is
//! served by the same build that answers the `/me` it parses — one URL for an
//! operator to point a module at, and no version to keep in step by hand.

use axum::http::header;
use axum::response::IntoResponse;

const PANEL_JS: &str = include_str!("../../assets/surge-panel.js");

/// `GET /surge/panel.js`
pub async fn panel_js() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            // Surge re-fetches on its own `script-update-interval`; this is for
            // whatever caches the response on the way.
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        PANEL_JS,
    )
}
