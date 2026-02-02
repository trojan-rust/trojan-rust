//! Debug API endpoint for querying rule matching results.
//!
//! Provides a `/debug/rules/match` endpoint that returns how a request
//! would be routed by the rule engine, useful for debugging and testing
//! rule configurations.

use std::net::IpAddr;
use std::sync::Arc;

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Json, Router, routing::get};
use serde::Deserialize;
use trojan_rules::HotRuleEngine;

/// Shared state for debug API handlers.
#[derive(Clone)]
pub(crate) struct DebugState {
    pub rule_engine: Arc<HotRuleEngine>,
}

/// Query parameters for rule match endpoint.
#[derive(Deserialize)]
pub(crate) struct MatchQuery {
    /// Target domain name (optional).
    domain: Option<String>,
    /// Target IP address (optional).
    dest_ip: Option<IpAddr>,
    /// Target port (default: 443).
    #[serde(default = "default_port")]
    dest_port: u16,
    /// Source IP address (default: 127.0.0.1).
    #[serde(default = "default_src_ip")]
    src_ip: IpAddr,
}

fn default_port() -> u16 {
    443
}

fn default_src_ip() -> IpAddr {
    IpAddr::from([127, 0, 0, 1])
}

/// Build the debug API router with rule matching endpoint.
pub(crate) fn debug_routes(engine: Arc<HotRuleEngine>) -> Router {
    let state = DebugState {
        rule_engine: engine,
    };
    Router::new()
        .route("/debug/rules/match", get(handle_match))
        .with_state(state)
}

async fn handle_match(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<DebugState>,
    Query(q): Query<MatchQuery>,
) -> impl IntoResponse {
    // Only allow requests from loopback addresses.
    if !peer.ip().is_loopback() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "debug endpoint is only accessible from localhost"
            })),
        );
    }

    if q.domain.is_none() && q.dest_ip.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "at least one of 'domain' or 'dest_ip' must be provided"
            })),
        );
    }

    let ctx = trojan_rules::rule::MatchContext {
        domain: q.domain.as_deref(),
        dest_ip: q.dest_ip,
        dest_port: q.dest_port,
        src_ip: q.src_ip,
    };

    let action = state.rule_engine.match_request(&ctx);
    let action_str = match &action {
        trojan_rules::Action::Direct => "DIRECT".to_string(),
        trojan_rules::Action::Reject => "REJECT".to_string(),
        trojan_rules::Action::Outbound(name) => name.clone(),
    };

    // Warn when the result may differ from live routing: live traffic
    // resolves DNS lazily, so domain-only queries here may skip IP rules.
    let note = if q.domain.is_some() && q.dest_ip.is_none() {
        Some("domain-only query: IP-CIDR and GEOIP rules are not evaluated; \
              provide dest_ip for accurate results")
    } else {
        None
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "action": action_str,
            "domain": q.domain,
            "dest_ip": q.dest_ip.map(|ip| ip.to_string()),
            "dest_port": q.dest_port,
            "src_ip": q.src_ip.to_string(),
            "note": note,
        })),
    )
}
