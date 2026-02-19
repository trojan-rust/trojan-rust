//! User self-service endpoint (Basic Auth).

use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::*;

use crate::types::*;
use crate::util::check_basic_auth;

/// GET /me — Basic Auth (username:password)
/// Returns user info, traffic logs, and subscription template names.
pub async fn handle_me(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user = match check_basic_auth(&req, &ctx).await {
        Ok(u) => u,
        Err(_) => return Response::error("unauthorized", 401),
    };
    let user_id = user.id as u64;

    let d1 = ctx.env.d1("DB")?;

    // Traffic aggregated by node
    let traffic_stmt = d1.prepare(
        "SELECT t.node_id, n.name AS node_name, SUM(t.bytes) AS total_bytes \
         FROM traffic_logs t JOIN nodes n ON t.node_id = n.id \
         WHERE t.user_id = ?1 GROUP BY t.node_id ORDER BY total_bytes DESC",
    );
    let traffic_rows = traffic_stmt
        .bind(&[JsValue::from(user_id as f64)])?
        .all()
        .await?
        .results::<NodeTrafficRow>()?;
    let traffic_by_node: Vec<NodeTrafficResponse> =
        traffic_rows.iter().map(|r| r.to_response()).collect();

    // Sub template names
    let tpl_stmt = d1.prepare("SELECT name FROM sub_templates ORDER BY id");
    #[derive(Deserialize)]
    struct TplName {
        name: String,
    }
    let tpl_rows = tpl_stmt.all().await?.results::<TplName>()?;
    let sub_templates: Vec<String> = tpl_rows.into_iter().map(|r| r.name).collect();

    let resp = MeResponse {
        user: user.to_response(),
        traffic_by_node,
        sub_templates,
    };
    Response::from_json(&resp)
}
