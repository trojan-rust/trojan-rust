//! Admin traffic log handler.

use wasm_bindgen::JsValue;
use worker::*;

use crate::types::*;

/// GET /admin/traffic?user_id=X&node_id=Y — JSON (optional filters)
pub async fn handle_list_traffic(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let url = _req.url()?;
    let params: std::collections::HashMap<String, String> =
        url.query_pairs().into_owned().collect();

    let mut conditions = Vec::new();
    let mut binds: Vec<JsValue> = Vec::new();
    let mut idx = 1u32;

    if let Some(user_id) = params.get("user_id") {
        conditions.push(format!("user_id = ?{idx}"));
        binds.push(JsValue::from(user_id));
        idx += 1;
    }
    if let Some(node_id) = params.get("node_id") {
        conditions.push(format!("node_id = ?{idx}"));
        binds.push(JsValue::from(node_id));
        let _ = idx; // suppress unused warning
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };

    let sql = format!("SELECT * FROM traffic_logs{where_clause} ORDER BY date DESC, id DESC LIMIT 1000");

    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare(&sql);
    let query = if binds.is_empty() {
        stmt.all().await?
    } else {
        stmt.bind(&binds)?.all().await?
    };

    let rows = query.results::<TrafficLogRow>()?;
    let logs: Vec<TrafficLogResponse> = rows.iter().map(|r| r.to_response()).collect();
    Response::from_json(&logs)
}
