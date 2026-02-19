//! Admin node CRUD handlers.

use wasm_bindgen::JsValue;
use worker::*;

use crate::types::*;
use crate::util::*;

/// GET /admin/nodes — JSON
pub async fn handle_list_nodes(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare("SELECT * FROM nodes ORDER BY id");
    let results = stmt.all().await?.results::<NodeRow>()?;

    let nodes: Vec<NodeResponse> = results.iter().map(|r| r.to_response()).collect();
    Response::from_json(&nodes)
}

/// POST /admin/nodes — JSON
pub async fn handle_add_node(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let body: AddNodeRequest = req.json().await?;
    let token = gen_password();

    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare(
        "INSERT INTO nodes (name, token, enabled, last_seen, created_at) \
         VALUES (?1, ?2, 1, 0, ?3) RETURNING *",
    );
    let query = stmt.bind(&[
        JsValue::from(&body.name),
        JsValue::from(&token),
        JsValue::from(now_secs() as f64),
    ])?;

    match query.first::<NodeRow>(None).await? {
        Some(row) => Response::from_json(&row.to_response()),
        None => Response::error("insert failed", 500),
    }
}

/// GET /admin/nodes/:id — JSON
pub async fn handle_get_node(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let id = ctx.param("id").unwrap();
    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare("SELECT * FROM nodes WHERE id = ?1");
    let query = stmt.bind(&[JsValue::from(id)])?;

    match query.first::<NodeRow>(None).await? {
        Some(row) => Response::from_json(&row.to_response()),
        None => Response::error("not found", 404),
    }
}

/// PATCH /admin/nodes/:id — JSON
pub async fn handle_update_node(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let id = ctx.param("id").unwrap().to_string();
    let body: UpdateNodeRequest = req.json().await?;

    let mut sets = Vec::new();
    let mut binds: Vec<JsValue> = Vec::new();
    let mut idx = 1u32;

    if let Some(ref name) = body.name {
        sets.push(format!("name = ?{idx}"));
        binds.push(JsValue::from(name));
        idx += 1;
    }
    if let Some(enabled) = body.enabled {
        sets.push(format!("enabled = ?{idx}"));
        binds.push(JsValue::from(if enabled { 1_f64 } else { 0_f64 }));
        idx += 1;
    }

    if sets.is_empty() {
        return Response::error("no fields to update", 400);
    }

    let sql = format!(
        "UPDATE nodes SET {} WHERE id = ?{idx} RETURNING *",
        sets.join(", ")
    );
    binds.push(JsValue::from(&id));

    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare(&sql);
    let query = stmt.bind(&binds)?;

    match query.first::<NodeRow>(None).await? {
        Some(row) => Response::from_json(&row.to_response()),
        None => Response::error("not found", 404),
    }
}

/// DELETE /admin/nodes/:id
pub async fn handle_delete_node(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let id = ctx.param("id").unwrap();
    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare("DELETE FROM nodes WHERE id = ?1");
    stmt.bind(&[JsValue::from(id)])?.run().await?;

    Response::ok("deleted")
}

/// POST /admin/nodes/:id/rotate — regenerate node token
pub async fn handle_rotate_node_token(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let id = ctx.param("id").unwrap();
    let new_token = gen_password();

    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare("UPDATE nodes SET token = ?1 WHERE id = ?2 RETURNING *");
    let query = stmt.bind(&[JsValue::from(&new_token), JsValue::from(id)])?;

    match query.first::<NodeRow>(None).await? {
        Some(row) => Response::from_json(&row.to_response()),
        None => Response::error("not found", 404),
    }
}
