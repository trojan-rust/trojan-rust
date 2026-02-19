//! Admin user CRUD handlers.

use wasm_bindgen::JsValue;
use worker::*;

use crate::types::*;
use crate::util::*;

/// GET /admin/users — JSON
pub async fn handle_list_users(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare("SELECT * FROM users ORDER BY id");
    let results = stmt.all().await?.results::<UserRow>()?;

    let users: Vec<UserResponse> = results.iter().map(|r| r.to_response()).collect();
    Response::from_json(&users)
}

/// POST /admin/users — JSON
pub async fn handle_add_user(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let body: AddUserRequest = req.json().await?;
    let password = match body.password {
        Some(ref p) if !p.is_empty() => p.clone(),
        _ => gen_password(),
    };
    let hash = sha224_hex(&password);

    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare(
        "INSERT INTO users (hash, username, traffic_limit, traffic_used, expires_at, enabled) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) RETURNING *",
    );
    let query = stmt.bind(&[
        JsValue::from(&hash),
        JsValue::from(&body.username),
        JsValue::from(body.traffic_limit as f64),
        JsValue::from(0_f64),
        JsValue::from(body.expires_at as f64),
        JsValue::from(if body.enabled { 1_f64 } else { 0_f64 }),
    ])?;

    match query.first::<UserRow>(None).await? {
        Some(row) => {
            // Pre-warm cache
            let kv = ctx.kv("CACHE")?;
            let data = row.to_cache_data();
            let _ = cache_put(&kv, &hash, &data).await;

            let mut resp = row.to_response();
            resp.password = Some(password);
            Response::from_json(&resp)
        }
        None => Response::error("insert failed", 500),
    }
}

/// GET /admin/users/:id — JSON
pub async fn handle_get_user(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let id = ctx.param("id").unwrap();
    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare("SELECT * FROM users WHERE id = ?1");
    let query = stmt.bind(&[JsValue::from(id)])?;

    match query.first::<UserRow>(None).await? {
        Some(row) => Response::from_json(&row.to_response()),
        None => Response::error("not found", 404),
    }
}

/// PATCH /admin/users/:id — JSON
pub async fn handle_update_user(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let id = ctx.param("id").unwrap().to_string();
    let body: UpdateUserRequest = req.json().await?;

    // Build dynamic SET clause
    let mut sets = Vec::new();
    let mut binds: Vec<JsValue> = Vec::new();
    let mut idx = 1u32;

    if let Some(ref username) = body.username {
        sets.push(format!("username = ?{idx}"));
        binds.push(JsValue::from(username));
        idx += 1;
    }
    if let Some(traffic_limit) = body.traffic_limit {
        sets.push(format!("traffic_limit = ?{idx}"));
        binds.push(JsValue::from(traffic_limit as f64));
        idx += 1;
    }
    if let Some(traffic_used) = body.traffic_used {
        sets.push(format!("traffic_used = ?{idx}"));
        binds.push(JsValue::from(traffic_used as f64));
        idx += 1;
    }
    if let Some(expires_at) = body.expires_at {
        sets.push(format!("expires_at = ?{idx}"));
        binds.push(JsValue::from(expires_at as f64));
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
        "UPDATE users SET {} WHERE id = ?{idx} RETURNING *",
        sets.join(", ")
    );
    binds.push(JsValue::from(&id));

    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare(&sql);
    let query = stmt.bind(&binds)?;

    match query.first::<UserRow>(None).await? {
        Some(row) => {
            // Update KV cache with new data (avoids a delete operation)
            let kv = ctx.kv("CACHE")?;
            let _ = cache_put(&kv, &row.hash, &row.to_cache_data()).await;

            Response::from_json(&row.to_response())
        }
        None => Response::error("not found", 404),
    }
}

/// DELETE /admin/users/:id
pub async fn handle_delete_user(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let id = ctx.param("id").unwrap();
    let d1 = ctx.env.d1("DB")?;

    // Get hash for cache invalidation before deleting
    let stmt = d1.prepare("DELETE FROM users WHERE id = ?1 RETURNING hash");
    let query = stmt.bind(&[JsValue::from(id)])?;

    #[derive(serde::Deserialize)]
    struct Returning {
        hash: String,
    }

    if let Some(ret) = query.first::<Returning>(None).await? {
        let kv = ctx.kv("CACHE")?;
        let _ = kv.delete(&ret.hash).await;
    }

    Response::ok("deleted")
}
