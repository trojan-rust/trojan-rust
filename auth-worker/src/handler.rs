//！Route handlers

use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::*;

use crate::types::*;
use crate::util::*;

/// POST /verify — bincode or JSON (auto-detected via Content-Type)
pub async fn handle_verify(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let codec = detect_codec(&req);
    let verify_req: VerifyRequest = decode(&mut req, &codec).await?;

    let kv = ctx.kv("CACHE")?;

    // 1. Try KV cache
    if let Some(cached) = kv.get(&verify_req.hash).bytes().await? {
        if let Ok(data) = bincode::deserialize::<CacheData>(&cached) {
            return encode(&validate_user(&data), &codec);
        }
    }

    // 2. Cache miss → D1
    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare("SELECT * FROM users WHERE hash = ?1");
    let query = stmt.bind(&[JsValue::from(&verify_req.hash)])?;

    let result: std::result::Result<AuthResult, AuthError> =
        match query.first::<UserRow>(None).await? {
            Some(row) => {
                let data = row.to_cache_data();
                let _ = cache_put(&kv, &verify_req.hash, &data).await;
                validate_user(&data)
            }
            None => Err(AuthError::NotFound),
        };

    encode(&result, &codec)
}

/// POST /traffic — bincode or JSON (auto-detected via Content-Type)
pub async fn handle_traffic(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let codec = detect_codec(&req);
    let traffic_req: TrafficRequest = decode(&mut req, &codec).await?;

    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare(
        "UPDATE users SET traffic_used = traffic_used + ?1 WHERE user_id = ?2 RETURNING hash",
    );
    let query = stmt.bind(&[
        JsValue::from(traffic_req.bytes as f64),
        JsValue::from(&traffic_req.user_id),
    ])?;

    #[derive(Deserialize)]
    struct Returning {
        hash: String,
    }

    let result: std::result::Result<(), AuthError> = match query.first::<Returning>(None).await? {
        Some(ret) => {
            let kv = ctx.kv("CACHE")?;
            let _ = kv.delete(&ret.hash).await;
            Ok(())
        }
        None => Err(AuthError::NotFound),
    };

    encode(&result, &codec)
}

/// POST /admin/users — JSON
pub async fn handle_add_user(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    check_admin(&req, &ctx)?;

    let body: AddUserRequest = req.json().await?;
    let hash = sha224_hex(&body.password);

    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare(
        "INSERT INTO users (hash, user_id, traffic_limit, traffic_used, expires_at, enabled) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    );
    stmt.bind(&[
        JsValue::from(&hash),
        JsValue::from(&body.user_id),
        JsValue::from(body.traffic_limit as f64),
        JsValue::from(0_f64),
        JsValue::from(body.expires_at as f64),
        JsValue::from(if body.enabled { 1_f64 } else { 0_f64 }),
    ])?
    .run()
    .await?;

    // Pre-warm cache
    let kv = ctx.kv("CACHE")?;
    let data = CacheData {
        user_id: body.user_id.clone(),
        traffic_limit: body.traffic_limit,
        traffic_used: 0,
        expires_at: body.expires_at,
        enabled: body.enabled,
    };
    let _ = cache_put(&kv, &hash, &data).await;

    Response::from_json(&UserResponse {
        hash,
        user_id: body.user_id,
        traffic_limit: body.traffic_limit,
        traffic_used: 0,
        expires_at: body.expires_at,
        enabled: body.enabled,
    })
}

/// GET /admin/users/:hash — JSON
pub async fn handle_get_user(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    check_admin(&req, &ctx)?;

    let hash = ctx.param("hash").unwrap();
    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare("SELECT * FROM users WHERE hash = ?1");
    let query = stmt.bind(&[JsValue::from(hash)])?;

    match query.first::<UserRow>(None).await? {
        Some(row) => Response::from_json(&UserResponse {
            hash: row.hash,
            user_id: row.user_id,
            traffic_limit: row.traffic_limit as u64,
            traffic_used: row.traffic_used as u64,
            expires_at: row.expires_at as u64,
            enabled: row.enabled != 0.0,
        }),
        None => Response::error("not found", 404),
    }
}

/// DELETE /admin/users/:hash
pub async fn handle_delete_user(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    check_admin(&req, &ctx)?;

    let hash = ctx.param("hash").unwrap();
    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare("DELETE FROM users WHERE hash = ?1");
    stmt.bind(&[JsValue::from(hash)])?.run().await?;

    let kv = ctx.kv("CACHE")?;
    let _ = kv.delete(hash).await;

    Response::ok("deleted")
}
