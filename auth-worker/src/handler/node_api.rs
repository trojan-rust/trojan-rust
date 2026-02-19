//! Node-facing API: verify and traffic (Bearer token auth).

use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::*;

use crate::types::*;
use crate::util::*;

/// POST /verify — bincode or JSON (auto-detected via Content-Type)
/// Requires node Bearer token in Authorization header.
pub async fn handle_verify(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let _node_id = check_node(&req, &ctx).await?;
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
/// Requires node Bearer token in Authorization header.
/// Also inserts a row into traffic_logs for per-node tracking.
pub async fn handle_traffic(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let node_id = check_node(&req, &ctx).await?;
    let codec = detect_codec(&req);
    let traffic_req: TrafficRequest = decode(&mut req, &codec).await?;

    let d1 = ctx.env.d1("DB")?;

    // Note: we no longer invalidate the KV user cache here.
    // The verify cache has a 5-min TTL, so traffic_used will be
    // slightly stale but will self-correct on next cache miss.
    // This avoids burning KV delete operations on every traffic report.

    #[derive(Deserialize)]
    struct Returning {
        _id: f64,
    }

    let update = d1
        .prepare("UPDATE users SET traffic_used = traffic_used + ?1 WHERE id = ?2 RETURNING id AS _id");
    let row = update
        .bind(&[
            JsValue::from(traffic_req.bytes as f64),
            JsValue::from(&traffic_req.user_id),
        ])?
        .first::<Returning>(None)
        .await?;

    let result: std::result::Result<(), AuthError> = match row {
        Some(_) => {
            // Upsert daily traffic aggregation
            let log_stmt = d1.prepare(
                "INSERT INTO traffic_logs (user_id, node_id, bytes, date) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(user_id, node_id, date) DO UPDATE SET bytes = bytes + ?3",
            );
            let _ = log_stmt
                .bind(&[
                    JsValue::from(&traffic_req.user_id),
                    JsValue::from(node_id as f64),
                    JsValue::from(traffic_req.bytes as f64),
                    JsValue::from(&today_date()),
                ])?
                .run()
                .await;

            Ok(())
        }
        None => Err(AuthError::NotFound),
    };

    encode(&result, &codec)
}
