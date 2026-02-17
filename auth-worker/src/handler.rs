//! Route handlers

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
    let stmt = d1
        .prepare("UPDATE users SET traffic_used = traffic_used + ?1 WHERE id = ?2 RETURNING hash");
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
            // Invalidate KV cache
            let kv = ctx.kv("CACHE")?;
            let _ = kv.delete(&ret.hash).await;

            // Insert traffic log entry
            let log_stmt = d1.prepare(
                "INSERT INTO traffic_logs (user_id, node_id, bytes, recorded_at) \
                 VALUES (?1, ?2, ?3, ?4)",
            );
            let _ = log_stmt
                .bind(&[
                    JsValue::from(&traffic_req.user_id),
                    JsValue::from(node_id as f64),
                    JsValue::from(traffic_req.bytes as f64),
                    JsValue::from(now_secs() as f64),
                ])?
                .run()
                .await;

            Ok(())
        }
        None => Err(AuthError::NotFound),
    };

    encode(&result, &codec)
}

/// GET /admin/users — JSON
pub async fn handle_list_users(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    check_admin(&req, &ctx)?;

    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare("SELECT * FROM users ORDER BY id");
    let results = stmt.all().await?.results::<UserRow>()?;

    let users: Vec<UserResponse> = results.iter().map(|r| r.to_response()).collect();
    Response::from_json(&users)
}

/// POST /admin/users — JSON
pub async fn handle_add_user(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    check_admin(&req, &ctx)?;

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
pub async fn handle_get_user(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    check_admin(&req, &ctx)?;

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
    check_admin(&req, &ctx)?;

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
            // Invalidate KV cache
            let kv = ctx.kv("CACHE")?;
            let _ = kv.delete(&row.hash).await;

            Response::from_json(&row.to_response())
        }
        None => Response::error("not found", 404),
    }
}

/// DELETE /admin/users/:id
pub async fn handle_delete_user(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    check_admin(&req, &ctx)?;

    let id = ctx.param("id").unwrap();
    let d1 = ctx.env.d1("DB")?;

    // Get hash for cache invalidation before deleting
    let stmt = d1.prepare("DELETE FROM users WHERE id = ?1 RETURNING hash");
    let query = stmt.bind(&[JsValue::from(id)])?;

    #[derive(Deserialize)]
    struct Returning {
        hash: String,
    }

    if let Some(ret) = query.first::<Returning>(None).await? {
        let kv = ctx.kv("CACHE")?;
        let _ = kv.delete(&ret.hash).await;
    }

    Response::ok("deleted")
}

// ── Node CRUD ────────────────────────────────────────────────────

/// GET /admin/nodes — JSON
pub async fn handle_list_nodes(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    check_admin(&req, &ctx)?;

    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare("SELECT * FROM nodes ORDER BY id");
    let results = stmt.all().await?.results::<NodeRow>()?;

    let nodes: Vec<NodeResponse> = results.iter().map(|r| r.to_response()).collect();
    Response::from_json(&nodes)
}

/// POST /admin/nodes — JSON
pub async fn handle_add_node(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    check_admin(&req, &ctx)?;

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
pub async fn handle_get_node(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    check_admin(&req, &ctx)?;

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
    check_admin(&req, &ctx)?;

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
pub async fn handle_delete_node(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    check_admin(&req, &ctx)?;

    let id = ctx.param("id").unwrap();
    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare("DELETE FROM nodes WHERE id = ?1");
    stmt.bind(&[JsValue::from(id)])?.run().await?;

    Response::ok("deleted")
}

/// POST /admin/nodes/:id/rotate — regenerate node token
pub async fn handle_rotate_node_token(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    check_admin(&req, &ctx)?;

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

// ── Traffic Logs ─────────────────────────────────────────────────

/// GET /admin/traffic?user_id=X&node_id=Y — JSON (optional filters)
pub async fn handle_list_traffic(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    check_admin(&req, &ctx)?;

    let url = req.url()?;
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

    let sql = format!("SELECT * FROM traffic_logs{where_clause} ORDER BY id DESC LIMIT 1000");

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

// ── Migration ────────────────────────────────────────────────────

/// POST /admin/migrate — auto-create tables
pub async fn handle_migrate(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    check_admin(&req, &ctx)?;

    let d1 = ctx.env.d1("DB")?;

    d1.prepare(
        "CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            hash          TEXT NOT NULL UNIQUE,
            username      TEXT NOT NULL UNIQUE,
            traffic_limit INTEGER NOT NULL DEFAULT 0,
            traffic_used  INTEGER NOT NULL DEFAULT 0,
            expires_at    INTEGER NOT NULL DEFAULT 0,
            enabled       INTEGER NOT NULL DEFAULT 1
        )",
    )
    .run()
    .await?;

    d1.prepare("CREATE INDEX IF NOT EXISTS idx_users_hash ON users(hash)")
        .run()
        .await?;

    d1.prepare(
        "CREATE TABLE IF NOT EXISTS nodes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL UNIQUE,
            token      TEXT NOT NULL UNIQUE,
            enabled    INTEGER NOT NULL DEFAULT 1,
            ip         TEXT NOT NULL DEFAULT '',
            last_seen  INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL DEFAULT 0
        )",
    )
    .run()
    .await?;

    d1.prepare(
        "CREATE TABLE IF NOT EXISTS traffic_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id),
            node_id     INTEGER NOT NULL REFERENCES nodes(id),
            bytes       INTEGER NOT NULL,
            recorded_at INTEGER NOT NULL
        )",
    )
    .run()
    .await?;

    d1.prepare("CREATE INDEX IF NOT EXISTS idx_traffic_logs_user ON traffic_logs(user_id)")
        .run()
        .await?;

    d1.prepare("CREATE INDEX IF NOT EXISTS idx_traffic_logs_node ON traffic_logs(node_id)")
        .run()
        .await?;

    Response::ok("migrated")
}
