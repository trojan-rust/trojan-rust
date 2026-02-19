//! Admin sub template CRUD handlers.

use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::*;

use crate::types::*;
use crate::util::now_secs;

/// GET /admin/sub-templates — JSON
pub async fn handle_list_sub_templates(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare("SELECT * FROM sub_templates ORDER BY id");
    let results = stmt.all().await?.results::<SubTemplateRow>()?;

    let templates: Vec<SubTemplateResponse> = results.iter().map(|r| r.to_response()).collect();
    Response::from_json(&templates)
}

/// POST /admin/sub-templates — JSON
pub async fn handle_add_sub_template(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let body: AddSubTemplateRequest = req.json().await?;
    let now = now_secs();

    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare(
        "INSERT INTO sub_templates (name, filename, content, content_type, update_interval, profile_url, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) RETURNING *",
    );
    let query = stmt.bind(&[
        JsValue::from(&body.name),
        JsValue::from(&body.filename),
        JsValue::from(&body.content),
        JsValue::from(&body.content_type),
        JsValue::from(&body.update_interval),
        JsValue::from(&body.profile_url),
        JsValue::from(now as f64),
        JsValue::from(now as f64),
    ])?;

    match query.first::<SubTemplateRow>(None).await? {
        Some(row) => Response::from_json(&row.to_response()),
        None => Response::error("insert failed", 500),
    }
}

/// GET /admin/sub-templates/:id — JSON
pub async fn handle_get_sub_template(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let id = ctx.param("id").unwrap();
    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare("SELECT * FROM sub_templates WHERE id = ?1");
    let query = stmt.bind(&[JsValue::from(id)])?;

    match query.first::<SubTemplateRow>(None).await? {
        Some(row) => Response::from_json(&row.to_response()),
        None => Response::error("not found", 404),
    }
}

/// PATCH /admin/sub-templates/:id — JSON
pub async fn handle_update_sub_template(
    mut req: Request,
    ctx: RouteContext<()>,
) -> Result<Response> {
    let id = ctx.param("id").unwrap().to_string();
    let body: UpdateSubTemplateRequest = req.json().await?;

    // Fetch old name for cache invalidation (in case name changes)
    let d1 = ctx.env.d1("DB")?;
    #[derive(Deserialize)]
    struct OldName {
        name: String,
    }
    let old_name = d1
        .prepare("SELECT name FROM sub_templates WHERE id = ?1")
        .bind(&[JsValue::from(&id)])?
        .first::<OldName>(None)
        .await?
        .map(|r| r.name);

    let mut sets = Vec::new();
    let mut binds: Vec<JsValue> = Vec::new();
    let mut idx = 1u32;

    if let Some(ref name) = body.name {
        sets.push(format!("name = ?{idx}"));
        binds.push(JsValue::from(name));
        idx += 1;
    }
    if let Some(ref filename) = body.filename {
        sets.push(format!("filename = ?{idx}"));
        binds.push(JsValue::from(filename));
        idx += 1;
    }
    if let Some(ref content) = body.content {
        sets.push(format!("content = ?{idx}"));
        binds.push(JsValue::from(content));
        idx += 1;
    }
    if let Some(ref content_type) = body.content_type {
        sets.push(format!("content_type = ?{idx}"));
        binds.push(JsValue::from(content_type));
        idx += 1;
    }
    if let Some(ref update_interval) = body.update_interval {
        sets.push(format!("update_interval = ?{idx}"));
        binds.push(JsValue::from(update_interval));
        idx += 1;
    }
    if let Some(ref profile_url) = body.profile_url {
        sets.push(format!("profile_url = ?{idx}"));
        binds.push(JsValue::from(profile_url));
        idx += 1;
    }

    if sets.is_empty() {
        return Response::error("no fields to update", 400);
    }

    // Always update updated_at
    sets.push(format!("updated_at = ?{idx}"));
    binds.push(JsValue::from(now_secs() as f64));
    idx += 1;

    let sql = format!(
        "UPDATE sub_templates SET {} WHERE id = ?{idx} RETURNING *",
        sets.join(", ")
    );
    binds.push(JsValue::from(&id));

    let stmt = d1.prepare(&sql);
    let query = stmt.bind(&binds)?;

    match query.first::<SubTemplateRow>(None).await? {
        Some(row) => {
            // Update KV cache with new data (avoids a delete + stale window)
            let kv = ctx.kv("CACHE")?;
            if let Ok(json) = serde_json::to_string(&row) {
                let _ = kv
                    .put(&format!("sub:{}", row.name), &json)?
                    .expiration_ttl(3600)
                    .execute()
                    .await;
            }
            // On rename, invalidate old name's cache entry
            if let Some(old) = old_name {
                if old != row.name {
                    let _ = kv.delete(&format!("sub:{old}")).await;
                }
            }
            Response::from_json(&row.to_response())
        }
        None => Response::error("not found", 404),
    }
}

/// DELETE /admin/sub-templates/:id
pub async fn handle_delete_sub_template(
    _req: Request,
    ctx: RouteContext<()>,
) -> Result<Response> {
    let id = ctx.param("id").unwrap();
    let d1 = ctx.env.d1("DB")?;

    // Get name for cache invalidation
    #[derive(Deserialize)]
    struct Returning {
        name: String,
    }
    let stmt = d1.prepare("DELETE FROM sub_templates WHERE id = ?1 RETURNING name");
    if let Some(ret) = stmt
        .bind(&[JsValue::from(id)])?
        .first::<Returning>(None)
        .await?
    {
        let kv = ctx.kv("CACHE")?;
        let _ = kv.delete(&format!("sub:{}", ret.name)).await;
    }

    Response::ok("deleted")
}
