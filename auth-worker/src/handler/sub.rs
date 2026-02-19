//! Public subscription endpoint.

use wasm_bindgen::JsValue;
use worker::*;

use crate::types::*;
use crate::util::*;

/// GET /sub/:name?pwd=<password> — public, no admin auth
/// Validates pwd against users table, renders template with {{ pwd }}.
pub async fn handle_sub(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let name = ctx.param("name").unwrap();
    let url = req.url()?;
    let params: std::collections::HashMap<String, String> =
        url.query_pairs().into_owned().collect();

    let pwd = match params.get("pwd") {
        Some(p) if !p.is_empty() => p.clone(),
        _ => return Response::error("missing pwd parameter", 400),
    };

    let d1 = ctx.env.d1("DB")?;
    let kv = ctx.kv("CACHE")?;
    let cache_key = format!("sub:{name}");

    // 1. Look up template (KV cache → D1 fallback)
    let cached = kv
        .get(&cache_key)
        .text()
        .await?
        .and_then(|s| serde_json::from_str::<SubTemplateRow>(&s).ok());

    let tpl = match cached {
        Some(t) => t,
        None => {
            let tpl_stmt = d1.prepare("SELECT * FROM sub_templates WHERE name = ?1");
            match tpl_stmt
                .bind(&[JsValue::from(name)])?
                .first::<SubTemplateRow>(None)
                .await?
            {
                Some(t) => {
                    if let Ok(json) = serde_json::to_string(&t) {
                        let _ = kv
                            .put(&cache_key, &json)?
                            .expiration_ttl(3600)
                            .execute()
                            .await;
                    }
                    t
                }
                None => return Response::error("template not found", 404),
            }
        }
    };

    // 2. Validate pwd against users table
    let hash = sha224_hex(&pwd);
    let user_stmt = d1.prepare("SELECT * FROM users WHERE hash = ?1");
    let user = user_stmt
        .bind(&[JsValue::from(&hash)])?
        .first::<UserRow>(None)
        .await?;
    let user = match user {
        Some(u) => u,
        None => return Response::error("unauthorized", 401),
    };

    // 3. Check user validity (enabled, expiry, traffic)
    let data = user.to_cache_data();
    if validate_user(&data).is_err() {
        return Response::error("unauthorized", 401);
    }

    // 4. Render template — replace variables
    let interval_secs = parse_duration_secs(&tpl.update_interval);
    let interval_hours = interval_secs / 3600;
    let rendered = tpl
        .content
        .replace("{{ pwd }}", &pwd)
        .replace("{{ name }}", name)
        .replace("{{ update_interval_seconds }}", &interval_secs.to_string())
        .replace("{{ update_interval_hours }}", &interval_hours.to_string());

    // 5. Build response with subscription headers
    let mut resp = Response::ok(rendered)?;
    resp.headers_mut().set("Content-Type", &tpl.content_type)?;
    let preview = params.get("preview").is_some_and(|v| v == "1" || v == "true");
    if !preview && !tpl.filename.is_empty() {
        resp.headers_mut().set(
            "Content-Disposition",
            &format!("attachment; filename={}", tpl.filename),
        )?;
    }
    // subscription-userinfo: upload=0; download=<used>; total=<limit>; expire=<unix>
    resp.headers_mut().set(
        "subscription-userinfo",
        &format!(
            "upload=0; download={}; total={}; expire={}",
            data.traffic_used, data.traffic_limit, data.expires_at
        ),
    )?;
    if interval_hours > 0 {
        resp.headers_mut()
            .set("profile-update-interval", &interval_hours.to_string())?;
    }
    if !tpl.profile_url.is_empty() {
        resp.headers_mut()
            .set("profile-web-page-url", &tpl.profile_url)?;
    }
    Ok(resp)
}
