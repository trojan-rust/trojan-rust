//! Public subscription endpoint.
//!
//! Clients fetch this URL directly, so the credential travels as a query
//! parameter and the response carries the headers subscription clients read.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use trojan_auth::sha224_hex;

use crate::entity::{sub_templates, users};
use crate::error::DashError;
use crate::state::AppState;
use crate::types::{CacheData, SubQuery};
use crate::util::{basic_auth, now_secs, parse_duration_secs, percent_encode_rfc5987};

/// `GET /sub/{name}?pwd=`
pub async fn sub(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<SubQuery>,
) -> Result<Response, DashError> {
    let pwd = query
        .pwd
        .filter(|p| !p.is_empty())
        .ok_or_else(|| DashError::BadRequest("missing pwd parameter".to_owned()))?;

    let template = match state.cache.sub.get(&name).await {
        Some(cached) => cached,
        None => {
            let row = sub_templates::Entity::find()
                .filter(sub_templates::Column::Name.eq(&name))
                .one(&state.db)
                .await?
                .ok_or(DashError::NotFound)?;
            state.cache.sub.insert(name.clone(), row.clone()).await;
            row
        }
    };

    let user = users::Entity::find()
        .filter(users::Column::Hash.eq(sha224_hex(&pwd)))
        .one(&state.db)
        .await?
        .ok_or(DashError::Unauthorized)?;

    let data = CacheData::from(&user);
    let auth = data
        .validate(now_secs())
        .map_err(|_| DashError::Unauthorized)?;
    let meta = auth.metadata.ok_or(DashError::Unauthorized)?;

    let interval_secs = parse_duration_secs(&template.update_interval);
    let interval_hours = interval_secs / 3600;
    let rendered = template
        .content
        .replace("{{ pwd }}", &pwd)
        .replace("{{ name }}", &name)
        .replace("{{ username }}", &user.username)
        .replace("{{ basic_auth }}", &basic_auth(&user.username, &pwd))
        .replace("{{ update_interval_seconds }}", &interval_secs.to_string())
        .replace("{{ update_interval_hours }}", &interval_hours.to_string());

    let mut response = rendered.into_response();
    let headers = response.headers_mut();

    let invalid = |field: &str| DashError::Config(format!("template {name}: invalid {field}"));

    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&template.content_type).map_err(|_| invalid("content_type"))?,
    );

    let preview = query.preview.is_some_and(|v| v == "1" || v == "true");
    if !preview && !template.filename.is_empty() {
        // RFC 6266 + RFC 5987: a quoted ASCII filename for compatibility, and
        // filename* for anything beyond ASCII. FlClash (Dart) rejects an
        // unquoted filename; see FlClash#937.
        let ascii: String = template.filename.chars().filter(char::is_ascii).collect();
        let encoded = percent_encode_rfc5987(&template.filename);
        headers.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_str(&format!(
                "attachment; filename=\"{ascii}\"; filename*=UTF-8''{encoded}"
            ))
            .map_err(|_| invalid("filename"))?,
        );
    }

    // What subscription clients display as remaining quota.
    headers.insert(
        "subscription-userinfo",
        HeaderValue::from_str(&format!(
            "upload=0; download={}; total={}; expire={}",
            meta.traffic_used, meta.traffic_limit, meta.expires_at
        ))
        .map_err(|_| invalid("subscription-userinfo"))?,
    );

    if interval_hours > 0 {
        headers.insert("profile-update-interval", HeaderValue::from(interval_hours));
    }

    if !template.profile_url.is_empty() {
        headers.insert(
            "profile-web-page-url",
            HeaderValue::from_str(&template.profile_url).map_err(|_| invalid("profile_url"))?,
        );
    }

    Ok(response)
}
