use wasm_bindgen::JsValue;
use worker::*;

use crate::types::*;

pub const CACHE_TTL: u64 = 3600; // 1 hour

pub fn sha224_hex(input: &str) -> String {
    use sha2::{Digest, Sha224};
    hex::encode(Sha224::digest(input.as_bytes()))
}

/// Generate a random password (24 random bytes, base64-encoded = 32 chars).
/// Equivalent to `openssl rand -base64 24`.
pub fn gen_password() -> String {
    use base64::Engine;
    let mut buf = [0u8; 24];
    getrandom::fill(&mut buf).expect("getrandom failed");
    base64::engine::general_purpose::STANDARD.encode(buf)
}

pub fn now_secs() -> u64 {
    Date::now().as_millis() / 1000
}

/// Return today's date as "YYYY-MM-DD" in UTC.
pub fn today_date() -> String {
    let ts = now_secs();
    let days = ts / 86400;
    // Convert days since epoch to y-m-d (civil calendar)
    // Algorithm from Howard Hinnant's chrono-compatible date algorithms
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}", y, m, d)
}

pub fn check_admin(req: &Request, ctx: &RouteContext<()>) -> Result<()> {
    let token = ctx.secret("ADMIN_TOKEN")?.to_string();
    let header = req.headers().get("Authorization")?.unwrap_or_default();
    if header != format!("Bearer {token}") {
        return Err(Error::from("unauthorized"));
    }
    Ok(())
}

pub async fn cache_put(kv: &kv::KvStore, hash: &str, data: &CacheData) -> Result<()> {
    let encoded = bincode::serialize(data).map_err(|e| Error::from(e.to_string()))?;
    kv.put_bytes(hash, &encoded)
        .map_err(|e| Error::from(e.to_string()))?
        .expiration_ttl(CACHE_TTL)
        .execute()
        .await
        .map_err(|e| Error::from(e.to_string()))
}

/// Default interval (seconds) between last_seen updates for nodes.
const DEFAULT_LAST_SEEN_TTL: u64 = 180;

/// Extract Bearer token from Authorization header, look up the node in D1,
/// verify it's enabled, update last_seen (throttled), and return the node id.
pub async fn check_node(req: &Request, ctx: &RouteContext<()>) -> Result<u64> {
    let header = req.headers().get("Authorization")?.unwrap_or_default();
    let token = header
        .strip_prefix("Bearer ")
        .ok_or_else(|| Error::from("unauthorized: missing bearer token"))?;

    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare("SELECT id, enabled, last_seen FROM nodes WHERE token = ?1");
    let query = stmt.bind(&[JsValue::from(token)])?;

    let node = query
        .first::<NodeLookup>(None)
        .await?
        .ok_or_else(|| Error::from("unauthorized: invalid node token"))?;

    if node.enabled == 0.0 {
        return Err(Error::from("unauthorized: node disabled"));
    }

    let node_id = node.id as u64;
    let now = now_secs();

    // Throttle last_seen updates: only write if older than TTL
    let ttl: u64 = ctx
        .var("NODE_LAST_SEEN_TTL")
        .ok()
        .and_then(|v| v.to_string().parse().ok())
        .unwrap_or(DEFAULT_LAST_SEEN_TTL);

    if now - (node.last_seen as u64) >= ttl {
        let ip = req
            .headers()
            .get("CF-Connecting-IP")
            .ok()
            .flatten()
            .unwrap_or_default();
        let update = d1.prepare("UPDATE nodes SET last_seen = ?1, ip = ?2 WHERE id = ?3");
        let _ = update
            .bind(&[
                JsValue::from(now as f64),
                JsValue::from(&ip),
                JsValue::from(node_id as f64),
            ])?
            .run()
            .await;
    }

    Ok(node_id)
}

/// Authenticate a user via HTTP Basic Auth (username:password).
/// Returns the UserRow on success.
pub async fn check_basic_auth(req: &Request, ctx: &RouteContext<()>) -> Result<UserRow> {
    let header = req
        .headers()
        .get("Authorization")?
        .unwrap_or_default();
    let encoded = header
        .strip_prefix("Basic ")
        .ok_or_else(|| Error::from("unauthorized"))?;

    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| Error::from("unauthorized"))?;
    let cred = String::from_utf8(decoded).map_err(|_| Error::from("unauthorized"))?;
    let (username, password) = cred
        .split_once(':')
        .ok_or_else(|| Error::from("unauthorized"))?;

    let hash = sha224_hex(password);
    let d1 = ctx.env.d1("DB")?;
    let stmt = d1.prepare("SELECT * FROM users WHERE username = ?1 AND hash = ?2");
    let query = stmt.bind(&[JsValue::from(username), JsValue::from(&hash)])?;

    query
        .first::<UserRow>(None)
        .await?
        .ok_or_else(|| Error::from("unauthorized"))
}

/// Parse a human-readable duration string like "24h", "30m", "1d12h", "90s".
/// Supported units: d (days), h (hours), m (minutes), s (seconds).
/// Returns total seconds, or 0 if the string is empty or invalid.
pub fn parse_duration_secs(s: &str) -> u64 {
    let s = s.trim();
    if s.is_empty() {
        return 0;
    }
    let mut total: u64 = 0;
    let mut num = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() {
            num.push(c);
        } else {
            let n: u64 = num.parse().unwrap_or(0);
            num.clear();
            match c {
                'd' => total += n * 86400,
                'h' => total += n * 3600,
                'm' => total += n * 60,
                's' => total += n,
                _ => {}
            }
        }
    }
    // Bare number without unit → treat as hours for backward compat
    if !num.is_empty() {
        let n: u64 = num.parse().unwrap_or(0);
        total += n * 3600;
    }
    total
}

/// Percent-encode a string for use in RFC 5987 `filename*` parameter.
/// Uses the `attr-char` set from RFC 5987 (unreserved chars only).
pub fn percent_encode_rfc5987(s: &str) -> String {
    /// RFC 5987 attr-char: ALPHA / DIGIT / "!" / "#" / "$" / "&" / "+" / "-" / "." /
    /// "^" / "_" / "`" / "|" / "~" (we use a conservative subset matching NON_ALPHANUMERIC
    /// minus the chars that need encoding in header parameters).
    const RFC5987_SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'!')
        .remove(b'#')
        .remove(b'$')
        .remove(b'&')
        .remove(b'+')
        .remove(b'-')
        .remove(b'.')
        .remove(b'^')
        .remove(b'_')
        .remove(b'`')
        .remove(b'|')
        .remove(b'~');
    percent_encoding::utf8_percent_encode(s, RFC5987_SET).to_string()
}

pub fn validate_user(data: &CacheData) -> std::result::Result<AuthResult, AuthError> {
    if !data.enabled {
        Err(AuthError::Disabled)
    } else if data.expires_at > 0 && now_secs() >= data.expires_at {
        Err(AuthError::Expired)
    } else if data.traffic_limit > 0 && data.traffic_used >= data.traffic_limit {
        Err(AuthError::TrafficExceeded)
    } else {
        Ok(AuthResult {
            user_id: Some(data.id.to_string()),
            metadata: Some(AuthMetadata {
                traffic_limit: data.traffic_limit,
                traffic_used: data.traffic_used,
                expires_at: data.expires_at,
                enabled: data.enabled,
            }),
        })
    }
}
