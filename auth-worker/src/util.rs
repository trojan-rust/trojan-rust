use worker::*;

use crate::types::*;

pub const CACHE_TTL: u64 = 300; // 5 min

pub fn sha224_hex(input: &str) -> String {
    use sha2::{Digest, Sha224};
    hex::encode(Sha224::digest(input.as_bytes()))
}

pub fn now_secs() -> u64 {
    Date::now().as_millis() / 1000
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

pub fn validate_user(data: &CacheData) -> std::result::Result<AuthResult, AuthError> {
    if !data.enabled {
        Err(AuthError::Disabled)
    } else if data.expires_at > 0 && now_secs() >= data.expires_at {
        Err(AuthError::Expired)
    } else if data.traffic_limit > 0 && data.traffic_used >= data.traffic_limit {
        Err(AuthError::TrafficExceeded)
    } else {
        Ok(AuthResult {
            user_id: Some(data.user_id.clone()),
            metadata: Some(AuthMetadata {
                traffic_limit: data.traffic_limit,
                traffic_used: data.traffic_used,
                expires_at: data.expires_at,
                enabled: data.enabled,
            }),
        })
    }
}
