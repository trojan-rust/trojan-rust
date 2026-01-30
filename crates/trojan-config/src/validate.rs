//! Configuration validation logic.

use crate::Config;
use crate::defaults::min_header_bytes;
use crate::loader::ConfigError;

pub fn validate_config(config: &Config) -> Result<(), ConfigError> {
    if config.server.listen.trim().is_empty() {
        return Err(ConfigError::Validation("server.listen is empty".into()));
    }
    if config.server.fallback.trim().is_empty() {
        return Err(ConfigError::Validation("server.fallback is empty".into()));
    }
    if config.tls.cert.trim().is_empty() {
        return Err(ConfigError::Validation("tls.cert is empty".into()));
    }
    if config.tls.key.trim().is_empty() {
        return Err(ConfigError::Validation("tls.key is empty".into()));
    }
    if config.auth.passwords.is_empty() && config.auth.users.is_empty() {
        return Err(ConfigError::Validation(
            "auth: at least one of 'passwords' or 'users' must be non-empty".into(),
        ));
    }
    if config.server.tcp_idle_timeout_secs == 0 {
        return Err(ConfigError::Validation(
            "server.tcp_idle_timeout_secs must be > 0".into(),
        ));
    }
    if config.server.udp_timeout_secs == 0 {
        return Err(ConfigError::Validation(
            "server.udp_timeout_secs must be > 0".into(),
        ));
    }
    if config.server.max_header_bytes < min_header_bytes() {
        return Err(ConfigError::Validation(format!(
            "server.max_header_bytes too small (min {})",
            min_header_bytes()
        )));
    }
    if config.server.max_udp_payload == 0 || config.server.max_udp_payload > u16::MAX as usize {
        return Err(ConfigError::Validation(
            "server.max_udp_payload must be 1..=65535".into(),
        ));
    }
    if config.server.max_udp_buffer_bytes == 0 {
        return Err(ConfigError::Validation(
            "server.max_udp_buffer_bytes must be > 0".into(),
        ));
    }
    if config.server.max_udp_buffer_bytes < config.server.max_udp_payload + 8 {
        return Err(ConfigError::Validation(
            "server.max_udp_buffer_bytes must be >= max_udp_payload + 8".into(),
        ));
    }
    // Validate TLS versions
    let valid_versions = ["tls12", "tls13"];
    if !valid_versions.contains(&config.tls.min_version.as_str()) {
        return Err(ConfigError::Validation(format!(
            "tls.min_version must be one of: {:?}",
            valid_versions
        )));
    }
    if !valid_versions.contains(&config.tls.max_version.as_str()) {
        return Err(ConfigError::Validation(format!(
            "tls.max_version must be one of: {:?}",
            valid_versions
        )));
    }
    // tls13 > tls12
    let min_ord = if config.tls.min_version == "tls13" {
        1
    } else {
        0
    };
    let max_ord = if config.tls.max_version == "tls13" {
        1
    } else {
        0
    };
    if min_ord > max_ord {
        return Err(ConfigError::Validation(
            "tls.min_version cannot be greater than tls.max_version".into(),
        ));
    }
    // Validate resource limits
    if let Some(ref rl) = config.server.resource_limits {
        if rl.relay_buffer_size < 1024 {
            return Err(ConfigError::Validation(
                "resource_limits.relay_buffer_size must be >= 1024".into(),
            ));
        }
        if rl.relay_buffer_size > 1024 * 1024 {
            return Err(ConfigError::Validation(
                "resource_limits.relay_buffer_size must be <= 1MB".into(),
            ));
        }
        if rl.connection_backlog == 0 {
            return Err(ConfigError::Validation(
                "resource_limits.connection_backlog must be > 0".into(),
            ));
        }
    }
    if let Some(ref pool) = config.server.fallback_pool {
        if pool.max_idle == 0 {
            return Err(ConfigError::Validation(
                "fallback_pool.max_idle must be > 0".into(),
            ));
        }
        if pool.max_age_secs == 0 {
            return Err(ConfigError::Validation(
                "fallback_pool.max_age_secs must be > 0".into(),
            ));
        }
        if pool.fill_batch == 0 || pool.fill_batch > pool.max_idle {
            return Err(ConfigError::Validation(
                "fallback_pool.fill_batch must be 1..=max_idle".into(),
            ));
        }
    }
    if config.websocket.mode != "mixed" && config.websocket.mode != "split" {
        return Err(ConfigError::Validation(
            "websocket.mode must be 'mixed' or 'split'".into(),
        ));
    }
    if config.websocket.path.is_empty() {
        return Err(ConfigError::Validation("websocket.path is empty".into()));
    }
    if config.websocket.enabled
        && config.websocket.mode == "split"
        && config.websocket.listen.as_deref().unwrap_or("").is_empty()
    {
        return Err(ConfigError::Validation(
            "websocket.listen is required in split mode".into(),
        ));
    }
    Ok(())
}
