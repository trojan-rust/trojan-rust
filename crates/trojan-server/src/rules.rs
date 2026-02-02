//! Bridge between trojan-config and trojan-rules.
//!
//! Converts server config into a compiled RuleEngine.

use std::path::Path;
#[cfg(feature = "geoip")]
use std::sync::Arc;

use trojan_config::ServerConfig;
use trojan_rules::rule::ParsedRule;
use trojan_rules::{Action, RuleEngine, RuleEngineBuilder, RulesError};

/// Build a RuleEngine from server configuration.
pub fn build_rule_engine(config: &ServerConfig) -> Result<RuleEngine, RulesError> {
    let mut builder = RuleEngineBuilder::new();

    // Load GeoIP database if configured and geoip feature is enabled
    #[cfg(feature = "geoip")]
    if let Some(ref geoip_cfg) = config.geoip {
        match load_geoip_matcher(geoip_cfg) {
            Ok(matcher) => {
                tracing::info!(source = %geoip_cfg.source, "GeoIP database loaded for rule engine");
                builder.set_geoip(Arc::new(matcher));
            }
            Err(e) => {
                tracing::warn!(source = %geoip_cfg.source, error = %e, "GeoIP database not available for rule engine");
            }
        }
    }

    // Load and register all rule-set providers
    for (name, provider_cfg) in &config.rule_providers {
        let rules = load_provider_rules(name, provider_cfg)?;
        builder.add_rule_set(name, rules);
    }

    // Register routing rules in order
    add_routing_rules(&mut builder, config)?;

    builder.build()
}

/// Build a RuleEngine asynchronously (for hot-reload: HTTP providers fetch remotely).
///
/// Individual provider fetch failures are tolerated: the failed provider
/// falls back to its cache (or an empty rule-set), while successfully
/// updated providers are swapped in. This avoids one bad URL blocking
/// all rule updates.
pub async fn build_rule_engine_async(config: &ServerConfig) -> Result<RuleEngine, RulesError> {
    let mut builder = RuleEngineBuilder::new();

    #[cfg(feature = "geoip")]
    if let Some(ref geoip_cfg) = config.geoip {
        match load_geoip_matcher(geoip_cfg) {
            Ok(matcher) => {
                builder.set_geoip(Arc::new(matcher));
            }
            Err(e) => {
                tracing::warn!(source = %geoip_cfg.source, error = %e, "GeoIP not available for async rule rebuild");
            }
        }
    }

    // Load all rule-set providers (HTTP providers fetch asynchronously).
    // Individual failures are logged but do not abort the entire rebuild.
    for (name, provider_cfg) in &config.rule_providers {
        let rules = match load_provider_rules_async(name, provider_cfg).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    provider = %name,
                    error = %e,
                    "provider fetch failed, falling back to cache/empty"
                );
                // Fall back to cache load on a blocking thread to avoid
                // stalling the async runtime with synchronous file I/O.
                let name_owned = name.clone();
                let cfg_owned = provider_cfg.clone();
                tokio::task::spawn_blocking(move || {
                    load_provider_rules(&name_owned, &cfg_owned).unwrap_or_else(|_| Vec::new())
                })
                .await
                .unwrap_or_default()
            }
        };
        builder.add_rule_set(name, rules);
    }

    add_routing_rules(&mut builder, config)?;

    builder.build()
}

/// Register routing rules from config onto a builder.
fn add_routing_rules(
    builder: &mut RuleEngineBuilder,
    config: &ServerConfig,
) -> Result<(), RulesError> {
    for rule_cfg in &config.rules {
        let action = parse_action(&rule_cfg.outbound);

        if let Some(ref rule_set_name) = rule_cfg.rule_set {
            // Rule references a named rule-set
            builder.add_rule_set_rule(rule_set_name, action);
        } else if let Some(ref rule_type) = rule_cfg.rule_type {
            match rule_type.as_str() {
                "FINAL" => {
                    builder.set_final(action);
                }
                "GEOIP" => {
                    let code = rule_cfg.value.as_deref().ok_or_else(|| {
                        RulesError::Parse("GEOIP rule requires a country code value".into())
                    })?;
                    if code.is_empty() {
                        return Err(RulesError::Parse(
                            "GEOIP rule country code must not be empty".into(),
                        ));
                    }
                    builder.add_geoip_rule(code, action);
                }
                _ => {
                    // Inline rule: parse type + value
                    let value = rule_cfg
                        .value
                        .as_deref()
                        .ok_or_else(|| RulesError::Parse(format!("missing value for inline rule type: {rule_type}")))?;
                    let parsed = parse_inline_rule(rule_type, value)?;
                    builder.add_inline_rule(parsed, action);
                }
            }
        } else {
            return Err(RulesError::Parse(
                "rule must have either 'rule_set' or 'type' field".into(),
            ));
        }
    }
    Ok(())
}

/// Load rules from a provider configuration (synchronous: file + cached HTTP).
fn load_provider_rules(
    name: &str,
    cfg: &trojan_config::RuleProviderConfig,
) -> Result<Vec<ParsedRule>, RulesError> {
    match cfg.source.as_str() {
        "file" => {
            let path = cfg.path.as_deref().ok_or_else(|| {
                RulesError::Provider(format!("rule-provider '{name}': path is required for file source"))
            })?;
            trojan_rules::provider::FileProvider::load(
                Path::new(path),
                &cfg.format,
                cfg.behavior.as_deref(),
            )
        }
        "http" => {
            // At startup, try to load from cache synchronously.
            // The background updater will fetch the latest version asynchronously.
            let url = cfg.url.as_deref().ok_or_else(|| {
                RulesError::Provider(format!("rule-provider '{name}': url is required for http source"))
            })?;
            let cache_path = cfg.path.as_ref().map(std::path::PathBuf::from);
            let provider = trojan_rules::provider::HttpProvider::new(
                url,
                cache_path,
                &cfg.format,
                cfg.behavior.clone(),
            );
            match provider.load_cached()? {
                Some(rules) => {
                    tracing::info!(name = %name, rules = rules.len(), "loaded HTTP rule-set from cache");
                    Ok(rules)
                }
                None => {
                    tracing::warn!(name = %name, url = %url, "no cached rules available for HTTP provider; will fetch in background");
                    Ok(Vec::new())
                }
            }
        }
        other => Err(RulesError::Provider(format!(
            "rule-provider '{name}': unsupported source: {other}"
        ))),
    }
}

/// Load rules from a provider configuration (async: HTTP providers fetch remotely).
async fn load_provider_rules_async(
    name: &str,
    cfg: &trojan_config::RuleProviderConfig,
) -> Result<Vec<ParsedRule>, RulesError> {
    match cfg.source.as_str() {
        "file" => {
            let path = cfg.path.as_deref().ok_or_else(|| {
                RulesError::Provider(format!("rule-provider '{name}': path is required for file source"))
            })?;
            trojan_rules::provider::FileProvider::load(
                Path::new(path),
                &cfg.format,
                cfg.behavior.as_deref(),
            )
        }
        "http" => {
            let url = cfg.url.as_deref().ok_or_else(|| {
                RulesError::Provider(format!("rule-provider '{name}': url is required for http source"))
            })?;
            let cache_path = cfg.path.as_ref().map(std::path::PathBuf::from);
            let provider = trojan_rules::provider::HttpProvider::new(
                url,
                cache_path,
                &cfg.format,
                cfg.behavior.clone(),
            );
            let rules = provider.load().await?;
            tracing::info!(name = %name, rules = rules.len(), url = %url, "fetched HTTP rule-set");
            Ok(rules)
        }
        other => Err(RulesError::Provider(format!(
            "rule-provider '{name}': unsupported source: {other}"
        ))),
    }
}

/// Returns true if any rule provider uses HTTP source.
pub fn has_http_providers(config: &ServerConfig) -> bool {
    config
        .rule_providers
        .values()
        .any(|p| p.source == "http")
}

/// Get the minimum update interval from HTTP providers (in seconds).
/// Returns `None` if no HTTP providers have an interval configured.
pub fn http_update_interval(config: &ServerConfig) -> Option<u64> {
    config
        .rule_providers
        .values()
        .filter(|p| p.source == "http")
        .filter_map(|p| p.interval)
        .min()
}

/// Parse an action string from config.
fn parse_action(outbound: &str) -> Action {
    match outbound {
        "DIRECT" => Action::Direct,
        "REJECT" => Action::Reject,
        name => Action::Outbound(name.to_string()),
    }
}

/// Parse an inline rule from type + value.
fn parse_inline_rule(rule_type: &str, value: &str) -> Result<ParsedRule, RulesError> {
    match rule_type {
        "DOMAIN" => Ok(ParsedRule::Domain(value.to_string())),
        "DOMAIN-SUFFIX" => Ok(ParsedRule::DomainSuffix(value.to_string())),
        "DOMAIN-KEYWORD" => Ok(ParsedRule::DomainKeyword(value.to_string())),
        "IP-CIDR" | "IP-CIDR6" => {
            let net = value
                .parse()
                .map_err(|e| RulesError::InvalidCidr(format!("{value}: {e}")))?;
            Ok(ParsedRule::IpCidr(net))
        }
        "DST-PORT" => {
            let port: u16 = value
                .parse()
                .map_err(|e| RulesError::Parse(format!("invalid port '{value}': {e}")))?;
            Ok(ParsedRule::DstPort(port))
        }
        "SRC-IP-CIDR" | "SRC-IP-CIDR6" => {
            let net = value
                .parse()
                .map_err(|e| RulesError::InvalidCidr(format!("{value}: {e}")))?;
            Ok(ParsedRule::SrcIpCidr(net))
        }
        _ => Err(RulesError::InvalidRuleType(rule_type.to_string())),
    }
}

/// Load a GeoipMatcher from GeoipConfig.
///
/// Tries `path` first, then `cache_path`.
#[cfg(feature = "geoip")]
fn load_geoip_matcher(
    cfg: &trojan_config::GeoipConfig,
) -> Result<trojan_rules::matcher::GeoipMatcher, trojan_rules::RulesError> {
    if let Some(ref path) = cfg.path {
        return trojan_rules::matcher::GeoipMatcher::from_file(Path::new(path));
    }
    if let Some(ref cache_path) = cfg.cache_path {
        let p = Path::new(cache_path);
        if p.exists() {
            return trojan_rules::matcher::GeoipMatcher::from_file(p);
        }
    }
    Err(trojan_rules::RulesError::GeoIp(format!(
        "no local GeoIP database for source '{}'; set 'path' or 'cache_path'",
        cfg.source
    )))
}
