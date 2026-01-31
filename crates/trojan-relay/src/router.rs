//! Rule router: matches listen addresses to chains and destinations.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use trojan_lb::LoadBalancer;

use crate::config::{ChainConfig, EntryConfig, RuleConfig};
use crate::error::RelayError;

/// Resolved routing table built from an EntryConfig.
#[derive(Debug)]
pub struct Router {
    /// listen address → rule index
    rules_by_addr: HashMap<SocketAddr, usize>,
    /// All rules in order
    rules: Vec<RuleConfig>,
    /// Chain name → chain config
    chains: HashMap<String, ChainConfig>,
    /// One LoadBalancer per rule, indexed same as `rules`.
    load_balancers: Vec<Arc<LoadBalancer>>,
}

/// A resolved route: the chain config + destination + load balancer.
pub struct ResolvedRoute<'a> {
    pub rule: &'a RuleConfig,
    pub chain: &'a ChainConfig,
    pub lb: &'a Arc<LoadBalancer>,
}

impl Router {
    /// Build a router from an entry config. Validates references.
    pub fn new(config: &EntryConfig) -> Result<Self, RelayError> {
        let mut rules_by_addr = HashMap::with_capacity(config.rules.len());
        let mut load_balancers = Vec::with_capacity(config.rules.len());

        for (i, rule) in config.rules.iter().enumerate() {
            // Validate: chain must exist
            if !config.chains.contains_key(&rule.chain) {
                return Err(RelayError::ChainNotFound(format!(
                    "rule '{}' references unknown chain '{}'",
                    rule.name, rule.chain
                )));
            }

            // Validate: dest must not be empty
            if rule.dest.is_empty() {
                return Err(RelayError::Config(format!(
                    "rule '{}' has empty dest",
                    rule.name
                )));
            }

            // Validate: listen address must be unique
            if rules_by_addr.contains_key(&rule.listen) {
                return Err(RelayError::Config(format!(
                    "duplicate listen address: {} (rule '{}')",
                    rule.listen, rule.name
                )));
            }

            rules_by_addr.insert(rule.listen, i);

            let lb = Arc::new(LoadBalancer::new(
                rule.dest.clone(),
                rule.strategy.clone(),
                Duration::from_secs(rule.failover_cooldown_secs),
            ));
            load_balancers.push(lb);
        }

        Ok(Self {
            rules_by_addr,
            rules: config.rules.clone(),
            chains: config.chains.clone(),
            load_balancers,
        })
    }

    /// Resolve a route for a given listen address.
    pub fn resolve(&self, listen_addr: &SocketAddr) -> Option<ResolvedRoute<'_>> {
        let idx = self.rules_by_addr.get(listen_addr)?;
        let rule = &self.rules[*idx];
        let chain = self.chains.get(&rule.chain)?;
        let lb = &self.load_balancers[*idx];
        Some(ResolvedRoute { rule, chain, lb })
    }

    /// Get all unique listen addresses.
    pub fn listen_addrs(&self) -> Vec<SocketAddr> {
        self.rules.iter().map(|r| r.listen).collect()
    }

    /// Get all rules.
    pub fn rules(&self) -> &[RuleConfig] {
        &self.rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> EntryConfig {
        toml::from_str(
            r#"
[chains.jp]
nodes = [
  { addr = "relay-hk:443", password = "hk-secret" },
]

[chains.direct]
nodes = []

[[rules]]
name = "japan"
listen = "127.0.0.1:1080"
chain = "jp"
dest = "trojan-jp:443"

[[rules]]
name = "singapore"
listen = "127.0.0.1:1082"
chain = "direct"
dest = "trojan-sg:443"
"#,
        )
        .unwrap()
    }

    #[test]
    fn test_router_resolve() {
        let config = make_config();
        let router = Router::new(&config).unwrap();

        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let route = router.resolve(&addr).unwrap();
        assert_eq!(route.rule.name, "japan");
        assert_eq!(route.rule.dest, vec!["trojan-jp:443"]);
        assert_eq!(route.chain.nodes.len(), 1);
        assert_eq!(route.chain.nodes[0].addr, "relay-hk:443");
        assert_eq!(route.lb.backend_count(), 1);

        let addr: SocketAddr = "127.0.0.1:1082".parse().unwrap();
        let route = router.resolve(&addr).unwrap();
        assert_eq!(route.rule.name, "singapore");
        assert!(route.chain.nodes.is_empty());

        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        assert!(router.resolve(&addr).is_none());
    }

    #[test]
    fn test_router_unknown_chain() {
        let config: EntryConfig = toml::from_str(
            r#"
[chains.jp]
nodes = []

[[rules]]
name = "bad"
listen = "127.0.0.1:1080"
chain = "nonexistent"
dest = "target:443"
"#,
        )
        .unwrap();

        let err = Router::new(&config).unwrap_err();
        assert!(err.to_string().contains("nonexistent"));
    }

    #[test]
    fn test_router_duplicate_listen() {
        let config: EntryConfig = toml::from_str(
            r#"
[chains.jp]
nodes = []

[[rules]]
name = "a"
listen = "127.0.0.1:1080"
chain = "jp"
dest = "target:443"

[[rules]]
name = "b"
listen = "127.0.0.1:1080"
chain = "jp"
dest = "other:443"
"#,
        )
        .unwrap();

        let err = Router::new(&config).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn test_router_listen_addrs() {
        let config = make_config();
        let router = Router::new(&config).unwrap();
        let addrs = router.listen_addrs();
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn test_router_multi_dest() {
        let config: EntryConfig = toml::from_str(
            r#"
[chains.jp]
nodes = []

[[rules]]
name = "ha"
listen = "127.0.0.1:1080"
chain = "jp"
dest = ["a:443", "b:443", "c:443"]
strategy = "ip_hash"
"#,
        )
        .unwrap();

        let router = Router::new(&config).unwrap();
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let route = router.resolve(&addr).unwrap();
        assert_eq!(route.lb.backend_count(), 3);
    }
}
