//! Rule router: matches listen addresses to chains and destinations.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use trojan_core::proxy_protocol::ChainInfo;
use trojan_lb::LoadBalancer;

use crate::config::{ChainConfig, EntryConfig, RuleConfig};
use crate::error::RelayError;
use crate::handshake;

/// A chain together with the per-hop password hashes derived from it.
///
/// Hashing happens once when the router is built. Doing it per connection
/// costs a SHA-224 and a `String` allocation per hop on the accept path, and
/// defers what is really a config error — a hop with no password — until the
/// first client shows up.
#[derive(Debug)]
pub struct CompiledChain {
    config: ChainConfig,
    password_hashes: Vec<String>,
    path: ChainInfo,
}

impl CompiledChain {
    /// Hash every hop's password, failing if any hop has none configured.
    ///
    /// `entry_node_id` is this node's own id, which leads the path reported to
    /// the exit — the entry carries every byte the chain does.
    fn new(
        name: &str,
        config: ChainConfig,
        entry_node_id: Option<&str>,
    ) -> Result<Self, RelayError> {
        let password_hashes = config
            .nodes
            .iter()
            .map(|node| {
                node.password
                    .as_deref()
                    .map(handshake::hash_password)
                    .ok_or_else(|| {
                        RelayError::Config(format!(
                            "chain '{name}': node '{}' is missing a password",
                            node.addr
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Hops with no id are left out rather than held a place: the list is
        // only ever used to credit traffic, and an id is what makes a hop
        // creditable.
        let path = ChainInfo::new(
            entry_node_id
                .into_iter()
                .chain(config.nodes.iter().filter_map(|n| n.node_id.as_deref()))
                .map(str::to_owned)
                .collect(),
        );

        Ok(Self {
            config,
            password_hashes,
            path,
        })
    }

    /// The chain's configuration.
    pub fn config(&self) -> &ChainConfig {
        &self.config
    }

    /// SHA-224 hex password hash for each hop, in chain order.
    ///
    /// Always the same length as `self.config().nodes`.
    pub fn password_hashes(&self) -> &[String] {
        &self.password_hashes
    }

    /// The hops to credit for traffic through this chain, entry node first.
    pub fn path(&self) -> &ChainInfo {
        &self.path
    }
}

/// Resolved routing table built from an EntryConfig.
#[derive(Debug)]
pub struct Router {
    /// listen address → rule index
    rules_by_addr: HashMap<SocketAddr, usize>,
    /// All rules in order
    rules: Vec<RuleConfig>,
    /// Chain name → compiled chain (Arc-wrapped to avoid cloning per connection)
    chains: HashMap<String, Arc<CompiledChain>>,
    /// One LoadBalancer per rule, indexed same as `rules`.
    load_balancers: Vec<Arc<LoadBalancer>>,
}

/// A resolved route: the compiled chain + destination + load balancer.
#[derive(Debug)]
pub struct ResolvedRoute<'a> {
    pub rule: &'a RuleConfig,
    pub chain: Arc<CompiledChain>,
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

        let chains = config
            .chains
            .iter()
            .map(|(name, chain)| {
                CompiledChain::new(name, chain.clone(), config.node_id.as_deref())
                    .map(|compiled| (name.clone(), Arc::new(compiled)))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;

        Ok(Self {
            rules_by_addr,
            rules: config.rules.clone(),
            chains,
            load_balancers,
        })
    }

    /// Resolve a route for a given listen address.
    pub fn resolve(&self, listen_addr: &SocketAddr) -> Option<ResolvedRoute<'_>> {
        let idx = self.rules_by_addr.get(listen_addr)?;
        let rule = &self.rules[*idx];
        let chain = self.chains.get(&rule.chain)?.clone();
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
        assert_eq!(route.chain.config().nodes.len(), 1);
        assert_eq!(route.chain.config().nodes[0].addr, "relay-hk:443");
        // One hash per hop, resolved at build time.
        assert_eq!(route.chain.password_hashes().len(), 1);
        assert_eq!(route.lb.backend_count(), 1);

        let addr: SocketAddr = "127.0.0.1:1082".parse().unwrap();
        let route = router.resolve(&addr).unwrap();
        assert_eq!(route.rule.name, "singapore");
        assert!(route.chain.config().nodes.is_empty());

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
    fn test_router_chain_node_missing_password() {
        let config: EntryConfig = toml::from_str(
            r#"
[chains.jp]
nodes = [
  { addr = "relay-hk:443" },
]

[[rules]]
name = "japan"
listen = "127.0.0.1:1080"
chain = "jp"
dest = "trojan-jp:443"
"#,
        )
        .unwrap();

        // A hop with no password is a config error. Hashes are resolved when
        // the router is built, so it surfaces at startup rather than on the
        // first connection through that chain.
        let err = Router::new(&config).unwrap_err();
        assert!(
            err.to_string().contains("missing a password"),
            "unexpected error: {err}"
        );
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
