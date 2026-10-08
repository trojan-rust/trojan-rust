//! Rule router: matches listen addresses to chains and destinations.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use trojan_core::proxy_protocol::ChainInfo;
use trojan_lb::{ConnectionGuard, LoadBalancer, NodeStateStore};

use crate::config::{ChainConfig, EntryConfig, RouteConfig, RuleConfig};
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
    pools: Vec<Arc<RoutePool>>,
}

/// The candidate pool for a resolved rule.
#[derive(Debug)]
pub struct ResolvedRoute<'a> {
    /// The rule matched by the listener address.
    pub rule: &'a RuleConfig,
    /// Select a candidate through this pool and retain its guard while forwarding.
    pub pool: &'a Arc<RoutePool>,
}

/// One compiled chain and its exit.
#[derive(Debug)]
pub struct RouteCandidate {
    key: String,
    chain_name: String,
    /// Compiled relay hops.
    pub chain: Arc<CompiledChain>,
    /// Final exit address.
    pub dest: String,
    node_id: Option<String>,
    node_ids: Vec<String>,
}

impl RouteCandidate {
    /// Opaque identifier within this pool, used to exclude an attempted route.
    pub fn key(&self) -> &str {
        &self.key
    }
}

/// A selected route and its active connection guard.
#[derive(Debug)]
pub struct RouteSelection {
    /// Selected chain and exit.
    pub candidate: Arc<RouteCandidate>,
    /// Keep this guard alive until forwarding ends.
    pub guard: Option<ConnectionGuard>,
}

/// Per-rule health, load balancing, and live quota selection.
#[derive(Debug)]
pub struct RoutePool {
    candidates: HashMap<String, Arc<RouteCandidate>>,
    lb: LoadBalancer,
    node_states: Option<Arc<NodeStateStore>>,
    retry_relays: bool,
}

impl RoutePool {
    /// Select an available route, excluding identifiers from [`RouteCandidate::key`].
    pub fn select(
        &self,
        peer: IpAddr,
        attempted: &[String],
    ) -> Result<RouteSelection, trojan_lb::LbError> {
        let state = self.node_states.as_ref().map(|states| states.snapshot());
        let selected = self.lb.select_available(peer, attempted, |key| {
            let candidate = &self.candidates[key];
            candidate.node_ids.iter().try_fold(1.0_f64, |capacity, id| {
                let remaining = state
                    .as_ref()
                    .map_or(Some(1.0), |state| state.remaining_fraction(id))?;
                Some(capacity.min(remaining))
            })
        })?;
        Ok(RouteSelection {
            candidate: self.candidates[&selected.addr].clone(),
            guard: selected.guard,
        })
    }

    pub(crate) fn retry_destinations(&self) -> bool {
        self.retry_relays || self.lb.is_failover()
    }

    pub(crate) fn retry_relays(&self) -> bool {
        self.retry_relays
    }

    pub(crate) fn failed(
        &self,
        route: &RouteCandidate,
        destination: bool,
        attempted: &mut Vec<String>,
    ) {
        for candidate in self.candidates.values() {
            let affected = if destination {
                candidate.dest == route.dest
                    || route
                        .node_id
                        .as_ref()
                        .is_some_and(|id| candidate.node_id.as_ref() == Some(id))
            } else {
                candidate.chain_name == route.chain_name
            };
            if affected {
                self.lb.mark_unhealthy(&candidate.key);
                attempted.push(candidate.key.clone());
            }
        }
    }
}

impl Router {
    /// Build a router from an entry config. Validates references.
    pub fn new(config: &EntryConfig) -> Result<Self, RelayError> {
        Self::build(config, None)
    }

    /// Build a router whose managed nodes require fresh panel state.
    pub fn with_node_states(
        config: &EntryConfig,
        states: Arc<NodeStateStore>,
    ) -> Result<Self, RelayError> {
        Self::build(config, Some(states))
    }

    fn build(
        config: &EntryConfig,
        states: Option<Arc<NodeStateStore>>,
    ) -> Result<Self, RelayError> {
        let mut rules_by_addr = HashMap::with_capacity(config.rules.len());
        let mut pools = Vec::with_capacity(config.rules.len());
        let chains = config
            .chains
            .iter()
            .map(|(name, chain)| {
                CompiledChain::new(name, chain.clone(), config.node_id.as_deref())
                    .map(|compiled| (name.clone(), Arc::new(compiled)))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;

        for (i, rule) in config.rules.iter().enumerate() {
            if !rule.routes.is_empty() && (!rule.chain.is_empty() || !rule.dest.is_empty()) {
                return Err(RelayError::Config(format!(
                    "rule '{}' must use routes or chain/dest, not both",
                    rule.name
                )));
            }
            let definitions: Vec<RouteConfig> = if rule.routes.is_empty() {
                rule.dest
                    .iter()
                    .map(|dest| RouteConfig {
                        chain: rule.chain.clone(),
                        dest: dest.clone(),
                        node_id: None,
                    })
                    .collect()
            } else {
                rule.routes.clone()
            };
            if definitions.is_empty() {
                return Err(RelayError::Config(format!(
                    "rule '{}' has empty dest",
                    rule.name
                )));
            }
            let mut candidates = HashMap::with_capacity(definitions.len());
            let mut keys = Vec::with_capacity(definitions.len());
            for (index, definition) in definitions.into_iter().enumerate() {
                let chain = chains
                    .get(&definition.chain)
                    .ok_or_else(|| {
                        RelayError::ChainNotFound(format!(
                            "rule '{}' references unknown chain '{}'",
                            rule.name, definition.chain
                        ))
                    })?
                    .clone();
                if definition.dest.trim().is_empty() {
                    return Err(RelayError::Config(format!(
                        "rule '{}' has empty dest",
                        rule.name
                    )));
                }
                let node_ids = config
                    .node_id
                    .iter()
                    .chain(
                        chain
                            .config()
                            .nodes
                            .iter()
                            .filter_map(|node| node.node_id.as_ref()),
                    )
                    .chain(definition.node_id.iter())
                    .cloned()
                    .collect();
                let key = index.to_string();
                keys.push(key.clone());
                candidates.insert(
                    key.clone(),
                    Arc::new(RouteCandidate {
                        key,
                        chain_name: definition.chain,
                        chain,
                        dest: definition.dest,
                        node_id: definition.node_id,
                        node_ids,
                    }),
                );
            }

            // Validate: listen address must be unique
            if rules_by_addr.contains_key(&rule.listen) {
                return Err(RelayError::Config(format!(
                    "duplicate listen address: {} (rule '{}')",
                    rule.listen, rule.name
                )));
            }

            rules_by_addr.insert(rule.listen, i);

            let lb = LoadBalancer::new(
                keys,
                rule.strategy.clone(),
                Duration::from_secs(rule.failover_cooldown_secs),
            );
            pools.push(Arc::new(RoutePool {
                candidates,
                lb,
                node_states: states.clone(),
                retry_relays: !rule.routes.is_empty(),
            }));
        }

        Ok(Self {
            rules_by_addr,
            rules: config.rules.clone(),
            pools,
        })
    }

    /// Resolve a route for a given listen address.
    pub fn resolve(&self, listen_addr: &SocketAddr) -> Option<ResolvedRoute<'_>> {
        let idx = self.rules_by_addr.get(listen_addr)?;
        let rule = &self.rules[*idx];
        Some(ResolvedRoute {
            rule,
            pool: &self.pools[*idx],
        })
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
mod tests;
