//! Service bootstrap — starts the appropriate service based on node type.

use std::sync::Arc;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use trojan_auth::{AuthBackend, AuthError, AuthResult, MemoryAuth, ReloadableAuth};
use trojan_config::{AuthConfig, Config};
use trojan_metrics::NodeStats;
use trojan_relay::config::{EntryConfig, RelayNodeConfig};

use crate::collector::TrafficCollector;
use crate::error::AgentError;
use crate::protocol::NodeType;

/// Where a booted service reports what it carried.
///
/// The agent pushes heartbeats rather than being scraped, so it needs the
/// numbers themselves, not a Prometheus endpoint someone might scrape.
#[derive(Debug, Clone, Default)]
pub struct ServiceSinks {
    /// Node-wide traffic and connection totals, read on every heartbeat.
    pub stats: Arc<NodeStats>,
    /// Per-user traffic, drained into each traffic report.
    ///
    /// Only an exit node ever fills this: entry and relay nodes cannot see
    /// whose traffic they carry, and the exit reports on their behalf over the
    /// panel's chain traffic endpoint.
    pub traffic: TrafficCollector,
}

/// Boot the appropriate service for the given node type.
///
/// This function blocks until the service exits or the shutdown token
/// is cancelled.
pub async fn run_service(
    node_type: NodeType,
    config_json: &serde_json::Value,
    sinks: ServiceSinks,
    shutdown: CancellationToken,
) -> Result<(), AgentError> {
    match node_type {
        NodeType::Server => run_server(config_json, sinks, shutdown).await,
        NodeType::Entry => run_entry(config_json, sinks, shutdown).await,
        NodeType::Relay => run_relay(config_json, sinks, shutdown).await,
    }
}

async fn run_server(
    config_json: &serde_json::Value,
    sinks: ServiceSinks,
    shutdown: CancellationToken,
) -> Result<(), AgentError> {
    let config: Config = serde_json::from_value(config_json.clone())
        .map_err(|e| AgentError::Service(format!("invalid server config: {e}")))?;
    // The rest of the config is checked by the server itself; this is the part
    // only a caller that builds the backend from config can be held to, and a
    // panel that pushes an empty `auth` section would otherwise produce a node
    // that authenticates nobody.
    trojan_config::validate_auth_source(&config.auth)
        .map_err(|e| AgentError::Service(e.to_string()))?;

    info!(listen = %config.server.listen, "starting server service");

    let auth = Arc::new(ReportingAuth {
        inner: ReloadableAuth::new(build_memory_auth(&config.auth)),
        collector: sinks.traffic,
    });

    trojan_server::run_with_stats(config, auth, sinks.stats, shutdown)
        .await
        .map_err(|e| {
            error!(error = %e, "server service exited with error");
            AgentError::Service(e.to_string())
        })
}

async fn run_entry(
    config_json: &serde_json::Value,
    sinks: ServiceSinks,
    shutdown: CancellationToken,
) -> Result<(), AgentError> {
    let config: EntryConfig = serde_json::from_value(config_json.clone())
        .map_err(|e| AgentError::Service(format!("invalid entry config: {e}")))?;

    info!("starting entry service");

    trojan_relay::entry::run_with_stats(config, sinks.stats, shutdown)
        .await
        .map_err(|e| {
            error!(error = %e, "entry service exited with error");
            AgentError::Service(e.to_string())
        })
}

async fn run_relay(
    config_json: &serde_json::Value,
    sinks: ServiceSinks,
    shutdown: CancellationToken,
) -> Result<(), AgentError> {
    let config: RelayNodeConfig = serde_json::from_value(config_json.clone())
        .map_err(|e| AgentError::Service(format!("invalid relay config: {e}")))?;

    info!(listen = %config.relay.listen, "starting relay service");

    trojan_relay::relay::run_with_stats(config, sinks.stats, shutdown)
        .await
        .map_err(|e| {
            error!(error = %e, "relay service exited with error");
            AgentError::Service(e.to_string())
        })
}

/// An auth backend that also tells the agent what each user spent.
///
/// The server settles a session by calling `record_traffic`, so wrapping the
/// backend catches every byte it accounts for without the server knowing a
/// panel exists.
#[derive(Debug)]
struct ReportingAuth<A> {
    inner: A,
    collector: TrafficCollector,
}

#[async_trait]
impl<A: AuthBackend> AuthBackend for ReportingAuth<A> {
    async fn verify(&self, hash: &str) -> Result<AuthResult, AuthError> {
        self.inner.verify(hash).await
    }

    async fn record_traffic(&self, user_id: &str, bytes: u64) -> Result<(), AuthError> {
        self.collector.record(user_id, bytes);
        self.inner.record_traffic(user_id, bytes).await
    }

    async fn record_chain_traffic(
        &self,
        user_id: &str,
        bytes: u64,
        nodes: &[String],
    ) -> Result<(), AuthError> {
        self.inner.record_chain_traffic(user_id, bytes, nodes).await
    }

    async fn shutdown(&self) {
        self.inner.shutdown().await;
    }
}

/// Build a `MemoryAuth` from both `passwords` and `users` in the config.
/// Pattern from `trojan-server/src/cli.rs:160-169`.
fn build_memory_auth(auth: &AuthConfig) -> MemoryAuth {
    let mut mem = MemoryAuth::new();
    for pw in &auth.passwords {
        mem.add_password(pw, None);
    }
    for u in &auth.users {
        mem.add_password(&u.password, Some(u.id.clone()));
    }
    mem
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn settled_traffic_reaches_the_collector() {
        let collector = TrafficCollector::new();
        let auth = ReportingAuth {
            inner: MemoryAuth::new(),
            collector: collector.clone(),
        };

        auth.record_traffic("alice", 1500).await.unwrap();
        auth.record_traffic("alice", 500).await.unwrap();

        let records = collector.drain();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].user_id, "alice");
        assert_eq!(records[0].bytes, 2000);
    }
}
