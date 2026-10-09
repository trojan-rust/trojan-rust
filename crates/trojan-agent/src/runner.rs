//! Service bootstrap — starts the appropriate service based on node type.

use std::sync::Arc;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use trojan_auth::{AuthBackend, AuthError, AuthResult};
use trojan_config::{AuthConfig, Config};
use trojan_lb::NodeStateStore;
use trojan_metrics::NodeStats;
use trojan_relay::config::{EntryConfig, RelayNodeConfig};

use crate::collector::TrafficCollector;
use crate::error::AgentError;
use crate::protocol::NodeType;

/// Where a booted service reports what it carried.
///
/// The agent reads counters directly for heartbeats, independently of the
/// optional Prometheus listener.
#[derive(Debug, Clone, Default)]
pub struct ServiceSinks {
    /// Authenticated node identity for managed entry admission.
    pub node_id: Option<String>,
    /// Enable managed admission only after the panel negotiates node accounting.
    pub node_traffic: bool,
    /// Current panel availability and quota state, shared with running services.
    pub node_states: Arc<NodeStateStore>,
    /// Node-wide traffic and connection totals, read on every heartbeat.
    pub stats: Arc<NodeStats>,
    /// Per-user traffic, drained into each traffic report.
    ///
    /// Only servers using local authentication fill this collector. HTTP
    /// authentication reports user and chain traffic directly to the panel.
    /// Entry and relay nodes cannot identify users.
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

    let auth: Arc<dyn AuthBackend> = build_auth(&config.auth, sinks.traffic).into();
    let result = trojan_server::run_with_stats(config, auth.clone(), sinks.stats, shutdown).await;
    auth.shutdown().await;
    result.map_err(|e| {
        error!(error = %e, "server service exited with error");
        AgentError::Service(e.to_string())
    })
}

async fn run_entry(
    config_json: &serde_json::Value,
    sinks: ServiceSinks,
    shutdown: CancellationToken,
) -> Result<(), AgentError> {
    let mut config: EntryConfig = serde_json::from_value(config_json.clone())
        .map_err(|e| AgentError::Service(format!("invalid entry config: {e}")))?;
    if let Some(node_id) = sinks.node_id {
        config.node_id = Some(node_id);
    }

    info!("starting entry service");

    let result = if sinks.node_traffic {
        trojan_relay::entry::run_with_node_states(config, sinks.stats, sinks.node_states, shutdown)
            .await
    } else {
        trojan_relay::entry::run_with_stats(config, sinks.stats, shutdown).await
    };
    result.map_err(|e| {
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

fn build_auth(config: &AuthConfig, collector: TrafficCollector) -> Box<dyn AuthBackend> {
    let inner = trojan_server::build_auth(config);
    if config.http_url.is_some() {
        // HTTP auth owns user and chain accounting; socket reports would bill the same bytes twice.
        inner
    } else {
        Box::new(ReportingAuth { inner, collector })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trojan_auth::MemoryAuth;

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

    #[tokio::test]
    async fn local_auth_configuration_reports_user_traffic_to_the_agent() {
        let config: AuthConfig = serde_json::from_value(serde_json::json!({
            "users": [{"id": "alice", "password": "local-secret"}]
        }))
        .unwrap();
        let collector = TrafficCollector::new();
        let auth = build_auth(&config, collector.clone());
        let user = auth
            .verify(&trojan_auth::sha224_hex("local-secret"))
            .await
            .unwrap();
        assert_eq!(user.user_id.as_deref(), Some("alice"));
        assert!(matches!(
            auth.verify(&trojan_auth::sha224_hex("wrong")).await,
            Err(AuthError::Invalid)
        ));
        auth.record_traffic(user.user_id.as_deref().unwrap(), 42)
            .await
            .unwrap();
        let records = collector.drain();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].user_id, "alice");
        assert_eq!(records[0].bytes, 42);
    }
}
