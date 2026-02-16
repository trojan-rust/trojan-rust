//! Service bootstrap — starts the appropriate service based on node type.

use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use trojan_auth::{MemoryAuth, ReloadableAuth};
use trojan_config::{AuthConfig, Config};
use trojan_relay::config::{EntryConfig, RelayNodeConfig};

use crate::error::AgentError;
use crate::protocol::NodeType;

/// Boot the appropriate service for the given node type.
///
/// This function blocks until the service exits or the shutdown token
/// is cancelled.
pub async fn run_service(
    node_type: NodeType,
    config_json: &serde_json::Value,
    shutdown: CancellationToken,
) -> Result<(), AgentError> {
    match node_type {
        NodeType::Server => run_server(config_json, shutdown).await,
        NodeType::Entry => run_entry(config_json, shutdown).await,
        NodeType::Relay => run_relay(config_json, shutdown).await,
    }
}

async fn run_server(
    config_json: &serde_json::Value,
    shutdown: CancellationToken,
) -> Result<(), AgentError> {
    let config: Config = serde_json::from_value(config_json.clone())
        .map_err(|e| AgentError::Service(format!("invalid server config: {e}")))?;

    info!(listen = %config.server.listen, "starting server service");

    let auth = Arc::new(ReloadableAuth::new(build_memory_auth(&config.auth)));

    trojan_server::run_with_shutdown(config, auth, shutdown)
        .await
        .map_err(|e| {
            error!(error = %e, "server service exited with error");
            AgentError::Service(e.to_string())
        })
}

async fn run_entry(
    config_json: &serde_json::Value,
    shutdown: CancellationToken,
) -> Result<(), AgentError> {
    let config: EntryConfig = serde_json::from_value(config_json.clone())
        .map_err(|e| AgentError::Service(format!("invalid entry config: {e}")))?;

    info!("starting entry service");

    trojan_relay::entry::run(config, shutdown)
        .await
        .map_err(|e| {
            error!(error = %e, "entry service exited with error");
            AgentError::Service(e.to_string())
        })
}

async fn run_relay(
    config_json: &serde_json::Value,
    shutdown: CancellationToken,
) -> Result<(), AgentError> {
    let config: RelayNodeConfig = serde_json::from_value(config_json.clone())
        .map_err(|e| AgentError::Service(format!("invalid relay config: {e}")))?;

    info!(listen = %config.relay.listen, "starting relay service");

    trojan_relay::relay::run(config, shutdown)
        .await
        .map_err(|e| {
            error!(error = %e, "relay service exited with error");
            AgentError::Service(e.to_string())
        })
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
