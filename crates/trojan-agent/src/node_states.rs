//! Persist panel snapshots and publish snapshot age independently of panel sessions.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use trojan_lb::NodeStateStore;
use trojan_protocol::NodeStateSnapshot;

use crate::error::AgentError;

const FILENAME: &str = "node-states.json";

pub(crate) async fn load(cache_dir: &Path, store: &NodeStateStore) -> Result<(), AgentError> {
    let path = cache_dir.join(FILENAME);
    let data = match tokio::fs::read(&path).await {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(AgentError::Cache(format!(
                "cannot read node states: {error}"
            )));
        }
    };
    let snapshot = serde_json::from_slice(&data)
        .map_err(|error| AgentError::Cache(format!("invalid node states: {error}")))?;
    store.update(snapshot);
    Ok(())
}

pub(crate) async fn update(
    cache_dir: &Path,
    store: &NodeStateStore,
    snapshot: NodeStateSnapshot,
) -> Result<(), AgentError> {
    if !store.update(snapshot.clone()) {
        return Ok(());
    }
    let path = cache_dir.join(FILENAME);
    tokio::task::spawn_blocking(move || -> Result<(), AgentError> {
        let temporary = path.with_extension("json.tmp");
        let mut file = BufWriter::new(File::create(&temporary)?);
        serde_json::to_writer(&mut file, &snapshot)?;
        file.flush()?;
        file.get_ref().sync_all()?;
        drop(file);
        atomicwrites::replace_atomic(&temporary, &path)?;
        Ok(())
    })
    .await
    .map_err(|error| AgentError::Cache(format!("node state cache task failed: {error}")))?
    .map_err(|error| AgentError::Cache(format!("cannot persist node states: {error}")))
}

pub(crate) fn record_age(store: &NodeStateStore) {
    let age = store
        .snapshot()
        .generated_at()
        .map_or(-1.0, |generated_at| {
            crate::runtime::unix_now().saturating_sub(generated_at) as f64
        });
    metrics::gauge!("trojan_agent_node_state_age_seconds").set(age);
}

#[cfg(test)]
#[path = "node_states_tests.rs"]
mod tests;
