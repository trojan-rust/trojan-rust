//! Durable node traffic deltas, independent of panel connection lifetime.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, mpsc, watch};
use tokio_util::sync::CancellationToken;
use trojan_metrics::{NodeSnapshot, NodeStats};

use crate::config::AgentConfig;
use crate::error::AgentError;
use crate::protocol::{AgentMessage, NodeTrafficReport};

const FILENAME: &str = "node-traffic.json";

#[derive(Clone)]
pub(crate) struct NodeTraffic {
    journal: Arc<Mutex<Journal>>,
    changed: Arc<Notify>,
    interval: watch::Sender<Duration>,
}

#[derive(Clone, Serialize, Deserialize)]
struct SavedTraffic {
    panel_url: String,
    token_hash: String,
    node_id: Option<String>,
    #[serde(default)]
    node_traffic: bool,
    stream_id: String,
    last_sequence: u64,
    acknowledged: u64,
    pending: VecDeque<NodeTrafficReport>,
}

struct Journal {
    path: PathBuf,
    saved: SavedTraffic,
    token_hash: String,
    baseline: NodeSnapshot,
    enabled: bool,
    _lock: File,
}

impl NodeTraffic {
    pub(crate) async fn open(
        cache_dir: &Path,
        config: &AgentConfig,
        interval_secs: u64,
    ) -> Result<Self, AgentError> {
        let path = cache_dir.to_owned();
        let panel_url = config.panel_url.clone();
        let token_hash = trojan_auth::sha224_hex(&config.token);
        let journal = tokio::task::spawn_blocking(move || {
            Journal::open(&path, panel_url, token_hash).map_err(accounting_error)
        })
        .await
        .map_err(|e| AgentError::Accounting(format!("journal task failed: {e}")))??;
        let (interval, _) = watch::channel(report_interval(interval_secs)?);
        Ok(Self {
            journal: Arc::new(Mutex::new(journal)),
            changed: Arc::new(Notify::new()),
            interval,
        })
    }

    async fn with_journal<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Journal) -> Result<T, AgentError> + Send + 'static,
    ) -> Result<T, AgentError> {
        let journal = self.journal.clone();
        // Blocking work finishes before releasing the lock, even if an async caller is cancelled.
        tokio::task::spawn_blocking(move || {
            let mut journal = journal
                .lock()
                .map_err(|e| AgentError::Accounting(format!("journal lock poisoned: {e}")))?;
            operation(&mut journal).map_err(accounting_error)
        })
        .await
        .map_err(|e| AgentError::Accounting(format!("journal task failed: {e}")))?
    }

    pub(crate) async fn bind_node(&self, node_id: &str) -> Result<(), AgentError> {
        let node_id = node_id.to_owned();
        self.with_journal(move |journal| match &journal.saved.node_id {
            Some(saved) if saved != &node_id => Err(AgentError::Accounting(
                "registered node differs from the traffic journal; restore the original node identity".into(),
            )),
            Some(_) if journal.saved.token_hash == journal.token_hash => Ok(()),
            _ => {
                let mut saved = journal.saved.clone();
                saved.node_id = Some(node_id);
                saved.token_hash.clone_from(&journal.token_hash);
                journal.commit(saved)
            }
        })
        .await
    }

    pub(crate) async fn can_start_cached(&self) -> Result<bool, AgentError> {
        self.with_journal(|journal| Ok(journal.saved.token_hash == journal.token_hash))
            .await
    }

    pub(crate) async fn requires_support(&self) -> Result<bool, AgentError> {
        self.with_journal(|journal| {
            // Earlier journals recorded traffic without an explicit capability marker.
            Ok(journal.saved.node_traffic || journal.saved.last_sequence > 0)
        })
        .await
    }

    pub(crate) async fn enable(&self, stats: Arc<NodeStats>) -> Result<(), AgentError> {
        self.with_journal(move |journal| {
            if !journal.enabled {
                let mut saved = journal.saved.clone();
                saved.node_traffic = true;
                journal.commit(saved)?;
                journal.baseline = stats.snapshot();
                journal.enabled = true;
            }
            Ok(())
        })
        .await
    }

    pub(crate) fn set_interval(&self, seconds: u64) -> Result<(), AgentError> {
        let duration = report_interval(seconds)?;
        self.interval.send_if_modified(|interval| {
            if *interval == duration {
                false
            } else {
                *interval = duration;
                true
            }
        });
        Ok(())
    }

    async fn sample_stats(&self, stats: Arc<NodeStats>) -> Result<(), AgentError> {
        self.with_journal(move |journal| {
            journal.sample(stats.snapshot(), crate::runtime::unix_now())
        })
        .await?;
        self.changed.notify_one();
        Ok(())
    }

    pub(crate) async fn run_sampler(
        &self,
        stats: Arc<NodeStats>,
        shutdown: CancellationToken,
    ) -> Result<(), AgentError> {
        let mut interval = self.interval.subscribe();
        loop {
            let delay = *interval.borrow_and_update();
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    return self.sample_stats(stats.clone()).await;
                }
                changed = interval.changed() => {
                    changed.map_err(|e| AgentError::Accounting(format!("sampling interval closed: {e}")))?;
                }
                _ = tokio::time::sleep(delay) => {
                    self.sample_stats(stats.clone()).await?;
                }
            }
        }
    }

    pub(crate) async fn acknowledge(
        &self,
        stream_id: String,
        sequence: u64,
    ) -> Result<(), AgentError> {
        self.with_journal(move |journal| {
            if stream_id != journal.saved.stream_id || sequence > journal.saved.last_sequence {
                return Err(AgentError::Accounting(
                    "invalid traffic acknowledgement".into(),
                ));
            }
            if sequence <= journal.saved.acknowledged {
                return Ok(());
            }
            let mut saved = journal.saved.clone();
            saved.acknowledged = sequence;
            saved.pending.retain(|report| report.sequence > sequence);
            journal.commit(saved)
        })
        .await?;
        self.changed.notify_one();
        Ok(())
    }

    pub(crate) async fn send_pending(
        &self,
        tx: mpsc::Sender<AgentMessage>,
    ) -> Result<(), AgentError> {
        let mut sent_sequence = 0;
        loop {
            let report = self
                .with_journal(|journal| Ok(journal.saved.pending.front().cloned()))
                .await?;
            if let Some(report) = report
                && report.sequence > sent_sequence
            {
                sent_sequence = report.sequence;
                tx.send(AgentMessage::NodeTraffic { report })
                    .await
                    .map_err(|_| AgentError::ConnectionClosed)?;
            }
            self.changed.notified().await;
        }
    }
}

fn report_interval(seconds: u64) -> Result<Duration, AgentError> {
    if seconds == 0 {
        return Err(AgentError::Config(
            "report_interval_secs must be positive".into(),
        ));
    }
    Ok(Duration::from_secs(seconds))
}

fn accounting_error(error: AgentError) -> AgentError {
    match error {
        AgentError::Accounting(_) => error,
        error => AgentError::AccountingStorage(Box::new(error)),
    }
}

impl Journal {
    fn open(path: &Path, panel_url: String, token_hash: String) -> Result<Self, AgentError> {
        std::fs::create_dir_all(path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path.join("node-traffic.lock"))?;
        lock.try_lock().map_err(|e| {
            AgentError::Accounting(format!("cannot exclusively lock node traffic journal: {e}"))
        })?;
        let path = path.join(FILENAME);
        let saved = match std::fs::read(&path) {
            Ok(bytes) => {
                let saved: SavedTraffic = serde_json::from_slice(&bytes).map_err(|e| {
                    AgentError::Accounting(format!("invalid node traffic journal: {e}"))
                })?;
                if saved.panel_url != panel_url {
                    return Err(AgentError::Accounting(
                        "panel differs from the traffic journal; restore the original configuration and settle pending reports before migration".into(),
                    ));
                }
                let mut sequence = saved.acknowledged;
                for report in &saved.pending {
                    sequence = sequence.checked_add(1).ok_or_else(|| {
                        AgentError::Accounting("traffic sequence overflow".into())
                    })?;
                    if report.stream_id != saved.stream_id || report.sequence != sequence {
                        return Err(AgentError::Accounting(
                            "invalid journal report sequence".into(),
                        ));
                    }
                }
                if sequence != saved.last_sequence {
                    return Err(AgentError::Accounting("incomplete traffic journal".into()));
                }
                saved
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut random = [0u8; 16];
                getrandom::fill(&mut random).map_err(|e| {
                    AgentError::Accounting(format!("cannot create traffic stream identity: {e}"))
                })?;
                SavedTraffic {
                    panel_url,
                    token_hash: token_hash.clone(),
                    node_id: None,
                    node_traffic: false,
                    stream_id: format!("{:032x}", u128::from_be_bytes(random)),
                    last_sequence: 0,
                    acknowledged: 0,
                    pending: VecDeque::new(),
                }
            }
            Err(e) => return Err(e.into()),
        };
        let journal = Self {
            path,
            saved,
            token_hash,
            baseline: NodeSnapshot::default(),
            enabled: false,
            _lock: lock,
        };
        journal.persist(&journal.saved)?;
        Ok(journal)
    }

    fn persist(&self, saved: &SavedTraffic) -> Result<(), AgentError> {
        // ponytail: Use append-only storage if backlog rewrite time reaches the report interval.
        let temporary = self.path.with_extension("json.tmp");
        let mut file = File::create(&temporary)?;
        serde_json::to_writer(&mut file, saved)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        atomicwrites::replace_atomic(&temporary, &self.path)?;
        Ok(())
    }

    fn commit(&mut self, saved: SavedTraffic) -> Result<(), AgentError> {
        self.persist(&saved)?;
        self.saved = saved;
        Ok(())
    }

    fn sample(&mut self, snapshot: NodeSnapshot, observed_at: u64) -> Result<(), AgentError> {
        if !self.enabled {
            self.baseline = snapshot;
            return Ok(());
        }
        let bytes_in = snapshot.bytes_in.checked_sub(self.baseline.bytes_in);
        let bytes_out = snapshot.bytes_out.checked_sub(self.baseline.bytes_out);
        let (Some(bytes_in), Some(bytes_out)) = (bytes_in, bytes_out) else {
            return Err(AgentError::Accounting(
                "node counters decreased within one process".into(),
            ));
        };
        if bytes_in == 0 && bytes_out == 0 {
            return Ok(());
        }
        let mut saved = self.saved.clone();
        saved.last_sequence = saved
            .last_sequence
            .checked_add(1)
            .ok_or_else(|| AgentError::Accounting("traffic sequence overflow".into()))?;
        saved.pending.push_back(NodeTrafficReport {
            stream_id: saved.stream_id.clone(),
            sequence: saved.last_sequence,
            observed_at,
            bytes_in,
            bytes_out,
        });
        self.commit(saved)?;
        self.baseline = snapshot;
        Ok(())
    }
}

#[cfg(test)]
#[path = "node_traffic_tests.rs"]
mod tests;
