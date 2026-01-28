//! Fallback file writer for when ClickHouse is unavailable.

use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

use crate::event::ConnectionEvent;

/// Write events to a fallback JSONL file.
pub async fn write_fallback(path: &str, events: &[ConnectionEvent]) -> Result<(), std::io::Error> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;

    for event in events {
        let json = serde_json::to_string(event)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        file.write_all(json.as_bytes()).await?;
        file.write_all(b"\n").await?;
    }

    file.flush().await?;
    Ok(())
}
