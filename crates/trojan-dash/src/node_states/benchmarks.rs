//! Reproducible SQLite snapshot scaling measurements; no timing assertions.

use std::sync::Arc;
use std::time::Instant;

use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

use super::*;
use crate::{DashConfig, cache::Caches};

#[tokio::test]
#[ignore = "run explicitly to measure SQLite snapshot scaling"]
async fn snapshot_scaling() {
    for count in [1, 100, 1000] {
        let db = crate::db::connect("sqlite::memory:").await.unwrap();
        let now = now_secs();
        db.execute(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
            "WITH RECURSIVE n(id) AS (SELECT 1 UNION ALL SELECT id + 1 FROM n WHERE id < ?1) \
             INSERT INTO nodes (id, name, token, last_seen) SELECT id, 'n' || id, 't' || id, ?2 FROM n",
            [count.into(), now.into()],
        )).await.unwrap();
        db.execute(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
            "WITH RECURSIVE samples(s) AS (SELECT 0 UNION ALL SELECT s + 1 FROM samples WHERE s < 999) \
             INSERT INTO node_traffic SELECT n.id, ?1 - samples.s * 30, 100, 200 FROM nodes n CROSS JOIN samples",
            [now.into()],
        )).await.unwrap();
        let config: DashConfig = toml::from_str("admin_token = 'test'").unwrap();
        let state = AppState {
            db,
            cache: Caches::new(Duration::ZERO, Duration::ZERO),
            admin_digest: Arc::new(String::new()),
            cfg: Arc::new(config),
            nodes: Arc::new(NodeMonitor::new()),
        };
        let cold = Instant::now();
        assert_eq!(
            snapshot_at(&state, now).await.unwrap().nodes.len(),
            usize::try_from(count).unwrap()
        );
        let cold = cold.elapsed();
        let warm = Instant::now();
        for _ in 0..20 {
            std::hint::black_box(snapshot_at(&state, now).await.unwrap());
        }
        eprintln!(
            "snapshot nodes={count} rows={} cold={cold:?} warm_mean={:?}",
            count * 1000,
            warm.elapsed() / 20
        );
    }
}
