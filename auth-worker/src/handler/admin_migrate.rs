//! Admin migration handler.

use serde::Deserialize;
use worker::*;

/// POST /admin/migrate — auto-create tables
pub async fn handle_migrate(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let d1 = ctx.env.d1("DB")?;

    d1.prepare(
        "CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            hash          TEXT NOT NULL UNIQUE,
            username      TEXT NOT NULL UNIQUE,
            traffic_limit INTEGER NOT NULL DEFAULT 0,
            traffic_used  INTEGER NOT NULL DEFAULT 0,
            expires_at    INTEGER NOT NULL DEFAULT 0,
            enabled       INTEGER NOT NULL DEFAULT 1
        )",
    )
    .run()
    .await?;

    d1.prepare("CREATE INDEX IF NOT EXISTS idx_users_hash ON users(hash)")
        .run()
        .await?;

    d1.prepare(
        "CREATE TABLE IF NOT EXISTS nodes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL UNIQUE,
            token      TEXT NOT NULL UNIQUE,
            enabled    INTEGER NOT NULL DEFAULT 1,
            ip         TEXT NOT NULL DEFAULT '',
            last_seen  INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL DEFAULT 0
        )",
    )
    .run()
    .await?;

    d1.prepare(
        "CREATE TABLE IF NOT EXISTS traffic_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id),
            node_id     INTEGER NOT NULL REFERENCES nodes(id),
            bytes       INTEGER NOT NULL DEFAULT 0,
            date        TEXT NOT NULL,
            UNIQUE(user_id, node_id, date)
        )",
    )
    .run()
    .await?;

    d1.prepare("CREATE INDEX IF NOT EXISTS idx_traffic_logs_user ON traffic_logs(user_id)")
        .run()
        .await?;

    d1.prepare("CREATE INDEX IF NOT EXISTS idx_traffic_logs_node ON traffic_logs(node_id)")
        .run()
        .await?;

    d1.prepare(
        "CREATE TABLE IF NOT EXISTS sub_templates (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT NOT NULL UNIQUE,
            filename     TEXT NOT NULL DEFAULT '',
            content      TEXT NOT NULL DEFAULT '',
            content_type    TEXT NOT NULL DEFAULT 'text/plain; charset=utf-8',
            update_interval TEXT NOT NULL DEFAULT '',
            profile_url     TEXT NOT NULL DEFAULT '',
            created_at      INTEGER NOT NULL DEFAULT 0,
            updated_at      INTEGER NOT NULL DEFAULT 0
        )",
    )
    .run()
    .await?;

    // Backfill: add columns if table existed before they were added
    let _ = d1
        .prepare("ALTER TABLE sub_templates ADD COLUMN filename TEXT NOT NULL DEFAULT ''")
        .run()
        .await;
    let _ = d1
        .prepare("ALTER TABLE sub_templates ADD COLUMN update_interval TEXT NOT NULL DEFAULT ''")
        .run()
        .await;
    let _ = d1
        .prepare("ALTER TABLE sub_templates ADD COLUMN profile_url TEXT NOT NULL DEFAULT ''")
        .run()
        .await;

    #[derive(Deserialize)]
    struct RecordedAtCheck {
        cnt: f64,
    }
    // Migrate traffic_logs to daily aggregation schema.
    // Old table had (user_id, node_id, bytes, recorded_at) with no unique constraint.
    // New table needs UNIQUE(user_id, node_id, date) for ON CONFLICT upsert to work.
    // Strategy: rebuild table by aggregating old data into new schema.
    let needs_rebuild = d1
        .prepare("SELECT COUNT(*) AS cnt FROM pragma_table_info('traffic_logs') WHERE name = 'recorded_at'")
        .all()
        .await
        .ok()
        .and_then(|r| r.results::<RecordedAtCheck>().ok())
        .map(|rows| rows.first().is_some_and(|r| r.cnt > 0.0))
        .unwrap_or(false);

    if needs_rebuild {
        // 1. Aggregate old rows into new table
        let _ = d1
            .prepare(
                "CREATE TABLE IF NOT EXISTS traffic_logs_new (
                    id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    node_id INTEGER NOT NULL REFERENCES nodes(id),
                    bytes   INTEGER NOT NULL DEFAULT 0,
                    date    TEXT NOT NULL,
                    UNIQUE(user_id, node_id, date)
                )",
            )
            .run()
            .await;
        let _ = d1
            .prepare(
                "INSERT OR REPLACE INTO traffic_logs_new (user_id, node_id, bytes, date)
                 SELECT user_id, node_id, SUM(bytes), strftime('%Y-%m-%d', recorded_at, 'unixepoch')
                 FROM traffic_logs
                 GROUP BY user_id, node_id, strftime('%Y-%m-%d', recorded_at, 'unixepoch')",
            )
            .run()
            .await;
        // 2. Swap tables
        let _ = d1
            .prepare("DROP TABLE IF EXISTS traffic_logs")
            .run()
            .await;
        let _ = d1
            .prepare("ALTER TABLE traffic_logs_new RENAME TO traffic_logs")
            .run()
            .await;
        // 3. Recreate indexes
        let _ = d1
            .prepare("CREATE INDEX IF NOT EXISTS idx_traffic_logs_user ON traffic_logs(user_id)")
            .run()
            .await;
        let _ = d1
            .prepare("CREATE INDEX IF NOT EXISTS idx_traffic_logs_node ON traffic_logs(node_id)")
            .run()
            .await;
    } else {
        // Table already has new schema, just ensure unique index exists
        let _ = d1
            .prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_traffic_logs_daily ON traffic_logs(user_id, node_id, date)")
            .run()
            .await;
    }

    Response::ok("migrated")
}
