//! Admin migration handler.

use worker::*;

/// POST /admin/migrate — auto-create tables and indexes
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
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            node_id INTEGER NOT NULL REFERENCES nodes(id),
            bytes   INTEGER NOT NULL DEFAULT 0,
            date    TEXT NOT NULL,
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
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT NOT NULL UNIQUE,
            filename        TEXT NOT NULL DEFAULT '',
            content         TEXT NOT NULL DEFAULT '',
            content_type    TEXT NOT NULL DEFAULT 'text/plain; charset=utf-8',
            update_interval TEXT NOT NULL DEFAULT '',
            profile_url     TEXT NOT NULL DEFAULT '',
            created_at      INTEGER NOT NULL DEFAULT 0,
            updated_at      INTEGER NOT NULL DEFAULT 0
        )",
    )
    .run()
    .await?;

    Response::ok("migrated")
}
