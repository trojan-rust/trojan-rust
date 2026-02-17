-- D1 schema for auth-worker
-- Apply with: npx wrangler d1 execute AUTH_DB --file=schema.sql

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hash          TEXT NOT NULL UNIQUE,
    username      TEXT NOT NULL UNIQUE,
    traffic_limit INTEGER NOT NULL DEFAULT 0,
    traffic_used  INTEGER NOT NULL DEFAULT 0,
    expires_at    INTEGER NOT NULL DEFAULT 0,
    enabled       INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_users_hash ON users(hash);

CREATE TABLE IF NOT EXISTS nodes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    token      TEXT NOT NULL UNIQUE,
    enabled    INTEGER NOT NULL DEFAULT 1,
    ip         TEXT NOT NULL DEFAULT '',
    last_seen  INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS traffic_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    node_id     INTEGER NOT NULL REFERENCES nodes(id),
    bytes       INTEGER NOT NULL,
    recorded_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_traffic_logs_user ON traffic_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_traffic_logs_node ON traffic_logs(node_id);
