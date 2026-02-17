-- D1 schema for auth-worker
-- Apply with: npx wrangler d1 execute AUTH_DB --file=schema.sql

CREATE TABLE IF NOT EXISTS users (
    hash        TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL UNIQUE,
    traffic_limit INTEGER NOT NULL DEFAULT 0,
    traffic_used  INTEGER NOT NULL DEFAULT 0,
    expires_at    INTEGER NOT NULL DEFAULT 0,
    enabled       INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_users_user_id ON users(user_id);
