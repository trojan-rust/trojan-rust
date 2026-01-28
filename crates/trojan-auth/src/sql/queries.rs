//! SQL queries for different databases.

/// Query to find user by password hash (PostgreSQL).
pub const FIND_BY_HASH_PG: &str = r#"
SELECT id, password_hash, user_id, traffic_limit, traffic_used, expires_at, enabled
FROM trojan_users
WHERE password_hash = $1
"#;

/// Query to find user by password hash (MySQL/SQLite).
pub const FIND_BY_HASH_MYSQL: &str = r#"
SELECT id, password_hash, user_id, traffic_limit, traffic_used, expires_at, enabled
FROM trojan_users
WHERE password_hash = ?
"#;

/// Query to update traffic usage (PostgreSQL).
pub const UPDATE_TRAFFIC_PG: &str = r#"
UPDATE trojan_users
SET traffic_used = traffic_used + $1
WHERE user_id = $2
"#;

/// Query to update traffic usage (MySQL/SQLite).
pub const UPDATE_TRAFFIC_MYSQL: &str = r#"
UPDATE trojan_users
SET traffic_used = traffic_used + ?
WHERE user_id = ?
"#;
