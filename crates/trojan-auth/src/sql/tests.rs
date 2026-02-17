//! Tests for SQL authentication backend.

use std::time::Duration;

use crate::sql::{DatabaseType, SqlAuth, SqlAuthConfig, TrafficRecordingMode};
use crate::{AuthBackend, AuthError, sha224_hex};

/// Create test database schema.
async fn create_schema(auth: &SqlAuth) {
    let create_table = r#"
        CREATE TABLE IF NOT EXISTS trojan_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash TEXT NOT NULL UNIQUE,
            user_id TEXT,
            traffic_limit INTEGER NOT NULL DEFAULT 0,
            traffic_used INTEGER NOT NULL DEFAULT 0,
            expires_at INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1
        )
    "#;

    sqlx::query(create_table)
        .execute(auth.pool())
        .await
        .expect("Failed to create table");
}

/// Insert a test user.
async fn insert_user(
    auth: &SqlAuth,
    password: &str,
    user_id: Option<&str>,
    traffic_limit: i64,
    traffic_used: i64,
    expires_at: i64,
    enabled: bool,
) {
    let hash = sha224_hex(password);
    let insert = r#"
        INSERT INTO trojan_users (password_hash, user_id, traffic_limit, traffic_used, expires_at, enabled)
        VALUES (?, ?, ?, ?, ?, ?)
    "#;

    sqlx::query(insert)
        .bind(&hash)
        .bind(user_id)
        .bind(traffic_limit)
        .bind(traffic_used)
        .bind(expires_at)
        .bind(enabled)
        .execute(auth.pool())
        .await
        .expect("Failed to insert user");
}

/// Create a test SqlAuth with in-memory SQLite.
async fn setup_test_db() -> SqlAuth {
    let config = SqlAuthConfig::new("sqlite::memory:")
        .max_connections(1)
        .traffic_mode(TrafficRecordingMode::Immediate);

    SqlAuth::connect(config).await.expect("Failed to connect")
}

#[tokio::test]
async fn test_database_type_detection() {
    assert_eq!(
        DatabaseType::from_url("postgres://localhost/db"),
        Some(DatabaseType::PostgreSQL)
    );
    assert_eq!(
        DatabaseType::from_url("postgresql://localhost/db"),
        Some(DatabaseType::PostgreSQL)
    );
    assert_eq!(
        DatabaseType::from_url("mysql://localhost/db"),
        Some(DatabaseType::MySQL)
    );
    assert_eq!(
        DatabaseType::from_url("mariadb://localhost/db"),
        Some(DatabaseType::MySQL)
    );
    assert_eq!(
        DatabaseType::from_url("sqlite:test.db"),
        Some(DatabaseType::SQLite)
    );
    assert_eq!(
        DatabaseType::from_url("sqlite::memory:"),
        Some(DatabaseType::SQLite)
    );
    assert_eq!(DatabaseType::from_url("invalid://localhost"), None);
}

#[tokio::test]
async fn test_connect_sqlite() {
    let auth = setup_test_db().await;
    assert_eq!(auth.database_type(), DatabaseType::SQLite);
}

#[tokio::test]
async fn test_verify_valid_password() {
    let auth = setup_test_db().await;
    create_schema(&auth).await;
    insert_user(&auth, "test_password", Some("user1"), 0, 0, 0, true).await;

    let hash = sha224_hex("test_password");
    let result = auth.verify(&hash).await;

    let auth_result = result.unwrap();
    assert_eq!(auth_result.user_id, Some("user1".to_string()));
}

#[tokio::test]
async fn test_verify_invalid_password() {
    let auth = setup_test_db().await;
    create_schema(&auth).await;
    insert_user(&auth, "test_password", Some("user1"), 0, 0, 0, true).await;

    let hash = sha224_hex("wrong_password");
    let result = auth.verify(&hash).await;

    assert!(matches!(result, Err(AuthError::Invalid)));
}

#[tokio::test]
async fn test_verify_disabled_user() {
    let auth = setup_test_db().await;
    create_schema(&auth).await;
    insert_user(&auth, "test_password", Some("user1"), 0, 0, 0, false).await;

    let hash = sha224_hex("test_password");
    let result = auth.verify(&hash).await;

    assert!(matches!(result, Err(AuthError::Disabled)));
}

#[tokio::test]
#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
async fn test_verify_expired_user() {
    let auth = setup_test_db().await;
    create_schema(&auth).await;

    // Set expires_at to 1 second ago
    let expired_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        - 1;

    insert_user(
        &auth,
        "test_password",
        Some("user1"),
        0,
        0,
        expired_time,
        true,
    )
    .await;

    let hash = sha224_hex("test_password");
    let result = auth.verify(&hash).await;

    assert!(matches!(result, Err(AuthError::Expired)));
}

#[tokio::test]
async fn test_verify_traffic_exceeded() {
    let auth = setup_test_db().await;
    create_schema(&auth).await;

    // Set traffic_used >= traffic_limit
    insert_user(
        &auth,
        "test_password",
        Some("user1"),
        1000, // limit
        1000, // used (at limit)
        0,
        true,
    )
    .await;

    let hash = sha224_hex("test_password");
    let result = auth.verify(&hash).await;

    assert!(matches!(result, Err(AuthError::TrafficExceeded)));
}

#[tokio::test]
async fn test_verify_unlimited_traffic() {
    let auth = setup_test_db().await;
    create_schema(&auth).await;

    // traffic_limit = 0 means unlimited
    insert_user(
        &auth,
        "test_password",
        Some("user1"),
        0,         // unlimited
        999999999, // high usage
        0,
        true,
    )
    .await;

    let hash = sha224_hex("test_password");
    let result = auth.verify(&hash).await;

    result.unwrap();
}

#[tokio::test]
async fn test_verify_no_expiry() {
    let auth = setup_test_db().await;
    create_schema(&auth).await;

    // expires_at = 0 means never expires
    insert_user(&auth, "test_password", Some("user1"), 0, 0, 0, true).await;

    let hash = sha224_hex("test_password");
    let result = auth.verify(&hash).await;

    result.unwrap();
}

#[tokio::test]
async fn test_verify_returns_metadata() {
    let auth = setup_test_db().await;
    create_schema(&auth).await;

    insert_user(
        &auth,
        "test_password",
        Some("user1"),
        10000, // traffic_limit
        5000,  // traffic_used
        0,
        true,
    )
    .await;

    let hash = sha224_hex("test_password");
    let result = auth.verify(&hash).await.unwrap();

    assert!(result.metadata.is_some());
    let meta = result.metadata.unwrap();
    assert_eq!(meta.traffic_limit, 10000);
    assert_eq!(meta.traffic_used, 5000);
    assert!(meta.enabled);
}

#[tokio::test]
async fn test_record_traffic_immediate() {
    let auth = setup_test_db().await;
    create_schema(&auth).await;
    insert_user(&auth, "test_password", Some("user1"), 0, 0, 0, true).await;

    // Record traffic
    auth.record_traffic("user1", 1000).await.unwrap();

    // Verify traffic was recorded
    let hash = sha224_hex("test_password");
    let result = auth.verify(&hash).await.unwrap();
    let meta = result.metadata.unwrap();

    assert_eq!(meta.traffic_used, 1000);
}

#[tokio::test]
async fn test_record_traffic_accumulates() {
    let auth = setup_test_db().await;
    create_schema(&auth).await;
    insert_user(&auth, "test_password", Some("user1"), 0, 100, 0, true).await;

    // Record additional traffic
    auth.record_traffic("user1", 500).await.unwrap();
    auth.record_traffic("user1", 400).await.unwrap();

    // Verify traffic accumulated: 100 + 500 + 400 = 1000
    let hash = sha224_hex("test_password");
    let result = auth.verify(&hash).await.unwrap();
    let meta = result.metadata.unwrap();

    assert_eq!(meta.traffic_used, 1000);
}

#[tokio::test]
async fn test_record_traffic_disabled_mode() {
    let config = SqlAuthConfig::new("sqlite::memory:")
        .max_connections(1)
        .traffic_mode(TrafficRecordingMode::Disabled);

    let auth = SqlAuth::connect(config).await.unwrap();
    create_schema(&auth).await;
    insert_user(&auth, "test_password", Some("user1"), 0, 0, 0, true).await;

    // Record traffic (should be no-op)
    auth.record_traffic("user1", 1000).await.unwrap();

    // Verify traffic was NOT recorded
    let hash = sha224_hex("test_password");
    let result = auth.verify(&hash).await.unwrap();
    let meta = result.metadata.unwrap();

    assert_eq!(meta.traffic_used, 0);
}

#[tokio::test]
async fn test_user_without_user_id() {
    let auth = setup_test_db().await;
    create_schema(&auth).await;
    insert_user(&auth, "test_password", None, 0, 0, 0, true).await;

    let hash = sha224_hex("test_password");
    let result = auth.verify(&hash).await.unwrap();

    assert!(result.user_id.is_none());
}

#[tokio::test]
async fn test_multiple_users() {
    let auth = setup_test_db().await;
    create_schema(&auth).await;

    insert_user(&auth, "password1", Some("user1"), 0, 0, 0, true).await;
    insert_user(&auth, "password2", Some("user2"), 0, 0, 0, true).await;
    insert_user(&auth, "password3", Some("user3"), 0, 0, 0, true).await;

    // Verify each user
    let hash1 = sha224_hex("password1");
    let hash2 = sha224_hex("password2");
    let hash3 = sha224_hex("password3");

    assert_eq!(
        auth.verify(&hash1).await.unwrap().user_id,
        Some("user1".to_string())
    );
    assert_eq!(
        auth.verify(&hash2).await.unwrap().user_id,
        Some("user2".to_string())
    );
    assert_eq!(
        auth.verify(&hash3).await.unwrap().user_id,
        Some("user3".to_string())
    );
}

#[tokio::test]
async fn test_config_builder() {
    let config = SqlAuthConfig::new("sqlite::memory:")
        .max_connections(20)
        .min_connections(5)
        .connect_timeout(Duration::from_secs(60))
        .traffic_mode(TrafficRecordingMode::Batched)
        .batch_flush_interval(Duration::from_secs(10))
        .batch_max_pending(500);

    assert_eq!(config.database_url, "sqlite::memory:");
    assert_eq!(config.max_connections, 20);
    assert_eq!(config.min_connections, 5);
    assert_eq!(config.connect_timeout, Duration::from_secs(60));
    assert_eq!(config.traffic_mode, TrafficRecordingMode::Batched);
    assert_eq!(config.batch_flush_interval, Duration::from_secs(10));
    assert_eq!(config.batch_max_pending, 500);
}

#[tokio::test]
async fn test_config_defaults() {
    let config = SqlAuthConfig::default();

    assert_eq!(config.max_connections, 10);
    assert_eq!(config.min_connections, 1);
    assert_eq!(config.traffic_mode, TrafficRecordingMode::Batched);
}

#[tokio::test]
async fn test_invalid_database_url() {
    let config = SqlAuthConfig::new("invalid://localhost/db");
    let result = SqlAuth::connect(config).await;

    result.unwrap_err();
}

#[tokio::test]
async fn test_debug_impl_hides_credentials() {
    let auth = setup_test_db().await;
    let debug_str = format!("{:?}", auth);

    // Should not contain the connection string
    assert!(!debug_str.contains("memory"));
    // Should contain struct name and fields
    assert!(debug_str.contains("StoreAuth"));
    assert!(debug_str.contains("SqlStore"));
}

/// Create a test SqlAuth with caching enabled.
async fn setup_test_db_with_cache() -> SqlAuth {
    let config = SqlAuthConfig::new("sqlite::memory:")
        .max_connections(1)
        .traffic_mode(TrafficRecordingMode::Immediate)
        .cache_enabled(true)
        .cache_ttl(Duration::from_secs(60));

    SqlAuth::connect(config).await.expect("Failed to connect")
}

#[tokio::test]
async fn test_cache_enabled() {
    let auth = setup_test_db_with_cache().await;
    assert!(auth.cache_enabled());

    let auth_no_cache = setup_test_db().await;
    assert!(!auth_no_cache.cache_enabled());
}

#[tokio::test]
async fn test_cache_hit() {
    let auth = setup_test_db_with_cache().await;
    create_schema(&auth).await;
    insert_user(&auth, "test_password", Some("user1"), 0, 0, 0, true).await;

    let hash = sha224_hex("test_password");

    // First call - cache miss, queries DB
    let result1 = auth.verify(&hash).await;
    result1.unwrap();

    let stats = auth.cache_stats().unwrap();
    assert_eq!(stats.misses, 1);
    assert_eq!(stats.hits, 0);

    // Second call - cache hit
    let result2 = auth.verify(&hash).await;
    result2.unwrap();

    let stats = auth.cache_stats().unwrap();
    assert_eq!(stats.misses, 1);
    assert_eq!(stats.hits, 1);
}

#[tokio::test]
async fn test_cache_invalidate() {
    let auth = setup_test_db_with_cache().await;
    create_schema(&auth).await;
    insert_user(&auth, "test_password", Some("user1"), 0, 0, 0, true).await;

    let hash = sha224_hex("test_password");

    // Populate cache
    let _ = auth.verify(&hash).await;
    assert_eq!(auth.cache_stats().unwrap().size, 1);

    // Invalidate
    auth.cache_invalidate(&hash);
    assert_eq!(auth.cache_stats().unwrap().size, 0);
}

#[tokio::test]
async fn test_cache_clear() {
    let auth = setup_test_db_with_cache().await;
    create_schema(&auth).await;
    insert_user(&auth, "password1", Some("user1"), 0, 0, 0, true).await;
    insert_user(&auth, "password2", Some("user2"), 0, 0, 0, true).await;

    // Populate cache
    let _ = auth.verify(&sha224_hex("password1")).await;
    let _ = auth.verify(&sha224_hex("password2")).await;
    assert_eq!(auth.cache_stats().unwrap().size, 2);

    // Clear all
    auth.cache_clear();
    assert_eq!(auth.cache_stats().unwrap().size, 0);
}

#[tokio::test]
async fn test_cache_does_not_cache_failures() {
    let auth = setup_test_db_with_cache().await;
    create_schema(&auth).await;

    let hash = sha224_hex("nonexistent");

    // Try to verify non-existent user
    let result = auth.verify(&hash).await;
    assert!(matches!(result, Err(AuthError::Invalid)));

    // Cache should be empty (failures not cached)
    assert_eq!(auth.cache_stats().unwrap().size, 0);
}

#[tokio::test]
async fn test_cache_respects_disabled_user() {
    let auth = setup_test_db_with_cache().await;
    create_schema(&auth).await;
    insert_user(&auth, "test_password", Some("user1"), 0, 0, 0, false).await;

    let hash = sha224_hex("test_password");

    // First call - should fail (disabled)
    let result = auth.verify(&hash).await;
    assert!(matches!(result, Err(AuthError::Disabled)));

    // Cache should be empty (disabled user not cached)
    assert_eq!(auth.cache_stats().unwrap().size, 0);
}

#[tokio::test]
async fn test_config_cache_builder() {
    let config = SqlAuthConfig::new("sqlite::memory:")
        .cache_enabled(true)
        .cache_ttl(Duration::from_secs(120));

    assert!(config.cache_enabled);
    assert_eq!(config.cache_ttl, Duration::from_secs(120));
}
