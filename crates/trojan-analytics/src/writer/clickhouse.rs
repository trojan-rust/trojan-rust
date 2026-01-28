//! ClickHouse client creation and utilities.

use clickhouse::Client;
use trojan_config::ClickHouseConfig;

use crate::error::AnalyticsError;

/// Create a ClickHouse client from configuration.
pub fn create_client(config: &ClickHouseConfig) -> Result<Client, AnalyticsError> {
    let mut client = Client::default()
        .with_url(&config.url)
        .with_database(&config.database);

    if let Some(ref username) = config.username {
        client = client.with_user(username);
    }

    if let Some(ref password) = config.password {
        client = client.with_password(password);
    }

    // Set timeouts via options
    client = client.with_option(
        "connect_timeout",
        format!("{}s", config.connect_timeout_secs),
    );

    Ok(client)
}

/// SQL for creating the connections table.
#[allow(dead_code)]
pub const CREATE_TABLE_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS trojan.connections
(
    -- Time dimension
    timestamp DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    date Date DEFAULT toDate(timestamp),
    hour UInt8 DEFAULT toHour(timestamp),
    duration_ms UInt64 CODEC(T64, ZSTD(1)),

    -- Connection identity
    conn_id UInt64,
    peer_ip IPv6,
    peer_port UInt16,

    -- User identity
    user_id LowCardinality(String),
    auth_result Enum8('success' = 1, 'failed' = 2, 'skipped' = 3),

    -- Target information
    target_type Enum8('ipv4' = 1, 'ipv6' = 2, 'domain' = 3),
    target_host String CODEC(ZSTD(1)),
    target_port UInt16,
    sni String CODEC(ZSTD(1)),

    -- Traffic statistics
    bytes_sent UInt64 CODEC(T64, ZSTD(1)),
    bytes_recv UInt64 CODEC(T64, ZSTD(1)),
    packets_sent UInt64 CODEC(T64, ZSTD(1)),
    packets_recv UInt64 CODEC(T64, ZSTD(1)),

    -- Connection metadata
    protocol Enum8('tcp' = 1, 'udp' = 2),
    transport Enum8('direct' = 1, 'websocket' = 2),
    close_reason Enum8('normal' = 1, 'timeout' = 2, 'error' = 3, 'reset' = 4, 'shutdown' = 5),
    is_fallback UInt8,

    -- Server information
    server_id LowCardinality(String),

    -- Indexes
    INDEX idx_user_id user_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_target_host target_host TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
    INDEX idx_sni sni TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (date, hour, user_id, timestamp)
TTL date + INTERVAL 90 DAY
SETTINGS index_granularity = 8192
"#;

/// SQL for creating the user hourly stats materialized view.
#[allow(dead_code)]
pub const CREATE_USER_HOURLY_VIEW_SQL: &str = r#"
CREATE MATERIALIZED VIEW IF NOT EXISTS trojan.user_hourly_stats
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (date, hour, user_id)
AS SELECT
    toDate(timestamp) AS date,
    toHour(timestamp) AS hour,
    user_id,
    sum(bytes_sent) AS bytes_sent,
    sum(bytes_recv) AS bytes_recv,
    count() AS connection_count,
    uniqExact(target_host) AS unique_targets
FROM trojan.connections
GROUP BY date, hour, user_id
"#;

/// SQL for creating the user daily stats materialized view.
#[allow(dead_code)]
pub const CREATE_USER_DAILY_VIEW_SQL: &str = r#"
CREATE MATERIALIZED VIEW IF NOT EXISTS trojan.user_daily_stats
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (date, user_id)
AS SELECT
    toDate(timestamp) AS date,
    user_id,
    sum(bytes_sent) AS bytes_sent,
    sum(bytes_recv) AS bytes_recv,
    sum(bytes_sent) + sum(bytes_recv) AS bytes_total,
    count() AS connection_count,
    sum(duration_ms) AS total_duration_ms
FROM trojan.connections
GROUP BY date, user_id
"#;
