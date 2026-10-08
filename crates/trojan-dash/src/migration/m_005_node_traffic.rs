//! Durable node accounting and monthly quota policies.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for sql in [
            "ALTER TABLE nodes ADD COLUMN traffic_limit INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE nodes ADD COLUMN reset_day INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE nodes ADD COLUMN reset_timezone TEXT NOT NULL DEFAULT 'UTC'",
            "ALTER TABLE nodes ADD COLUMN traffic_total INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE nodes ADD COLUMN traffic_period_start INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE nodes ADD COLUMN traffic_period_end INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE nodes ADD COLUMN traffic_period_bytes_in INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE nodes ADD COLUMN traffic_period_bytes_out INTEGER NOT NULL DEFAULT 0",
            "CREATE TABLE node_traffic_streams (\
                node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE, \
                stream_id TEXT NOT NULL, sequence INTEGER NOT NULL, \
                PRIMARY KEY (node_id, stream_id))",
            "CREATE TABLE node_traffic (\
                node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE, \
                observed_at INTEGER NOT NULL, \
                bytes_in INTEGER NOT NULL CHECK(typeof(bytes_in) = 'integer' AND bytes_in >= 0), \
                bytes_out INTEGER NOT NULL CHECK(typeof(bytes_out) = 'integer' AND bytes_out >= 0), \
                PRIMARY KEY (node_id, observed_at))",
        ] {
            manager.get_connection().execute_unprepared(sql).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for sql in [
            "DROP TABLE node_traffic",
            "DROP TABLE node_traffic_streams",
            "ALTER TABLE nodes DROP COLUMN traffic_period_bytes_out",
            "ALTER TABLE nodes DROP COLUMN traffic_period_bytes_in",
            "ALTER TABLE nodes DROP COLUMN traffic_period_end",
            "ALTER TABLE nodes DROP COLUMN traffic_period_start",
            "ALTER TABLE nodes DROP COLUMN traffic_total",
            "ALTER TABLE nodes DROP COLUMN reset_timezone",
            "ALTER TABLE nodes DROP COLUMN reset_day",
            "ALTER TABLE nodes DROP COLUMN traffic_limit",
        ] {
            manager.get_connection().execute_unprepared(sql).await?;
        }
        Ok(())
    }
}
