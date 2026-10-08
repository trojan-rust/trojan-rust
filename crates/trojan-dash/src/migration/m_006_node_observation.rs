//! Last accepted report times; receipt time before this migration is unknown.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for sql in [
            "ALTER TABLE nodes ADD COLUMN traffic_last_observed_at INTEGER",
            "ALTER TABLE nodes ADD COLUMN traffic_last_received_at INTEGER",
            "UPDATE nodes SET traffic_last_observed_at = (SELECT MAX(observed_at) FROM node_traffic WHERE node_id = nodes.id)",
        ] {
            manager.get_connection().execute_unprepared(sql).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for sql in [
            "ALTER TABLE nodes DROP COLUMN traffic_last_received_at",
            "ALTER TABLE nodes DROP COLUMN traffic_last_observed_at",
        ] {
            manager.get_connection().execute_unprepared(sql).await?;
        }
        Ok(())
    }
}
