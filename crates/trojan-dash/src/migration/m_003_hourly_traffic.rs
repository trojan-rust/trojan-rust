//! An hourly rollup beside the daily one.
//!
//! `traffic_logs` aggregates on a `YYYY-MM-DD` date, so the shortest window it
//! can describe is a day — a "last 24 hours" chart drawn from it is one bar.
//! This table carries the same sum under a `YYYY-MM-DDTHH` key, written by the
//! same accounting event.
//!
//! It is not a replacement: 24 rows per user per node per day is worth keeping
//! only as long as something reads them, so rows past the retention window are
//! pruned and the daily table stays the record of history.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &'static str {
        "m_003_hourly_traffic"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(TrafficHourly::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(TrafficHourly::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(TrafficHourly::UserId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TrafficHourly::NodeId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TrafficHourly::Bytes)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(TrafficHourly::Hour).text().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_traffic_hourly_user")
                            .from(TrafficHourly::Table, TrafficHourly::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_traffic_hourly_node")
                            .from(TrafficHourly::Table, TrafficHourly::NodeId)
                            .to(Nodes::Table, Nodes::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    // What the upsert conflicts on.
                    .index(
                        Index::create()
                            .name("uq_traffic_hourly_user_node_hour")
                            .col(TrafficHourly::UserId)
                            .col(TrafficHourly::NodeId)
                            .col(TrafficHourly::Hour)
                            .unique(),
                    )
                    .to_owned(),
            )
            .await?;

        // Every read is a range over `hour`, and so is the prune.
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_traffic_hourly_hour")
                    .table(TrafficHourly::Table)
                    .col(TrafficHourly::Hour)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(TrafficHourly::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum TrafficHourly {
    Table,
    Id,
    UserId,
    NodeId,
    Bytes,
    Hour,
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Nodes {
    Table,
    Id,
}
