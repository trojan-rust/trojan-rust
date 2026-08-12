//! Per-node allowances, on top of the account-wide one.
//!
//! A user's `traffic_limit` covers everything they move; this caps what they
//! may move through one node in particular — typically an entry, whose
//! bandwidth is the scarce thing in a relay chain. The spend is not stored:
//! it is summed from `traffic_logs` over the current month, so nothing has to
//! be reset when the month turns.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &'static str {
        "m_004_user_node_limits"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(UserNodeLimits::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UserNodeLimits::UserId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserNodeLimits::NodeId)
                            .big_integer()
                            .not_null(),
                    )
                    // Zero means unlimited, matching `users.traffic_limit`.
                    .col(
                        ColumnDef::new(UserNodeLimits::MonthlyBytes)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    // One allowance per pair, and the pair is the identity —
                    // no surrogate id to carry around.
                    .primary_key(
                        Index::create()
                            .col(UserNodeLimits::UserId)
                            .col(UserNodeLimits::NodeId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(UserNodeLimits::Table, UserNodeLimits::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(UserNodeLimits::Table, UserNodeLimits::NodeId)
                            .to(Nodes::Table, Nodes::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserNodeLimits::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum UserNodeLimits {
    Table,
    UserId,
    NodeId,
    MonthlyBytes,
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
