//! The columns the agent socket needs on `nodes`.
//!
//! Kept out of `m_001_init` on purpose: a database created by the previous
//! panel already has that migration recorded, so anything folded into it would
//! never run there. These are `ADD COLUMN`s, which SQLite applies to an
//! existing table without rewriting it.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &'static str {
        "m_002_agent_columns"
    }
}

/// Every column, with the value existing rows take.
fn columns() -> Vec<ColumnDef> {
    vec![
        ColumnDef::new(Nodes::NodeType)
            .text()
            .not_null()
            .default("server")
            .to_owned(),
        ColumnDef::new(Nodes::Config)
            .text()
            .not_null()
            .default("{}")
            .to_owned(),
        ColumnDef::new(Nodes::ConfigVersion)
            .big_integer()
            .not_null()
            .default(1)
            .to_owned(),
        ColumnDef::new(Nodes::AgentVersion)
            .text()
            .not_null()
            .default("")
            .to_owned(),
        ColumnDef::new(Nodes::ConnectionsActive)
            .big_integer()
            .not_null()
            .default(0)
            .to_owned(),
        ColumnDef::new(Nodes::BytesIn)
            .big_integer()
            .not_null()
            .default(0)
            .to_owned(),
        ColumnDef::new(Nodes::BytesOut)
            .big_integer()
            .not_null()
            .default(0)
            .to_owned(),
        ColumnDef::new(Nodes::UptimeSecs)
            .big_integer()
            .not_null()
            .default(0)
            .to_owned(),
    ]
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for mut column in columns() {
            manager
                .alter_table(
                    Table::alter()
                        .table(Nodes::Table)
                        .add_column(&mut column)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for column in columns() {
            manager
                .alter_table(
                    Table::alter()
                        .table(Nodes::Table)
                        .drop_column(Alias::new(column.get_column_name()))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Nodes {
    Table,
    NodeType,
    Config,
    ConfigVersion,
    AgentVersion,
    ConnectionsActive,
    BytesIn,
    BytesOut,
    UptimeSecs,
}
