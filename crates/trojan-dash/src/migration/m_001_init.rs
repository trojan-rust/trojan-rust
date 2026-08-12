use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &'static str {
        "m_001_init"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Users::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Users::Hash).text().not_null().unique_key())
                    .col(
                        ColumnDef::new(Users::Username)
                            .text()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(Users::TrafficLimit)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(Users::TrafficUsed)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(Users::ExpiresAt)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(Users::Enabled)
                            .big_integer()
                            .not_null()
                            .default(1),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_users_hash")
                    .table(Users::Table)
                    .col(Users::Hash)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Nodes::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Nodes::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Nodes::Name).text().not_null().unique_key())
                    .col(ColumnDef::new(Nodes::Token).text().not_null().unique_key())
                    .col(
                        ColumnDef::new(Nodes::Enabled)
                            .big_integer()
                            .not_null()
                            .default(1),
                    )
                    .col(ColumnDef::new(Nodes::Ip).text().not_null().default(""))
                    .col(
                        ColumnDef::new(Nodes::LastSeen)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(Nodes::CreatedAt)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(TrafficLogs::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(TrafficLogs::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(TrafficLogs::UserId).big_integer().not_null())
                    .col(ColumnDef::new(TrafficLogs::NodeId).big_integer().not_null())
                    .col(
                        ColumnDef::new(TrafficLogs::Bytes)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(TrafficLogs::Date).text().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_traffic_logs_user")
                            .from(TrafficLogs::Table, TrafficLogs::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_traffic_logs_node")
                            .from(TrafficLogs::Table, TrafficLogs::NodeId)
                            .to(Nodes::Table, Nodes::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .index(
                        Index::create()
                            .name("uq_traffic_user_node_date")
                            .col(TrafficLogs::UserId)
                            .col(TrafficLogs::NodeId)
                            .col(TrafficLogs::Date)
                            .unique(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_traffic_logs_user")
                    .table(TrafficLogs::Table)
                    .col(TrafficLogs::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_traffic_logs_node")
                    .table(TrafficLogs::Table)
                    .col(TrafficLogs::NodeId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(SubTemplates::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SubTemplates::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(SubTemplates::Name)
                            .text()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(SubTemplates::Filename)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(SubTemplates::Content)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(SubTemplates::ContentType)
                            .text()
                            .not_null()
                            .default("text/plain; charset=utf-8"),
                    )
                    .col(
                        ColumnDef::new(SubTemplates::UpdateInterval)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(SubTemplates::ProfileUrl)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(SubTemplates::CreatedAt)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(SubTemplates::UpdatedAt)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SubTemplates::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(TrafficLogs::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Nodes::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Users::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
    Hash,
    Username,
    TrafficLimit,
    TrafficUsed,
    ExpiresAt,
    Enabled,
}

#[derive(DeriveIden)]
enum Nodes {
    Table,
    Id,
    Name,
    Token,
    Enabled,
    Ip,
    LastSeen,
    CreatedAt,
}

#[derive(DeriveIden)]
enum TrafficLogs {
    Table,
    Id,
    UserId,
    NodeId,
    Bytes,
    Date,
}

#[derive(DeriveIden)]
enum SubTemplates {
    Table,
    Id,
    Name,
    Filename,
    Content,
    ContentType,
    UpdateInterval,
    ProfileUrl,
    CreatedAt,
    UpdatedAt,
}
