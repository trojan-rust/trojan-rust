//! Schema migrations.
//!
//! `m_001_init` carries the name the previous panel (`board`) gave it, and
//! creates the same tables: a database that panel created already has the row
//! in `seaql_migrations`, so it is recognised as applied rather than re-run.
//! That is what lets this service open an existing deployment's database with
//! no migration step at all.

use sea_orm_migration::prelude::*;

mod m_001_init;
mod m_002_agent_columns;
mod m_003_hourly_traffic;
mod m_004_user_node_limits;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m_001_init::Migration),
            Box::new(m_002_agent_columns::Migration),
            Box::new(m_003_hourly_traffic::Migration),
            Box::new(m_004_user_node_limits::Migration),
        ]
    }
}
