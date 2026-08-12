use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "nodes")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    #[sea_orm(unique)]
    pub name: String,
    #[sea_orm(unique)]
    pub token: String,
    pub enabled: i64,
    pub ip: String,
    pub last_seen: i64,
    pub created_at: i64,

    // ── What the panel tells the agent to run ──
    /// Which service the agent on this node boots.
    pub node_type: String,
    /// Opaque service config, handed to the agent verbatim.
    pub config: String,
    /// Bumped on every config change, so an agent can tell one apart.
    pub config_version: i64,

    // ── What the agent reports back ──
    /// Agent build, from the last registration. Empty until one connects.
    pub agent_version: String,
    pub connections_active: i64,
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub uptime_secs: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::traffic_logs::Entity")]
    TrafficLogs,
}

impl Related<super::traffic_logs::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::TrafficLogs.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
