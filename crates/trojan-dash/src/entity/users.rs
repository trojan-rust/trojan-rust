use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    #[sea_orm(unique, indexed)]
    pub hash: String,
    #[sea_orm(unique)]
    pub username: String,
    pub traffic_limit: i64,
    pub traffic_used: i64,
    pub expires_at: i64,
    pub enabled: i64,
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
