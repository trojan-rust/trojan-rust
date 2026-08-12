use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// What one user may move through one node in a month.
///
/// The spend it is compared against is summed from `traffic_logs`, so this
/// table holds only the allowance.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "user_node_limits")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: i64,
    #[sea_orm(primary_key, auto_increment = false)]
    pub node_id: i64,
    /// Bytes per calendar month, UTC. Zero means unlimited.
    pub monthly_bytes: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::UserId",
        to = "super::users::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    Users,
    #[sea_orm(
        belongs_to = "super::nodes::Entity",
        from = "Column::NodeId",
        to = "super::nodes::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    Nodes,
}

impl Related<super::users::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Users.def()
    }
}

impl Related<super::nodes::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Nodes.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
