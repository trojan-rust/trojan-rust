//! Admin views of the traffic log.

use axum::Json;
use axum::extract::{Query, State};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait, FromQueryResult, QueryFilter,
    QueryOrder, QuerySelect, Statement, Value,
};

use crate::entity::traffic_logs;
use crate::error::DashError;
use crate::state::AppState;
use crate::types::{
    Bucket, Grouping, Range, SeriesPoint, SeriesQuery, SeriesResponse, SeriesRow,
    TrafficLogResponse, TrafficQuery,
};
use crate::util::{date_days_ago, hour_hours_ago, today_date};

/// The raw log is unbounded; a page of it is all any view needs.
const LIMIT: u64 = 1000;

/// Past this, a whole-history chart switches from weekly to monthly points.
const WEEKLY_SPAN_LIMIT_DAYS: i64 = 730;

/// `GET /admin/traffic?user_id=&node_id=`
pub async fn list(
    State(state): State<AppState>,
    Query(filter): Query<TrafficQuery>,
) -> Result<Json<Vec<TrafficLogResponse>>, DashError> {
    let mut select = traffic_logs::Entity::find();
    if let Some(user_id) = filter.user_id {
        select = select.filter(traffic_logs::Column::UserId.eq(user_id));
    }
    if let Some(node_id) = filter.node_id {
        select = select.filter(traffic_logs::Column::NodeId.eq(node_id));
    }

    let rows = select
        .order_by_desc(traffic_logs::Column::Date)
        .order_by_desc(traffic_logs::Column::Id)
        .limit(LIMIT)
        .all(&state.db)
        .await?;

    Ok(Json(rows.iter().map(TrafficLogResponse::from).collect()))
}

/// `GET /admin/traffic/series?range=&group=&user_id=&node_id=`
///
/// Totals bucketed over time. The raw log endpoint stops at 1000 rows, which a
/// chart of any real deployment would exhaust within days; this aggregates in
/// SQLite instead, so the response is bounded by buckets × lines.
pub async fn series(
    State(state): State<AppState>,
    Query(query): Query<SeriesQuery>,
) -> Result<Json<SeriesResponse>, DashError> {
    Ok(Json(build(&state, &query).await?))
}

/// Where a range reads from, and how its time column becomes a bucket.
struct Plan {
    table: &'static str,
    /// The bucket, as SQL over the source table aliased `t`.
    bucket_sql: &'static str,
    /// The column a lower bound compares against.
    column: &'static str,
    bucket: Bucket,
    start: String,
}

impl Plan {
    /// Ranges shorter than a day can only come from the hourly rollup; the
    /// daily table has no finer key than a date.
    async fn resolve<C: ConnectionTrait>(range: Range, conn: &C) -> Result<Self, DashError> {
        let plan = match range {
            Range::Day => Self::hourly(23),
            Range::ThreeDays => Self::hourly(71),
            Range::Week => Self::daily(Bucket::Day, "t.date", date_days_ago(6)),
            Range::Month => Self::daily(Bucket::Day, "t.date", date_days_ago(29)),
            Range::Quarter => Self::daily(Bucket::Day, "t.date", date_days_ago(89)),
            Range::All => {
                // Weekly points over several years are noise, and monthly ones
                // over a few months are four bars. Let the data decide.
                let earliest = earliest_date(conn).await?;
                let start = earliest.unwrap_or_else(today_date);
                if start < date_days_ago(WEEKLY_SPAN_LIMIT_DAYS) {
                    Self::daily(Bucket::Month, "substr(t.date, 1, 7)", start)
                } else {
                    // SQLite counts weekday 0 as Sunday, so the Sunday on or
                    // after a date, less six days, is that date's Monday.
                    Self::daily(Bucket::Week, "date(t.date, 'weekday 0', '-6 days')", start)
                }
            }
        };
        Ok(plan)
    }

    fn hourly(hours_back: i64) -> Self {
        Self {
            table: "traffic_hourly",
            bucket_sql: "t.hour",
            column: "t.hour",
            bucket: Bucket::Hour,
            start: hour_hours_ago(hours_back),
        }
    }

    fn daily(bucket: Bucket, bucket_sql: &'static str, start: String) -> Self {
        Self {
            table: "traffic_logs",
            bucket_sql,
            column: "t.date",
            bucket,
            start,
        }
    }
}

/// The oldest day the log knows about, or `None` when it is empty.
async fn earliest_date<C: ConnectionTrait>(conn: &C) -> Result<Option<String>, DashError> {
    #[derive(FromQueryResult)]
    struct Earliest {
        earliest: Option<String>,
    }

    let row = Earliest::find_by_statement(Statement::from_string(
        DatabaseBackend::Sqlite,
        "SELECT MIN(date) AS earliest FROM traffic_logs",
    ))
    .one(conn)
    .await?;

    Ok(row.and_then(|r| r.earliest))
}

/// Build a series. Shared with `/me/traffic`, which supplies the caller's own
/// `user_id` rather than taking one from the query string.
pub(crate) async fn build(
    state: &AppState,
    query: &SeriesQuery,
) -> Result<SeriesResponse, DashError> {
    let plan = Plan::resolve(query.range, &state.db).await?;

    // Only the bound values are parameters; every fragment spliced in here is
    // one of the fixed strings above.
    let (key, label, join) = match query.group {
        Grouping::Node => (
            "t.node_id",
            "n.name",
            " JOIN nodes n ON t.node_id = n.id".to_owned(),
        ),
        Grouping::User => (
            "t.user_id",
            "u.username",
            " JOIN users u ON t.user_id = u.id".to_owned(),
        ),
        Grouping::None => ("NULL", "NULL", String::new()),
    };

    let mut values: Vec<Value> = vec![plan.start.clone().into()];
    let mut wheres = format!("{} >= ?1", plan.column);
    if let Some(user_id) = query.user_id {
        values.push(user_id.into());
        wheres.push_str(&format!(" AND t.user_id = ?{}", values.len()));
    }
    if let Some(node_id) = query.node_id {
        values.push(node_id.into());
        wheres.push_str(&format!(" AND t.node_id = ?{}", values.len()));
    }

    let group_by = if query.group == Grouping::None {
        "GROUP BY 1".to_owned()
    } else {
        format!("GROUP BY 1, {key}")
    };

    let sql = format!(
        "SELECT {bucket} AS t, {key} AS key, {label} AS label, SUM(t.bytes) AS bytes \
         FROM {table} t{join} WHERE {wheres} {group_by} ORDER BY 1, label",
        bucket = plan.bucket_sql,
        table = plan.table,
    );

    let rows = SeriesRow::find_by_statement(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        sql,
        values,
    ))
    .all(&state.db)
    .await?;

    Ok(SeriesResponse {
        bucket: plan.bucket,
        start: plan.start,
        points: rows.iter().map(SeriesPoint::from).collect(),
    })
}
