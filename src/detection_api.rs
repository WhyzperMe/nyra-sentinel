//! Authenticated, read-only, bounded access to Phase 3 results.
use crate::api::{self, AppState};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Serialize, FromRow)]
struct Detection {
    id: String,
    rule_id: String,
    rule_version: i64,
    severity: String,
    classification: String,
    entity_kind: String,
    entity_value: String,
    incident_id: String,
    window_start_epoch: i64,
    first_seen_epoch: i64,
    last_seen_epoch: i64,
    observed_count: i64,
    title: String,
    explanation: String,
    details_json: String,
}
#[derive(Debug, Serialize, FromRow)]
struct Incident {
    id: String,
    subject_kind: String,
    subject_value: String,
    status: String,
    severity: String,
    first_seen_epoch: i64,
    last_seen_epoch: i64,
    detection_count: i64,
    title: String,
}
#[derive(Debug, Serialize, FromRow)]
struct Asset {
    asset_key: String,
    first_seen_epoch: i64,
    last_seen_epoch: i64,
    total_dns_queries: i64,
    total_firewall_blocks: i64,
    total_outbound_passes: i64,
}
#[derive(Debug, Serialize, FromRow)]
struct DomainRow {
    domain: String,
    first_seen_epoch: i64,
    last_seen_epoch: i64,
    query_count: i64,
}
#[derive(Debug, Serialize, FromRow)]
struct EngineState {
    last_row_id: i64,
    processed_events: i64,
    skipped_events: i64,
    updated_at: String,
    latest_security_row: Option<i64>,
}

#[derive(Deserialize)]
pub struct PageQuery {
    limit: Option<i64>,
    before: Option<i64>,
    severity: Option<String>,
}
#[derive(Serialize)]
struct Page<T: Serialize> {
    items: Vec<T>,
    next_cursor: Option<i64>,
}
use crate::api::error as err;

fn auth(headers: &HeaderMap, state: &AppState) -> Result<(), api::ApiError> {
    if api::authorized(headers, &state.config.api_token) {
        Ok(())
    } else {
        Err(api::ApiError(StatusCode::UNAUTHORIZED, "unauthorized"))
    }
}
fn validate_page(q: &PageQuery) -> Result<i64, api::ApiError> {
    api::pagination(q.limit, q.before)
}
const DET_SELECT:&str="SELECT id,rule_id,rule_version,severity,classification,entity_kind,entity_value,incident_id,window_start_epoch,first_seen_epoch,last_seen_epoch,observed_count,title,explanation,details_json FROM detections WHERE id=?1";
const INC_SELECT:&str="SELECT id,subject_kind,subject_value,status,severity,first_seen_epoch,last_seen_epoch,detection_count,title FROM incidents WHERE id=?1";

pub async fn detections(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Response {
    if let Err(e) = auth(&headers, &s) {
        return e.into_response();
    }
    let limit = match validate_page(&q) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    if q.severity
        .as_deref()
        .is_some_and(|v| !matches!(v, "low" | "medium" | "high"))
    {
        return err(StatusCode::BAD_REQUEST, "invalid severity");
    }
    // Use internal monotonic SQLite rowid for stable cursor pagination.
    let query="SELECT d.rowid AS page_id,d.id,d.rule_id,d.rule_version,d.severity,d.classification,d.entity_kind,d.entity_value,d.incident_id,d.window_start_epoch,d.first_seen_epoch,d.last_seen_epoch,d.observed_count,d.title,d.explanation,d.details_json FROM detections d WHERE (?1 IS NULL OR d.rowid<?1) AND (?2 IS NULL OR d.severity=?2) ORDER BY d.rowid DESC LIMIT ?3";
    #[derive(FromRow)]
    struct Item {
        page_id: i64,
        #[sqlx(flatten)]
        data: Detection,
    }
    let rows = sqlx::query_as::<_, Item>(query)
        .bind(q.before)
        .bind(q.severity)
        .bind(limit)
        .fetch_all(&s.pool)
        .await;
    match rows {
        Ok(rows) => {
            let cursor = if rows.len() == limit as usize {
                rows.last().map(|r| r.page_id)
            } else {
                None
            };
            (
                StatusCode::OK,
                Json(Page {
                    items: rows.into_iter().map(|r| r.data).collect(),
                    next_cursor: cursor,
                }),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error=%e,"detections API failed");
            err(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable")
        }
    }
}
pub async fn detection(
    State(s): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(e) = auth(&headers, &s) {
        return e.into_response();
    }
    if uuid::Uuid::parse_str(&id).is_err() {
        return err(StatusCode::BAD_REQUEST, "invalid id");
    }
    match sqlx::query_as::<_, Detection>(DET_SELECT)
        .bind(&id)
        .fetch_optional(&s.pool)
        .await
    {
        Ok(Some(d)) => {
            let evidence=sqlx::query_scalar::<_,String>("SELECT security_event_id FROM detection_evidence WHERE detection_id=?1 ORDER BY security_event_id LIMIT 32")
                .bind(&id).fetch_all(&s.pool).await;
            match evidence {
                Ok(ids) => (
                    StatusCode::OK,
                    Json(serde_json::json!({"detection":d,"evidence_security_event_ids":ids})),
                )
                    .into_response(),
                Err(_) => err(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"),
            }
        }
        Ok(None) => err(StatusCode::NOT_FOUND, "detection not found"),
        Err(_) => err(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"),
    }
}
pub async fn incidents(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Response {
    if let Err(e) = auth(&headers, &s) {
        return e.into_response();
    }
    let limit = match validate_page(&q) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    if q.severity.is_some() {
        return err(StatusCode::BAD_REQUEST, "unsupported filter");
    }
    #[derive(FromRow)]
    struct Item {
        page_id: i64,
        #[sqlx(flatten)]
        data: Incident,
    }
    let sql="SELECT rowid AS page_id,id,subject_kind,subject_value,status,severity,first_seen_epoch,last_seen_epoch,detection_count,title FROM incidents WHERE (?1 IS NULL OR rowid<?1) ORDER BY rowid DESC LIMIT ?2";
    match sqlx::query_as::<_, Item>(sql)
        .bind(q.before)
        .bind(limit)
        .fetch_all(&s.pool)
        .await
    {
        Ok(rows) => {
            let cursor = if rows.len() == limit as usize {
                rows.last().map(|r| r.page_id)
            } else {
                None
            };
            (
                StatusCode::OK,
                Json(Page {
                    items: rows.into_iter().map(|r| r.data).collect(),
                    next_cursor: cursor,
                }),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error=%e,"incidents API failed");
            err(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable")
        }
    }
}
pub async fn incident(
    State(s): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(e) = auth(&headers, &s) {
        return e.into_response();
    }
    if uuid::Uuid::parse_str(&id).is_err() {
        return err(StatusCode::BAD_REQUEST, "invalid id");
    }
    match sqlx::query_as::<_, Incident>(INC_SELECT)
        .bind(&id)
        .fetch_optional(&s.pool)
        .await
    {
        Ok(Some(i)) => {
            let detections=sqlx::query_scalar::<_,String>("SELECT id FROM detections WHERE incident_id=?1 ORDER BY last_seen_epoch DESC LIMIT 200")
                .bind(&id).fetch_all(&s.pool).await;
            match detections {
                Ok(ids) => {
                    let truncated = i.detection_count > 200;
                    (StatusCode::OK,Json(serde_json::json!({"incident":i,"detection_ids":ids,"detection_ids_truncated":truncated}))).into_response()
                }
                Err(_) => err(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"),
            }
        }
        Ok(None) => err(StatusCode::NOT_FOUND, "incident not found"),
        Err(_) => err(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"),
    }
}
pub async fn assets(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Response {
    if let Err(e) = auth(&headers, &s) {
        return e.into_response();
    }
    let limit = match validate_page(&q) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    if q.severity.is_some() {
        return err(StatusCode::BAD_REQUEST, "unsupported filter");
    }
    #[derive(FromRow)]
    struct Item {
        page_id: i64,
        #[sqlx(flatten)]
        data: Asset,
    }
    let sql="SELECT rowid AS page_id,asset_key,first_seen_epoch,last_seen_epoch,total_dns_queries,total_firewall_blocks,total_outbound_passes FROM assets WHERE (?1 IS NULL OR rowid<?1) ORDER BY rowid DESC LIMIT ?2";
    match sqlx::query_as::<_, Item>(sql)
        .bind(q.before)
        .bind(limit)
        .fetch_all(&s.pool)
        .await
    {
        Ok(rows) => {
            let cursor = if rows.len() == limit as usize {
                rows.last().map(|r| r.page_id)
            } else {
                None
            };
            (
                StatusCode::OK,
                Json(Page {
                    items: rows.into_iter().map(|r| r.data).collect(),
                    next_cursor: cursor,
                }),
            )
                .into_response()
        }
        Err(_) => err(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"),
    }
}
pub async fn asset_activity(
    State(s): State<AppState>,
    headers: HeaderMap,
    Path(ip): Path<String>,
) -> Response {
    if let Err(e) = auth(&headers, &s) {
        return e.into_response();
    }
    if ip.parse::<std::net::IpAddr>().is_err() {
        return err(StatusCode::BAD_REQUEST, "invalid IP");
    }
    match sqlx::query_as::<_,Asset>("SELECT asset_key,first_seen_epoch,last_seen_epoch,total_dns_queries,total_firewall_blocks,total_outbound_passes FROM assets WHERE asset_key=?1")
        .bind(&ip).fetch_optional(&s.pool).await{
        Ok(Some(asset))=>{
            let domains=sqlx::query_as::<_,DomainRow>("SELECT domain,first_seen_epoch,last_seen_epoch,query_count FROM asset_domains WHERE asset_key=?1 ORDER BY last_seen_epoch DESC LIMIT 30")
                .bind(&ip).fetch_all(&s.pool).await;
            match domains{
                Ok(domains)=>(StatusCode::OK,Json(serde_json::json!({"asset":asset,"recent_domains":domains,"recent_domains_limit":30}))).into_response(),
                Err(_)=>err(StatusCode::SERVICE_UNAVAILABLE,"storage unavailable"),
            }
        },
        Ok(None)=>err(StatusCode::NOT_FOUND,"asset not found"),
        Err(_)=>err(StatusCode::SERVICE_UNAVAILABLE,"storage unavailable"),
    }
}
pub async fn status(State(s): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(e) = auth(&headers, &s) {
        return e.into_response();
    }
    match sqlx::query_as::<_,EngineState>("SELECT last_row_id,processed_events,skipped_events,updated_at,(SELECT MAX(row_id) FROM security_events) AS latest_security_row FROM detection_cursor WHERE pipeline='default'")
        .fetch_one(&s.pool).await{
        Ok(x)=>{
            let remaining=(x.latest_security_row.unwrap_or(0)-x.last_row_id).max(0);
            (StatusCode::OK,Json(serde_json::json!({"engine":x,"unprocessed_security_rows":remaining,"status":if remaining>10000{"backlog"}else{"tracking"}}))).into_response()
        },
        Err(_)=>err(StatusCode::SERVICE_UNAVAILABLE,"storage unavailable"),
    }
}
