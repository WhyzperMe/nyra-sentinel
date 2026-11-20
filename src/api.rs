use crate::{config::Config, db, ingest};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub config: Config,
    pub harness_gate: Arc<Semaphore>,
}
pub(crate) struct ApiError(pub StatusCode, pub &'static str);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({"error": self.1}))).into_response()
    }
}

pub(crate) fn error(status: StatusCode, message: &'static str) -> Response {
    ApiError(status, message).into_response()
}

async fn api_response(mut response: Response) -> Response {
    let status = response.status();
    let headers = response.headers();
    if (status.is_client_error() || status.is_server_error())
        && !headers
            .get(axum::http::header::CONTENT_TYPE)
            .is_some_and(|v| v == "application/json")
    {
        let mut json = error(
            status,
            status.canonical_reason().unwrap_or("request failed"),
        );
        if let Some(allow) = headers.get(axum::http::header::ALLOW) {
            json.headers_mut()
                .insert(axum::http::header::ALLOW, allow.clone());
        }
        response = json;
    }
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

async fn limit_in_flight(
    State(gate): State<Arc<Semaphore>>,
    request: Request,
    next: middleware::Next,
) -> Response {
    let Ok(_permit) = gate.try_acquire() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "API capacity exhausted");
    };
    match tokio::time::timeout(std::time::Duration::from_secs(15), next.run(request)).await {
        Ok(response) => response,
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "API request timed out"),
    }
}
pub(crate) fn authorized(headers: &HeaderMap, secret: &str) -> bool {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    match token {
        Some(t) if t.len() == secret.len() => bool::from(t.as_bytes().ct_eq(secret.as_bytes())),
        _ => false,
    }
}
#[derive(Serialize)]
struct Health {
    status: &'static str,
    storage: &'static str,
}
async fn health(State(state): State<AppState>) -> Response {
    match sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&state.pool)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(Health {
                status: "ok",
                storage: "ok",
            }),
        )
            .into_response(),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"),
    }
}
async fn ready(State(state): State<AppState>) -> Response {
    let processed: Option<(i64, i64)> = match sqlx::query_as(
        "SELECT last_row_id,COALESCE(CAST(strftime('%s',updated_at) AS INTEGER),0) FROM detection_cursor WHERE pipeline='default'")
        .fetch_optional(&state.pool).await {
            Ok(value)=>value,
            Err(_)=>return error(StatusCode::SERVICE_UNAVAILABLE,"storage unavailable"),
        };
    let latest: i64 =
        match sqlx::query_scalar("SELECT COALESCE(MAX(row_id),0) FROM security_events")
            .fetch_one(&state.pool)
            .await
        {
            Ok(n) => n,
            Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"),
        };
    let (cursor, updated) = processed.unwrap_or((0, 0));
    let backlog = latest.saturating_sub(cursor);
    let stalled = backlog > 0 && jiff::Timestamp::now().as_second().saturating_sub(updated) > 120;
    let payload = serde_json::json!({"status":if stalled {"degraded"} else {"ok"},
        "storage":"ok","detection_backlog_rows":backlog,"detection_engine_stalled":stalled});
    (
        if stalled {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::OK
        },
        Json(payload),
    )
        .into_response()
}
async fn ingest_batch(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if !authorized(&headers, &state.config.ingest_token) {
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let events = match ingest::parse_ndjson(&body) {
        Ok(v) => v,
        Err(reason) => return error(StatusCode::BAD_REQUEST, reason),
    };
    match ingest::persist(&state.pool, events).await {
        Ok((inserted, duplicates)) => {
            if let Err(err) = db::mark_source(
                &state.pool,
                "opnsense-syslog",
                true,
                None,
                inserted as i64,
                duplicates as i64,
            )
            .await
            {
                tracing::warn!(error = %err, "source health update failed");
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({"accepted":inserted,"duplicates":duplicates})),
            )
                .into_response()
        }
        Err(err) => {
            tracing::error!(error=%err, "ingest transaction failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable")
        }
    }
}
#[derive(Deserialize)]
struct EventsQuery {
    limit: Option<i64>,
    before: Option<i64>,
}
#[derive(Deserialize)]
struct SecurityQuery {
    limit: Option<i64>,
    before: Option<i64>,
    source: Option<String>,
    action: Option<String>,
}
#[derive(Serialize)]
struct ListResponse<T: Serialize> {
    events: Vec<T>,
    next_cursor: Option<i64>,
}
pub(crate) fn pagination(limit: Option<i64>, before: Option<i64>) -> Result<i64, ApiError> {
    let limit = limit.unwrap_or(50);
    if !(1..=200).contains(&limit) || before.is_some_and(|v| v < 1) {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid pagination parameters",
        ));
    }
    Ok(limit)
}
async fn list_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<EventsQuery>,
) -> Response {
    if !authorized(&headers, &state.config.api_token) {
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let limit = match pagination(q.limit, q.before) {
        Ok(v) => v,
        Err(err) => return err.into_response(),
    };
    match db::list(&state.pool, q.before, limit).await {
        Ok(events) => {
            let next_cursor = if events.len() == limit as usize {
                events.last().map(|e| e.row_id)
            } else {
                None
            };
            (
                StatusCode::OK,
                Json(ListResponse {
                    events,
                    next_cursor,
                }),
            )
                .into_response()
        }
        Err(err) => {
            tracing::error!(error=%err, "event query failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable")
        }
    }
}
async fn security_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<SecurityQuery>,
) -> Response {
    if !authorized(&headers, &state.config.api_token) {
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let limit = match pagination(q.limit, q.before) {
        Ok(v) => v,
        Err(err) => return err.into_response(),
    };
    if q.source
        .as_ref()
        .is_some_and(|s| s.len() > 64 || !s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'))
        || q.action.as_ref().is_some_and(|s| {
            s.len() > 32 || !s.bytes().all(|c| c.is_ascii_alphabetic() || c == b'_')
        })
    {
        return error(StatusCode::BAD_REQUEST, "invalid event filter");
    }
    match db::list_security(
        &state.pool,
        q.source.as_deref(),
        q.action.as_deref(),
        q.before,
        limit,
    )
    .await
    {
        Ok(events) => {
            let next_cursor = if events.len() == limit as usize {
                events.last().map(|e| e.row_id)
            } else {
                None
            };
            (
                StatusCode::OK,
                Json(ListResponse {
                    events,
                    next_cursor,
                }),
            )
                .into_response()
        }
        Err(err) => {
            tracing::error!(error=%err, "security event query failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable")
        }
    }
}
async fn event_details(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(event_id): Path<String>,
) -> Response {
    if !authorized(&headers, &state.config.api_token) {
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if uuid::Uuid::parse_str(&event_id).is_err() {
        return error(StatusCode::BAD_REQUEST, "invalid event id");
    }
    match db::get(&state.pool, &event_id).await {
        Ok(Some(e)) => (StatusCode::OK, Json(e)).into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND, "event not found"),
        Err(err) => {
            tracing::error!(error=%err, "event detail query failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable")
        }
    }
}
async fn sources(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorized(&headers, &state.config.api_token) {
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    match db::sources(&state.pool).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(err) => {
            tracing::error!(error=%err, "source query failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable")
        }
    }
}
#[derive(Deserialize)]
struct DecisionQuery {
    limit: Option<i64>,
}
async fn decisions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<DecisionQuery>,
) -> Response {
    if !authorized(&headers, &state.config.api_token) {
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let limit = match pagination(q.limit, None) {
        Ok(v) => v,
        Err(err) => return err.into_response(),
    };
    match db::decisions(&state.pool, limit).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(err) => {
            tracing::error!(error=%err, "decision query failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable")
        }
    }
}
// Prometheus text exposition is authenticated and deliberately low-cardinality.
// Counts are gauges because evidence-safe retention can decrease their value.
async fn metrics(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorized(&headers, &state.config.api_token) {
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let sql = [
        ("sentinel_raw_events", "SELECT COUNT(*) FROM raw_events"),
        ("sentinel_security_events", "SELECT COUNT(*) FROM security_events"),
        ("sentinel_detections", "SELECT COUNT(*) FROM detections"),
        ("sentinel_open_incidents", "SELECT COUNT(*) FROM incidents WHERE status='open'"),
        ("sentinel_investigations", "SELECT COUNT(*) FROM investigations"),
        ("sentinel_pending_responses", "SELECT COUNT(*) FROM response_proposals WHERE status='proposed'"),
        ("sentinel_approved_responses", "SELECT COUNT(*) FROM response_proposals WHERE status='approved'"),
        ("sentinel_source_failures_current", "SELECT COALESCE(SUM(consecutive_failures),0) FROM source_health"),
        ("sentinel_detection_cursor_row", "SELECT COALESCE(MAX(last_row_id),0) FROM detection_cursor"),
        ("sentinel_detection_backlog_rows", "SELECT MAX(0,COALESCE((SELECT MAX(row_id) FROM security_events),0)-COALESCE((SELECT last_row_id FROM detection_cursor WHERE pipeline='default'),0))"),
        ("sentinel_last_ingest_age_seconds", "SELECT COALESCE(CAST(strftime('%s','now') AS INTEGER)-CAST(strftime('%s',(SELECT MAX(ingested_at) FROM raw_events)) AS INTEGER),-1)"),
    ];
    let mut out = String::with_capacity(1024);
    for (name, statement) in sql {
        let value: i64 = match sqlx::query_scalar(statement).fetch_one(&state.pool).await {
            Ok(n) => n,
            Err(err) => {
                tracing::warn!(error=%err, "metrics unavailable");
                return error(StatusCode::SERVICE_UNAVAILABLE, "metrics unavailable");
            }
        };
        out.push_str("# TYPE ");
        out.push_str(name);
        out.push_str(" gauge\n");
        out.push_str(name);
        out.push(' ');
        out.push_str(&value.to_string());
        out.push('\n');
    }
    out.push_str("# TYPE sentinel_source_last_success_age_seconds gauge\n");
    for source in ["opnsense-syslog", "adguard-querylog", "crowdsec-decision"] {
        let age: Option<i64> = match sqlx::query_scalar(
            "SELECT COALESCE(CAST(strftime('%s','now') AS INTEGER)-CAST(strftime('%s',last_success) AS INTEGER),-1) FROM source_health WHERE source=?1")
            .bind(source).fetch_optional(&state.pool).await {
                Ok(value) => value,
                Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "metrics unavailable"),
            };
        out.push_str(&format!(
            "sentinel_source_last_success_age_seconds{{source=\"{source}\"}} {}\n",
            age.unwrap_or(-1)
        ));
    }
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
        .into_response()
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(crate::ui::redirect))
        .route("/ui", get(crate::ui::index))
        .route("/ui/app.js", get(crate::ui::javascript))
        .route("/ui/styles.css", get(crate::ui::stylesheet))
        .route("/api/v1/health", get(health))
        .route("/api/v1/ready", get(ready))
        .route("/api/v1/metrics", get(metrics))
        .route("/api/v1/events", get(list_events))
        .route("/api/v1/events/{event_id}", get(event_details))
        .route("/api/v1/security-events", get(security_events))
        .route("/api/v1/sources", get(sources))
        .route("/api/v1/crowdsec/decisions", get(decisions))
        .route("/api/v1/detections", get(crate::detection_api::detections))
        .route(
            "/api/v1/detections/{id}",
            get(crate::detection_api::detection),
        )
        .route("/api/v1/incidents", get(crate::detection_api::incidents))
        .route(
            "/api/v1/incidents/{id}",
            get(crate::detection_api::incident),
        )
        .route("/api/v1/assets", get(crate::detection_api::assets))
        .route(
            "/api/v1/assets/{ip}/activity",
            get(crate::detection_api::asset_activity),
        )
        .route(
            "/api/v1/detection-engine/status",
            get(crate::detection_api::status),
        )
        .route(
            "/api/v1/harness/query",
            post(crate::harness_api::query_tool),
        )
        .route(
            "/api/v1/harness/reports",
            get(crate::harness_api::list_reports).post(crate::harness_api::save_report),
        )
        .route(
            "/api/v1/harness/reports/{id}",
            get(crate::harness_api::report_details),
        )
        .route(
            "/api/v1/response/proposals",
            get(crate::response_api::list).post(crate::response_api::create),
        )
        .route(
            "/api/v1/response/proposals/{id}",
            get(crate::response_api::details),
        )
        .route(
            "/api/v1/response/proposals/{id}/approve",
            post(crate::response_api::approve),
        )
        .route(
            "/api/v1/response/proposals/{id}/reject",
            post(crate::response_api::reject),
        )
        .route(
            "/api/v1/response/proposals/{id}/simulate",
            post(crate::response_api::simulate),
        )
        .route(
            "/api/v1/response/proposals/{id}/rollback",
            post(crate::response_api::rollback),
        )
        .route("/internal/v1/ingest", post(ingest_batch))
        .layer(DefaultBodyLimit::max(512 * 1024))
        .layer(middleware::from_fn_with_state(
            Arc::new(Semaphore::new(16)),
            limit_in_flight,
        ))
        .layer(middleware::map_response(api_response))
        .with_state(state)
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header::AUTHORIZATION, HeaderValue};
    #[test]
    fn token_auth_is_exact() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer abcdef"));
        assert!(authorized(&headers, "abcdef"));
        assert!(!authorized(&headers, "abcdeg"));
        assert!(!authorized(&headers, "abcdefg"));
    }
}

// Additional API regression tests should use a running server against a temporary SQLite DB.
