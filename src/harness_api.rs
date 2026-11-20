//! Policy-enforced, structured, read-only investigation tools; no freeform SQL, shell or fetch URL.
//! Agent authentication is separate from the operator API and ingestion credentials.
use crate::api::{self, AppState};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Column, Row, SqlitePool};
use std::{net::IpAddr, time::Instant};
use uuid::Uuid;

const MAX_WINDOW_SECS: i64 = 7 * 86_400;
const MAX_RESULTS: i64 = 50;
const MAX_TOOL_RESPONSE_BYTES: usize = 48 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRequest {
    pub trace_id: String,
    pub tool: String,
    #[serde(default)]
    pub arguments: ToolArguments,
}
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ToolArguments {
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub event_id: Option<String>,
    #[serde(default)]
    pub incident_id: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub hours: Option<i64>,
    #[serde(default)]
    pub limit: Option<i64>,
}
#[derive(Serialize)]
pub struct ToolResponse {
    pub tool: String,
    pub data: Value,
    pub result_count: usize,
}

use crate::api::error as err;
fn read_auth(h: &HeaderMap, s: &AppState) -> bool {
    s.config
        .harness_read_token
        .as_deref()
        .is_some_and(|t| api::authorized(h, t))
}
fn report_auth(h: &HeaderMap, s: &AppState) -> bool {
    s.config
        .harness_report_token
        .as_deref()
        .is_some_and(|t| api::authorized(h, t))
}
fn valid_domain(s: &str) -> bool {
    s.len() <= 253
        && !s.is_empty()
        && s.is_ascii()
        && s.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn valid_source(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}
fn validate(req: &ToolRequest) -> Result<(i64, i64), &'static str> {
    if Uuid::parse_str(&req.trace_id).is_err() {
        return Err("invalid trace id");
    }
    if req.tool.len() > 64
        || !req
            .tool
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c == b'_')
    {
        return Err("invalid tool");
    }
    let a = &req.arguments;
    if a.ip.as_ref().is_some_and(|s| s.parse::<IpAddr>().is_err()) {
        return Err("invalid IP address");
    }
    if a.domain.as_ref().is_some_and(|s| !valid_domain(s)) {
        return Err("invalid domain");
    }
    if a.event_id
        .as_ref()
        .is_some_and(|s| Uuid::parse_str(s).is_err())
        || a.incident_id
            .as_ref()
            .is_some_and(|s| Uuid::parse_str(s).is_err())
    {
        return Err("invalid event/incident ID");
    }
    if a.source.as_ref().is_some_and(|s| !valid_source(s)) {
        return Err("invalid source");
    }
    let hours = a.hours.unwrap_or(24);
    if !(1..=168).contains(&hours) {
        return Err("hours outside allowed range");
    }
    let limit = a.limit.unwrap_or(25);
    if !(1..=MAX_RESULTS).contains(&limit) {
        return Err("limit outside allowed range");
    }
    let required = match req.tool.as_str() {
        "get_ip_history"
        | "get_dns_activity"
        | "get_firewall_activity"
        | "get_asset_profile"
        | "correlate_events"
        | "get_network_baseline" => a.ip.is_some(),
        "get_domain_history" => a.domain.is_some(),
        "get_event_details" => a.event_id.is_some(),
        "get_incident" => a.incident_id.is_some(),
        "search_events" => a.ip.is_some() || a.domain.is_some(),
        "get_source_health" | "get_crowdsec_decisions" | "get_detections" => true,
        _ => return Err("unknown or prohibited tool"),
    };
    if !required {
        return Err("required subject argument missing");
    }
    Ok((hours * 3600, limit))
}
fn to_json_rows(rows: Vec<sqlx::sqlite::SqliteRow>) -> Value {
    // We return only an explicit allowlist of fields per query (no raw logs or arbitrary details_json).
    Value::Array(
        rows.into_iter()
            .map(|r| {
                let mut out = serde_json::Map::new();
                for col in r.columns() {
                    let field = col.name();
                    let v = r.try_get::<Option<String>, _>(field).ok().flatten();
                    if let Some(s) = v {
                        out.insert(field.to_owned(), Value::String(s));
                    } else if let Ok(i) = r.try_get::<i64, _>(field) {
                        out.insert(field.to_owned(), json!(i));
                    } else {
                        out.insert(field.to_owned(), Value::Null);
                    }
                }
                Value::Object(out)
            })
            .collect(),
    )
}

async fn run(
    pool: &SqlitePool,
    req: &ToolRequest,
    secs: i64,
    limit: i64,
) -> Result<Value, sqlx::Error> {
    let a = &req.arguments;
    let cutoff = jiff::Timestamp::now().as_second() - secs.min(MAX_WINDOW_SECS);
    let ip =
        a.ip.as_deref()
            .and_then(|s| s.parse::<IpAddr>().ok())
            .map(|ip| ip.to_string());
    let domain = a.domain.as_deref().map(str::to_ascii_lowercase);
    let value = match req.tool.as_str() {
        "search_events"
        | "get_ip_history"
        | "get_domain_history"
        | "get_dns_activity"
        | "get_firewall_activity"
        | "correlate_events" => {
            let category = match req.tool.as_str() {
                "get_dns_activity" => Some("dns.query"),
                "get_firewall_activity" => Some("firewall.filterlog"),
                _ => None,
            };
            let rows = sqlx::query(
                "SELECT event_id,source,category,action,source_ip,destination_ip,source_port,destination_port,protocol,domain,event_epoch \
                 FROM security_events WHERE event_epoch >= ?1 AND (?2 IS NULL OR source_ip=?2 OR destination_ip=?2) \
                 AND (?3 IS NULL OR domain IN (?3, ?3 || '.')) AND (?4 IS NULL OR category=?4) \
                 ORDER BY event_epoch DESC,row_id DESC LIMIT ?5")
                .bind(cutoff).bind(ip).bind(domain).bind(category).bind(limit).fetch_all(pool).await?;
            to_json_rows(rows)
        }
        "get_event_details" => {
            let rows = sqlx::query("SELECT event_id,source,category,action,source_ip,destination_ip,source_port,destination_port,protocol,domain,event_epoch,parser_version FROM security_events WHERE event_id=?1 LIMIT 1")
                .bind(a.event_id.as_deref()).fetch_all(pool).await?;
            to_json_rows(rows)
        }
        "get_incident" => {
            let rows = sqlx::query("SELECT id,subject_kind,subject_value,status,severity,first_seen_epoch,last_seen_epoch,detection_count,title FROM incidents WHERE id=?1 LIMIT 1")
                .bind(a.incident_id.as_deref()).fetch_all(pool).await?;
            to_json_rows(rows)
        }
        "get_detections" => {
            let rows = sqlx::query("SELECT id,rule_id,severity,classification,entity_kind,entity_value,incident_id,first_seen_epoch,last_seen_epoch,observed_count,title FROM detections WHERE last_seen_epoch>=?1 AND (?2 IS NULL OR entity_value=?2) ORDER BY last_seen_epoch DESC LIMIT ?3")
                .bind(cutoff).bind(ip).bind(limit).fetch_all(pool).await?;
            to_json_rows(rows)
        }
        "get_asset_profile" => {
            let rows = sqlx::query("SELECT asset_key,first_seen_epoch,last_seen_epoch,total_dns_queries,total_firewall_blocks,total_outbound_passes FROM assets WHERE asset_key=?1 LIMIT 1")
                .bind(ip).fetch_all(pool).await?;
            to_json_rows(rows)
        }
        "get_network_baseline" => {
            let rows = sqlx::query("SELECT asset_key,bucket_start_epoch,query_count FROM asset_dns_buckets WHERE asset_key=?1 AND bucket_start_epoch>=?2 ORDER BY bucket_start_epoch DESC LIMIT ?3")
                .bind(ip).bind(cutoff).bind(limit).fetch_all(pool).await?;
            to_json_rows(rows)
        }
        "get_crowdsec_decisions" => {
            let rows = sqlx::query("SELECT id,scope,value,action,scenario,origin,first_seen,last_seen FROM crowdsec_decisions WHERE active=1 AND (?1 IS NULL OR value=?1) ORDER BY last_seen DESC LIMIT ?2")
                .bind(ip).bind(limit).fetch_all(pool).await?;
            to_json_rows(rows)
        }
        "get_source_health" => {
            let rows = sqlx::query("SELECT source,status,last_attempt,last_success,consecutive_failures,last_batch_inserted,last_batch_duplicates FROM source_health WHERE (?1 IS NULL OR source=?1) ORDER BY source LIMIT ?2")
                .bind(a.source.as_deref()).bind(limit).fetch_all(pool).await?;
            to_json_rows(rows)
        }
        _ => Value::Array(vec![]), // Already blocked in `validate`.
    };
    Ok(value)
}

// An atomic server-owned call budget prevents concurrent requests from bypassing
// the quota by racing separate COUNT and INSERT statements. A trace expires after
// 15 minutes and cannot be resurrected or extended by the model.
async fn reserve_call(pool: &SqlitePool, req: &ToolRequest) -> Result<bool, sqlx::Error> {
    // The FIRST tool in each trace identifies its investigation subject.
    // Subsequent tools can correlate freely but cannot change that binding.
    let (kind, value) = match req.tool.as_str() {
        "get_ip_history" => ("ip", req.arguments.ip.as_deref().unwrap_or("")),
        "get_domain_history" => ("domain", req.arguments.domain.as_deref().unwrap_or("")),
        "get_incident" => (
            "incident",
            req.arguments.incident_id.as_deref().unwrap_or(""),
        ),
        _ => ("unknown", ""),
    };
    let mut tx = pool.begin().await?;
    sqlx::query("INSERT OR IGNORE INTO harness_sessions(trace_id,subject_kind,subject_value,expires_epoch) SELECT ?1,?2,?3,unixepoch()+900 WHERE ?2<>'unknown'")
        .bind(&req.trace_id).bind(kind).bind(value).execute(&mut *tx).await?;
    let changed = sqlx::query("UPDATE harness_sessions SET tool_calls=tool_calls+1 WHERE trace_id=?1 AND expires_epoch>CAST(strftime('%s','now') AS INTEGER) AND tool_calls<24")
        .bind(&req.trace_id).execute(&mut *tx).await?.rows_affected();
    tx.commit().await?;
    Ok(changed == 1)
}

// Persist returned evidence ONLY when it was present in a successful, audited
// structured tool response. Never trust evidence IDs declared by the model.
async fn audit(
    pool: &SqlitePool,
    req: &ToolRequest,
    status: &str,
    data: Option<&Value>,
    elapsed: u128,
) -> Result<(), sqlx::Error> {
    let args = serde_json::to_vec(&req.arguments).map_err(|e| sqlx::Error::Encode(Box::new(e)))?;
    let hash = hex::encode(Sha256::digest(&args));
    let count = data.and_then(Value::as_array).map_or(0, Vec::len);
    let mut tx = pool.begin().await?;
    let result = sqlx::query("INSERT INTO harness_tool_audit(trace_id,tool_name,args_sha256,status,result_count,elapsed_ms) VALUES (?1,?2,?3,?4,?5,?6)")
        .bind(&req.trace_id).bind(&req.tool).bind(hash).bind(status)
        .bind(count.min(50) as i64).bind(elapsed.min(60_000) as i64)
        .execute(&mut *tx).await?;
    if status == "ok" {
        if let Some(Value::Array(rows)) = data {
            let mut seen = std::collections::BTreeSet::new();
            for event_id in rows
                .iter()
                .filter_map(|r| r.get("event_id").and_then(Value::as_str))
            {
                if !seen.insert(event_id) {
                    continue;
                }
                // SQL FK ensures these are genuine normalized security event IDs.
                sqlx::query("INSERT INTO harness_tool_evidence(audit_row_id,trace_id,security_event_id) VALUES (?1,?2,?3)")
                    .bind(result.last_insert_rowid()).bind(&req.trace_id).bind(event_id)
                    .execute(&mut *tx).await?;
            }
        }
    }
    tx.commit().await?;
    Ok(())
}

pub async fn query_tool(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ToolRequest>,
) -> Response {
    if !read_auth(&headers, &state) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    // Concurrent model requests must never crowd out the collector's ingestion connection pool.
    let _permit = match state.harness_gate.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return err(
                StatusCode::TOO_MANY_REQUESTS,
                "harness concurrent query capacity exhausted",
            )
        }
    };
    let started = Instant::now();
    let (secs, limit) = match validate(&req) {
        Ok(p) => p,
        Err(reason) => {
            if audit(
                &state.pool,
                &req,
                "rejected",
                None,
                started.elapsed().as_millis(),
            )
            .await
            .is_err()
            {
                return err(StatusCode::SERVICE_UNAVAILABLE, "audit storage unavailable");
            }
            return (StatusCode::BAD_REQUEST, Json(json!({"error":reason}))).into_response();
        }
    };
    match reserve_call(&state.pool, &req).await {
        Ok(true) => {}
        Ok(false) => {
            return err(
                StatusCode::TOO_MANY_REQUESTS,
                "trace expired or tool budget exhausted",
            )
        }
        Err(_) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "session storage unavailable",
            )
        }
    }
    match run(&state.pool, &req, secs, limit).await {
        Ok(data) => {
            let count = data.as_array().map_or(0, Vec::len);
            if serde_json::to_vec(&data).is_ok_and(|b| b.len() > MAX_TOOL_RESPONSE_BYTES) {
                if audit(
                    &state.pool,
                    &req,
                    "rejected",
                    None,
                    started.elapsed().as_millis(),
                )
                .await
                .is_err()
                {
                    return err(StatusCode::SERVICE_UNAVAILABLE, "audit storage unavailable");
                }
                return err(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "tool response exceeds maximum",
                );
            }
            if audit(
                &state.pool,
                &req,
                "ok",
                Some(&data),
                started.elapsed().as_millis(),
            )
            .await
            .is_err()
            {
                return err(StatusCode::SERVICE_UNAVAILABLE, "audit storage unavailable");
            }
            (
                StatusCode::OK,
                Json(ToolResponse {
                    tool: req.tool,
                    data,
                    result_count: count,
                }),
            )
                .into_response()
        }
        Err(e) => {
            tracing::warn!(error=%e,tool=%req.tool,"harness query failed");
            if audit(
                &state.pool,
                &req,
                "failed",
                None,
                started.elapsed().as_millis(),
            )
            .await
            .is_err()
            {
                return err(StatusCode::SERVICE_UNAVAILABLE, "audit storage unavailable");
            }
            err(StatusCode::SERVICE_UNAVAILABLE, "query unavailable")
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvestigationReport {
    trace_id: String,
    subject_kind: String,
    subject_value: String,
    model: String,
    status: String,
    summary: String,
    evidence_ids: Vec<String>,
    tool_calls: usize,
}
fn validate_report(r: &InvestigationReport) -> bool {
    Uuid::parse_str(&r.trace_id).is_ok()
        && matches!(r.subject_kind.as_str(), "ip" | "domain" | "incident")
        && (match r.subject_kind.as_str() {
            "ip" => r.subject_value.parse::<IpAddr>().is_ok(),
            "domain" => valid_domain(&r.subject_value),
            "incident" => Uuid::parse_str(&r.subject_value).is_ok(),
            _ => false,
        })
        && matches!(r.status.as_str(), "hypothesis" | "incomplete")
        && !r.model.is_empty()
        && r.model.len() <= 128
        && !r.summary.trim().is_empty()
        && r.summary.len() <= 12_000
        && r.evidence_ids.len() <= 64
        && r.evidence_ids.iter().all(|id| Uuid::parse_str(id).is_ok())
        && r.tool_calls <= 24
}
fn verified_summary(report: &InvestigationReport) -> String {
    let allowed: std::collections::HashSet<Uuid> = report
        .evidence_ids
        .iter()
        .filter_map(|id| Uuid::parse_str(id).ok())
        .collect();
    let incident = (report.subject_kind == "incident")
        .then(|| Uuid::parse_str(&report.subject_value).ok())
        .flatten();
    let mut summary = String::with_capacity(report.summary.len());
    for word in report
        .summary
        .split_inclusive(|c: char| !c.is_ascii_hexdigit() && c != '-')
    {
        let candidate = word.trim_end_matches(|c: char| !c.is_ascii_hexdigit() && c != '-');
        match Uuid::parse_str(candidate) {
            Ok(id) if !allowed.contains(&id) && incident != Some(id) => {
                summary.push_str("[unverified reference]");
                summary.push_str(&word[candidate.len()..]);
            }
            _ => summary.push_str(word),
        }
    }
    summary
}
pub async fn save_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(report): Json<InvestigationReport>,
) -> Response {
    if !report_auth(&headers, &state) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if !validate_report(&report) {
        return err(StatusCode::BAD_REQUEST, "invalid report");
    }
    let mut tx = match state.pool.begin_with("BEGIN IMMEDIATE").await {
        Ok(tx) => tx,
        Err(_) => return err(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"),
    };
    // A report is only allowed for an ACTIVE server-owned investigation session.
    let session: Result<Option<i64>,_> = sqlx::query_scalar(
        "SELECT tool_calls FROM harness_sessions WHERE trace_id=?1 AND subject_kind=?2 AND subject_value=?3 AND expires_epoch>CAST(strftime('%s','now') AS INTEGER)")
        .bind(&report.trace_id).bind(&report.subject_kind).bind(&report.subject_value)
        .fetch_optional(&mut *tx).await;
    let session_calls = match session {
        Ok(Some(n)) if n > 0 => n,
        Ok(_) => {
            return err(
                StatusCode::BAD_REQUEST,
                "missing or expired investigation session",
            )
        }
        Err(_) => return err(StatusCode::SERVICE_UNAVAILABLE, "session unavailable"),
    };
    // Each evidence reference must originate from a successful tool response
    // within THIS trace, not simply exist in the database.
    let mut distinct = std::collections::BTreeSet::new();
    for event_id in &report.evidence_ids {
        if !distinct.insert(event_id) {
            return err(StatusCode::BAD_REQUEST, "duplicate evidence reference");
        }
        let found: Result<Option<i64>,_> = sqlx::query_scalar(
            "SELECT 1 FROM harness_tool_evidence e JOIN harness_tool_audit a ON a.row_id=e.audit_row_id WHERE e.trace_id=?1 AND e.security_event_id=?2 AND a.status='ok' LIMIT 1")
            .bind(&report.trace_id).bind(event_id).fetch_optional(&mut *tx).await;
        match found {
            Ok(Some(_)) => {}
            Ok(None) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    "evidence not retrieved by this investigation",
                )
            }
            Err(error) => {
                tracing::error!(%error, "investigation evidence lookup failed");
                return err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "evidence storage unavailable",
                );
            }
        }
    }
    let id = Uuid::new_v4().to_string();
    let evidence = json!(report.evidence_ids);
    let summary = verified_summary(&report);
    let payload = json!({"summary":summary,"evidence_ids":evidence,"classification":"unverified; requires analyst validation"});
    let result = sqlx::query("INSERT INTO investigations(id,trace_id,subject_kind,subject_value,model,status,summary,report_json,evidence_json,tool_calls) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)")
        .bind(&id).bind(&report.trace_id).bind(&report.subject_kind).bind(&report.subject_value)
        .bind(&report.model).bind(&report.status).bind(&summary).bind(payload.to_string()).bind(evidence.to_string()).bind(session_calls)
        .execute(&mut *tx).await;
    if let Err(error) = result {
        if matches!(&error, sqlx::Error::Database(e) if e.is_unique_violation()) {
            return err(
                StatusCode::CONFLICT,
                "report already exists for this investigation",
            );
        }
        tracing::error!(%error, "investigation report insert failed");
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "report storage unavailable",
        );
    }
    if tx.commit().await.is_err() {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "report storage unavailable",
        );
    }
    (
        StatusCode::CREATED,
        Json(json!({"id":id,"trace_id":report.trace_id,"classification":"unverified","summary":summary,"tool_calls":session_calls})),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct ReportsQuery {
    limit: Option<i64>,
}
pub async fn list_reports(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ReportsQuery>,
) -> Response {
    if !read_auth(&headers, &state) && !api::authorized(&headers, &state.config.api_token) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let limit = q.limit.unwrap_or(20);
    if !(1..=50).contains(&limit) {
        return err(StatusCode::BAD_REQUEST, "invalid limit");
    }
    let result = sqlx::query("SELECT id,trace_id,subject_kind,subject_value,model,status,summary,evidence_json,tool_calls,created_at FROM investigations ORDER BY created_at DESC LIMIT ?1").bind(limit).fetch_all(&state.pool).await;
    match result {
        Ok(rows) => (StatusCode::OK, Json(to_json_rows(rows))).into_response(),
        Err(_) => err(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"),
    }
}
pub async fn report_details(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !read_auth(&headers, &state) && !api::authorized(&headers, &state.config.api_token) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if Uuid::parse_str(&id).is_err() {
        return err(StatusCode::BAD_REQUEST, "invalid ID");
    }
    let result=sqlx::query("SELECT id,trace_id,subject_kind,subject_value,model,status,summary,evidence_json,tool_calls,created_at FROM investigations WHERE id=?1 LIMIT 1").bind(id).fetch_all(&state.pool).await;
    match result {
        Ok(rows) if rows.is_empty() => err(StatusCode::NOT_FOUND, "report not found"),
        Ok(rows) => (StatusCode::OK, Json(to_json_rows(rows))).into_response(),
        Err(_) => err(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn good_req(tool: &str) -> ToolRequest {
        ToolRequest {
            trace_id: Uuid::new_v4().to_string(),
            tool: tool.into(),
            arguments: ToolArguments {
                ip: Some("192.0.2.7".into()),
                ..Default::default()
            },
        }
    }
    #[test]
    fn rejects_injected_tool_or_arguments() {
        assert!(validate(&good_req("get_ip_history")).is_ok());
        assert!(validate(&good_req("execute_shell")).is_err());
        assert!(serde_json::from_str::<ToolArguments>(
            r#"{"ip":"127.0.0.1","command":"rm -rf /"}"#
        )
        .is_err());
        let mut q = good_req("get_ip_history");
        q.arguments.ip = Some("127.0.0.1 && curl".into());
        assert!(validate(&q).is_err());
    }
    #[test]
    fn bounded_time_window() {
        let mut q = good_req("get_dns_activity");
        q.arguments.hours = Some(169);
        assert!(validate(&q).is_err());
        q.arguments.hours = Some(168);
        assert!(validate(&q).is_ok());
        q.arguments.limit = Some(51);
        assert!(validate(&q).is_err());
    }
    #[tokio::test]
    async fn quota_is_atomic_and_trace_expires() {
        use sqlx::sqlite::SqlitePoolOptions;
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let req = good_req("get_ip_history");
        for _ in 0..24 {
            assert!(reserve_call(&pool, &req).await.unwrap());
        }
        assert!(!reserve_call(&pool, &req).await.unwrap());
        sqlx::query(
            "UPDATE harness_sessions SET created_epoch=0,expires_epoch=1 WHERE trace_id=?1",
        )
        .bind(&req.trace_id)
        .execute(&pool)
        .await
        .unwrap();
        assert!(!reserve_call(&pool, &req).await.unwrap());
    }
    #[tokio::test]
    async fn provenance_is_from_successful_tools_not_model_assertions() {
        use sqlx::sqlite::SqlitePoolOptions;
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let event_id = Uuid::new_v4().to_string();
        let raw_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO raw_events(event_id,source,ingested_at,raw_json,payload_sha256,parser_version) VALUES (?1,'test','2026-11-20T19:00:00Z','{}',?2,2)")
            .bind(&raw_id).bind("0".repeat(64)).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO security_events(event_id,raw_event_id,source,category) VALUES (?1,?2,'test','dns.query')")
            .bind(&event_id).bind(&raw_id).execute(&pool).await.unwrap();
        let req = good_req("get_ip_history");
        assert!(reserve_call(&pool, &req).await.unwrap());
        audit(&pool, &req, "ok", Some(&json!([{"event_id":event_id}])), 1)
            .await
            .unwrap();
        let linked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM harness_tool_evidence WHERE trace_id=?1 AND security_event_id=?2",
        )
        .bind(&req.trace_id)
        .bind(&event_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(linked, 1);
        let kind: String =
            sqlx::query_scalar("SELECT subject_kind FROM harness_sessions WHERE trace_id=?1")
                .bind(&req.trace_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(kind, "ip");
        let other = Uuid::new_v4().to_string();
        let forged: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM harness_tool_evidence WHERE trace_id=?1 AND security_event_id=?2",
        )
        .bind(&req.trace_id)
        .bind(&other)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(forged, 0);
    }
    #[test]
    fn domain_validation() {
        assert!(valid_domain("example.org"));
        assert!(!valid_domain("ex ample.org"));
        assert!(!valid_domain("-bad.org"));
        assert!(!valid_domain(""));
    }
}
