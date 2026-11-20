//! Human-controlled defensive action workflow. This module NEVER modifies a firewall.
//! The simulation gateway is a separate credential and cannot authorize its own proposal.
use crate::api::{self, AppState};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{FromRow, SqlitePool};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use uuid::Uuid;

#[derive(Debug, Serialize, FromRow)]
struct Proposal {
    id: String,
    incident_id: Option<String>,
    evidence_event_id: String,
    action: String,
    target_ip: String,
    justification: String,
    duration_minutes: i64,
    requester: String,
    status: String,
    approver: Option<String>,
    approved_epoch: Option<i64>,
    valid_until_epoch: Option<i64>,
    created_epoch: i64,
    updated_epoch: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewProposal {
    target_ip: String,
    evidence_event_id: String,
    incident_id: Option<String>,
    justification: String,
    duration_minutes: i64,
    requester: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    actor: String,
    confirm: String,
    reason: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Simulation {
    actor: String,
    confirm: String,
}
#[derive(Deserialize)]
pub struct Page {
    limit: Option<i64>,
    before: Option<i64>,
}

use crate::api::error as err;
fn operator(h: &HeaderMap, s: &AppState) -> bool {
    api::authorized(h, &s.config.api_token)
}
fn approver(h: &HeaderMap, s: &AppState) -> bool {
    s.config
        .response_approval_token
        .as_deref()
        .is_some_and(|t| api::authorized(h, t))
}
fn executor(h: &HeaderMap, s: &AppState) -> bool {
    s.config
        .response_executor_token
        .as_deref()
        .is_some_and(|t| api::authorized(h, t))
}
fn valid_actor(actor: &str) -> bool {
    (3..=64).contains(&actor.len())
        && actor
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}
fn external_target(ip: &str) -> Option<IpAddr> {
    let parsed = ip.parse().ok()?;
    match parsed {
        IpAddr::V4(a) if allowed_ipv4(a) => Some(parsed),
        IpAddr::V6(a) if allowed_ipv6(a) => Some(parsed),
        _ => None,
    }
}
fn allowed_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    // Fail closed for internal, special, benchmark, multicast, documentation, and
    // CGNAT destinations. A false negative requires explicit human investigation.
    (1..224).contains(&a)
        && a != 127
        && !ip.is_private()
        && !ip.is_link_local()
        && !(a == 100 && (64..=127).contains(&b))
        && !(a == 192
            && matches!(
                (b, c),
                (0, _) | (31, 196) | (52, 193) | (88, 99) | (175, 48)
            ))
        && !(a == 198 && (b == 18 || b == 19))
        && !(a == 198 && b == 51 && c == 100)
        && !(a == 203 && b == 0 && c == 113)
}
fn allowed_ipv6(ip: Ipv6Addr) -> bool {
    let [a, b, c, ..] = ip.segments();
    (0x2000..=0x3fff).contains(&a)
        && a != 0x2002
        && !(a == 0x2001 && (b <= 0x01ff || b == 0x0db8))
        && !(a == 0x2620 && b == 0x004f && c == 0x8000)
        && !(a == 0x3fff && b <= 0x0fff)
}
fn uuid(s: &str) -> bool {
    Uuid::parse_str(s).is_ok()
}
const SELECT_BY_ID: &str = "SELECT id,incident_id,evidence_event_id,action,target_ip,justification,duration_minutes,requester,status,approver,approved_epoch,valid_until_epoch,created_epoch,updated_epoch FROM response_proposals WHERE id=?1";

pub async fn create(
    State(s): State<AppState>,
    h: HeaderMap,
    Json(req): Json<NewProposal>,
) -> Response {
    if !operator(&h, &s) {
        return err(StatusCode::UNAUTHORIZED, "operator credential required");
    }
    let Some(target_ip) = external_target(&req.target_ip).map(|ip| ip.to_string()) else {
        return err(StatusCode::BAD_REQUEST, "invalid or unsafe proposal target");
    };
    if !uuid(&req.evidence_event_id)
        || req.incident_id.as_ref().is_some_and(|i| !uuid(i))
        || !(5..=1440).contains(&req.duration_minutes)
        || !valid_actor(&req.requester)
        || !(20..=1024).contains(&req.justification.len())
        || req
            .justification
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return err(StatusCode::BAD_REQUEST, "invalid or unsafe proposal");
    }
    let mut tx = match s.pool.begin_with("BEGIN IMMEDIATE").await {
        Ok(t) => t,
        Err(_) => return err(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"),
    };
    // Check evidence and insert the proposal within one writer transaction.
    let count: i64 = match sqlx::query_scalar(
        "SELECT COUNT(*) FROM security_events WHERE event_id=?1 AND source_ip=?2 AND event_epoch BETWEEN unixepoch()-604800 AND unixepoch()+300")
        .bind(&req.evidence_event_id).bind(&target_ip).fetch_one(&mut *tx).await {
        Ok(n)=>n, Err(_)=>return err(StatusCode::SERVICE_UNAVAILABLE,"storage unavailable"),
    };
    if count != 1 {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "recent matching source-IP evidence required",
        );
    }
    if let Some(id) = &req.incident_id {
        let exists: bool = match sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM detections d JOIN detection_evidence e ON e.detection_id=d.id WHERE d.incident_id=?1 AND e.security_event_id=?2)")
            .bind(id)
            .bind(&req.evidence_event_id)
            .fetch_one(&mut *tx)
            .await
        {
            Ok(n) => n,
            Err(_) => return err(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"),
        };
        if !exists {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "event is not linked to this incident",
            );
        }
    }
    let id = Uuid::new_v4().to_string();
    let inserted=sqlx::query("INSERT INTO response_proposals(id,incident_id,evidence_event_id,action,target_ip,justification,duration_minutes,requester) VALUES (?1,?2,?3,'temporary_block_ip',?4,?5,?6,?7)")
        .bind(&id).bind(&req.incident_id).bind(&req.evidence_event_id).bind(&target_ip)
        .bind(&req.justification).bind(req.duration_minutes).bind(&req.requester).execute(&mut *tx).await;
    if let Err(e) = inserted {
        if let sqlx::Error::Database(ref db) = e {
            if db.is_unique_violation() {
                return err(
                    StatusCode::CONFLICT,
                    "active proposal already exists for this target",
                );
            }
        }
        tracing::error!(error=%e,"cannot persist response proposal");
        return err(StatusCode::SERVICE_UNAVAILABLE, "cannot persist proposal");
    }
    if sqlx::query("INSERT INTO response_audit(proposal_id,transition,actor,reason,credential_role) VALUES (?1,'proposed',?2,'created','operator')")
        .bind(&id).bind(&req.requester).execute(&mut *tx).await.is_err() || tx.commit().await.is_err() {
        return err(StatusCode::SERVICE_UNAVAILABLE,"cannot persist audit");
    }
    (
        StatusCode::CREATED,
        Json(json!({"id":id,"status":"proposed","live_firewall_change":false})),
    )
        .into_response()
}
pub async fn list(State(s): State<AppState>, h: HeaderMap, Query(q): Query<Page>) -> Response {
    if !operator(&h, &s) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let limit = q.limit.unwrap_or(30);
    if !(1..=100).contains(&limit) || q.before.is_some_and(|v| v < 1) {
        return err(StatusCode::BAD_REQUEST, "invalid pagination");
    }
    #[derive(FromRow)]
    struct PageRow {
        page_id: i64,
        #[sqlx(flatten)]
        data: Proposal,
    }
    let sql="SELECT rowid AS page_id,id,incident_id,evidence_event_id,action,target_ip,justification,duration_minutes,requester,status,approver,approved_epoch,valid_until_epoch,created_epoch,updated_epoch FROM response_proposals WHERE (?1 IS NULL OR rowid<?1) ORDER BY rowid DESC LIMIT ?2";
    match sqlx::query_as::<_, PageRow>(sql)
        .bind(q.before)
        .bind(limit)
        .fetch_all(&s.pool)
        .await
    {
        Ok(rows) => {
            let next = if rows.len() == limit as usize {
                rows.last().map(|r| r.page_id)
            } else {
                None
            };
            (StatusCode::OK,Json(json!({"items":rows.into_iter().map(|r|r.data).collect::<Vec<_>>(),"next_cursor":next}))).into_response()
        }
        Err(e) => {
            tracing::error!(error=%e,"response list failed");
            err(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable")
        }
    }
}
pub async fn details(State(s): State<AppState>, h: HeaderMap, Path(id): Path<String>) -> Response {
    if !operator(&h, &s) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if !uuid(&id) {
        return err(StatusCode::BAD_REQUEST, "invalid id");
    }
    match sqlx::query_as::<_, Proposal>(SELECT_BY_ID)
        .bind(&id)
        .fetch_optional(&s.pool)
        .await
    {
        Ok(Some(p)) => {
            let log=sqlx::query_as::<_,(String,String,String,i64)>("SELECT transition,actor,reason,created_epoch FROM response_audit WHERE proposal_id=?1 ORDER BY row_id LIMIT 100")
                .bind(&id).fetch_all(&s.pool).await;
            match log {
                Ok(rows) => {
                    (StatusCode::OK, Json(json!({"proposal":p,"audit":rows}))).into_response()
                }
                Err(_) => err(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable"),
            }
        }
        Ok(None) => err(StatusCode::NOT_FOUND, "not found"),
        Err(_) => err(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"),
    }
}
pub async fn approve(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<Decision>,
) -> Response {
    transition_human(s, h, id, req, "approved").await
}
pub async fn reject(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<Decision>,
) -> Response {
    transition_human(s, h, id, req, "rejected").await
}
async fn transition_human(
    s: AppState,
    h: HeaderMap,
    id: String,
    req: Decision,
    target: &str,
) -> Response {
    if !approver(&h, &s) {
        return err(StatusCode::UNAUTHORIZED, "approval credential required");
    }
    if !uuid(&id)
        || !valid_actor(&req.actor)
        || req.confirm != format!("{} {}", target.to_uppercase(), id)
        || req.reason.len() < 12
        || req.reason.len() > 512
        || req
            .reason
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid decision or confirmation phrase",
        );
    }
    let mut tx = match s.pool.begin().await {
        Ok(t) => t,
        Err(_) => return err(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"),
    };
    // The role token authorizes the operation. The submitted handle is an operator note.
    let result=sqlx::query("UPDATE response_proposals SET status=?1,approver=?2,approved_epoch=CASE WHEN ?1='approved' THEN CAST(strftime('%s','now') AS INTEGER) ELSE NULL END,valid_until_epoch=CASE WHEN ?1='approved' THEN CAST(strftime('%s','now') AS INTEGER)+900 ELSE NULL END,updated_epoch=CAST(strftime('%s','now') AS INTEGER) WHERE id=?3 AND status='proposed' AND requester<>?2")
        .bind(target).bind(&req.actor).bind(&id).execute(&mut *tx).await;
    let changed = match result {
        Ok(r) => r.rows_affected(),
        Err(_) => return err(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"),
    };
    if changed != 1 {
        return err(
            StatusCode::CONFLICT,
            "proposal not pending, or same requester/approver",
        );
    }
    if sqlx::query(
        "INSERT INTO response_audit(proposal_id,transition,actor,reason,credential_role) VALUES (?1,?2,?3,?4,'approver')",
    )
    .bind(&id)
    .bind(target)
    .bind(&req.actor)
    .bind(&req.reason)
    .execute(&mut *tx)
    .await
    .is_err()
        || tx.commit().await.is_err()
    {
        return err(StatusCode::SERVICE_UNAVAILABLE, "audit not committed");
    }
    (
        StatusCode::OK,
        Json(json!({"id":id,"status":target,"live_firewall_change":false})),
    )
        .into_response()
}
pub async fn simulate(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<Simulation>,
) -> Response {
    if !executor(&h, &s) {
        return err(StatusCode::UNAUTHORIZED, "gateway credential required");
    }
    if !uuid(&id) || !valid_actor(&req.actor) || req.confirm != format!("SIMULATE {}", id) {
        return err(StatusCode::BAD_REQUEST, "invalid simulation request");
    }
    let mut tx = match s.pool.begin().await {
        Ok(t) => t,
        Err(_) => return err(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"),
    };
    let changed=match sqlx::query("UPDATE response_proposals SET status='simulated',updated_epoch=CAST(strftime('%s','now') AS INTEGER) WHERE id=?1 AND status='approved' AND valid_until_epoch>CAST(strftime('%s','now') AS INTEGER)")
        .bind(&id).execute(&mut *tx).await {Ok(r)=>r.rows_affected(),Err(_)=>return err(StatusCode::SERVICE_UNAVAILABLE,"storage unavailable")};
    if changed != 1 {
        return err(StatusCode::CONFLICT, "not approved or approval expired");
    }
    if sqlx::query("INSERT INTO response_audit(proposal_id,transition,actor,reason,credential_role) VALUES (?1,'simulated',?2,'no firewall mutation','executor')")
        .bind(&id).bind(&req.actor).execute(&mut *tx).await.is_err() || tx.commit().await.is_err() {return err(StatusCode::SERVICE_UNAVAILABLE,"audit not committed")}
    (
        StatusCode::OK,
        Json(json!({"id":id,"status":"simulated","live_firewall_change":false})),
    )
        .into_response()
}
pub async fn rollback(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<Simulation>,
) -> Response {
    if !executor(&h, &s) {
        return err(StatusCode::UNAUTHORIZED, "gateway credential required");
    }
    if !uuid(&id) || !valid_actor(&req.actor) || req.confirm != format!("ROLLBACK {}", id) {
        return err(StatusCode::BAD_REQUEST, "invalid rollback request");
    }
    let mut tx = match s.pool.begin().await {
        Ok(t) => t,
        Err(_) => return err(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"),
    };
    let changed=match sqlx::query("UPDATE response_proposals SET status='rolled_back',updated_epoch=CAST(strftime('%s','now') AS INTEGER) WHERE id=?1 AND status='simulated'")
        .bind(&id).execute(&mut *tx).await {Ok(r)=>r.rows_affected(),Err(_)=>return err(StatusCode::SERVICE_UNAVAILABLE,"storage unavailable")};
    if changed != 1 {
        return err(StatusCode::CONFLICT, "no simulated proposal to roll back");
    }
    if sqlx::query("INSERT INTO response_audit(proposal_id,transition,actor,reason,credential_role) VALUES (?1,'rolled_back',?2,'simulation rollback','executor')")
        .bind(&id).bind(&req.actor).execute(&mut *tx).await.is_err() || tx.commit().await.is_err() {return err(StatusCode::SERVICE_UNAVAILABLE,"audit not committed")}
    (
        StatusCode::OK,
        Json(json!({"id":id,"status":"rolled_back","live_firewall_change":false})),
    )
        .into_response()
}

/// Expire unconsumed approvals; never create a rule or extend a permit.
pub async fn expire_approvals(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
    let now = jiff::Timestamp::now().as_second();
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let ids = sqlx::query_scalar::<_, String>(
        "SELECT id FROM response_proposals WHERE status='approved' AND valid_until_epoch <= ?1 ORDER BY valid_until_epoch LIMIT 100")
        .bind(now).fetch_all(&mut *tx).await?;
    let mut expired = 0_u64;
    for id in ids {
        let changed=sqlx::query("UPDATE response_proposals SET status='expired',updated_epoch=?2 WHERE id=?1 AND status='approved' AND valid_until_epoch<=?2")
            .bind(&id).bind(now).execute(&mut *tx).await?.rows_affected();
        if changed == 1 {
            sqlx::query("INSERT INTO response_audit(proposal_id,transition,actor,reason,credential_role) VALUES (?1,'expired','system','approval permit expired','system')")
                .bind(&id).execute(&mut *tx).await?;
            expired += 1;
        }
    }
    tx.commit().await?;
    Ok(expired)
}
pub async fn run_expiration_loop(pool: SqlitePool) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        interval.tick().await;
        if let Err(err) = expire_approvals(&pool).await {
            tracing::warn!(error=%err,"response approval expiration failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_policy_fail_closed() {
        for ip in [
            "192.168.1.1",
            "10.0.0.2",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.3",
            "203.0.113.4",
            "198.51.100.10",
            "2001:db8::1",
            "::1",
            "ff02::1",
        ] {
            assert!(external_target(ip).is_none(), "must reject {ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700::1111"] {
            assert!(external_target(ip).is_some());
        }
        for ip in [
            "192.88.99.1",
            "64:ff9b::abcd",
            "3fff:fff::1",
            "2001:2::1",
            "2002::1",
            "::ffff:8.8.8.8",
        ] {
            assert!(external_target(ip).is_none(), "must reject {ip}");
        }
    }
    #[test]
    fn actors_are_strict() {
        assert!(valid_actor("operator.1"));
        assert!(!valid_actor("operator name"));
    }
}
