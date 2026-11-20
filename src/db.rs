use crate::normalizer::SecurityEvent;
use jiff::Timestamp;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    SqliteConnection, SqlitePool,
};
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct EventRow {
    pub row_id: i64,
    pub event_id: String,
    pub source: String,
    pub event_ts: Option<String>,
    pub ingested_at: String,
    pub hostname: Option<String>,
    pub appname: Option<String>,
    pub severity: Option<String>,
    pub facility: Option<String>,
    pub message: Option<String>,
    pub transport_peer_ip: Option<String>,
    pub payload_sha256: String,
    pub parser_version: i64,
    pub parse_status: String,
    pub parse_error: Option<String>,
}
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct EventDetailRow {
    #[serde(flatten)]
    #[sqlx(flatten)]
    pub event: EventRow,
    pub raw_json: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct SecurityRow {
    pub row_id: i64,
    pub event_id: String,
    pub raw_event_id: String,
    pub source: String,
    pub event_ts: Option<String>,
    pub category: String,
    pub action: Option<String>,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub source_port: Option<i64>,
    pub destination_port: Option<i64>,
    pub protocol: Option<String>,
    pub interface: Option<String>,
    pub direction: Option<String>,
    pub rule_tracker: Option<String>,
    pub domain: Option<String>,
    pub dns_qtype: Option<String>,
    pub details_json: String,
    pub parser_version: i64,
}
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct SourceHealth {
    pub source: String,
    pub status: String,
    pub last_attempt: Option<String>,
    pub last_success: Option<String>,
    pub last_error: Option<String>,
    pub consecutive_failures: i64,
    pub last_batch_inserted: i64,
    pub last_batch_duplicates: i64,
}
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct DecisionRow {
    pub id: String,
    pub active: i64,
    pub scope: Option<String>,
    pub value: Option<String>,
    pub action: Option<String>,
    pub scenario: Option<String>,
    pub origin: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub last_changed: String,
}

pub struct RawRecord {
    pub source: String,
    pub source_native_id: Option<String>,
    pub delivery_id: Option<String>,
    pub event_ts: Option<String>,
    pub hostname: Option<String>,
    pub appname: Option<String>,
    pub severity: Option<String>,
    pub facility: Option<String>,
    pub message: Option<String>,
    pub transport_peer_ip: Option<String>,
    pub raw_json: String,
    pub parse_status: String,
    pub parse_error: Option<String>,
    pub normalized: Option<SecurityEvent>,
}
impl RawRecord {
    pub fn polled(
        source: &str,
        native_id: String,
        json: &Value,
        normalized: SecurityEvent,
    ) -> Result<Self, serde_json::Error> {
        Ok(Self {
            source: source.to_owned(),
            source_native_id: Some(native_id),
            delivery_id: None,
            event_ts: normalized.event_ts.clone(),
            hostname: None,
            appname: None,
            severity: None,
            facility: None,
            message: None,
            transport_peer_ip: None,
            raw_json: serde_json::to_string(json)?,
            parse_status: "parsed".to_owned(),
            parse_error: None,
            normalized: Some(normalized),
        })
    }
}

pub async fn connect(
    path: &std::path::Path,
) -> Result<SqlitePool, Box<dyn std::error::Error + Send + Sync>> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// Exactly one raw row and at most one normalized row per committed transaction.
/// Stable identity is delivery_id (Vector) or source-native_id (pollers); not payload hash.
pub async fn insert_record(conn: &mut SqliteConnection, e: RawRecord) -> Result<bool, sqlx::Error> {
    let raw_id = Uuid::new_v4().to_string();
    let digest = hex::encode(Sha256::digest(e.raw_json.as_bytes()));
    let result = sqlx::query(
        "INSERT INTO raw_events \
         (event_id, source, source_native_id, event_ts, ingested_at, hostname, appname, severity, facility, \
         message, transport_peer_ip, raw_json, payload_sha256, parser_version, delivery_id, parse_status, parse_error) \
         VALUES (?1, ?2, ?3, ?4, strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 2, ?13, ?14, ?15) ON CONFLICT DO NOTHING"
    ).bind(raw_id.as_str()).bind(e.source.as_str()).bind(e.source_native_id.as_deref()).bind(e.event_ts.as_deref())
        .bind(e.hostname.as_deref()).bind(e.appname.as_deref()).bind(e.severity.as_deref()).bind(e.facility.as_deref())
        .bind(e.message.as_deref()).bind(e.transport_peer_ip.as_deref()).bind(e.raw_json.as_str()).bind(digest)
        .bind(e.delivery_id.as_deref()).bind(e.parse_status.as_str()).bind(e.parse_error.as_deref())
        .execute(&mut *conn).await?;
    if result.rows_affected() == 0 {
        return Ok(false);
    }
    if let Some(n) = e.normalized {
        let epoch = n
            .event_ts
            .as_deref()
            .and_then(|s| s.parse::<Timestamp>().ok())
            .map(|d| d.as_second());
        sqlx::query("INSERT INTO security_events (event_id,raw_event_id,source,event_ts,category,action,source_ip,destination_ip,source_port,destination_port,protocol,interface,direction,rule_tracker,domain,dns_qtype,details_json,parser_version,event_epoch) \
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,2,?18)")
        .bind(Uuid::new_v4().to_string()).bind(raw_id)
        .bind(n.source).bind(n.event_ts).bind(n.category).bind(n.action)
        .bind(n.source_ip).bind(n.destination_ip).bind(n.source_port).bind(n.destination_port)
        .bind(n.protocol).bind(n.interface).bind(n.direction).bind(n.rule_tracker)
        .bind(n.domain).bind(n.dns_qtype).bind(n.details_json).bind(epoch)
        .execute(&mut *conn).await?;
    }
    Ok(true)
}

const EVENT_PAGE: &str = "SELECT row_id, event_id, source, event_ts, ingested_at, hostname, appname, severity, facility, message, transport_peer_ip, payload_sha256, parser_version, parse_status, parse_error FROM raw_events WHERE (?1 IS NULL OR row_id < ?1) ORDER BY row_id DESC LIMIT ?2";

pub async fn list(
    pool: &SqlitePool,
    before: Option<i64>,
    limit: i64,
) -> Result<Vec<EventRow>, sqlx::Error> {
    sqlx::query_as::<_, EventRow>(EVENT_PAGE)
        .bind(before)
        .bind(limit)
        .fetch_all(pool)
        .await
}
pub async fn get(pool: &SqlitePool, event_id: &str) -> Result<Option<EventDetailRow>, sqlx::Error> {
    sqlx::query_as::<_, EventDetailRow>("SELECT row_id, event_id, source, event_ts, ingested_at, hostname, appname, severity, facility, message, transport_peer_ip, payload_sha256, parser_version, parse_status, parse_error, raw_json FROM raw_events WHERE event_id = ?1")
        .bind(event_id).fetch_optional(pool).await
}
pub async fn list_security(
    pool: &SqlitePool,
    source: Option<&str>,
    action: Option<&str>,
    before: Option<i64>,
    limit: i64,
) -> Result<Vec<SecurityRow>, sqlx::Error> {
    sqlx::query_as::<_, SecurityRow>("SELECT row_id, event_id, raw_event_id, source, event_ts, category, action, source_ip, destination_ip, source_port, destination_port, protocol, interface, direction, rule_tracker, domain, dns_qtype, details_json, parser_version \
       FROM security_events WHERE (?1 IS NULL OR source = ?1) AND (?2 IS NULL OR action = ?2) AND (?3 IS NULL OR row_id < ?3) ORDER BY row_id DESC LIMIT ?4")
       .bind(source).bind(action).bind(before).bind(limit).fetch_all(pool).await
}
pub async fn sources(pool: &SqlitePool) -> Result<Vec<SourceHealth>, sqlx::Error> {
    sqlx::query_as("SELECT source,status,last_attempt,last_success,last_error,consecutive_failures,last_batch_inserted,last_batch_duplicates FROM source_health ORDER BY source").fetch_all(pool).await
}
pub async fn decisions(pool: &SqlitePool, limit: i64) -> Result<Vec<DecisionRow>, sqlx::Error> {
    sqlx::query_as("SELECT id,active,scope,value,action,scenario,origin,first_seen,last_seen,last_changed FROM crowdsec_decisions WHERE active=1 ORDER BY id LIMIT ?1")
        .bind(limit).fetch_all(pool).await
}
pub async fn checkpoint(pool: &SqlitePool, source: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT cursor FROM ingestion_checkpoints WHERE source=?1")
        .bind(source)
        .fetch_optional(pool)
        .await
}
pub async fn set_checkpoint(
    conn: &mut SqliteConnection,
    source: &str,
    cursor: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO ingestion_checkpoints(source,cursor,updated_at) VALUES (?1,?2,strftime('%Y-%m-%dT%H:%M:%fZ','now')) \
      ON CONFLICT(source) DO UPDATE SET cursor=excluded.cursor,updated_at=excluded.updated_at")
        .bind(source).bind(cursor).execute(conn).await?;
    Ok(())
}
pub async fn mark_source(
    pool: &SqlitePool,
    source: &str,
    success: bool,
    error: Option<&str>,
    inserted: i64,
    dup: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO source_health(source,status,last_attempt,last_success,last_error,consecutive_failures,last_batch_inserted,last_batch_duplicates) \
      VALUES (?1,?2,strftime('%Y-%m-%dT%H:%M:%fZ','now'),CASE WHEN ?3 THEN strftime('%Y-%m-%dT%H:%M:%fZ','now') ELSE NULL END,?4,CASE WHEN ?3 THEN 0 ELSE 1 END,?5,?6) \
      ON CONFLICT(source) DO UPDATE SET status=excluded.status,last_attempt=excluded.last_attempt, \
        last_success=CASE WHEN ?3 THEN excluded.last_success ELSE source_health.last_success END, \
        last_error=excluded.last_error,consecutive_failures=CASE WHEN ?3 THEN 0 ELSE source_health.consecutive_failures+1 END, \
        last_batch_inserted=excluded.last_batch_inserted,last_batch_duplicates=excluded.last_batch_duplicates")
       .bind(source).bind(if success { "ok" } else { "degraded" }).bind(success)
       .bind(error).bind(inserted).bind(dup).execute(pool).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn migration_dedup_and_snapshot_tables() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        for attempt in 0..2 {
            let event = RawRecord {
                source: "test".into(),
                source_native_id: Some("id-1".into()),
                delivery_id: None,
                event_ts: None,
                hostname: None,
                appname: None,
                severity: None,
                facility: None,
                message: None,
                transport_peer_ip: None,
                raw_json: "{}".into(),
                parse_status: "parsed".into(),
                parse_error: None,
                normalized: None,
            };
            assert_eq!(insert_record(&mut tx, event).await.unwrap(), attempt == 0);
        }
        tx.commit().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM raw_events")
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );
    }
}
