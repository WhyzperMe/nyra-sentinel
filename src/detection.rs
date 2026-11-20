//! Phase 3 deterministic detection. Not an intrusion confirmation or autonomous response.
//!
//! One SQLite transaction owns the cursor, derived asset state, detections, incidents and
//! evidence links. A failed batch rolls back all of them. Never evaluate untrusted log text
//! as executable rules. Every detection references stored normalized security_event IDs.
use std::{collections::HashSet, net::IpAddr, time::Duration};

use jiff::Timestamp;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{SqliteConnection, SqlitePool};
use uuid::Uuid;

const MAX_EVIDENCE: i64 = 32;
const FIVE_MIN: i64 = 300;
const SIX_HOURS: i64 = 21_600;
const ONE_DAY: i64 = 86_400;
const LIVE_WINDOW: i64 = 15 * 60;

#[derive(Debug, Clone)]
pub struct DetectionConfig {
    pub interval: Duration,
    pub batch_size: i64,
    pub firewall_blocks: i64,
    pub dns_per_min: i64,
    pub admin_probes: i64,
    pub outbound_fanout: i64,
    pub dns_anomaly_min_5min: i64,
    pub baseline_min_queries: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct Event {
    row_id: i64,
    event_id: String,
    category: String,
    action: Option<String>,
    source_ip: Option<String>,
    destination_ip: Option<String>,
    destination_port: Option<i64>,
    direction: Option<String>,
    domain: Option<String>,
    event_epoch: Option<i64>,
}

#[derive(Debug, sqlx::FromRow)]
struct AssetPrior {
    first_seen_epoch: i64,
    total_dns_queries: i64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BatchResult {
    pub processed: usize,
    pub skipped: usize,
}

fn private_asset(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v)) => v.is_private(),
        Ok(IpAddr::V6(v)) => (v.segments()[0] & 0xfe00) == 0xfc00,
        _ => false,
    }
}
fn valid_ip(ip: &str) -> bool {
    ip.parse::<IpAddr>().is_ok()
}
fn fingerprint(rule: &str, entity: &str, bucket: i64) -> String {
    hex::encode(Sha256::digest(
        format!("v1\0{rule}\0{entity}\0{bucket}").as_bytes(),
    ))
}
fn severity_rank(severity: &str) -> i32 {
    match severity {
        "high" => 3,
        "medium" => 2,
        _ => 1,
    }
}

struct Trigger<'a> {
    rule: &'static str,
    severity: &'static str,
    classification: &'static str,
    entity: &'a str,
    event_epoch: i64,
    fingerprint_bucket: i64,
    count: i64,
    title: &'static str,
    explanation: &'static str,
    details: Value,
    evidence: Vec<String>,
}

async fn record(conn: &mut SqliteConnection, t: Trigger<'_>) -> Result<(), sqlx::Error> {
    let fp = fingerprint(
        t.rule,
        t.entity,
        t.event_epoch.div_euclid(t.fingerprint_bucket),
    );
    let existing: Option<(String, String)> =
        sqlx::query_as("SELECT id,incident_id FROM detections WHERE fingerprint=?1")
            .bind(&fp)
            .fetch_optional(&mut *conn)
            .await?;
    let detection_id = if let Some((id, incident_id)) = existing {
        sqlx::query("UPDATE detections SET last_seen_epoch=MAX(last_seen_epoch,?2),first_seen_epoch=MIN(first_seen_epoch,?2),observed_count=MAX(observed_count,?3),updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?1")
            .bind(&id).bind(t.event_epoch).bind(t.count).execute(&mut *conn).await?;
        sqlx::query("UPDATE incidents SET last_seen_epoch=MAX(last_seen_epoch,?2),first_seen_epoch=MIN(first_seen_epoch,?2),updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?1")
            .bind(&incident_id).bind(t.event_epoch).execute(&mut *conn).await?;
        id
    } else {
        let prior_incident: Option<(String, String)> = sqlx::query_as(
            "SELECT id,severity FROM incidents WHERE subject_kind='ip' AND subject_value=?1 AND status='open' AND first_seen_epoch<=?2 AND last_seen_epoch>=?3 ORDER BY last_seen_epoch DESC LIMIT 1")
            .bind(t.entity).bind(t.event_epoch.saturating_add(SIX_HOURS))
            .bind(t.event_epoch.saturating_sub(SIX_HOURS))
            .fetch_optional(&mut *conn).await?;
        let incident_id = if let Some((id, existing_severity)) = prior_incident {
            let new_severity = if severity_rank(t.severity) > severity_rank(&existing_severity) {
                t.severity
            } else {
                &existing_severity
            };
            sqlx::query("UPDATE incidents SET severity=?2,first_seen_epoch=MIN(first_seen_epoch,?3),last_seen_epoch=MAX(last_seen_epoch,?3),detection_count=detection_count+1,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?1")
                .bind(&id).bind(new_severity).bind(t.event_epoch).execute(&mut *conn).await?;
            id
        } else {
            let id = Uuid::new_v4().to_string();
            sqlx::query("INSERT INTO incidents(id,subject_kind,subject_value,severity,first_seen_epoch,last_seen_epoch,detection_count,title) VALUES (?1,'ip',?2,?3,?4,?4,1,?5)")
                .bind(&id).bind(t.entity).bind(t.severity).bind(t.event_epoch)
                .bind(format!("Security observations involving {}",t.entity))
                .execute(&mut *conn).await?;
            id
        };
        let detection_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO detections(id,fingerprint,rule_id,rule_version,severity,classification,entity_kind,entity_value,incident_id,window_start_epoch,first_seen_epoch,last_seen_epoch,observed_count,title,explanation,details_json) VALUES (?1,?2,?3,1,?4,?5,'ip',?6,?7,?8,?9,?9,?10,?11,?12,?13)")
            .bind(&detection_id).bind(&fp).bind(t.rule).bind(t.severity)
            .bind(t.classification).bind(t.entity).bind(&incident_id)
            .bind(t.event_epoch.div_euclid(t.fingerprint_bucket) * t.fingerprint_bucket)
            .bind(t.event_epoch).bind(t.count).bind(t.title).bind(t.explanation)
            .bind(t.details.to_string())
            .execute(&mut *conn).await?;
        detection_id
    };
    // Event IDs are foreign-keyed; evidence stays bounded and cannot be fabricated by the LLM.
    let mut seen = HashSet::new();
    for event_id in t.evidence.into_iter().take(MAX_EVIDENCE as usize) {
        if seen.insert(event_id.clone()) {
            sqlx::query("INSERT OR IGNORE INTO detection_evidence(detection_id,security_event_id) SELECT ?1,?2 WHERE (SELECT COUNT(*) FROM detection_evidence WHERE detection_id=?1) < 32")
                .bind(&detection_id).bind(event_id).execute(&mut *conn).await?;
        }
    }
    Ok(())
}

async fn ids(
    conn: &mut SqliteConnection,
    sql: &'static str,
    ip: &str,
    from: i64,
    through: i64,
    max_row: i64,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(sql)
        .bind(ip)
        .bind(from)
        .bind(through)
        .bind(max_row)
        .fetch_all(&mut *conn)
        .await
}
const FIREWALL_IDS: &str = "SELECT event_id FROM security_events WHERE source_ip=?1 AND category='firewall.filterlog' AND action IN ('block','reject') AND event_epoch BETWEEN ?2 AND ?3 AND row_id<=?4 ORDER BY row_id DESC LIMIT 32";
const DNS_IDS: &str = "SELECT event_id FROM security_events WHERE source_ip=?1 AND category='dns.query' AND event_epoch BETWEEN ?2 AND ?3 AND row_id<=?4 ORDER BY row_id DESC LIMIT 32";

async fn update_asset(
    conn: &mut SqliteConnection,
    e: &Event,
    ts: i64,
) -> Result<Option<AssetPrior>, sqlx::Error> {
    let ip = match e.source_ip.as_deref().filter(|s| private_asset(s)) {
        Some(s) => s,
        None => return Ok(None),
    };
    let prior: Option<AssetPrior> =
        sqlx::query_as("SELECT first_seen_epoch,total_dns_queries FROM assets WHERE asset_key=?1")
            .bind(ip)
            .fetch_optional(&mut *conn)
            .await?;
    let dns = i64::from(e.category == "dns.query");
    let firewall = i64::from(
        e.category == "firewall.filterlog"
            && matches!(e.action.as_deref(), Some("block" | "reject")),
    );
    let outbound = i64::from(
        e.category == "firewall.filterlog"
            && e.action.as_deref() == Some("pass")
            && e.direction.as_deref() == Some("out"),
    );
    sqlx::query("INSERT INTO assets(asset_key,first_seen_epoch,last_seen_epoch,total_dns_queries,total_firewall_blocks,total_outbound_passes) VALUES (?1,?2,?2,?3,?4,?5) ON CONFLICT(asset_key) DO UPDATE SET first_seen_epoch=MIN(first_seen_epoch,excluded.first_seen_epoch),last_seen_epoch=MAX(last_seen_epoch,excluded.last_seen_epoch),total_dns_queries=total_dns_queries+excluded.total_dns_queries,total_firewall_blocks=total_firewall_blocks+excluded.total_firewall_blocks,total_outbound_passes=total_outbound_passes+excluded.total_outbound_passes")
        .bind(ip).bind(ts).bind(dns).bind(firewall).bind(outbound).execute(&mut *conn).await?;
    Ok(prior)
}

async fn handle_dns(
    conn: &mut SqliteConnection,
    e: &Event,
    ts: i64,
    cfg: &DetectionConfig,
    prior: Option<AssetPrior>,
    alerts: Option<bool>,
) -> Result<(), sqlx::Error> {
    let ip = match e.source_ip.as_deref().filter(|s| private_asset(s)) {
        Some(ip) => ip,
        None => return Ok(()),
    };
    let warm = prior.as_ref().is_some_and(|p| {
        p.total_dns_queries >= cfg.baseline_min_queries
            && ts.saturating_sub(p.first_seen_epoch) >= ONE_DAY
    });
    let bucket = ts.div_euclid(FIVE_MIN) * FIVE_MIN;
    sqlx::query("INSERT INTO asset_dns_buckets(asset_key,bucket_start_epoch,query_count) VALUES (?1,?2,1) ON CONFLICT(asset_key,bucket_start_epoch) DO UPDATE SET query_count=query_count+1")
        .bind(ip).bind(bucket).execute(&mut *conn).await?;
    if let Some(domain) = e.domain.as_deref().filter(|s| !s.is_empty()) {
        let result = sqlx::query("INSERT OR IGNORE INTO asset_domains(asset_key,domain,first_seen_epoch,last_seen_epoch) VALUES (?1,?2,?3,?3)")
            .bind(ip).bind(domain).bind(ts).execute(&mut *conn).await?;
        let novel = result.rows_affected() == 1;
        if !novel {
            sqlx::query("UPDATE asset_domains SET first_seen_epoch=MIN(first_seen_epoch,?3),last_seen_epoch=MAX(last_seen_epoch,?3),query_count=query_count+1 WHERE asset_key=?1 AND domain=?2")
                .bind(ip).bind(domain).bind(ts).execute(&mut *conn).await?;
        }
        // A new domain is *not* by itself suspicious. Only low-severity previously unknown,
        // explicitly filtered domains on established clients are reported.
        if alerts == Some(true) && novel && warm && e.action.as_deref() == Some("filtered") {
            record(conn,Trigger { rule:"dns_new_filtered_domain", severity:"low",classification:"deterministic",entity:ip,
                event_epoch:ts,fingerprint_bucket:900,count:1,title:"New filtered DNS domain on established asset",
                explanation:"A previously unseen DNS name was filtered. This is an observation, not evidence of compromise.",
                details:json!({"domain":domain,"baseline_previous_dns_queries":prior.as_ref().map(|p|p.total_dns_queries)}),evidence:vec![e.event_id.clone()] }).await?;
        }
    }
    let Some(statistical_allowed) = alerts else {
        return Ok(());
    };
    let from = ts.saturating_sub(59);
    let volume: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_events WHERE category='dns.query' AND source_ip=?1 AND event_epoch BETWEEN ?2 AND ?3 AND row_id<=?4")
        .bind(ip).bind(from).bind(ts).bind(e.row_id).fetch_one(&mut *conn).await?;
    if volume >= cfg.dns_per_min {
        let evidence = ids(conn, DNS_IDS, ip, from, ts, e.row_id).await?;
        record(conn,Trigger { rule:"dns_query_volume",severity:"medium",classification:"deterministic",entity:ip,
            event_epoch:ts,fingerprint_bucket:300,count:volume,title:"Elevated DNS query volume",
            explanation:"A DNS query-count threshold was exceeded. Investigate client behavior and telemetry quality before inferring malicious activity.",
            details:json!({"window_seconds":60,"threshold":cfg.dns_per_min}),evidence }).await?;
    }
    // Statistical anomaly: the preceding 24h of 5-minute buckets, including quiet buckets,
    // forms a rolling baseline. Current bucket is excluded to avoid training on the spike.
    if warm && statistical_allowed {
        let current: i64 = sqlx::query_scalar("SELECT query_count FROM asset_dns_buckets WHERE asset_key=?1 AND bucket_start_epoch=?2")
            .bind(ip).bind(bucket).fetch_one(&mut *conn).await?;
        if current >= cfg.dns_anomaly_min_5min {
            let counts: Vec<i64> = sqlx::query_scalar("SELECT query_count FROM asset_dns_buckets WHERE asset_key=?1 AND bucket_start_epoch>=?2 AND bucket_start_epoch<?3")
                .bind(ip).bind(bucket-ONE_DAY).bind(bucket).fetch_all(&mut *conn).await?;
            let prior_count: i64 = counts.iter().sum();
            if prior_count >= cfg.baseline_min_queries {
                let mean = prior_count as f64 / 288.0;
                let sq = counts.iter().map(|n| (*n as f64).powi(2)).sum::<f64>() / 288.0;
                let sd = (sq - mean.powi(2)).max(0.0).sqrt();
                let floor = (mean * 3.0)
                    .max(mean + 4.0 * sd)
                    .max(cfg.dns_anomaly_min_5min as f64);
                if current as f64 >= floor {
                    let evidence = ids(conn, DNS_IDS, ip, bucket, ts, e.row_id).await?;
                    record(conn,Trigger { rule:"dns_baseline_spike",severity:"medium",classification:"statistical",entity:ip,
                        event_epoch:ts,fingerprint_bucket:FIVE_MIN,count:current,title:"DNS activity deviates from 24h baseline",
                        explanation:"A statistical DNS-volume deviation was observed. It may reflect legitimate workload changes; confirmation requires investigation.",
                        details:json!({"window_seconds":300,"baseline_seconds":ONE_DAY,"baseline_mean":mean,"baseline_stddev":sd,"trigger_count":current,"threshold":floor.ceil() as i64}),evidence }).await?;
                }
            }
        }
    }
    Ok(())
}

async fn handle_firewall(
    conn: &mut SqliteConnection,
    e: &Event,
    ts: i64,
    cfg: &DetectionConfig,
) -> Result<(), sqlx::Error> {
    let ip = match e.source_ip.as_deref().filter(|s| valid_ip(s)) {
        Some(s) => s,
        None => return Ok(()),
    };
    if matches!(e.action.as_deref(), Some("block" | "reject")) {
        let from = ts.saturating_sub(299);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_events WHERE source_ip=?1 AND category='firewall.filterlog' AND action IN ('block','reject') AND event_epoch BETWEEN ?2 AND ?3 AND row_id<=?4")
            .bind(ip).bind(from).bind(ts).bind(e.row_id).fetch_one(&mut *conn).await?;
        if count >= cfg.firewall_blocks {
            let evidence = ids(conn, FIREWALL_IDS, ip, from, ts, e.row_id).await?;
            record(conn,Trigger {rule:"repeated_firewall_blocks",severity:"medium",classification:"deterministic",entity:ip,
                event_epoch:ts,fingerprint_bucket:300,count,title:"Repeated firewall blocks",
                explanation:"Multiple connections were blocked or rejected. Blocking does not imply intrusion or successful access.",
                details:json!({"window_seconds":300,"threshold":cfg.firewall_blocks}),evidence}).await?;
        }
        const ADMIN_PORTS: [i64; 8] = [22, 445, 3389, 5900, 8080, 8443, 8291, 10443];
        if e.destination_port.is_some_and(|p| ADMIN_PORTS.contains(&p)) {
            let admin_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_events WHERE source_ip=?1 AND category='firewall.filterlog' AND action IN ('block','reject') AND destination_port IN (22,445,3389,5900,8080,8443,8291,10443) AND event_epoch BETWEEN ?2 AND ?3 AND row_id<=?4")
                .bind(ip).bind(from).bind(ts).bind(e.row_id).fetch_one(&mut *conn).await?;
            if admin_count >= cfg.admin_probes {
                let evidence: Vec<String> = sqlx::query_scalar("SELECT event_id FROM security_events WHERE source_ip=?1 AND category='firewall.filterlog' AND action IN ('block','reject') AND destination_port IN (22,445,3389,5900,8080,8443,8291,10443) AND event_epoch BETWEEN ?2 AND ?3 AND row_id<=?4 ORDER BY row_id DESC LIMIT 32")
                    .bind(ip).bind(from).bind(ts).bind(e.row_id).fetch_all(&mut *conn).await?;
                record(conn,Trigger {rule:"admin_service_probing",severity:"medium",classification:"deterministic",entity:ip,
                    event_epoch:ts,fingerprint_bucket:300,count:admin_count,title:"Blocked administrative-service probing",
                    explanation:"Repeated blocked requests targeted common administrative ports; no successful access is implied.",
                    details:json!({"window_seconds":300,"threshold":cfg.admin_probes,"ports":ADMIN_PORTS}),evidence}).await?;
            }
        }
        // Co-occurrence is correlation, not proof that CrowdSec blocked this exact request.
        let recent_crowdsec: Vec<String> = sqlx::query_scalar("SELECT event_id FROM security_events WHERE source_ip=?1 AND category='crowdsec.decision' AND action IN ('added','observed','reactivated','changed') AND event_epoch BETWEEN ?2 AND ?3 AND row_id<=?4 ORDER BY row_id DESC LIMIT 8")
            .bind(ip).bind(ts-1800).bind(ts).bind(e.row_id).fetch_all(&mut *conn).await?;
        if !recent_crowdsec.is_empty() {
            correlate(conn, e, ts, ip, recent_crowdsec).await?;
        }
        // Inbound multi-asset reconnaissance (private destination IPs only).
        if !private_asset(ip)
            && e.direction.as_deref() == Some("in")
            && e.destination_ip.as_deref().is_some_and(private_asset)
        {
            let dests: Vec<String> = sqlx::query_scalar("SELECT DISTINCT destination_ip FROM security_events WHERE source_ip=?1 AND category='firewall.filterlog' AND direction='in' AND action IN ('block','reject') AND event_epoch BETWEEN ?2 AND ?3 AND destination_ip IS NOT NULL AND row_id<=?4 LIMIT 128")
                .bind(ip).bind(ts-899).bind(ts).bind(e.row_id).fetch_all(&mut *conn).await?;
            let distinct = dests.iter().filter(|d| private_asset(d)).count();
            if distinct >= 2 {
                let evidence = ids(conn, FIREWALL_IDS, ip, ts - 899, ts, e.row_id).await?;
                record(conn,Trigger {rule:"multi_asset_inbound_probing",severity:"medium",classification:"deterministic",entity:ip,
                    event_epoch:ts,fingerprint_bucket:900,count:distinct as i64,title:"Inbound blocks targeting multiple internal assets",
                    explanation:"A public source was observed hitting multiple private destinations; these are blocked attempts, not confirmed compromise.",
                    details:json!({"window_seconds":900,"distinct_private_destinations":distinct}),evidence}).await?;
            }
        }
    }
    if private_asset(ip)
        && e.action.as_deref() == Some("pass")
        && e.direction.as_deref() == Some("out")
        && e.destination_ip
            .as_deref()
            .is_some_and(|d| valid_ip(d) && !private_asset(d))
    {
        let dests:Vec<String>=sqlx::query_scalar("SELECT DISTINCT destination_ip FROM security_events WHERE source_ip=?1 AND category='firewall.filterlog' AND action='pass' AND direction='out' AND event_epoch BETWEEN ?2 AND ?3 AND destination_ip IS NOT NULL AND row_id<=?4 LIMIT 256")
            .bind(ip).bind(ts-599).bind(ts).bind(e.row_id).fetch_all(&mut *conn).await?;
        let fanout = dests
            .iter()
            .filter(|d| valid_ip(d) && !private_asset(d))
            .count();
        if fanout >= cfg.outbound_fanout as usize {
            let evidence:Vec<String>=sqlx::query_scalar("SELECT event_id FROM security_events WHERE source_ip=?1 AND category='firewall.filterlog' AND action='pass' AND direction='out' AND event_epoch BETWEEN ?2 AND ?3 AND row_id<=?4 ORDER BY row_id DESC LIMIT 32")
                .bind(ip).bind(ts-599).bind(ts).bind(e.row_id).fetch_all(&mut *conn).await?;
            record(conn,Trigger {rule:"outbound_destination_fanout",severity:"medium",classification:"deterministic",entity:ip,
                event_epoch:ts,fingerprint_bucket:600,count:fanout as i64,title:"High outbound destination fan-out",
                explanation:"A local source connected to many distinct public addresses. Verify interface direction and legitimate client workloads.",
                details:json!({"window_seconds":600,"distinct_destinations":fanout,"threshold":cfg.outbound_fanout}),evidence}).await?;
        }
    }
    Ok(())
}

async fn correlate(
    conn: &mut SqliteConnection,
    e: &Event,
    ts: i64,
    ip: &str,
    related: Vec<String>,
) -> Result<(), sqlx::Error> {
    let blocks = ids(conn, FIREWALL_IDS, ip, ts - 1800, ts, e.row_id).await?;
    if blocks.is_empty() {
        return Ok(());
    }
    let mut evidence = vec![e.event_id.clone()];
    evidence.extend(related);
    evidence.extend(blocks.iter().cloned());
    record(conn,Trigger {rule:"crowdsec_firewall_correlation",severity:"medium",classification:"deterministic",entity:ip,
        event_epoch:ts,fingerprint_bucket:900,count:blocks.len() as i64,title:"CrowdSec decision correlated with firewall blocks",
        explanation:"CrowdSec and blocked firewall requests involve the same source IP. This is a temporal association, not proof of compromise.",
        details:json!({"window_seconds":1800,"bounded_evidence":true}),evidence}).await
}

async fn handle_crowdsec(
    conn: &mut SqliteConnection,
    e: &Event,
    ts: i64,
) -> Result<(), sqlx::Error> {
    let ip = match e.source_ip.as_deref().filter(|s| valid_ip(s)) {
        Some(ip) => ip,
        None => return Ok(()),
    };
    if matches!(
        e.action.as_deref(),
        Some("added" | "observed" | "reactivated" | "changed")
    ) {
        correlate(conn, e, ts, ip, vec![e.event_id.clone()]).await?;
    }
    Ok(())
}

/// Bounded batch, deterministic cursor and derived state in one atomic transaction.
/// A persisted source event is never deleted or modified by this engine.
pub async fn run_batch(
    pool: &SqlitePool,
    cfg: &DetectionConfig,
) -> Result<BatchResult, sqlx::Error> {
    let mut tx = pool.begin().await?;
    // Acquire the SQLite write reservation before reading the cursor, preventing races with
    // another engine worker and avoiding read-to-write WAL snapshot promotion failures.
    sqlx::query("UPDATE detection_cursor SET updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE pipeline='default'")
        .execute(&mut *tx).await?;
    let cursor: i64 =
        sqlx::query_scalar("SELECT last_row_id FROM detection_cursor WHERE pipeline='default'")
            .fetch_one(&mut *tx)
            .await?;
    let events:Vec<Event>=sqlx::query_as("SELECT row_id,event_id,category,action,source_ip,destination_ip,destination_port,direction,domain,event_epoch FROM security_events WHERE row_id>?1 ORDER BY row_id ASC LIMIT ?2")
        .bind(cursor).bind(cfg.batch_size).fetch_all(&mut *tx).await?;
    let mut result = BatchResult::default();
    // Suppress learned-baseline alerts when the DNS source currently reports a gap/error.
    // The absolute DNS count rule remains observable but source health still needs review.
    let dns_health: Option<String> =
        sqlx::query_scalar("SELECT status FROM source_health WHERE source='adguard-querylog'")
            .fetch_optional(&mut *tx)
            .await?;
    let statistical_allowed = dns_health.as_deref() == Some("ok");
    let now = Timestamp::now().as_second();
    let mut last = cursor;
    for e in &events {
        last = e.row_id;
        result.processed += 1;
        let Some(ts) = e.event_epoch else {
            result.skipped += 1;
            continue;
        };
        // Recent historical data can fill rollups. Only the live window emits detections.
        if ts < now - ONE_DAY || ts > now + 300 {
            result.skipped += 1;
            continue;
        };
        let prior = update_asset(&mut tx, e, ts).await?;
        let live = ts >= now - LIVE_WINDOW;
        result.skipped += usize::from(!live);
        match e.category.as_str() {
            "dns.query" => {
                handle_dns(
                    &mut tx,
                    e,
                    ts,
                    cfg,
                    prior,
                    live.then_some(statistical_allowed),
                )
                .await?
            }
            "firewall.filterlog" if live => handle_firewall(&mut tx, e, ts, cfg).await?,
            "crowdsec.decision" if live => handle_crowdsec(&mut tx, e, ts).await?,
            _ => {}
        }
    }
    if result.processed > 0 {
        // Retain three days of rollup buckets (24h baseline plus recovery margin).
        // Raw events and detection evidence are never pruned here.
        sqlx::query("DELETE FROM asset_dns_buckets WHERE bucket_start_epoch < ?1")
            .bind(now - 3 * ONE_DAY)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE detection_cursor SET last_row_id=?1,processed_events=processed_events+?2,skipped_events=skipped_events+?3,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE pipeline='default'")
            .bind(last).bind(result.processed as i64).bind(result.skipped as i64)
            .execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(result)
}

pub async fn run_loop(pool: SqlitePool, cfg: DetectionConfig) {
    loop {
        let saturated = match run_batch(&pool, &cfg).await {
            Ok(result) if result.processed > 0 => {
                tracing::info!(
                    processed = result.processed,
                    skipped = result.skipped,
                    "detection batch committed"
                );
                result.processed as i64 >= cfg.batch_size
            }
            Ok(_) => false,
            Err(error) => {
                tracing::warn!(error=%error,"detection batch failed; cursor unchanged");
                false
            }
        };
        if saturated {
            tokio::task::yield_now().await;
        } else {
            tokio::time::sleep(cfg.interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        db::{self, RawRecord},
        normalizer::SecurityEvent,
    };
    use sqlx::sqlite::SqlitePoolOptions;

    fn cfg() -> DetectionConfig {
        DetectionConfig {
            interval: Duration::from_secs(1),
            batch_size: 5,
            firewall_blocks: 4,
            dns_per_min: 5,
            admin_probes: 4,
            outbound_fanout: 3,
            dns_anomaly_min_5min: 40,
            baseline_min_queries: 20,
        }
    }
    async fn pool() -> SqlitePool {
        let p = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&p).await.unwrap();
        p
    }
    fn event(category: &str, src: &str, action: &str, ts: i64) -> SecurityEvent {
        SecurityEvent {
            source: "test".into(),
            event_ts: Some(Timestamp::from_second(ts).unwrap().to_string()),
            category: category.into(),
            action: Some(action.into()),
            source_ip: Some(src.into()),
            destination_ip: Some("192.168.1.10".into()),
            source_port: Some(5555),
            destination_port: Some(443),
            protocol: Some("tcp".into()),
            interface: Some("lan".into()),
            direction: Some("in".into()),
            rule_tracker: None,
            domain: None,
            dns_qtype: None,
            details_json: "{}".into(),
        }
    }
    async fn insert(pool: &SqlitePool, native: &str, event: SecurityEvent) {
        let mut tx = pool.begin().await.unwrap();
        let value = json!({"native":native});
        let rec = RawRecord::polled("test", native.to_owned(), &value, event).unwrap();
        assert!(db::insert_record(&mut tx, rec).await.unwrap());
        tx.commit().await.unwrap();
    }
    async fn drain(p: &SqlitePool, c: &DetectionConfig) {
        loop {
            if run_batch(p, c).await.unwrap().processed == 0 {
                break;
            }
        }
    }
    #[tokio::test]
    async fn blocks_deduplicate_incident_and_replay_cursor() {
        let p = pool().await;
        let now = Timestamp::now().as_second();
        for i in 0..10 {
            insert(
                &p,
                &format!("fw-{i}"),
                event("firewall.filterlog", "203.0.113.10", "block", now),
            )
            .await;
        }
        drain(&p, &cfg()).await;
        let detections: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM detections WHERE rule_id='repeated_firewall_blocks'",
        )
        .fetch_one(&p)
        .await
        .unwrap();
        assert_eq!(detections, 1);
        let count: i64 = sqlx::query_scalar("SELECT detection_count FROM incidents LIMIT 1")
            .fetch_one(&p)
            .await
            .unwrap();
        assert_eq!(count, 1);
        let evidence: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM detection_evidence")
            .fetch_one(&p)
            .await
            .unwrap();
        assert_eq!(evidence, 10);
        assert_eq!(run_batch(&p, &cfg()).await.unwrap().processed, 0);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM detections")
                .fetch_one(&p)
                .await
                .unwrap(),
            1
        );
    }
    #[tokio::test]
    async fn crowdsec_cross_source_is_observation_not_compromise() {
        let p = pool().await;
        let now = Timestamp::now().as_second();
        insert(
            &p,
            "block",
            event("firewall.filterlog", "203.0.113.22", "block", now - 10),
        )
        .await;
        insert(
            &p,
            "decision",
            event("crowdsec.decision", "203.0.113.22", "observed", now),
        )
        .await;
        drain(&p, &cfg()).await;
        let result:(String,String)=sqlx::query_as("SELECT classification,explanation FROM detections WHERE rule_id='crowdsec_firewall_correlation'")
            .fetch_one(&p).await.unwrap();
        assert_eq!(result.0, "deterministic");
        assert!(result.1.contains("not proof of compromise"));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM detection_evidence")
                .fetch_one(&p)
                .await
                .unwrap(),
            2
        );
    }
    #[tokio::test]
    async fn dns_threshold_and_asset_baseline_materialization() {
        let p = pool().await;
        let now = Timestamp::now().as_second();
        for i in 0..9 {
            let mut e = event("dns.query", "192.168.1.10", "observed", now);
            e.domain = Some(format!("n{i}.example"));
            insert(&p, &format!("dns-{i}"), e).await;
        }
        drain(&p, &cfg()).await;
        let vol: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM detections WHERE rule_id='dns_query_volume'")
                .fetch_one(&p)
                .await
                .unwrap();
        assert_eq!(vol, 1);
        let asset: (i64,) =
            sqlx::query_as("SELECT total_dns_queries FROM assets WHERE asset_key='192.168.1.10'")
                .fetch_one(&p)
                .await
                .unwrap();
        assert_eq!(asset.0, 9);
        let domains: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM asset_domains")
            .fetch_one(&p)
            .await
            .unwrap();
        assert_eq!(domains, 9);
    }
    #[tokio::test]
    async fn failure_rolls_back_assets_and_cursor() {
        let p = pool().await;
        let now = Timestamp::now().as_second();
        let mut e = event("dns.query", "192.168.1.10", "observed", now);
        e.domain = Some("example.com".into());
        insert(&p, "query", e).await;
        sqlx::query("DROP TABLE asset_domains")
            .execute(&p)
            .await
            .unwrap();
        assert!(run_batch(&p, &cfg()).await.is_err());
        let cursor: i64 =
            sqlx::query_scalar("SELECT last_row_id FROM detection_cursor WHERE pipeline='default'")
                .fetch_one(&p)
                .await
                .unwrap();
        let assets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM assets")
            .fetch_one(&p)
            .await
            .unwrap();
        assert_eq!(cursor, 0);
        assert_eq!(assets, 0);
    }
    #[tokio::test]
    async fn old_events_do_not_create_retroactive_alerts() {
        let p = pool().await;
        let ts = Timestamp::now().as_second() - LIVE_WINDOW - 30;
        for i in 0..10 {
            insert(
                &p,
                &format!("old-{i}"),
                event("firewall.filterlog", "203.0.113.30", "block", ts),
            )
            .await;
        }
        drain(&p, &cfg()).await;
        let d: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM detections")
            .fetch_one(&p)
            .await
            .unwrap();
        let skipped: i64 = sqlx::query_scalar(
            "SELECT skipped_events FROM detection_cursor WHERE pipeline='default'",
        )
        .fetch_one(&p)
        .await
        .unwrap();
        assert_eq!(d, 0);
        assert_eq!(skipped, 10);
    }
    #[test]
    fn private_assets_only_and_stable_fingerprints() {
        assert!(private_asset("192.168.1.20"));
        assert!(private_asset("fd00::1"));
        assert!(!private_asset("8.8.8.8"));
        assert!(!private_asset("2001:4860:4860::8888"));
        assert_eq!(
            fingerprint("x", "192.0.2.1", 4),
            fingerprint("x", "192.0.2.1", 4)
        );
        assert_ne!(
            fingerprint("x", "192.0.2.1", 4),
            fingerprint("x", "192.0.2.1", 5)
        );
    }
}
