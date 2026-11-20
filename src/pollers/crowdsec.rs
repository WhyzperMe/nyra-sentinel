use super::{json as fetch_json, PollResult};
use crate::{
    config::CrowdsecConfig,
    db::{self, RawRecord},
    normalizer,
};
use reqwest::Client;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::collections::HashSet;
use uuid::Uuid;
const SOURCE: &str = "crowdsec-decision";

fn id_of(value: &Value) -> Result<String, &'static str> {
    match value.get("id") {
        Some(Value::Number(v)) => Ok(v.to_string()),
        Some(Value::String(v)) if !v.is_empty() && v.len() <= 128 => Ok(v.clone()),
        _ => Err("CrowdSec decision missing ID"),
    }
}
fn stable_hash(value: &Value) -> String {
    let relevant = json!({"id":value.get("id"),"scope":value.get("scope"),
        "value":value.get("value"),"type":value.get("type"),"origin":value.get("origin"),
        "scenario":value.get("scenario"),"alert_id":value.get("alert_id")});
    hex::encode(Sha256::digest(relevant.to_string().as_bytes()))
}
fn string(v: &Value, field: &str) -> Option<String> {
    v.get(field).and_then(Value::as_str).map(ToOwned::to_owned)
}

/// Full snapshot each time: no reliance on CrowdSec stream's consumer-dependent delta cursor.
pub async fn poll(
    pool: &SqlitePool,
    client: &Client,
    config: &CrowdsecConfig,
) -> Result<PollResult, &'static str> {
    let observed_at = jiff::Timestamp::now().to_string();
    let endpoint = config
        .url
        .join("v1/decisions/stream?startup=true")
        .map_err(|_| "invalid CrowdSec URL")?;
    let mut payload = fetch_json(
        client
            .get(endpoint)
            .header("X-Api-Key", config.api_key.as_str()),
        4 * 1024 * 1024,
    )
    .await?;
    let rows = match payload.get_mut("new").map(Value::take) {
        Some(Value::Array(rows)) => rows,
        Some(Value::Null) => Vec::new(),
        _ => return Err("CrowdSec response missing valid snapshot"),
    };
    if rows.len() > config.max_decisions {
        return Err("CrowdSec snapshot exceeded configured decision budget");
    }
    let mut ids = HashSet::new();
    let mut prepared = Vec::with_capacity(rows.len());
    for row in rows {
        let id = id_of(&row)?;
        if !ids.insert(id.clone()) {
            return Err("CrowdSec snapshot has duplicate decision IDs");
        }
        let hash = stable_hash(&row);
        prepared.push((id, hash, row));
    }
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| "CrowdSec transaction failed")?;
    let checkpoint: Option<String> =
        sqlx::query_scalar("SELECT cursor FROM ingestion_checkpoints WHERE source=?1")
            .bind(SOURCE)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| "CrowdSec checkpoint read failed")?;
    if let Some(cursor) = checkpoint {
        let stored = cursor
            .parse::<jiff::Timestamp>()
            .map_err(|_| "invalid saved CrowdSec checkpoint")?;
        let observed = observed_at
            .parse::<jiff::Timestamp>()
            .map_err(|_| "invalid CrowdSec poll timestamp")?;
        if stored > observed {
            return Err("another CrowdSec poll advanced the checkpoint");
        }
    }
    let active: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM crowdsec_decisions WHERE active=1 ORDER BY id LIMIT 10001",
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| "CrowdSec state read failed")?;
    if active.len() > 10000 {
        return Err("CrowdSec active state exceeds safe reconciliation budget");
    }
    let mut inserted = 0_i64;
    let mut duplicates = 0_i64;
    for (id, hash, row) in &prepared {
        let previous: Option<(i64, String)> =
            sqlx::query_as("SELECT active,stable_hash FROM crowdsec_decisions WHERE id=?1")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| "CrowdSec state read failed")?;
        let change = match previous {
            None => Some("observed"),
            Some((0, _)) => Some("reactivated"),
            Some((_, prior_hash)) if prior_hash != *hash => Some("changed"),
            _ => None,
        };
        if let Some(state) = change {
            let normalized = normalizer::crowdsec(row, state);
            let native = format!("{}:{}", id, Uuid::new_v4());
            let record = RawRecord::polled(SOURCE, native, row, normalized)
                .map_err(|_| "CrowdSec serialization failed")?;
            if db::insert_record(&mut tx, record)
                .await
                .map_err(|_| "CrowdSec event insert failed")?
            {
                inserted += 1;
            } else {
                duplicates += 1;
            }
        } else {
            duplicates += 1;
        }
        sqlx::query("INSERT INTO crowdsec_decisions (id,active,stable_hash,scope,value,action,scenario,origin,raw_json,first_seen,last_seen,last_changed) \
          VALUES (?1,1,?2,?3,?4,?5,?6,?7,?8,strftime('%Y-%m-%dT%H:%M:%fZ','now'),strftime('%Y-%m-%dT%H:%M:%fZ','now'),strftime('%Y-%m-%dT%H:%M:%fZ','now')) \
          ON CONFLICT(id) DO UPDATE SET active=1,stable_hash=excluded.stable_hash,scope=excluded.scope,value=excluded.value,action=excluded.action,scenario=excluded.scenario,origin=excluded.origin,raw_json=excluded.raw_json,last_seen=excluded.last_seen, \
          last_changed=CASE WHEN crowdsec_decisions.active=0 OR crowdsec_decisions.stable_hash != excluded.stable_hash THEN excluded.last_changed ELSE crowdsec_decisions.last_changed END")
          .bind(id).bind(hash).bind(string(row,"scope")).bind(string(row,"value"))
          .bind(string(row,"type")).bind(string(row,"scenario")).bind(string(row,"origin"))
          .bind(row.to_string()).execute(&mut *tx).await.map_err(|_| "CrowdSec state upsert failed")?;
    }
    for id in &active {
        if ids.contains(id) {
            continue;
        }
        let raw: String = sqlx::query_scalar("SELECT raw_json FROM crowdsec_decisions WHERE id=?1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| "CrowdSec state read failed")?;
        let value: Value =
            serde_json::from_str(&raw).map_err(|_| "stored CrowdSec JSON invalid")?;
        let event = RawRecord::polled(
            SOURCE,
            format!("{}:{}", id, Uuid::new_v4()),
            &value,
            normalizer::crowdsec(&value, "removed"),
        )
        .map_err(|_| "CrowdSec removal serialization failed")?;
        if db::insert_record(&mut tx, event)
            .await
            .map_err(|_| "CrowdSec removal insert failed")?
        {
            inserted += 1;
        }
        sqlx::query("UPDATE crowdsec_decisions SET active=0,last_changed=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?1")
            .bind(id).execute(&mut *tx).await.map_err(|_| "CrowdSec removal state failed")?;
    }
    // Last successfully reconciled snapshot is committed along with transitions.
    db::set_checkpoint(&mut tx, SOURCE, &observed_at)
        .await
        .map_err(|_| "CrowdSec checkpoint write failed")?;
    tx.commit()
        .await
        .map_err(|_| "CrowdSec snapshot commit failed")?;
    Ok(PollResult {
        inserted,
        duplicates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duration_changes_do_not_create_false_transitions() {
        let a = json!({"id":7,"scope":"Ip","value":"8.8.8.8","type":"ban","duration":"8m0s"});
        let b = json!({"id":7,"scope":"Ip","value":"8.8.8.8","type":"ban","duration":"7m0s"});
        assert_eq!(stable_hash(&a), stable_hash(&b));
    }
    #[test]
    fn decision_id_can_be_number_or_text() {
        assert_eq!(id_of(&json!({"id":77})).unwrap(), "77");
        assert!(id_of(&json!({"id":null})).is_err());
    }
    #[tokio::test]
    async fn snapshots_detect_new_unchanged_and_removed() {
        use axum::{extract::State, routing::get, Json, Router};
        use sqlx::sqlite::SqlitePoolOptions;
        use std::sync::{Arc, Mutex};
        let body = Arc::new(Mutex::new(
            json!({"new":[{"id":33,"scope":"Ip","value":"203.0.113.88",
            "type":"ban","scenario":"crowdsecurity/http-probing","duration":"10m"}], "deleted":null}),
        ));
        let app = Router::new()
            .route(
                "/v1/decisions/stream",
                get(|State(value): State<Arc<Mutex<Value>>>| async move {
                    Json(value.lock().unwrap().clone())
                }),
            )
            .with_state(body.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url =
            reqwest::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let cfg = CrowdsecConfig {
            url,
            api_key: "mock-key".into(),
            ca_file: None,
            interval: std::time::Duration::from_secs(30),
            max_decisions: 10,
        };
        let client = Client::new();
        assert_eq!(poll(&pool, &client, &cfg).await.unwrap().inserted, 1);
        assert_eq!(poll(&pool, &client, &cfg).await.unwrap().inserted, 0);
        *body.lock().unwrap() = json!({"deleted":[]});
        assert!(poll(&pool, &client, &cfg).await.is_err());
        assert_eq!(db::decisions(&pool, 10).await.unwrap().len(), 1);
        *body.lock().unwrap() = json!({"new":null,"deleted":[]});
        assert_eq!(poll(&pool, &client, &cfg).await.unwrap().inserted, 1);
        assert!(db::decisions(&pool, 10).await.unwrap().is_empty());
        let events = db::list_security(&pool, Some(SOURCE), None, None, 10)
            .await
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].action.as_deref(), Some("removed"));
        task.abort();
    }
}
