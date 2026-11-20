use super::{json, PollResult};
use crate::{
    config::AdguardConfig,
    db::{self, RawRecord},
    normalizer,
};
use jiff::{SignedDuration, Timestamp};
use reqwest::Client;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::collections::HashMap;
use tokio::time::{timeout_at, Instant};
const SOURCE: &str = "adguard-querylog";
const MAX_PAGE_BYTES: usize = 2 * 1024 * 1024;
const MAX_POLL_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug)]
struct Page {
    entries: Vec<Value>,
    oldest: Option<String>,
}
fn decode(mut v: Value) -> Result<Page, &'static str> {
    let oldest = v
        .get("oldest")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);
    let Some(Value::Array(entries)) = v.get_mut("data").map(Value::take) else {
        return Err("DNS response missing data array");
    };
    Ok(Page { entries, oldest })
}

pub async fn poll(
    pool: &SqlitePool,
    client: &Client,
    config: &AdguardConfig,
) -> Result<PollResult, &'static str> {
    let old_cursor = db::checkpoint(pool, SOURCE)
        .await
        .map_err(|_| "checkpoint read failed")?;
    let threshold = if let Some(ref cursor) = old_cursor {
        cursor
            .parse::<Timestamp>()
            .map_err(|_| "invalid saved DNS cursor")?
    } else {
        Timestamp::now() - SignedDuration::from_mins(config.initial_lookback_minutes)
    };
    // Overlap makes same-timestamp queries and delayed log writes less likely to be missed.
    let cutoff = threshold
        .checked_sub(SignedDuration::from_secs(5))
        .map_err(|_| "invalid saved DNS cursor")?;
    let future_limit = Timestamp::now() + SignedDuration::from_mins(5);
    let mut newest = threshold;
    let mut older_than: Option<(String, Timestamp)> = None;
    let mut records = Vec::new();
    let mut occurrences: HashMap<String, u64> = HashMap::new();
    let mut retained_bytes = 0;
    let mut exhausted = false;
    let deadline = Instant::now() + std::time::Duration::from_secs(30);
    for _ in 0..config.max_pages {
        let mut url = config
            .url
            .join("control/querylog")
            .map_err(|_| "invalid AdGuard URL")?;
        url.query_pairs_mut()
            .append_pair("limit", &config.page_limit.to_string());
        if let Some((ref cursor, _)) = older_than {
            url.query_pairs_mut().append_pair("older_than", cursor);
        }
        let value = timeout_at(
            deadline,
            json(
                client
                    .get(url)
                    .basic_auth(&config.username, Some(&config.password)),
                MAX_PAGE_BYTES,
            ),
        )
        .await
        .map_err(|_| "DNS poll exceeded deadline; checkpoint unchanged")??;
        let page = decode(value)?;
        let count = page.entries.len();
        if count > config.page_limit {
            return Err("upstream exceeded requested DNS page size");
        }
        let mut last_time = None;
        for item in page.entries {
            let raw_time = item
                .get("time")
                .and_then(Value::as_str)
                .ok_or("DNS entry missing timestamp")?;
            let time = raw_time
                .parse::<Timestamp>()
                .map_err(|_| "DNS timestamp malformed")?;
            if time > future_limit {
                return Err("DNS event timestamp exceeds clock skew tolerance");
            }
            if last_time.is_some_and(|last| time > last)
                || older_than
                    .as_ref()
                    .is_some_and(|(_, previous)| time >= *previous)
            {
                return Err("DNS page is not ordered or overlaps the previous page");
            }
            last_time = Some(time);
            newest = newest.max(time);
            if time > cutoff {
                let mut record =
                    RawRecord::polled(SOURCE, String::new(), &item, normalizer::adguard(&item)?)
                        .map_err(|_| "DNS event serialization failed")?;
                retained_bytes += record.raw_json.len();
                if retained_bytes > MAX_POLL_BYTES {
                    return Err("DNS backlog exceeded safe byte budget; checkpoint unchanged");
                }
                let digest = hex::encode(Sha256::digest(record.raw_json.as_bytes()));
                let occurrence = occurrences.entry(digest.clone()).or_default();
                // The first occurrence deliberately keeps the pre-Phase-6 identity.
                record.source_native_id = Some(if *occurrence == 0 {
                    digest
                } else {
                    format!("{digest}:{occurrence}")
                });
                *occurrence += 1;
                records.push(record);
            }
        }
        let Some(next) = page.oldest else {
            exhausted = true;
            break;
        };
        let timestamp = next
            .parse::<Timestamp>()
            .map_err(|_| "invalid DNS pagination cursor")?;
        if timestamp > future_limit
            || last_time.is_some_and(|last| timestamp > last)
            || older_than
                .as_ref()
                .is_some_and(|(_, previous)| timestamp >= *previous)
        {
            return Err("DNS pagination cursor did not advance");
        }
        if timestamp <= cutoff || last_time.is_some_and(|last| last <= cutoff) {
            exhausted = true;
            break;
        }
        older_than = Some((next, timestamp));
    }
    if !exhausted {
        return Err("DNS backlog exceeded safe page budget; checkpoint unchanged");
    }
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| "DNS transaction start failed")?;
    let current: Option<String> =
        sqlx::query_scalar("SELECT cursor FROM ingestion_checkpoints WHERE source=?1")
            .bind(SOURCE)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| "checkpoint read failed")?;
    if current != old_cursor {
        return Err("another DNS poll advanced the checkpoint");
    }
    let mut inserted = 0;
    let mut duplicates = 0;
    for record in records {
        if db::insert_record(&mut tx, record)
            .await
            .map_err(|_| "DNS insert failed")?
        {
            inserted += 1;
        } else {
            duplicates += 1;
        }
    }
    db::set_checkpoint(&mut tx, SOURCE, &newest.to_string())
        .await
        .map_err(|_| "DNS checkpoint write failed")?;
    tx.commit()
        .await
        .map_err(|_| "DNS transaction commit failed")?;
    Ok(PollResult {
        inserted,
        duplicates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn accepts_current_openapi_shape() {
        let page = decode(
            json!({"data": [{"time":"2026-11-20T19:05:00Z"}],"oldest":"2026-11-20T19:05:00Z"}),
        )
        .unwrap();
        assert_eq!(page.entries.len(), 1);
    }
    #[test]
    fn refuses_missing_data() {
        assert!(decode(json!({"oldest": "x"})).is_err());
    }
    #[tokio::test]
    async fn http_polling_commits_checkpoint_and_deduplicates_replay() {
        use axum::{routing::get, Json, Router};
        use sqlx::sqlite::SqlitePoolOptions;
        let timestamp = Timestamp::now().to_string();
        let result = json!({"data": [{"time": timestamp,"client":"192.168.1.10",
            "question":{"name":"example.org.","type":"A"},"reason":"NotFilteredNotFound"}],"oldest":""});
        let app = Router::new().route(
            "/control/querylog",
            get(move || {
                let value = result.clone();
                async move { Json(value) }
            }),
        );
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
        let config = AdguardConfig {
            url,
            username: "demo".into(),
            password: "demo_password".into(),
            ca_file: None,
            interval: std::time::Duration::from_secs(30),
            page_limit: 20,
            max_pages: 2,
            initial_lookback_minutes: 15,
        };
        let client = Client::new();
        let one = poll(&pool, &client, &config).await.unwrap();
        let two = poll(&pool, &client, &config).await.unwrap();
        assert_eq!(one.inserted, 1);
        assert_eq!(two.duplicates, 1);
        assert_eq!(
            db::list_security(&pool, Some(SOURCE), None, None, 10)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(db::checkpoint(&pool, SOURCE).await.unwrap().is_some());
        task.abort();
    }
    #[tokio::test]
    async fn preserves_two_identical_queries_in_one_snapshot() {
        use axum::{routing::get, Json, Router};
        use sqlx::sqlite::SqlitePoolOptions;
        let timestamp = Timestamp::now().to_string();
        let entry = json!({"time": timestamp,"client":"192.168.1.10",
            "question":{"name":"same.example.","type":"A"}});
        let response = json!({"data": [entry.clone(),entry], "oldest":""});
        let app = Router::new().route(
            "/control/querylog",
            get(move || {
                let value = response.clone();
                async move { Json(value) }
            }),
        );
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
        let cfg = AdguardConfig {
            url,
            username: "tester".into(),
            password: "secret".into(),
            ca_file: None,
            interval: std::time::Duration::from_secs(30),
            page_limit: 10,
            max_pages: 2,
            initial_lookback_minutes: 15,
        };
        let client = Client::new();
        let first = poll(&pool, &client, &cfg).await.unwrap();
        let replay = poll(&pool, &client, &cfg).await.unwrap();
        assert_eq!(first.inserted, 2);
        assert_eq!(replay.inserted, 0);
        assert_eq!(replay.duplicates, 2);
        task.abort();
    }
    #[tokio::test]
    async fn follows_older_than_pagination_without_skipping_rows() {
        use axum::{extract::Query, routing::get, Json, Router};
        use sqlx::sqlite::SqlitePoolOptions;
        use std::collections::HashMap;
        let now = Timestamp::now();
        let t0 = now.to_string();
        let t1 = (now - SignedDuration::from_secs(10)).to_string();
        let t2 = (now - SignedDuration::from_secs(20)).to_string();
        let route = Router::new().route("/control/querylog", get(move |Query(q): Query<HashMap<String,String>>| {
            let t0=t0.clone(); let t1=t1.clone(); let t2=t2.clone();
            async move {
                let data = if q.contains_key("older_than") {
                    json!({"data":[{"time":t2,"client":"192.168.1.30","question":{"name":"three.example.","type":"A"}}],"oldest":""})
                } else {
                    json!({"data":[
                        {"time":t0,"client":"192.168.1.10","question":{"name":"one.example.","type":"A"}},
                        {"time":t1.clone(),"client":"192.168.1.20","question":{"name":"two.example.","type":"AAAA"}}],"oldest":t1})
                };
                Json(data)
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url =
            reqwest::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, route).await.unwrap();
        });
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let cfg = AdguardConfig {
            url,
            username: "user".into(),
            password: "password".into(),
            ca_file: None,
            interval: std::time::Duration::from_secs(30),
            page_limit: 2,
            max_pages: 3,
            initial_lookback_minutes: 15,
        };
        let result = poll(&pool, &Client::new(), &cfg).await.unwrap();
        assert_eq!(result.inserted, 3);
        assert_eq!(
            db::list_security(&pool, Some(SOURCE), None, None, 10)
                .await
                .unwrap()
                .len(),
            3
        );
        task.abort();
    }
    #[tokio::test]
    async fn budget_exhaustion_does_not_advance_checkpoint() {
        use axum::{routing::get, Json, Router};
        use sqlx::sqlite::SqlitePoolOptions;
        let time = Timestamp::now().to_string();
        let results: Vec<Value> = (0..10)
            .map(|_| json!({"time":time,"question":{"name":"example.org.","type":"A"}}))
            .collect();
        let response = json!({"data":results,"oldest":time});
        let app = Router::new().route(
            "/control/querylog",
            get(move || {
                let response = response.clone();
                async move { Json(response) }
            }),
        );
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
        let cfg = AdguardConfig {
            url,
            username: "user".into(),
            password: "password".into(),
            ca_file: None,
            interval: std::time::Duration::from_secs(30),
            page_limit: 10,
            max_pages: 1,
            initial_lookback_minutes: 15,
        };
        assert!(poll(&pool, &Client::new(), &cfg).await.is_err());
        assert_eq!(db::checkpoint(&pool, SOURCE).await.unwrap(), None);
        task.abort();
    }
}
