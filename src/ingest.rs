use crate::{
    db::{self, RawRecord},
    normalizer,
};
use jiff::Timestamp;
use serde_json::Value;
use sqlx::SqlitePool;

pub const MAX_BATCH_EVENTS: usize = 200;
pub const MAX_EVENT_BYTES: usize = 128 * 1024;

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(ToOwned::to_owned)
}

pub fn parse_ndjson(body: &[u8]) -> Result<Vec<RawRecord>, &'static str> {
    let text = std::str::from_utf8(body).map_err(|_| "body must be UTF-8")?;
    let mut result = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if result.len() >= MAX_BATCH_EVENTS {
            return Err("batch event limit exceeded");
        }
        if line.len() > MAX_EVENT_BYTES {
            return Err("event exceeds size limit");
        }
        let event: Value = serde_json::from_str(line).map_err(|_| "malformed event JSON")?;
        if !event.is_object() {
            return Err("events must be JSON objects");
        }
        let event_ts = string_field(&event, "timestamp")
            .and_then(|v| v.parse::<Timestamp>().ok())
            .map(|v| v.to_string());
        let delivery_id = event
            .get("sentinel_delivery_id")
            .map(|value| {
                let raw = value.as_str().ok_or("invalid Vector delivery UUID")?;
                let id = uuid::Uuid::parse_str(raw).map_err(|_| "invalid Vector delivery UUID")?;
                if id.to_string() != raw {
                    return Err("invalid Vector delivery UUID");
                }
                Ok(raw.to_owned())
            })
            .transpose()?;
        let appname = string_field(&event, "appname");
        let message = string_field(&event, "message");
        let parsed = if appname.as_deref() == Some("filterlog") {
            Some(match message.as_deref() {
                Some(line) => normalizer::filterlog(line, event_ts.clone()),
                None => Err("filterlog missing message"),
            })
        } else {
            None
        };
        let (normalized, status, error) = match parsed {
            Some(Ok(event)) => (Some(event), "parsed", None),
            Some(Err(reason)) => (None, "malformed", Some(reason.to_owned())),
            None => (None, "not_applicable", None),
        };
        result.push(RawRecord {
            source: "opnsense-syslog".to_owned(),
            source_native_id: None,
            delivery_id,
            event_ts,
            hostname: string_field(&event, "hostname"),
            appname,
            severity: string_field(&event, "severity"),
            facility: string_field(&event, "facility"),
            message,
            transport_peer_ip: string_field(&event, "source_ip"),
            raw_json: line.to_owned(),
            parse_status: status.to_owned(),
            parse_error: error,
            normalized,
        });
    }
    if result.is_empty() {
        return Err("empty batch");
    }
    Ok(result)
}

pub async fn persist(
    pool: &SqlitePool,
    events: Vec<RawRecord>,
) -> Result<(usize, usize), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let mut inserted = 0;
    let mut duplicates = 0;
    for e in events {
        if db::insert_record(&mut tx, e).await? {
            inserted += 1;
        } else {
            duplicates += 1;
        }
    }
    tx.commit().await?;
    Ok((inserted, duplicates))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replay_id_survives_vector_retries() {
        let batch = b"{\"message\":\"probe\",\"source_ip\":\"192.168.1.1\",\"sentinel_delivery_id\":\"2adcc9e5-8005-4e5e-a3dd-a4b3d784fd8f\"}\n";
        let first = parse_ndjson(batch).unwrap();
        let second = parse_ndjson(batch).unwrap();
        assert_eq!(first[0].delivery_id, second[0].delivery_id);
        assert_eq!(first[0].transport_peer_ip.as_deref(), Some("192.168.1.1"));
    }
    #[test]
    fn bad_filterlog_is_raw_not_fabricated() {
        let rows =
            parse_ndjson(b"{\"appname\":\"filterlog\",\"message\":\"invalid,short\"}\n").unwrap();
        assert!(rows[0].normalized.is_none());
        assert_eq!(rows[0].parse_status, "malformed");
    }
    #[test]
    fn rejects_invalid_batch() {
        assert!(parse_ndjson(b"{\"message\":\"ok\"}\nmalformed\n").is_err());
        assert!(parse_ndjson(b"[]\n").is_err());
        assert!(parse_ndjson(b" \n").is_err());
    }
}
