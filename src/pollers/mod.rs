//! Read-only pollers. Each source is optional and never blocks syslog ingestion.
pub mod adguard;
pub mod crowdsec;

use reqwest::{Client, RequestBuilder};
use serde_json::Value;
use sqlx::SqlitePool;
use std::{path::Path, time::Duration};

#[derive(Debug, Clone, Copy)]
pub struct PollResult {
    pub inserted: i64,
    pub duplicates: i64,
}

pub fn client(ca_file: Option<&Path>) -> Result<Client, String> {
    let mut builder = Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(12))
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(2)
        .user_agent("NYRA-Sentinel/0.2 (read-only telemetry)");
    if let Some(path) = ca_file {
        let bytes = std::fs::read(path)
            .map_err(|_| "configured upstream CA file unavailable".to_owned())?;
        let ca = reqwest::Certificate::from_pem(&bytes)
            .map_err(|_| "invalid upstream CA certificate".to_owned())?;
        builder = builder.add_root_certificate(ca);
    }
    builder
        .build()
        .map_err(|_| "HTTP client setup failed".to_owned())
}

/// Protect memory usage independently of HTTP Content-Length and block redirects.
pub async fn json(request: RequestBuilder, max_bytes: usize) -> Result<Value, &'static str> {
    let mut response = request
        .send()
        .await
        .map_err(|_| "upstream connection failed")?;
    if !response.status().is_success() {
        return Err("upstream non-success HTTP status");
    }
    let mut data = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "upstream body read failed")?
    {
        if data.len().saturating_add(chunk.len()) > max_bytes {
            return Err("upstream response too large");
        }
        data.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&data).map_err(|_| "invalid upstream JSON")
}

pub async fn run_loop<F, Fut>(
    pool: SqlitePool,
    source: &'static str,
    interval: Duration,
    mut poll: F,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<PollResult, &'static str>>,
{
    let mut failures = 0_u32;
    loop {
        match poll().await {
            Ok(stats) => {
                failures = 0;
                if let Err(err) = crate::db::mark_source(
                    &pool,
                    source,
                    true,
                    None,
                    stats.inserted,
                    stats.duplicates,
                )
                .await
                {
                    tracing::warn!(source, error = %err, "cannot update source health");
                }
                tracing::info!(
                    source,
                    inserted = stats.inserted,
                    duplicates = stats.duplicates,
                    "poll completed"
                );
            }
            Err(category) => {
                failures = failures.saturating_add(1);
                tracing::warn!(source, category, "poll failed (no cursor advanced)");
                if let Err(err) =
                    crate::db::mark_source(&pool, source, false, Some(category), 0, 0).await
                {
                    tracing::warn!(source, error = %err, "cannot update failed source health");
                }
            }
        }
        let multiplier = 2_u64.saturating_pow(failures.min(4));
        tokio::time::sleep(
            interval
                .saturating_mul(multiplier as u32)
                .min(interval.max(Duration::from_secs(300))),
        )
        .await;
    }
}
