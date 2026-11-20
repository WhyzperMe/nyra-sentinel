//! Separate, simulation-only response gateway. Does not contain firewall drivers.
use reqwest::Url;
use serde_json::json;
use std::{env, fs, time::Duration};
use uuid::Uuid;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("sentinel-respond: {e}");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() == 1 && args[0] == "--help" {
        println!("Usage: sentinel-respond <simulate|rollback> <proposal-UUID> <actor-id>\nSimulation only. No firewall mutations. Uses scoped SENTINEL_RESPONSE_EXECUTOR_TOKEN_FILE.");
        return Ok(());
    }
    if args.len() != 3
        || !matches!(args[0].as_str(), "simulate" | "rollback")
        || Uuid::parse_str(&args[1]).is_err()
        || !(3..=64).contains(&args[2].len())
        || !args[2]
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
    {
        return Err(
            "usage: sentinel-respond <simulate|rollback> <proposal-UUID> <actor-id>".into(),
        );
    }
    let token_path = env::var("SENTINEL_RESPONSE_EXECUTOR_TOKEN_FILE")
        .map_err(|_| "scoped gateway token file missing")?;
    let token = fs::read_to_string(token_path).map_err(|_| "gateway credential file unreadable")?;
    let token = token.trim();
    if !(32..=256).contains(&token.len()) || !token.bytes().all(|c| c.is_ascii_graphic()) {
        return Err("gateway token invalid".into());
    }
    let raw = env::var("SENTINEL_API_URL").unwrap_or_else(|_| "http://sentinel:8080/".into());
    let base = Url::parse(&raw).map_err(|_| "invalid API base URL")?;
    if base.path() != "/"
        || base.query().is_some()
        || base.fragment().is_some()
        || !base.username().is_empty()
        || base.password().is_some()
        || !(base.scheme() == "https"
            || (base.scheme() == "http"
                && matches!(
                    base.host_str(),
                    Some("sentinel" | "localhost" | "127.0.0.1")
                )))
    {
        return Err("gateway requires HTTPS or internal service DNS".into());
    }
    let confirm = format!("{} {}", args[0].to_uppercase(), args[1]);
    let route = format!("api/v1/response/proposals/{}/{}", args[1], args[0]);
    let endpoint = base.join(&route).map_err(|_| "invalid gateway API route")?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "cannot create HTTP client")?;
    let mut resp = client
        .post(endpoint)
        .bearer_auth(token)
        .json(&json!({"actor":args[2],"confirm":confirm}))
        .send()
        .await
        .map_err(|_| "gateway request failed")?;
    let code = resp.status();
    if !code.is_success() {
        return Err(format!("gateway denied request: HTTP {code}"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|_| "gateway response unavailable")?
    {
        if bytes.len() + chunk.len() > 4096 {
            return Err("gateway response too large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let payload = std::str::from_utf8(&bytes).map_err(|_| "invalid gateway response encoding")?;
    println!("{payload}");
    Ok(())
}
