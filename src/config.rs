use std::{env, fs, path::PathBuf, time::Duration};

#[derive(Clone)]
pub struct Config {
    pub database_path: PathBuf,
    pub api_token: String,
    pub ingest_token: String,
    pub harness_read_token: Option<String>,
    pub harness_report_token: Option<String>,
    pub response_approval_token: Option<String>,
    pub response_executor_token: Option<String>,
    pub adguard: Option<AdguardConfig>,
    pub crowdsec: Option<CrowdsecConfig>,
    pub detection: crate::detection::DetectionConfig,
}
#[derive(Clone)]
pub struct AdguardConfig {
    pub url: reqwest::Url,
    pub username: String,
    pub password: String,
    pub ca_file: Option<PathBuf>,
    pub interval: Duration,
    pub page_limit: usize,
    pub max_pages: usize,
    pub initial_lookback_minutes: i64,
}
#[derive(Clone)]
pub struct CrowdsecConfig {
    pub url: reqwest::Url,
    pub api_key: String,
    pub ca_file: Option<PathBuf>,
    pub interval: Duration,
    pub max_decisions: usize,
}

fn required(key: &str) -> Result<String, String> {
    let value = env::var(key).map_err(|_| format!("{key} is required"))?;
    if value.trim().is_empty() {
        return Err(format!("{key} cannot be empty"));
    }
    Ok(value)
}
fn enabled(key: &str) -> Result<bool, String> {
    match env::var(key)
        .unwrap_or_else(|_| "false".to_owned())
        .to_ascii_lowercase()
        .as_str()
    {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(format!("{key} must be true or false")),
    }
}
fn range(key: &str, default: u64, min: u64, max: u64) -> Result<u64, String> {
    let v = match env::var(key) {
        Ok(s) => s
            .parse::<u64>()
            .map_err(|_| format!("{key} must be numeric"))?,
        Err(_) => default,
    };
    if !(min..=max).contains(&v) {
        return Err(format!("{key} out of supported range"));
    }
    Ok(v)
}
fn endpoint(key: &str, allow_http: bool) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(&required(key)?).map_err(|_| format!("{key} invalid URL"))?;
    let scheme = url.scheme();
    if scheme != "https" && !(allow_http && scheme == "http") {
        return Err(format!(
            "{key} requires HTTPS (or explicit insecure HTTP opt-in)"
        ));
    }
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().ends_with('/')
    {
        return Err(format!(
            "{key} must be an origin/prefix URL ending with / and no credentials/query"
        ));
    }
    Ok(url)
}
fn secret_file(key: &str) -> Result<String, String> {
    let path = required(key)?;
    let meta = fs::metadata(&path).map_err(|_| format!("{key}: secret file unavailable"))?;
    if !meta.is_file() || meta.len() > 4096 || meta.len() == 0 {
        return Err(format!("{key}: bad secret file"));
    }
    let content =
        fs::read_to_string(&path).map_err(|_| format!("{key}: cannot read secret file"))?;
    let content = content.trim_end_matches(['\r', '\n']).to_owned();
    if content.len() < 8 || content.chars().any(char::is_control) {
        return Err(format!("{key}: malformed secret"));
    }
    Ok(content)
}
// The *_FILE path is the supported production interface; env fallback preserves older
// non-Compose deployments until the operator migrates their secrets explicitly.
fn required_token(key: &str) -> Result<String, String> {
    let file_key = format!("{key}_FILE");
    let file_set = env::var_os(&file_key).is_some_and(|v| !v.is_empty());
    let env_set = env::var_os(key).is_some_and(|v| !v.is_empty());
    if file_set && env_set {
        return Err(format!("set only {file_key}, not both token sources"));
    }
    let value = if file_set {
        secret_file(&file_key)?
    } else {
        required(key)?
    };
    validate_token(key, &value)?;
    Ok(value)
}
fn optional_secret_file(key: &str) -> Result<Option<String>, String> {
    if env::var_os(key).is_none_or(|s| s.is_empty()) {
        return Ok(None);
    }
    let token = secret_file(key)?;
    validate_token(key, &token)?;
    Ok(Some(token))
}
fn validate_token(key: &str, token: &str) -> Result<(), String> {
    if !(32..=256).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!(
            "{key}: expected 32 to 256 printable ASCII characters without whitespace"
        ));
    }
    Ok(())
}
fn ca_file(key: &str) -> Option<PathBuf> {
    env::var_os(key)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}
impl Config {
    pub fn from_env() -> Result<Self, String> {
        let database_path = env::var("SENTINEL_DB_PATH")
            .unwrap_or_else(|_| "/var/lib/sentinel/sentinel.sqlite".to_owned())
            .into();
        let api_token = required_token("SENTINEL_API_TOKEN")?;
        let ingest_token = required_token("SENTINEL_INGEST_TOKEN")?;
        let allow_http = enabled("SENTINEL_ALLOW_HTTP_UPSTREAMS")?;
        let adguard = if enabled("SENTINEL_ADGUARD_ENABLED")? {
            Some(AdguardConfig {
                url: endpoint("SENTINEL_ADGUARD_URL", allow_http)?,
                username: required("SENTINEL_ADGUARD_USERNAME")?,
                password: secret_file("SENTINEL_ADGUARD_PASSWORD_FILE")?,
                ca_file: ca_file("SENTINEL_ADGUARD_CA_FILE"),
                interval: Duration::from_secs(range("SENTINEL_ADGUARD_POLL_SECS", 30, 10, 3600)?),
                page_limit: range("SENTINEL_ADGUARD_PAGE_LIMIT", 200, 10, 500)? as usize,
                max_pages: range("SENTINEL_ADGUARD_MAX_PAGES", 15, 1, 100)? as usize,
                initial_lookback_minutes: range(
                    "SENTINEL_ADGUARD_INITIAL_LOOKBACK_MINS",
                    15,
                    1,
                    10080,
                )? as i64,
            })
        } else {
            None
        };
        let crowdsec = if enabled("SENTINEL_CROWDSEC_ENABLED")? {
            Some(CrowdsecConfig {
                url: endpoint("SENTINEL_CROWDSEC_URL", allow_http)?,
                api_key: secret_file("SENTINEL_CROWDSEC_API_KEY_FILE")?,
                ca_file: ca_file("SENTINEL_CROWDSEC_CA_FILE"),
                interval: Duration::from_secs(range("SENTINEL_CROWDSEC_POLL_SECS", 30, 10, 3600)?),
                max_decisions: range("SENTINEL_CROWDSEC_MAX_DECISIONS", 3000, 10, 10000)? as usize,
            })
        } else {
            None
        };
        let harness_read_token = optional_secret_file("SENTINEL_HARNESS_READ_TOKEN_FILE")?;
        let harness_report_token = optional_secret_file("SENTINEL_HARNESS_REPORT_TOKEN_FILE")?;
        let response_approval_token =
            optional_secret_file("SENTINEL_RESPONSE_APPROVAL_TOKEN_FILE")?;
        let response_executor_token =
            optional_secret_file("SENTINEL_RESPONSE_EXECUTOR_TOKEN_FILE")?;
        let all_tokens = [
            Some(api_token.as_str()),
            Some(ingest_token.as_str()),
            harness_read_token.as_deref(),
            harness_report_token.as_deref(),
            response_approval_token.as_deref(),
            response_executor_token.as_deref(),
        ];
        for (i, left) in all_tokens.iter().enumerate() {
            if let Some(a) = left {
                for b in all_tokens.iter().skip(i + 1).flatten() {
                    if a == b {
                        return Err("all authentication tokens must be distinct".into());
                    }
                }
            }
        }
        let detection = crate::detection::DetectionConfig {
            interval: Duration::from_secs(range("SENTINEL_DETECTION_INTERVAL_SECS", 5, 1, 300)?),
            batch_size: range("SENTINEL_DETECTION_BATCH_SIZE", 150, 1, 500)? as i64,
            firewall_blocks: range("SENTINEL_RULE_FIREWALL_BLOCKS", 12, 2, 1000)? as i64,
            dns_per_min: range("SENTINEL_RULE_DNS_PER_MIN", 120, 5, 10000)? as i64,
            admin_probes: range("SENTINEL_RULE_ADMIN_PROBES", 5, 2, 1000)? as i64,
            outbound_fanout: range("SENTINEL_RULE_OUTBOUND_FANOUT", 25, 2, 128)? as i64,
            dns_anomaly_min_5min: range("SENTINEL_RULE_DNS_ANOMALY_MIN", 40, 10, 10000)? as i64,
            baseline_min_queries: range("SENTINEL_BASELINE_MIN_QUERIES", 200, 20, 10000)? as i64,
        };
        Ok(Self {
            database_path,
            api_token,
            ingest_token,
            harness_read_token,
            harness_report_token,
            response_approval_token,
            response_executor_token,
            adguard,
            crowdsec,
            detection,
        })
    }
}
