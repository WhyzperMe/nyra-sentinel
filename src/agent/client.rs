use reqwest::{Client, Url};
use serde_json::{json, Value};
use std::{env, fs, time::Duration};

pub struct AgentConfig {
    api: Url,
    ollama: Url,
    read_token: String,
    report_token: String,
    model: String,
}
pub struct AgentClient {
    http: Client,
    config: AgentConfig,
    pub model: String,
}
fn secret(var: &str) -> Result<String, String> {
    let path = env::var(var).map_err(|_| format!("{var} missing"))?;
    let content = fs::read_to_string(path).map_err(|_| format!("{var} file not readable"))?;
    let value = content.trim_end_matches(['\r', '\n']).to_owned();
    if value.len() < 32 || value.len() > 256 || value.chars().any(char::is_whitespace) {
        return Err(format!("{var} invalid"));
    }
    Ok(value)
}
fn origin(key: &str, default: &str) -> Result<Url, String> {
    let raw = env::var(key).unwrap_or_else(|_| default.into());
    let url = Url::parse(&raw).map_err(|_| format!("{key} invalid"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
        || url.path() != "/"
    {
        return Err(format!("{key} must be a plain HTTP(S) origin ending in /"));
    }
    // Plain HTTP is only allowed for private container/loopback endpoints. HTTPS required otherwise.
    if url.scheme() == "http" {
        let host = url.host_str().unwrap_or("");
        let loopback_or_service = matches!(
            host,
            "sentinel" | "ollama" | "localhost" | "127.0.0.1" | "::1" | "host.docker.internal"
        ) || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
        let private_lan = host.parse::<std::net::IpAddr>().is_ok_and(|ip| match ip {
            std::net::IpAddr::V4(v) => v.is_private(),
            std::net::IpAddr::V6(v) => (v.segments()[0] & 0xfe00) == 0xfc00,
        });
        let explicit_exception = key == "SENTINEL_OLLAMA_URL"
            && env::var("SENTINEL_ALLOW_HTTP_MODEL").is_ok_and(|v| v == "true")
            && private_lan;
        if !loopback_or_service && !explicit_exception {
            return Err(format!("{key} requires HTTPS unless localhost/service DNS or explicitly approved private model HTTP"));
        }
    }
    Ok(url)
}
impl AgentConfig {
    pub fn load() -> Result<Self, String> {
        let read_token = secret("SENTINEL_HARNESS_READ_TOKEN_FILE")?;
        let report_token = secret("SENTINEL_HARNESS_REPORT_TOKEN_FILE")?;
        if read_token == report_token {
            return Err("read and report tokens must differ".into());
        }
        let model = env::var("SENTINEL_LLM_MODEL").unwrap_or_else(|_| "qwen3:4b".into());
        if model.is_empty()
            || model.len() > 128
            || !model
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
        {
            return Err("invalid Ollama model name".into());
        }
        Ok(Self {
            api: origin("SENTINEL_API_URL", "http://sentinel:8080/")?,
            ollama: origin("SENTINEL_OLLAMA_URL", "http://ollama:11434/")?,
            read_token,
            report_token,
            model,
        })
    }
}
impl AgentClient {
    pub fn new(config: AgentConfig) -> Result<Self, String> {
        let mut builder = Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(120))
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(2)
            .user_agent("NYRA-Sentinel/0.6-Agent");
        if let Ok(path) = env::var("SENTINEL_OLLAMA_CA_FILE") {
            if !path.is_empty() {
                let pem = fs::read(path).map_err(|_| "custom model CA file unreadable")?;
                let cert =
                    reqwest::Certificate::from_pem(&pem).map_err(|_| "invalid model CA PEM")?;
                builder = builder.add_root_certificate(cert);
            }
        }
        let http = builder
            .build()
            .map_err(|e| format!("client initialization failed: {e}"))?;
        Ok(Self {
            model: config.model.clone(),
            http,
            config,
        })
    }
    async fn json_response(
        &self,
        req: reqwest::RequestBuilder,
        max: usize,
    ) -> Result<Value, String> {
        let mut response = req
            .send()
            .await
            .map_err(|e| format!("upstream request failed: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("upstream returned {}", response.status()));
        }
        let mut data = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "upstream stream failed")?
        {
            if data.len().saturating_add(chunk.len()) > max {
                return Err("upstream response budget exceeded".into());
            }
            data.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&data).map_err(|_| "upstream returned invalid JSON".into())
    }
    pub async fn query_tool(&self, trace: &str, tool: &str, args: Value) -> Result<Value, String> {
        let url = self
            .config
            .api
            .join("api/v1/harness/query")
            .map_err(|_| "bad API path")?;
        self.json_response(
            self.http
                .post(url)
                .bearer_auth(&self.config.read_token)
                .json(&json!({"trace_id":trace,"tool":tool,"arguments":args})),
            48 * 1024 + 2048,
        )
        .await
    }
    pub async fn save_report(&self, report: &Value) -> Result<Value, String> {
        let url = self
            .config
            .api
            .join("api/v1/harness/reports")
            .map_err(|_| "bad report path")?;
        self.json_response(
            self.http
                .post(url)
                .bearer_auth(&self.config.report_token)
                .json(report),
            128 * 1024,
        )
        .await
    }
    pub async fn chat(&self, messages: &[Value], tools: &Value) -> Result<Value, String> {
        let url = self
            .config
            .ollama
            .join("api/chat")
            .map_err(|_| "bad model endpoint")?;
        self.json_response(self.http.post(url).json(&json!({"model":self.model,"messages":messages,
            "tools":tools,"stream":false,"options":{"temperature":0.1,"num_predict":1200,"num_ctx":8192}})),256*1024).await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_local_http_or_public_tls() {
        std::env::set_var("SENTINEL_API_URL", "http://public.example/");
        assert!(origin("SENTINEL_API_URL", "http://sentinel:8080/").is_err());
        std::env::set_var("SENTINEL_API_URL", "http://sentinel:8080/");
        assert!(origin("SENTINEL_API_URL", "http://sentinel:8080/").is_ok());
        std::env::remove_var("SENTINEL_API_URL");
    }
}
