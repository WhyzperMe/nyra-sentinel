//! Starts a real sentinel-server binary on loopback using a temporary SQLite DB.
//! No Docker, OPNsense or internet access required.
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection};
use sqlx::Connection;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const ROLES: [(&str, char); 6] = [
    ("API", 'a'),
    ("INGEST", 'b'),
    ("HARNESS_READ", 'c'),
    ("HARNESS_REPORT", 'd'),
    ("RESPONSE_APPROVAL", 'e'),
    ("RESPONSE_EXECUTOR", 'f'),
];

struct Cleanup(Child, std::path::PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}
fn request(port: u16, path: &str, token: Option<&str>) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let auth = token.map_or_else(String::new, |t| format!("Authorization: Bearer {t}\r\n"));
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{auth}Connection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut result = String::new();
    stream.read_to_string(&mut result).unwrap();
    result
}
#[test]
fn live_health_auth_metrics_and_recovery() {
    let port = {
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap().port()
    };
    let base = std::env::temp_dir().join(format!("nyra-e2e-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&base).unwrap();
    let db = base.join("sentinel.sqlite");
    let api_token = "a".repeat(64);
    let ingest_token = "b".repeat(64);
    let child = Command::new(env!("CARGO_BIN_EXE_sentinel-server"))
        .env("SENTINEL_DB_PATH", &db)
        .env("SENTINEL_API_TOKEN", &api_token)
        .env("SENTINEL_INGEST_TOKEN", &ingest_token)
        .env("SENTINEL_BIND_ADDR", format!("127.0.0.1:{port}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _server = Cleanup(child, base);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "server failed to start");
        thread::sleep(Duration::from_millis(100));
    }
    assert!(request(port, "/api/v1/health", None).starts_with("HTTP/1.1 200"));
    let ui = request(port, "/ui", None);
    assert!(ui.starts_with("HTTP/1.1 200"));
    assert!(ui.contains("content-security-policy"));
    assert!(ui.contains("NYRA Sentinel"));
    assert!(request(port, "/api/v1/response/proposals", None).starts_with("HTTP/1.1 401"));
    assert!(
        request(port, "/api/v1/response/proposals", Some(&api_token)).starts_with("HTTP/1.1 200")
    );
    assert!(request(port, "/api/v1/events", None).starts_with("HTTP/1.1 401"));
    assert!(request(port, "/api/v1/events", Some(&api_token)).starts_with("HTTP/1.1 200"));
    assert!(request(port, "/api/v1/metrics", None).starts_with("HTTP/1.1 401"));
    let metrics = request(port, "/api/v1/metrics", Some(&api_token));
    assert!(metrics.starts_with("HTTP/1.1 200"));
    assert!(metrics.contains("sentinel_raw_events 0"));
}

async fn start_scoped_server() -> (Cleanup, Client, String) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let base = std::env::temp_dir().join(format!("nyra-roles-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&base).unwrap();
    let mut process = Command::new(env!("CARGO_BIN_EXE_sentinel-server"));
    process
        .env_clear()
        .env("SENTINEL_DB_PATH", base.join("sentinel.sqlite"))
        .env("SENTINEL_BIND_ADDR", addr.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    for (role, value) in ROLES {
        let file = base.join(role);
        std::fs::write(&file, value.to_string().repeat(64)).unwrap();
        process.env(format!("SENTINEL_{role}_TOKEN_FILE"), file);
    }
    let guard = Cleanup(process.spawn().unwrap(), base);
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap();
    let base_url = format!("http://{addr}");
    let deadline = Instant::now() + Duration::from_secs(15);
    while !client
        .get(format!("{base_url}/api/v1/health"))
        .send()
        .await
        .is_ok_and(|r| r.status() == 200)
    {
        assert!(Instant::now() < deadline, "server failed to start");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    (guard, client, base_url)
}

async fn post(client: &Client, url: &str, token: char, body: &Value) -> reqwest::Response {
    client
        .post(url)
        .bearer_auth(token.to_string().repeat(64))
        .json(body)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn scoped_mutations_evidence_and_transactional_audit() {
    let (server, client, base) = start_scoped_server().await;
    let ingest_url = format!("{base}/internal/v1/ingest");
    let oversized = client
        .post(&ingest_url)
        .bearer_auth("b".repeat(64))
        .body(vec![b'x'; 512 * 1024 + 1])
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(oversized.json::<Value>().await.unwrap()["error"].is_string());

    let timestamp = jiff::Timestamp::now().to_string();
    let synthetic = |ip: &str| {
        json!({"appname":"filterlog","timestamp":timestamp,
        "message":format!("85,,,rule,igb0,match,block,in,4,0x0,,63,11771,0,DF,6,tcp,60,{ip},192.168.1.10,43802,443")})
    };
    let batch = format!("{}\n{}\n", synthetic("8.8.8.8"), synthetic("1.1.1.1"));
    let ingest = client
        .post(ingest_url)
        .bearer_auth("b".repeat(64))
        .body(batch)
        .send()
        .await
        .unwrap();
    assert_eq!(ingest.status(), StatusCode::OK);
    let events: Value = client
        .get(format!("{base}/api/v1/security-events"))
        .bearer_auth("a".repeat(64))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let event = events["events"][1]["event_id"].as_str().unwrap();
    let other = events["events"][0]["event_id"].as_str().unwrap();
    let harness = format!("{base}/api/v1/harness");
    let trace = uuid::Uuid::new_v4();
    let query = json!({"trace_id":trace,"tool":"get_ip_history","arguments":{"ip":"8.8.8.8"}});
    assert_eq!(
        post(&client, &format!("{harness}/query"), 'd', &query)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post(&client, &format!("{harness}/query"), 'c', &query)
            .await
            .status(),
        StatusCode::OK
    );
    let mut report = json!({"trace_id":trace,"subject_kind":"ip","subject_value":"8.8.8.8",
        "model":"test","status":"hypothesis","summary":format!("Observed {event}. Fake reference {other}."),
        "evidence_ids":[other],"tool_calls":1});
    assert_eq!(
        post(&client, &format!("{harness}/reports"), 'd', &report)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    report["evidence_ids"] = json!([event]);
    let stored = post(&client, &format!("{harness}/reports"), 'd', &report).await;
    assert_eq!(stored.status(), StatusCode::CREATED);
    let stored = stored.json::<Value>().await.unwrap();
    assert!(!stored["summary"].as_str().unwrap().contains(other));
    assert!(stored["summary"].as_str().unwrap().contains(event));
    assert_eq!(
        post(&client, &format!("{harness}/reports"), 'd', &report)
            .await
            .status(),
        StatusCode::CONFLICT
    );

    let proposals = format!("{base}/api/v1/response/proposals");
    let mut proposal = json!({"target_ip":"8.8.8.8","evidence_event_id":event,"duration_minutes":15,
        "requester":"test-operator","justification":"Synthetic evidence for transition tests."});
    assert_eq!(
        post(&client, &proposals, 'c', &proposal).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let created = post(&client, &proposals, 'a', &proposal).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = created.json::<Value>().await.unwrap();
    let id = created["id"].as_str().unwrap();
    let approve = format!("{proposals}/{id}/approve");
    let simulate = format!("{proposals}/{id}/simulate");
    let mut decision = json!({"actor":"test-operator","reason":"Synthetic approval reason","confirm":format!("APPROVED {id}")});
    let simulation = json!({"actor":"test-executor","confirm":format!("SIMULATE {id}")});
    assert_eq!(
        post(&client, &approve, 'a', &decision).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post(&client, &approve, 'e', &decision).await.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        post(&client, &simulate, 'f', &simulation).await.status(),
        StatusCode::CONFLICT
    );
    decision["actor"] = json!("test-approver");
    let mut db = SqliteConnection::connect_with(
        &SqliteConnectOptions::new().filename(server.1.join("sentinel.sqlite")),
    )
    .await
    .unwrap();
    sqlx::query("CREATE TRIGGER reject_approval_audit BEFORE INSERT ON response_audit WHEN NEW.transition='approved' BEGIN SELECT RAISE(ABORT,'test'); END").execute(&mut db).await.unwrap();
    assert_eq!(
        post(&client, &approve, 'e', &decision).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT status FROM response_proposals WHERE id=?")
            .bind(id)
            .fetch_one(&mut db)
            .await
            .unwrap(),
        "proposed"
    );
    sqlx::query("DROP TRIGGER reject_approval_audit")
        .execute(&mut db)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        post(&client, &approve, 'e', &decision),
        post(&client, &approve, 'e', &decision)
    );
    assert!(matches!(
        (a.status(), b.status()),
        (StatusCode::OK, StatusCode::CONFLICT) | (StatusCode::CONFLICT, StatusCode::OK)
    ));
    assert_eq!(
        post(&client, &simulate, 'e', &simulation).await.status(),
        StatusCode::UNAUTHORIZED
    );
    sqlx::query("UPDATE response_proposals SET valid_until_epoch=unixepoch()-1 WHERE id=?")
        .bind(id)
        .execute(&mut db)
        .await
        .unwrap();
    assert_eq!(
        post(&client, &simulate, 'f', &simulation).await.status(),
        StatusCode::CONFLICT
    );

    proposal["target_ip"] = json!("1.1.1.1");
    proposal["evidence_event_id"] = json!(other);
    let created = post(&client, &proposals, 'a', &proposal)
        .await
        .json::<Value>()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap();
    decision["confirm"] = json!(format!("REJECTED {id}"));
    assert_eq!(
        post(&client, &format!("{proposals}/{id}/reject"), 'e', &decision)
            .await
            .status(),
        StatusCode::OK
    );
    let roles: Vec<String> =
        sqlx::query_scalar("SELECT credential_role FROM response_audit ORDER BY row_id")
            .fetch_all(&mut db)
            .await
            .unwrap();
    assert_eq!(roles, ["operator", "approver", "operator", "approver"]);
}
