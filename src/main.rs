mod api;
mod config;
mod db;
mod detection;
mod detection_api;
mod harness_api;
mod ingest;
mod normalizer;
mod pollers;
mod response_api;
mod ui;

use std::{
    error::Error,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
type AnyError = Box<dyn Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        return check_health();
    }
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let shutdown = async move {
        #[cfg(unix)]
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
        #[cfg(not(unix))]
        tokio::signal::ctrl_c().await
    };
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let config = config::Config::from_env()?;
    let listener = TcpListener::bind(bind_addr()?).await?;
    let addr = listener.local_addr()?;
    let pool = db::connect(&config.database_path).await?;
    let mut workers = tokio::task::JoinSet::new();
    if let Some(adguard) = config.adguard.clone() {
        let client = pollers::client(adguard.ca_file.as_deref())?;
        let query_pool = pool.clone();
        let status_pool = pool.clone();
        let interval = adguard.interval;
        workers.spawn(async move {
            pollers::run_loop(status_pool, "adguard-querylog", interval, move || {
                let pool = query_pool.clone();
                let client = client.clone();
                let cfg = adguard.clone();
                async move { pollers::adguard::poll(&pool, &client, &cfg).await }
            })
            .await;
        });
    }
    if let Some(crowdsec) = config.crowdsec.clone() {
        let client = pollers::client(crowdsec.ca_file.as_deref())?;
        let query_pool = pool.clone();
        let status_pool = pool.clone();
        let interval = crowdsec.interval;
        workers.spawn(async move {
            pollers::run_loop(status_pool, "crowdsec-decision", interval, move || {
                let pool = query_pool.clone();
                let client = client.clone();
                let cfg = crowdsec.clone();
                async move { pollers::crowdsec::poll(&pool, &client, &cfg).await }
            })
            .await;
        });
    }
    let engine_pool = pool.clone();
    let engine_config = config.detection.clone();
    workers.spawn(async move {
        detection::run_loop(engine_pool, engine_config).await;
    });
    let expiry_pool = pool.clone();
    workers.spawn(async move {
        response_api::run_expiration_loop(expiry_pool).await;
    });
    let state = api::AppState {
        pool: pool.clone(),
        config,
        harness_gate: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
    };
    tracing::info!(%addr, "NYRA Sentinel v0.6 listening");
    let result = axum::serve(listener, api::router(state))
        .with_graceful_shutdown(async {
            if let Err(error) = shutdown.await {
                tracing::error!(%error, "shutdown signal listener failed");
            }
            tracing::info!("draining HTTP requests");
        })
        .await;
    workers.shutdown().await;
    pool.close().await;
    result?;
    Ok(())
}
fn bind_addr() -> Result<SocketAddr, std::net::AddrParseError> {
    std::env::var("SENTINEL_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()
}
fn check_health() -> Result<(), AnyError> {
    let mut addr = bind_addr()?;
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() {
            std::net::Ipv4Addr::LOCALHOST.into()
        } else {
            std::net::Ipv6Addr::LOCALHOST.into()
        });
    }
    let mut socket = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.write_all(
        b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )?;
    let mut status = [0_u8; 13];
    socket.read_exact(&mut status)?;
    if &status != b"HTTP/1.1 200 " {
        return Err("health endpoint did not return 200".into());
    }
    Ok(())
}
