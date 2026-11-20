//! Separate executable with NO database, firewall, shell, or upstream administration access.
#[path = "../agent/mod.rs"]
mod agent;

#[tokio::main]
async fn main() {
    if let Err(err) = agent::run_cli().await {
        eprintln!("sentinel-agent: {err}");
        std::process::exit(1);
    }
}
