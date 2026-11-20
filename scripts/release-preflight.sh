#!/usr/bin/env bash
# Release gate: must be executed on a host with Rust and Docker, not simulated.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
for binary in cargo python3 docker node; do
  command -v "$binary" >/dev/null || { echo "Required executable missing: $binary" >&2; exit 1; }
done
[[ -f Cargo.lock ]] || { echo 'Cargo.lock missing. Run cargo generate-lockfile, review and commit it.' >&2; exit 1; }
cargo fmt --all -- --check
cargo metadata --locked --format-version 1 >/dev/null
cargo check --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked --release --bins
cargo audit
bash scripts/verify-offline.sh
docker compose --env-file .env.example config --quiet
docker build -t nyra-sentinel:release-candidate .
echo 'Local static and build checks passed. Live OPNsense/Ollama tests and secure production review still required.'
