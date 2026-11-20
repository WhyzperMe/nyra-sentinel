#!/usr/bin/env bash
# One-time maintainer command. Never fabricate Cargo.lock from registry metadata.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
command -v cargo >/dev/null || { echo 'Rust/Cargo required: https://rustup.rs' >&2; exit 1; }
if [[ -f Cargo.lock ]]; then
  echo 'Cargo.lock already exists. Review/update it explicitly.' >&2
  exit 1
fi
cargo generate-lockfile
cargo fmt --all
cargo metadata --locked --format-version 1 >/dev/null
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
printf '%s\n' 'Lockfile resolved and local checks passed. Review diff, commit Cargo.lock, push and confirm CI.'
