# Phase 4 implementation validation record — 2026-11-20

## Successfully executed in the authoring environment

- Python SQLite upgrade path: all four migrations, foreign keys, audit/report
  consistency, unique trace IDs and existing Phase 2/3 replay scenarios.
- YAML and TOML structural validation (Compose, Vector, Cargo, workflows).
- Shell `bash -n` syntax checks for `scripts/*.sh`.
- ZIP integrity checks and SHA-256 file inventory (on final packaging).

## Not tested here — must be completed by CI or target Debian host

- `cargo fmt`, Clippy, unit/integration tests, release compilation of both Rust binaries.
- Real Docker Engine / Compose configuration and multi-service deployment.
- Real OPNsense remote mTLS and parser behavior, AdGuard/CrowdSec API credentials.
- Ollama model tool-calling success and adversarial prompt-injection tests.
- Security performance, fault injection, token rotation, retention, backup restore.

The project is therefore an **implementation candidate**, not a production-ready verified
release. The GitHub Actions workflow is provided but has **not yet been run** in a repository.
A reviewed, committed `Cargo.lock` is required before reproducible release tagging.

## Release gate checklist

1. Generate/commit `Cargo.lock`, run strict Rust checks and fix all warnings.
2. Run GitHub CI on both a push and a PR from a fork (no secrets exposed).
3. Build and run Compose on a clean Debian VM; check both binaries.
4. Exercise `--no-llm`, mock Ollama tool calls, tool denial, real model tool calls,
   and event evidence IDs, plus report persistence after reboot.
5. Verify failed model cannot stop collection, and revoked scoped tokens are denied.
6. Verify bounded queries under load, persisted audits, backups, restore and log rotation.
7. Have a second reviewer inspect authentication, privacy, token permissions and migrations.
