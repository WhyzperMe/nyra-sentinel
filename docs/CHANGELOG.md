# Change history

## v0.6.0 hardening revision (2026-11-20)

- Added a resolved Cargo lockfile, patched SQLite, updated Tokio and pinned container bases by digest.
- Fixed the published Vector listener, bounded upstream snapshots, separated historical events from live alerts and corrected CrowdSec decision correlation.
- Preserved audit evidence through retention and protected the old database during offline restore.
- Recorded credential roles separately from response actor handles and strengthened investigation evidence validation.
- Added live HTTP, Compose fault-recovery and Chromium checks.

## v0.6.0 (2026-11-20)

- Added local, accessible, dependency-free SOC dashboard with strict Content Security Policy and no browser token persistence.
- Added Phase-6 response proposal/approval/simulation-only workflow with separate credentials, recent matching-event evidence, actor separation, execution permits, expiry and audit.
- Added sixth SQLite migration with append-only response audit triggers; updated retention to preserve response evidence.
- Moved community policies under `.github/`, legacy validation into `docs/history/`, and consolidated the README/installation guide.
- Added response simulation gateway binary and regression tests.
- Fixed identical AdGuard query entries within one snapshot being collapsed by content-only hashes.
- Added detection-backlog-aware readiness and replaced Vector version-only check with native config validation.
- Fail-closed release gates remain until `Cargo.lock`, Rust and Docker testing are verified.

---

# Changelog

## v0.4.0 — Phase 4 — 2026-11-20 (implementation candidate)

- Added independent Rust `sentinel-agent` binary (bounded Ollama tool-calling workflow).
- Added fixed-schema, scoped read-only harness API and report-only authenticated path.
- Added SQLite audit and unverified investigation report migration.
- Added strict argument validation, query/result budgets, event reference checks.
- Docker Compose optional agent and model profiles; scoped secret-file bootstrap/upgrade.
- Whyzper.Me branding, MIT OR Apache-2.0 dual license, contributor/security docs.
- GitHub Rust/SQLite/Docker workflows, pinned checkout SHA, Dependabot and templates.
- Preserved all Phase 1–3 source ingestion, normalization, detection and incident features.
- Compilation and real deployment **not yet verified** in this authoring environment.

Earlier rule design is documented in [Phase 3](phase3-detection-design.md).

## 0.5.0 — 2026-11-20 — Operations, hardening and stabilization candidate

- Removed the missing `mod model;` declaration that blocked compilation.
- Added additive migration 005: server-owned TTL investigation sessions,
  atomic tool budgets and trace-scoped returned-evidence provenance.
- Reports now reject evidence never retrieved by their investigation.
- Added authenticated Prometheus text exposition at `/api/v1/metrics` and
  `/api/v1/ready` with bounded, low-cardinality metrics.
- Replaced Compose plaintext core tokens with protected secret-file paths;
  added a one-time Phase-4 credential migration tool.
- Segmented vector, collector, agent and Ollama trust boundaries into distinct
  internal networks. Ollama-only download egress; agent remote model egress is
  explicit opt-in plus host ACLs.
- Added `sentinelctl.py` init/doctor/online-backup/verify/offline-restore/
  evidence-preserving retention, with Python regression tests.
- Added Rust API-process contract test (requires Cargo on a test host).
- Made GitHub CI and Docker production builds fail on absent Cargo.lock.
- Added operation runbook, release guidance, and static phase-5 regression checks.
- Unverified: no Rust or Docker toolchain in authoring environment; native
  builds/tests and live integrations must pass before release promotion.
