# Phase 3 Validation Manifest

**Code status:** Candidate implementation, not a verified production release.

## Successfully executed in this generation environment

- Python's `sqlite3` applied all three migration scripts in ascending order on a clean database; table creation succeeded.
- A simulated migration from a populated Phase-2 database parsed a `+02:00` event timestamp to the correct UTC epoch.
- SQLite foreign-key tests rejected fabricated event references; unique-fingerprint tests rejected duplicate detections.
- SQL bounded-window query excluded a row after the current detection cursor.
- Phase-2 replay delivery-ID and checkpoint checks passed.
- YAML parse of Compose/Vector, strict Vector TLS certificate and disk-buffer setting assertions, shell `bash -n` checks and ZIP integrity checks.

## Not executed here (environment limitations)

- Rust `cargo fmt`, `cargo test`, `cargo clippy`, `cargo build --release`: Rust/Cargo not installed and internet for installing unavailable.
- Docker Compose actual container build and runtime checks: Docker not installed here.
- Vector config semantic validation, mTLS session with OPNsense, live AdGuard/CrowdSec APIs, performance/load tests, recovery under power loss.
- CI workflow execution: workflow is included but unexecuted.

**Hard release gates:** run all native checks before shipping. Investigate and fix any compiler, clippy, test or Docker errors found. Populate a verified `Cargo.lock` after resolving dependencies and commit the lock file. Do not treat the presence of test source as a test pass.
