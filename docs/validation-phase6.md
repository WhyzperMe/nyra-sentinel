# NYRA Sentinel v0.6.0 hardening report

**Validation date** 2026-11-20

**Release status** INTEGRATION-VERIFIED, NOT PRODUCTION-QUALIFIED

## A. Executive summary

The revised source builds all three executables and the Debian 13 runtime image. A disposable Linux Docker Compose stack under WSL2 passed mTLS ingestion, SQLite persistence, detection and incident evidence, the tool-only agent, response simulation, graceful server shutdown and buffered recovery. Real upstream hardware, the target VM and hosted GitHub Actions still require acceptance.

## B. Critical baseline findings

| Priority | Finding | Root cause and observed effect |
|---|---|---|
| P0 | Missing Cargo lockfile | Both the release build and CI required locked dependencies, so the supplied source snapshot could not pass its own release gate. |
| P0 | Broken syslog delivery in the supplied Compose configuration | Vector used only an internal bridge, so Docker did not publish TCP/6514. After fixing the bind, Vector 0.62 returned unauthorized on ingest because interpolation is disabled by default and the literal placeholder was used as the token. |
| P1 | Vulnerable locked dependency set | The first RustSec run flagged the old bundled SQLite and the RSA package in the lock graph. It also reported warnings for the pinned Tokio and Chrono. The affected SQLite version was actually linked into the old server. |
| P1 | Incorrect live detection and missing CrowdSec correlation | Delayed data inside the old 24-hour processing window could create fresh alerts. The CrowdSec poller emitted `observed` or `reactivated`, while the correlation rule expected a different state set. |
| P1 | Restore and retention could undermine recovery | Restore renamed the previous database away before replacement and could leave the replacement owned by root. Retention could delete standalone audit records and cascade their evidence links. |
| P1 | Actor attribution and narrative evidence were weaker than the UI implied | Request-provided handles identify no individual principal. Structured evidence had trace checks, but prose and agent-side recursive ID extraction could carry unrelated references. |

## C. Implemented fixes

- Cargo resolved `Cargo.lock` with Rust 1.100.0. SQLx 0.9.1 pulls patched bundled SQLite through `libsqlite3-sys` 0.40.0. Tokio moved to 1.54.1 and UTC timestamp handling uses Jiff. The Debian, Rust, Vector and Ollama images are referenced by digest. [SQLite RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2026-0459) · [Tokio RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2026-0386)
- Vector publishes syslog on a dedicated ingress bridge and reads its token via the native directory backend. The collector continues to authenticate every ingest request and retains the private telemetry bridge. [Vector interpolation behavior](https://vector.dev/docs/reference/environment_variables/) · [Vector secret backends](https://vector.dev/docs/reference/configuration/secrets/)
- AdGuard validates page order and progress and bounds the number of pages, wall time and retained bytes per poll. The original first-occurrence identity survives upgrade. CrowdSec uses the documented full-stream snapshot and reconciles bounded active state transactionally. [AdGuard query-log API](https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml) · [CrowdSec decision stream](https://docs.crowdsec.net/docs/local_api/bouncers/)
- Migration 007 adds response credential role attribution and indexes. The first six migrations are byte-for-byte identical to the delivered baseline. Backups use SQLite's online snapshot API, verify metadata, hashes and database integrity, and stage restore before atomic replacement. Retention keeps standalone auditable evidence.
- The dashboard handles loading and errors, fits a 390-pixel viewport and clears the approval dialog on close. The maintenance CLI checks the actual Compose config and server certificate, and provides a status command.

## D. Architecture and reliability

The existing Rust server, agent and simulation gateway remain separate binaries. SQLite transactions own response transitions and their audit writes, poller writes and checkpoints, and detection cursor updates. Live alerts and historical rollup updates have separate event-time policies. Collector shutdown handles SIGTERM and drains requests before closing SQLite. The optional model sits outside the collection path.

## E. Security

The server defaults to loopback when run directly. Compose publishes the operator API on loopback and syslog on the configured host IP. HTTP requests have size, in-flight and time limits. Investigation uses fixed read-only queries, scoped credentials, audited provenance and a per-trace budget. The report keeps only validated structured event references, and UUIDs outside the authorized evidence set are filtered from ordinary summary text.

The response audit records a credential role and a self-asserted handle separately. Separate bearer tokens enforce role separation. Two-person approval requires individual authenticated accounts and is outside the guarantee of this deployment. The gateway executes only simulation and simulation rollback.

## F. Verification

| Executed check | Result |
|---|---|
| `cargo metadata --locked --format-version 1` | Passed with the delivered lockfile |
| `cargo fmt --all -- --check` | Passed |
| `cargo check --locked --all-targets` | Passed |
| `cargo clippy --locked --all-targets -- -D warnings` | Passed |
| `cargo test --locked --all-targets` | 38 passed, including live HTTP scopes, evidence forgery, concurrent approval and audit failure rollback |
| `cargo build --locked --release --bins` | All three release binaries built |
| `cargo audit` | No advisories reported for the final lockfile in the database used |
| `bash scripts/verify-offline.sh` | Seven migrations, 13 Python tests, phase fixtures, shell and JavaScript syntax passed |
| Phase-6 binary and database upgrade | Original SQLx 0.8 server created the database. SQLx 0.9 applied migration 007 and preserved the six recorded checksums, foreign keys and original AdGuard identity. |
| `docker build --network host --progress=plain -t nyra-sentinel:0.6.0 .` | Built pinned Debian 13 image with all three binaries under WSL2 |
| `docker compose config --quiet` | Core, all profiles and remote-Ollama override validated |
| `vector validate --no-environment /etc/vector/vector.yaml` | Passed inside the pinned Vector 0.62.0 container |
| `sentinelctl.py init`, `doctor`, `status` and `bash scripts/smoke-test.sh` | Passed on the disposable stack |
| `python3 tests/compose_smoke.py` | Passed valid, missing and untrusted client certificate cases, distinct deliveries, detection, incident/evidence, tool-only report, simulation/rollback, graceful shutdown and buffered recovery |
| `node tests/browser_smoke.cjs` | Passed using installed Windows Chromium via Playwright against the running Docker stack |
| `actionlint .github/workflows/ci.yml` | Passed locally |
| `gitleaks dir --redact --no-banner .` | No findings in the scanned source snapshot |

## G. Performance observations

A single `docker compose stats --no-stream` sample after the isolated smoke test showed Sentinel at **4.90 MiB / 768 MiB** and Vector at **41.18 MiB / 512 MiB**. Sampled CPU was **0.00%** and **0.04%** respectively. These are WSL2 point observations with synthetic traffic and the model disabled. Throughput, tail latency, sustained CPU and disk growth on the target configuration remain unmeasured.

## H. Remaining risks

- **High for production qualification.** Complete a Debian VM soak, validate OPNsense mTLS against the installed version and test any enabled AdGuard, CrowdSec and Ollama endpoints. The exercised CrowdSec and AdGuard endpoints were mocks. A real Ollama model was outside the run.
- **Medium.** An earlier rapid newline-delimited TLS test burst became visible only after further traffic. The final RFC 5425 byte-counted smoke scenario passed. Verify the sender's actual framing, delivery latency and reconnect behavior during the soak. Upstream rotation and transport loss limit delivery guarantees.
- **Medium.** Measure detection false positives with representative labeled traffic. Exercise disk-full, sustained load, prolonged outages and ongoing evidence growth. Evidence-linked rows deliberately have no automatic expiration.
- **Medium.** GitHub Actions were linted locally. The supplied workspace had no Git metadata or remote, so a commit and hosted workflow run require the actual repository. The RustSec scan covers the Rust dependency graph. Image-level advisory scanning and cross-platform byte-for-byte reproducibility remain unverified. The optional Ollama container retains the upstream root user and its model volume.

## I. Deployment

The installation guide includes exact commands for Debian packages, a fresh setup, a Phase-6 upgrade with backup verification and an image/database rollback. [Installation and upgrade](quickstart.md) · [Recovery and retention](phase5-operations.md)

## J. Release decision

**INTEGRATION-VERIFIED, NOT PRODUCTION-QUALIFIED.** The build and isolated integration results support staging use. Production qualification depends on the target-host and upstream acceptance outlined above.
