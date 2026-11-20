# Architecture, trust boundaries and acceptance

## Trust boundaries

1. **OPNsense → Vector** over TCP/6514. Vector serves mTLS on a dedicated ingress bridge with masquerading disabled. It requires a client certificate signed by the configured CA. TCP syslog has no end-to-end SQLite acknowledgement.
2. **Vector → Rust** uses NDJSON on the private telemetry bridge. Vector reads the scoped ingest token from its mounted secret file through the native directory backend. Each event receives a UUID before entering the disk queue. Network retries reuse the UUID. The collector limits requests to 512 KiB and 200 records.
3. **Rust → SQLite**: serializable-by-single-transaction insert of raw and optionally normalized events; UNIQUE IDs prevent retry duplication. WAL FULL persistence, explicit indexed queries, DB not exposed over network.
4. **Rust → AdGuard / CrowdSec** uses GET requests with redirects and environment proxies disabled, bounded bodies and a 12-second request limit. Separate source health reports poll success and errors.
5. **Clients → API** through host loopback TCP/8765. Bearer credentials separate operator, ingestion, harness read, report write, approval and simulation. Request deadlines, concurrency limits and cursor pagination bound application work.
6. **Agent → Ollama** uses a fixed model origin and the configured TLS policy. Tools expose fixed-schema read-only queries. Reports are written through a distinct credential and their structured evidence comes from audited results in the same trace.

## Normalization semantics

- `transport_peer_ip` always denotes the syslog TCP sender, not a hostile IP.
- OPNsense `filterlog`: derive packet source and destination ONLY from the documented CSV columns; validate IP version, protocol, optional TCP/UDP ports. Unknown/truncated filterlog retains the raw record and `parse_status=malformed`, without a synthetic security event.
- OPNsense filterlog 4th CSV field may be a label or rule identity depending on emission; `rule_tracker` is not asserted to be a globally unique ID.
- CrowdSec active decisions are reconciled using `GET /v1/decisions/stream?startup=true`. Observed, changed, reactivated and removed states produce normalized events. A decision indicates mitigation activity and needs separate incident confirmation.
- AdGuard polls newest-first with `older_than` and a five-second checkpoint overlap. SHA-256 and an occurrence index retain identical entries within one snapshot and preserve the original first-occurrence identity. The deadline, page cap and byte cap apply before the events and checkpoint commit.
- All telemetry strings are untrusted. Tool calls validate their inputs independently of model output. The evidence store verifies event identifiers and preserves their audit links.

## Release acceptance gates

| Gate | Method | Expected |
|---|---|---|
| Rust code style | `cargo fmt --all -- --check` | PASS |
| Rust lint | `cargo clippy --locked --all-targets -- -D warnings` | PASS |
| Rust functional tests | `cargo test --locked --all-targets` | PASS, including mock HTTP tests |
| Docker config | `docker compose config --quiet` | PASS |
| Vector runtime | native `vector validate --no-environment` and the Compose smoke test | PASS |
| mTLS | valid client cert accepted, missing or invalid cert rejected | PASS |
| Syslog replay | resend same Vector delivery ID | one raw and one normalized record |
| Same-content distinct events | different delivery IDs, same message text | two raw records |
| Invalid filterlog | malformed/truncated CSV | raw-only with parse error, no fabricated IP |
| API authentication | omit/alter API token | HTTP 401 |
| AdGuard pagination | mock multi-page, replay, cap exceeded | correct checkpoint & no skipped commit |
| CrowdSec transitions | full mock snapshots | exact observed/removed transitions |
| Poller disruption | upstream timeout or 401 | syslog still ingests, source degraded |
| Persistence | restart containers | data and checkpoints preserved |
| Real sensor compatibility | 24-hour soak and fixture capture | no silent format drift |
| Backup/restore | WAL-consistent backup then `PRAGMA integrity_check` | OK |

The engine processes normalized rows by monotonic ID. Derived state and cursor commit together. Live detection evaluates events aged up to 15 minutes with up to five minutes of future clock skew. Events between 15 minutes and 24 hours old can contribute to asset rollups without creating live detections. Older events and events outside clock-skew tolerance remain queryable. [Rule details](phase3-detection-design.md)

Review the recorded test scope before qualifying a deployment. [Release validation](validation-phase6.md)
