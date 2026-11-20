# Phase 3 — Deterministic Detection, Correlation, Baselines, Incidents

**Scope:** Detection and reporting only. No agent, model, shell, write API, automatic firewall changes or external enrichment.

## Guarantees and non-guarantees

- **Transactional materialization:** `detection_cursor` updates in the same SQLite transaction as assets, buckets, alerts, incidents and evidence. If any SQL operation fails, the entire batch rolls back. One worker at a time takes a SQLite writer reservation.
- **Replay-safe scheduled processing:** the engine consumes `security_events.row_id` ascending, max `SENTINEL_DETECTION_BATCH_SIZE` per transaction. Only previously consumed records (`row_id <= current row_id`) contribute to a threshold. Persisted detection fingerprints deduplicate alerts for identical rule/IP/time buckets.
- **Immutable evidence references:** detections reference normalized `security_events.event_id` via foreign keys; original raw events and payload hashes remain separate and unmodified.
- **No compromise inference:** labels are explicit `deterministic` or `statistical`, with impact-neutral wording. An incident is a correlated cluster of observations, **not a confirmed security incident**.
- **Event-time policy:** the current live window starts 15 minutes before engine time and allows five minutes of future skew. Rows up to 24 hours old can fill rollups without creating live detections. Rows outside the live window and rows with invalid timestamps count toward `skipped_events`.
- **Upstream constraints:** AdGuard uses occurrence indices within a snapshot. CrowdSec polls current state. Each upstream can have gaps. [Telemetry limitations](telemetry-limitations.md)
- **Backpressure:** engine drains full batches without sleeping, yields between transactions, sleeps when idle/failing. SQLite WAL serializes writers; 2 vCPU VM should be load-tested with real volumes.

## Detection rules (v1)

| Rule ID | Trigger | Default threshold | Classification | Interpretation |
|---|---|---:|---|---|
| `repeated_firewall_blocks` | Same source IP, blocked/rejected firewall records, trailing 5m | >=12 | deterministic | repeated blocked traffic, not breach |
| `admin_service_probing` | Block/reject to common admin ports (22,445,3389,5900,8080,8443,8291,10443), 5m | >=5 | deterministic | possible probes; attempts blocked |
| `multi_asset_inbound_probing` | Public IP blocked inbound toward >=2 private destination IPs, 15m | >=2 assets | deterministic | multi-target observation |
| `dns_query_volume` | Client's query count in trailing 60s | >=120 | deterministic | unusually busy querying; may be benign |
| `dns_new_filtered_domain` | First observed and *filtered* domain after client warmup | client >=200 historic queries + >=24h age | deterministic | low-priority novelty observation |
| `dns_baseline_spike` | Current 5m DNS volume above prior 24h mean+4σ and >=3×mean, with absolute floor | >=40 current, >=200 queries in prior 24h | statistical | hypothesis, not maliciousness |
| `outbound_destination_fanout` | Local source, pass/out to distinct public IPs within 10m | >=25 destinations | deterministic | high fan-out, confirm filterlog interface orientation |
| `crowdsec_firewall_correlation` | CrowdSec add/change and one or more blocked firewall events for same IP within trailing 30m | >=1 block | deterministic | temporal co-occurrence only |

**Planned, not implemented:** authentication failure detection without trusted auth-log parser; Zenarmor-based flow analysis; source-specific evidence severity scores; per-device hour-of-week baseline; automated mitigation. No ungrounded alert claims are generated for these.

## Event and identity semantics

- Asset keys are private **IP addresses**, not trusted device identities. DHCP changes, NAT and multiple devices sharing an address can confound profiles. Future inventory should resolve IP-to-MAC/hostname with time bounds before labeling a specific device.
- `source_ip` means protocol-level source IP according to the normalized source; the **syslog transport peer is never treated as attacker IP**.
- Passive DNS source IP can be null (hostname, anonymization), in which case per-client rules do not run.
- `in` / `out` reflect OPNsense log interface direction. They are not automatically equivalent to the direction of a successful internet session. Outbound fan-out interpretation needs live validation.
- Prior 24-hour DNS baseline includes zero-traffic 5m buckets. Baseline uses known observations, not proof of perfect source completeness. Age is measured from materialized first seen, not device registration.
- Repeated detections from the same rule/IP/15m or 5m time bucket are consolidated into one fingerprint. A single long attack can produce additional detections across bucket boundaries, but an IP-centric incident groups adjacent detections within six hours. This is intentional.
- Bounded evidence: at most 32 normalized security event references per detection. Summary `observed_count` may be larger. Incident detail lists at most 200 detection IDs and returns `detection_ids_truncated=true` if truncated.

## Tables / indexes

`security_events.event_epoch` stores integer Unix seconds; older RFC-3339 event timestamps are backfilled via SQLite `strftime('%s',...)`. Phase 3 adds `detection_cursor`, `assets`, `asset_domains`, `asset_dns_buckets`, `incidents`, `detections`, `detection_evidence`. All additive; no destructive migration of Phase 1/2 rows.

`asset_dns_buckets` older than 72 hours are removed during active detection batches. Raw evidence, asset identities and detections are **not** automatically deleted; long-term retention remains a Phase-5 operations task. Disk growth must be monitored.

## Failure modes and operational signals

- SQLite writer errors: batch rollback, next-loop retry, no cursor advancement.
- Bad timestamps: source rows remain searchable, `skipped_events` increments.
- Disabled AdGuard/CrowdSec: corresponding rules cannot trigger; no fabricated inputs.
- AdGuard backlog: source marked degraded by Phase 2; the statistical DNS-baseline spike is suppressed until source health recovers. Absolute DNS-volume detections still run. Investigate source health before treating any anomaly as meaningful.
- Absent DNS baseline: statistical anomaly and first-seen filtered-domain rules do not fire until warmup; absolute volume detection still works.
- Containers restart: persisted cursor and state resume, detection fingerprints prevent duplicated detections.
- The current verification and outstanding deployment checks are recorded in [release validation](validation-phase6.md).

## CI and acceptance criteria

Run `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --all-targets`, `cargo build --release`, SQLite static scripts, Vector native `vector validate`, `docker compose config --quiet`, production-like fake-syslog replay, DB backup/restore test and live network integration. Check: source/event timestamps, parser errors, detection cursor monotonically increases, expected test detections appear exactly once, evidence links resolve, source failure does not stall ingestion and zero unauthorized responses leak telemetry.
