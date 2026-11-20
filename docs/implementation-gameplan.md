# NYRA Sentinel implementation roadmap

- **Phase 1:** Vector mTLS syslog → Rust collector → SQLite raw and normalized storage → read API. Candidate foundation; run live tests.
- **Phase 2:** OPNsense filterlog, AdGuard query log, CrowdSec decision snapshot, source health and checkpoints. Added as optional pollers.
- **Phase 3 (this package):** Deterministic 5m/60s detection windows, DNS statistical baseline, distinct-domain novelty with warmup, inbound multi-target and outbound fan-out, CrowdSec/firewall correlation, IP-centric incident grouping, durable cursor, evidence-backed read APIs and bounded historical handling.
- **Phase 3 release gate:** Rust compiler + clippy + integration suites, Docker/Vector semantic checks, real OPNsense log fixtures, source-specific validation and backup/restore on a **nonproduction** Debian VM.
- **Phase 4:** NYRA Harness typed read-only tools with call budgets, prompt-injection containment, no privileged credentials and evidence-grounded reporting.
- **Phase 5:** Metrics, alert tuning, structured operations, least-privilege credential rotation, database retention/backup/restore, disaster recovery, image pinning by digest and vulnerability scanning.
- **Phase 6:** Action proposals, human approval gateway, time-bounded defensive actions with rollback and auditable authorization.

Risk priority: source correctness, event identity, SQLite contention/latency, evidence integrity, source health and false-positive analysis **before** model integration or dashboard polish.
