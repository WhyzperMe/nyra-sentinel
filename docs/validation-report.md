# Phase 2 Validation Report — 2026-11-20

## Executed here (offline container)

- Python sqlite3 applied both `migrations/*.sql` in sequence on a clean database.
- Migration produced expected raw/security/checkpoint/health/CrowdSec tables.
- A simulated duplicate delivery ID was ignored; two distinct delivery IDs containing the same raw payload were separately stored.
- Checkpoint storage was checked.
- `compose.yaml` and `vector/vector.yaml` loaded successfully using PyYAML; required TLS verification, disk buffer, and VRL delivery-ID transform were present.
- All shell scripts passed `bash -n`.
- The updated PKI bootstrap was executed in a fresh isolated temporary directory; OpenSSL verified both certificate purposes, SAN contained the chosen VM IP, new secrets directories were created, and a second run refused to overwrite credentials.

Run offline checks again with `python3 scripts/static-validation.py`.

## Supplied but NOT executed here

- `cargo fmt`, `cargo clippy`, `cargo test`, `cargo build --release`: no Rust toolchain available.
- Rust HTTP poller mock tests (AdGuard replay/overload, CrowdSec state reconciliation) are included in the code but **not yet run**.
- Docker Compose execution and Vector native schema/VRL validation: Docker/Vector not installed.
- Genuine AdGuard Home / CrowdSec / OPNsense integration: no access to private homelab; no API credentials provided.
- Real mTLS network handshake and outage recovery: not performed.

## Explicit limitations

1. No Cargo.lock can be generated offline: run `cargo generate-lockfile`, commit it, then enable `--locked` in CI/build after a successful dependency audit. Until then builds are not fully reproducible.
2. AdGuard query-log API does not provide native per-event IDs. Log rotation, timestamp collisions, and pagination windows can yield data gaps; no exact-once claim.
3. CrowdSec LAPI bouncer key only grants read-decision functionality. No alert-history API is claimed.
4. Local Docker bridge forwarding uses bearer-authenticated HTTP (not internal TLS), acceptable only for single-host trusted-container threat model.
5. Zenarmor deliberately remains disabled until a supported export interface and license features are confirmed.
6. Privacy/retention/backup/restore and production observability still need Phase 5 hardening.

**Status:** Phase 2 candidate source release, structurally validated. Not compiled or operationally verified.
