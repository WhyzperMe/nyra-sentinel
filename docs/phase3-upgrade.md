# Upgrade Phase 2 → Phase 3 (safe procedure)

Do **not** overwrite existing `.env`, `pki/`, `secrets/`, `data/`, upstream CA files or credentials with the ZIP. Phase 3 is an additive schema migration but still requires a backup and functional restore path.

1. In a maintenance window, confirm the current Phase-2 service is healthy and note volume/ingestion rates. **Stop both writers**: `sudo docker compose down` (do not use `-v`). Ensure no external process is using the DB.
2. Backup `data/sqlite/` with all journal sidecars, `.env`, `pki/`, `secrets/`, `vector/`, `compose.yaml`, and source version to an encrypted location accessible only by root. Test restore in an isolated VM before cutting over. A clean stop followed by `cp -a data/sqlite ...` is acceptable; for live backups use SQLite's backup API, not a raw `.sqlite` copy.
3. Keep old mutable state and copy only source, migrations, scripts, Dockerfile, docs, fixtures, `compose.yaml`, `.github/` from this ZIP. Never run `bootstrap.sh` over established PKI.
4. Add optional threshold overrides from `.env.example`. Default settings work without adding environment variables to the existing `.env`.
5. Generate and commit `Cargo.lock` with a trusted compatible Rust toolchain (`cargo generate-lockfile`), review dependencies, run `cargo fmt`, `cargo clippy`, and `cargo test` before deployment. The ZIP does not contain a preverified Cargo.lock, so `--locked` cannot be required until this gate passes.
6. Run `python3 scripts/static-validation.py`, `python3 scripts/check-phase3-offline.py`, `bash -n scripts/*.sh` and `sudo docker compose config --quiet`.
7. Build/run: `sudo docker compose up -d --build`; check `sudo docker compose ps` and `sudo docker compose logs --tail=200 sentinel vector`.
8. Query the local, authenticated API: `/api/v1/detection-engine/status`, `/api/v1/detections`, `/api/v1/incidents`, `/api/v1/assets`, `/api/v1/sources`. Check backlog decreases and historical invalid rows count as skipped rather than false alerts.
9. Load-test in a test environment; verify idempotent alerts with fixtures and confirm no alert claims compromise from blocked events. Only after verified, activate more aggressive detection thresholds in production.

**Rollback:** stop both containers, restore the **entire** database backup (not just the older executable: SQLx migrations are not reversible merely by rolling back a binary), restore old source/config, start Phase-2 image. Never point Phase-2 at a mutated Phase-3 DB assuming automatic rollback. Verify prior event counts, then monitor traffic.
