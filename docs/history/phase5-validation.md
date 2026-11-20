# Phase 5 validation report — 2026-11-20

## Scope

Source revision: `0.5.0` (Whyzper.Me). The ZIP contains all previous source
modules and five incremental migrations, not just a patch or diff.

## Checks actually executed in the authoring environment

| Check | Result | Scope / limitation |
|---|---|---|
| `python3 scripts/static-validation.py` | PASS | YAML + SQLite structural checks, replay identities |
| `python3 scripts/check-phase3-offline.py` | PASS | Historical epoch migration, detector FK and cursor contracts |
| `python3 scripts/check-phase4-offline.py` | PASS | Fixed harness SQL queries, Phase-4 reporting schema |
| `python3 scripts/check-phase5-offline.py` | PASS | Phase-5 schema, session budgets, evidence FK, networks and secrets |
| `python3 -m unittest discover -s tests -p 'test_*.py' -v` | PASS (4 tests) | Online backup with live WAL writer, tamper detection, offline restore, evidence retention, legacy upgrade |
| `python3 -m compileall -q scripts tests` | PASS | Python syntax only |
| `bash -n scripts/*.sh` | PASS | Shell syntax only |
| ZIP CRC and SHA-256 manifest | PASS when packaged | Packaging integrity, not code execution |

The verification environment **does not have** `rustc`, `cargo`, or `docker`.
Network access for installing Rust/crates is unavailable. We therefore **did
not run** Rustfmt, Clippy, Cargo tests, release builds, the Docker build,
Vector runtime config validation, true end-to-end OPNsense/Ollama integration,
or an actual GitHub Actions run. A lockfile cannot be responsibly fabricated.

## Remaining release gates (mandatory)

1. On a Rust 1.100.0 host with registry access, run
   `./scripts/prepare-lockfile.sh`; review and commit `Cargo.lock`.
2. Run `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`,
   `cargo test --locked --all-targets`, `cargo build --locked --release --bins`.
   Fix all native warnings, test failures, and compiler errors.
3. Validate `docker compose config` and `docker build` using that lockfile.
4. Check GitHub Actions jobs **actually report success** on the intended branch.
5. On the target Debian VM, verify actual OPNsense client-certificate Syslog
   delivery, dropped-connection replay, source API keys, and the Ollama model.
6. Verify CPU/memory/disk use, restore tested backups, and log source
   freshness alerts under representative load. Assess Docker/host egress ACLs.
7. Only then tag v0.5.0 or mark it production-ready.

## Important limits still present

- AdGuard query-log entries without a reliable native event ID cannot have
  provably lossless duplicate handling; content hashes are a documented
  approximation. The adapter raises a backlog-gap error when page limits are
  exhausted rather than pretending to have a complete history.
- SQLite is a single-host data store; do not share its live files via NFS.
- SHA-256 manifests detect accidental modification but do **not** authenticate
  a malicious editor with write access to both backup and manifest; store
  offsite backups in authenticated encrypted repositories.
- A health endpoint that can query SQLite is not proof that Vector,
  CrowdSec, AdGuard or Ollama is working.
- Agent tool access is read-only, but model conclusions remain hypotheses.
- Network segmentation with Compose alone does not guarantee policy-enforced
  host egress. Configure host/firewall ACLs for the deployment.
