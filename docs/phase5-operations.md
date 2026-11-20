# Operations and recovery

## Health and source diagnostics

```bash
sudo python3 scripts/sentinelctl.py status
sudo docker compose logs --tail=100 sentinel vector
curl -fsS http://127.0.0.1:8765/api/v1/health
curl -fsS http://127.0.0.1:8765/api/v1/ready
```

Use `/health` for storage liveness and `/ready` for storage and detection backlog checks. Use authenticated `/sources` and `/metrics` for upstream freshness. A source age of `-1` indicates no successful observation yet. Compare age against each enabled source's normal cadence. The metrics endpoint uses fixed source labels and gauges because retention can reduce totals.

```bash
sudo sh -c 'printf "header = \"Authorization: Bearer %s\"\n" "$(cat secrets/api_token)" | curl --config - -fsS http://127.0.0.1:8765/api/v1/metrics'
sudo docker compose exec vector vector top
```

Check Vector buffer fill, available disk space and external sensor delivery separately. An unavailable model affects investigations. Collection and detection continue independently. [Telemetry limitations](telemetry-limitations.md)

## Online backup and offline restore

```bash
sudo install -d -m 0700 /var/backups/nyra-sentinel
sudo python3 scripts/sentinelctl.py backup --db data/sqlite/sentinel.sqlite \
  --dir /var/backups/nyra-sentinel
sudo python3 scripts/sentinelctl.py verify /var/backups/nyra-sentinel/NAME.sqlite
```

Backups use SQLite's online backup API and produce a standalone snapshot with a SHA-256 manifest. Verification checks the hash, byte count, database integrity, foreign keys and migration versions. Store the database and JSON manifest together. Use encrypted off-host storage and preserve the PKI and secret files separately.

Stop other database writers and readers before restoring. Confirm the database has completed its normal shutdown and has no WAL, SHM or rollback-journal sidecars. Run restore from a local filesystem supporting hardlinks. If the destination exists, restore links the old file to a timestamped recovery name before atomically replacing it. Run as root for the default Compose deployment so file ownership follows the existing database or database directory.

```bash
sudo docker compose stop vector sentinel
sudo python3 scripts/sentinelctl.py verify /var/backups/nyra-sentinel/NAME.sqlite
sudo python3 scripts/sentinelctl.py restore /var/backups/nyra-sentinel/NAME.sqlite \
  --db data/sqlite/sentinel.sqlite --offline-confirm
sudo docker compose up -d --wait sentinel vector
sudo python3 scripts/sentinelctl.py status
sudo bash scripts/smoke-test.sh
```

## Evidence-preserving retention

```bash
sudo python3 scripts/sentinelctl.py retention --event-days 30 --raw-days 45 --dry-run
sudo python3 scripts/sentinelctl.py retention --event-days 30 --raw-days 45 --confirm
```

Each pass deletes up to 50,000 rows per table in a transaction. Events linked to detections, investigations including legacy report evidence, response proposals and audited tool evidence remain available with their raw records. The detection cursor protects events awaiting evaluation. Derived DNS domain state expires after at least 90 days of inactivity, so a domain may later be treated as newly seen. Evidence-bearing rows have no automatic expiration. Monitor disk usage and run compaction during a maintenance window.

## Legacy credential migration

For older deployments with core tokens in `.env`, stop writers and verify a backup before converting to secret files.

```bash
sudo python3 scripts/migrate-core-secrets.py
sudo bash scripts/setup-agent-secrets.sh
```

Keep secret files owned by `root:10001` with mode `0640`. Rotate credentials that were exposed to unauthorized users.

## Scheduled investigations

Copy `configs/hunt-targets.example` to `configs/hunt-targets.txt`. Set ownership to root and restrict write permission. The optional script uses the agent profile and processes up to five configured subjects per run.

```bash
sudo bash scripts/scheduled-hunt.sh
```

The agent's default networks reach the Sentinel API and local Ollama. Remote model deployments require explicit egress configuration. [Deployment instructions](deployment.md#local-vs-remote-ollama)
