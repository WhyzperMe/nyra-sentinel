# Phase 3 → Phase 4 upgrade and rollback

**Do not overwrite** `.env`, `pki/`, `data/`, `secrets/` or upstream certificates.
Snapshot the VM or perform a consistent SQLite backup BEFORE touching code.

```bash
cd /opt/nyra-sentinel
sudo docker compose stop
sudo install -d -m 0700 /root/nyra-backups
sudo cp -a data/sqlite "/root/nyra-backups/sqlite-phase3-$(date +%Y%m%d-%H%M%S)"
# Copy the new source files + compose.yaml + migrations (exclude .env/data/pki/secrets).
sudo ./scripts/setup-agent-secrets.sh
sudo docker compose config --quiet
sudo docker compose up -d --build sentinel vector
sudo docker compose --profile agent run --rm agent --ip 203.0.113.7 --no-llm
```

Expected: migration 4 creates `harness_tool_audit` and `investigations`. Existing
telemetry, detections, incidents and source checkpoints remain. Verify `GET /health`,
source health, detection cursor and SQLite integrity; take a fresh post-upgrade backup.
Only then opt into Ollama and the AI agent.

**Rollback:** Because schema 4 is additive, old binaries should not depend on new tables,
but do not claim blanket downgrade compatibility. Preferred recovery: stop all
containers, restore the full pre-upgrade SQLite backup and the old Phase 3 code/Compose
configuration (with data and secrets), then run original smoke tests. Avoid restoring
a snapshot while any SQLite writer is active.
