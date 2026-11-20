# Verification

- `cargo test --locked --all-targets` exercises normalization, pollers on mock HTTP servers, SQLx, detections, the investigation allowlist and real HTTP handlers with temporary databases.
- `bash scripts/verify-offline.sh` runs SQLite fixtures, Python backup/restore and retention tests, plus shell and JavaScript syntax checks. Install PyYAML for the configuration tests.
- `tests/compose_smoke.py` verifies the full pipeline with synthetic loopback TLS traffic and an agent run in tool-only mode. It deliberately stops and restarts the isolated Sentinel container.
- `tests/browser_smoke.cjs` exercises dashboard login, rendering of untrusted telemetry, mobile layout and browser token handling in Chromium.

## Run the isolated container and browser tests

Use a disposable copy of the source on a Linux host with ports 6514 and 8765 available on loopback.

```bash
sudo bash scripts/bootstrap.sh 127.0.0.1
sudo docker compose up -d --build --wait sentinel vector
sudo python3 tests/compose_smoke.py

npm install --prefix /tmp/nyra-browser --no-audit --no-fund --ignore-scripts playwright@1.61.1
/tmp/nyra-browser/node_modules/.bin/playwright install --with-deps chromium
NODE_PATH=/tmp/nyra-browser/node_modules NYRA_TEST_TOKEN="$(sudo cat secrets/api_token)" \
  node tests/browser_smoke.cjs

sudo docker compose down --remove-orphans
```

Acceptance against the actual Debian VM, OPNsense and enabled upstream services is recorded separately. [Release validation](../docs/validation-phase6.md)
