# NYRA Sentinel

**Self-hosted security telemetry and evidence-backed investigations by Whyzper.Me.**

NYRA Sentinel receives OPNsense syslog over mTLS, polls optional AdGuard Home and CrowdSec APIs, and stores normalized events in SQLite. Deterministic rules and statistical signals are available in a self-hosted SOC dashboard. An optional agent uses scoped investigation tools with Ollama. Response proposals, approvals, simulation and rollback are audited. The response gateway runs exclusively in simulation mode.

## Quick start

On a dedicated Debian 13 host with Docker Engine, Compose, Python 3, OpenSSL and curl, enter the extracted project directory. Substitute the host's actual private address.

```bash
sudo python3 scripts/sentinelctl.py init 192.168.1.200
sudo python3 scripts/sentinelctl.py doctor
sudo docker compose up -d --build --wait sentinel vector
sudo bash scripts/smoke-test.sh
```

The API and dashboard are published on host loopback. Open an SSH tunnel from your workstation with `ssh -L 8765:127.0.0.1:8765 user@SENTINEL_HOST`, then visit <http://127.0.0.1:8765/ui>. Retrieve the operator credential from `secrets/api_token` on the VM. The dashboard keeps the token in tab memory.

- [Fresh installation, configuration and Phase-6 upgrades](docs/quickstart.md)
- [Debian packages and upstream integration](docs/deployment.md)
- [Configuration reference](docs/configuration.md)
- [Architecture and acceptance checks](docs/architecture-and-acceptance.md)
- [Backups, restore and retention](docs/phase5-operations.md)
- [Response roles and safety boundary](docs/response-safety.md)
- [Telemetry limitations](docs/telemetry-limitations.md)
- [Engineering report and release readiness](docs/validation-phase6.md)

## Development

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
bash scripts/verify-offline.sh
```

The release preflight also builds all three binaries and the Docker image, validates Compose and runs RustSec. See [contributing](.github/CONTRIBUTING.md) for prerequisites and [tests](tests/README.md) for the isolated integration and browser checks.

Source is licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE). Vulnerability reporting instructions are in the [security policy](.github/SECURITY.md).
