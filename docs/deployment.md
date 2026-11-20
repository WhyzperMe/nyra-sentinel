# Debian deployment, integration and hardening

## Docker Engine on Debian 13

Use Docker's official Debian repository and packages. [Docker Engine installation on Debian](https://docs.docker.com/engine/install/debian/)

```bash
sudo apt update
sudo apt install -y ca-certificates curl python3 openssl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF2
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: $(. /etc/os-release && echo "$VERSION_CODENAME")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF2
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
```

## Bootstrap

```bash
sudo ./scripts/bootstrap.sh 192.168.1.200  # use your REAL VM LAN IP
sudo docker compose config --quiet
sudo docker compose up -d --build sentinel vector
sudo docker compose ps
sudo ./scripts/smoke-test.sh
```

`bootstrap.sh` creates an internal CA, server certificate and client certificate,
Vector disk buffer directory, SQLite data folder, operator/ingest keys and scoped
agent keys. Protect the CA private key OFF the VM after enrollment. Rotate certificates
before their 365-day expiration. Use dedicated management network ACLs for port 6514.

## OPNsense source configuration

- Trust the generated CA certificate (never the CA private key).
- Import the dedicated client certificate **with private key** for logging client auth.
- In OPNsense **System → Settings → Logging → Remote** select TLS remote syslog,
  correct VM address port 6514, certificate, and only required firewall/system categories.
- Test mTLS path, actual timestamps, and parsed `filterlog` examples after every OPNsense upgrade.
- Avoid installing custom code on OPNsense or exposing the Rust service to the internet.

## AdGuard and CrowdSec adapters

The integrations are opt-in. Run `sudo bash scripts/install-secret.sh adguard_password` or
`sudo bash scripts/install-secret.sh crowdsec_api_key`. Set the appropriate URL and enable the adapter in `.env`.
CrowdSec requires a dedicated bouncer key. AdGuard Home's Basic Auth credential may have broader API rights depending on deployment. Where supported, restrict its use through a private TLS reverse proxy allowing only `GET /control/querylog`. [Configuration reference](configuration.md)

## Local vs remote Ollama

```bash
sudo docker compose --profile ollama up -d ollama
sudo docker compose exec ollama ollama pull qwen3:4b
sudo docker compose --profile agent run --rm agent --ip 203.0.113.7 --no-llm
sudo docker compose --profile agent run --rm agent --ip 203.0.113.7
```

CPU inference can be very slow or memory-hungry. For dedicated AI hardware, leave
`ollama` profile stopped, set `SENTINEL_OLLAMA_URL` and opt into the reviewed
`deploy/compose.remote-ollama.yaml` override. Allow only that destination through host
firewall/OPNsense ACLs; the default agent intentionally has no external egress.
Never transmit bearer credentials to an untrusted endpoint.

## Reliability and backup

- Run `cargo test`, migrations and Docker smoke in CI/staging before upgrading.
- Monitor `docker compose ps`, Sentinel `/api/v1/health`, `/api/v1/sources`,
  and `/api/v1/detection-engine/status`, plus disk use and Vector buffer fill.
- Prefer `sudo python3 scripts/sentinelctl.py backup --db data/sqlite/sentinel.sqlite
  --dir /var/backups/nyra-sentinel` while collecting. Do not copy live WAL files.
  Use `sentinelctl.py verify` and practice an explicitly offline restore.
  See `phase5-operations.md` for the authoritative Phase-5 instructions.
- Rotate agent tokens if leaked; revoke and reissue certs if the CA or client key leaks.
- Audit Docker host mounts and firewall rules: Docker-published ports can bypass
  UFW assumptions; do not rely on UFW alone.
- Reclaim older files only after confirming retention requirements and backup success.
