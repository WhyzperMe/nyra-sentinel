# Install, upgrade and verify

## Fresh Debian 13 installation

The initial deployment target is 2 vCPU, 4 GiB RAM and a 40 GB SSD. Plan to run Ollama on a separate host at this size. Install Docker Engine and the Compose plugin, Python 3, OpenSSL and curl. [Debian package commands](deployment.md#docker-engine-on-debian-13)

Extract the source archive to a local Linux filesystem and open its project directory. The archive includes the Cargo lockfile and builds the three Rust executables inside Docker.

```bash
sudo python3 scripts/sentinelctl.py init 192.168.1.200
sudo python3 scripts/sentinelctl.py doctor
sudo docker compose up -d --build --wait sentinel vector
sudo python3 scripts/sentinelctl.py status
sudo bash scripts/smoke-test.sh
```

Use your VM's actual private IPv4 address. Bootstrap protects existing configuration, databases and certificate files. Keep the CA private key offline after enrollment. Import the CA certificate and dedicated client certificate and key into OPNsense. Restrict access to TCP/6514 to approved syslog clients at the network boundary. [OPNsense configuration](deployment.md#opnsense-source-configuration)

The dashboard is served at <http://127.0.0.1:8765/ui>. Use an SSH tunnel for access from another machine. Source adapters and the Ollama profile are optional. Enable them individually after verifying their endpoints and certificate trust. [Configuration reference](configuration.md)

## Upgrade an existing Phase-6 deployment

Keep two separate source trees on the same host. In this example the existing tree is `/opt/nyra-sentinel` and the extracted replacement is `/opt/nyra-sentinel-hardened`. Stop the existing stack before copying operator state.

```bash
cd /opt/nyra-sentinel
sudo docker image tag nyra-sentinel:0.6.0 nyra-sentinel:phase6-rollback
sudo docker compose down
sudo install -d -m 0700 /var/backups/nyra-sentinel
sudo python3 /opt/nyra-sentinel-hardened/scripts/sentinelctl.py backup \
  --db /opt/nyra-sentinel/data/sqlite/sentinel.sqlite --dir /var/backups/nyra-sentinel
# Use the exact Backup verified path printed above.
sudo python3 /opt/nyra-sentinel-hardened/scripts/sentinelctl.py verify \
  /var/backups/nyra-sentinel/REPLACE_WITH_PRINTED_BACKUP.sqlite
sudo cp -a .env data pki secrets /opt/nyra-sentinel-hardened/

cd /opt/nyra-sentinel-hardened
sudo bash scripts/setup-agent-secrets.sh
sudo python3 scripts/sentinelctl.py doctor
sudo docker compose up -d --build --wait sentinel vector
sudo python3 scripts/sentinelctl.py status
sudo bash scripts/smoke-test.sh
```

Startup applies additive migration `202611200007_operational_hardening.sql`. Previously applied migrations retain their original contents and checksums. Check polling endpoints, existing evidence and source freshness after upgrading.

To roll back, stop the new stack and restart the original tree with the preserved image and database.

```bash
cd /opt/nyra-sentinel-hardened
sudo docker compose down
sudo docker image tag nyra-sentinel:phase6-rollback nyra-sentinel:0.6.0
cd /opt/nyra-sentinel
sudo docker compose up -d --no-build --wait sentinel vector
```

Use the maintenance CLI to verify a backup and restore it into an offline database. Keep a separate copy of TLS files and configuration. [Recovery procedures](phase5-operations.md)
