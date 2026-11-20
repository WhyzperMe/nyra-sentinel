#!/usr/bin/env bash
# Creates a lab-only CA, server and client certificates, and scoped credentials.
set -Eeuo pipefail
umask 077
cd "$(dirname "$0")/.."
if (( EUID != 0 )); then echo 'Run as root: sudo ./scripts/bootstrap.sh <DEBIAN_VM_LAN_IP>' >&2; exit 1; fi
if (( $# != 1 )); then echo 'Usage: sudo ./scripts/bootstrap.sh <DEBIAN_VM_LAN_IP>' >&2; exit 1; fi
IP="$1"
python3 - "$IP" <<'PY'
import ipaddress, sys
ip = ipaddress.ip_address(sys.argv[1])
lan = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')
if ip.version != 4 or not (ip == ipaddress.ip_address('127.0.0.1') or any(ip in ipaddress.ip_network(net) for net in lan)):
    raise SystemExit("Use the private IPv4 address of your Debian VM or 127.0.0.1 for isolated tests")
PY
for directory in pki pki/vector pki/client pki/upstreams secrets data data/sqlite data/vector; do
  if [[ -L "$directory" ]]; then echo "Refusing symlinked $directory" >&2; exit 1; fi
done
for path in .env secrets/{api_token,ingest_token} pki/{ca.key,ca.crt,ca.srl,server.ext,client.ext} \
    pki/vector/{ca.crt,server.crt,server.key,server.csr} pki/client/{client.crt,client.key,client.csr} \
    data/sqlite/sentinel.sqlite{,-wal,-shm,-journal}; do
  if [[ -e "$path" || -L "$path" ]]; then
    echo "Existing file found: $path. Use the upgrade or recovery procedure." >&2
    exit 1
  fi
done
mkdir -p pki/vector pki/client pki/upstreams secrets data/sqlite data/vector
cat > .env <<CONFIG
SENTINEL_HOST_IP=$IP
CONFIG
chmod 600 .env
openssl rand -hex 32 > secrets/api_token
openssl rand -hex 32 > secrets/ingest_token
chown root:10001 secrets/api_token secrets/ingest_token
chmod 640 secrets/api_token secrets/ingest_token
openssl req -x509 -newkey rsa:3072 -noenc -days 3650 \
  -keyout pki/ca.key -out pki/ca.crt -sha256 \
  -subj '/CN=NYRA Sentinel Homelab CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
openssl req -newkey rsa:3072 -noenc -keyout pki/vector/server.key \
  -out pki/vector/server.csr -subj '/CN=nyra-sentinel.home.arpa' >/dev/null 2>&1
cat > pki/server.ext <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:nyra-sentinel.home.arpa,IP:$IP
EXT
openssl x509 -req -in pki/vector/server.csr -CA pki/ca.crt -CAkey pki/ca.key \
  -CAcreateserial -out pki/vector/server.crt -days 365 -sha256 -extfile pki/server.ext >/dev/null 2>&1
openssl req -newkey rsa:3072 -noenc -keyout pki/client/client.key \
  -out pki/client/client.csr -subj '/CN=opnsense.home.arpa' >/dev/null 2>&1
cat > pki/client.ext <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EXT
openssl x509 -req -in pki/client/client.csr -CA pki/ca.crt -CAkey pki/ca.key \
  -CAcreateserial -out pki/client/client.crt -days 365 -sha256 -extfile pki/client.ext >/dev/null 2>&1
cp pki/ca.crt pki/vector/ca.crt
rm -f pki/vector/server.csr pki/client/client.csr pki/server.ext pki/client.ext pki/ca.srl
chown 10001:10001 pki/vector/{server.key,server.crt,ca.crt} pki/vector data/sqlite data/vector
chown root:10001 secrets pki/upstreams
chmod 750 secrets pki/upstreams
chmod 750 pki/vector data/sqlite data/vector
chmod 640 pki/vector/server.key pki/vector/server.crt pki/vector/ca.crt
chmod 700 pki/client
chmod 600 pki/ca.key pki/client/client.key
openssl verify -CAfile pki/ca.crt -purpose sslserver pki/vector/server.crt
openssl verify -CAfile pki/ca.crt -purpose sslclient pki/client/client.crt
bash ./scripts/setup-agent-secrets.sh
echo "Prepared $IP:6514 (TLS), localhost:8765 (API), and scoped harness credentials."
echo 'Next: import CA and client certificate/key into OPNsense, then deploy with sudo docker compose up -d --build.'
echo 'KEEP pki/ca.key SECRET; do not copy the CA private key to OPNsense.'
