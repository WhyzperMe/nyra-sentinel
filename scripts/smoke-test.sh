#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
if [[ ! -f .env ]]; then echo 'Missing .env: run bootstrap.sh first' >&2; exit 1; fi
# Do not source .env as executable shell: read only the expected host IP.
SENTINEL_HOST_IP="$(sed -n 's/^SENTINEL_HOST_IP=//p' .env)"
if [[ ! "$SENTINEL_HOST_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
  echo 'Invalid SENTINEL_HOST_IP in .env' >&2; exit 1
fi
[[ -r secrets/api_token ]] || { echo 'API token file unreadable; use sudo' >&2; exit 1; }
SENTINEL_API_TOKEN="$(<secrets/api_token)"
curl -fsS http://127.0.0.1:8765/api/v1/health
printf '\n'
TOKEN="sentinel-smoke-$(date +%s)-$(openssl rand -hex 4)"
SYSLOG_LINE="<134>1 $(date -u +%Y-%m-%dT%H:%M:%SZ) opnsense.home.arpa sentinel-smoke 1234 PROBE - $TOKEN"
{ printf '%s\n' "$SYSLOG_LINE"; sleep 1; } | \
 timeout 8 openssl s_client -quiet -no_ign_eof -verify_return_error -verify_ip "$SENTINEL_HOST_IP" \
  -connect "${SENTINEL_HOST_IP}:6514" -CAfile pki/ca.crt \
  -cert pki/client/client.crt -key pki/client/client.key >/dev/null
for i in {1..12}; do
  if response=$(curl -fsS --max-time 5 --config - \
    'http://127.0.0.1:8765/api/v1/events?limit=200' \
    <<< "header = \"Authorization: Bearer $SENTINEL_API_TOKEN\"") && [[ "$response" == *"$TOKEN"* ]]; then
    echo "End-to-end smoke test PASSED: $TOKEN"
    exit 0
  fi
  sleep 1
done
echo "Smoke event did not appear in newest 200 results: $TOKEN" >&2
exit 1
