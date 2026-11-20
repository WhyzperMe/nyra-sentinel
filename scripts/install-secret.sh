#!/usr/bin/env bash
# Store an adapter credential without putting it in shell history or argv.
set -Eeuo pipefail
umask 077
cd "$(dirname "$0")/.."
if (( EUID != 0 )); then echo 'Use sudo.' >&2; exit 1; fi
if [[ $# -ne 1 || ( "$1" != "adguard_password" && "$1" != "crowdsec_api_key" ) ]]; then
  echo 'Usage: sudo ./scripts/install-secret.sh adguard_password|crowdsec_api_key' >&2
  exit 1
fi
[[ ! -L secrets ]] || { echo 'Refusing symlinked secrets directory' >&2; exit 1; }
install -d -m 0750 -o root -g 10001 secrets
read -rs -p "Paste $1, then Enter: " SECRET
printf '\n'
if [[ ${#SECRET} -lt 8 || "$SECRET" == *$'\n'* || "$SECRET" == *$'\r'* ]]; then
  echo 'Credential too short or contains newline.' >&2; exit 1
fi
TEMP=$(mktemp secrets/.secret.XXXXXX)
trap 'rm -f "$TEMP"' EXIT
printf '%s\n' "$SECRET" > "$TEMP"
unset SECRET
chown root:10001 "$TEMP"
chmod 0640 "$TEMP"
mv -f -- "$TEMP" "secrets/$1"
trap - EXIT
echo "Secret installed with permissions 0640, owner root:10001."
