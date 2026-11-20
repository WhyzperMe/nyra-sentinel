#!/usr/bin/env bash
# Idempotent, fail-safe token creation for existing Phase 1/2/3 installations.
set -Eeuo pipefail
umask 077
cd "$(dirname "$0")/.."
if (( EUID != 0 )); then echo 'Usage: sudo ./scripts/setup-agent-secrets.sh' >&2; exit 1; fi
[[ ! -L secrets ]] || { echo 'Refusing symlinked secrets directory' >&2; exit 1; }
install -d -m 0750 -o root -g 10001 secrets
for name in harness_read_token harness_report_token response_approval_token response_executor_token; do
  target="secrets/$name"
  if [[ -e "$target" || -L "$target" ]]; then
    [[ -f "$target" && ! -L "$target" ]] || { echo "Refusing non-regular secret: $target" >&2; exit 1; }
    echo "Preserved existing secret: $name"
    continue
  fi
  tmp="$(mktemp "secrets/.${name}.XXXXXXXX")"
  trap 'rm -f "$tmp"' EXIT
  openssl rand -hex 32 > "$tmp"
  chown root:10001 "$tmp"
  chmod 0640 "$tmp"
  ln -T "$tmp" "$target"
  rm -f "$tmp"
  trap - EXIT
  echo "Created scoped credential: $name"
done
printf '%s\n' 'Harness credentials configured. Keep secrets/ out of Git and backups encrypted.'
