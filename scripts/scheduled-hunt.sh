#!/usr/bin/env bash
# Optional host-run scheduled investigations; never modifies a security appliance.
# Example crontab: 15 3 * * * /opt/nyra-sentinel/scripts/scheduled-hunt.sh >/dev/null 2>&1
set -Eeuo pipefail
umask 077
cd "$(dirname "$0")/.."
if (( EUID != 0 )); then echo "Run scheduled hunts as root from a secured host task" >&2; exit 1; fi
if [[ ! -f configs/hunt-targets.txt || -L configs/hunt-targets.txt ]]; then
  echo 'No configs/hunt-targets.txt; copy the example and review targets first.' >&2
  exit 1
fi
command -v flock >/dev/null || { echo 'flock required (util-linux)' >&2; exit 1; }
command -v docker >/dev/null || { echo 'Docker CLI required' >&2; exit 1; }
if [[ $(stat -c '%u' configs/hunt-targets.txt) != 0 ]] || [[ -n $(find configs/hunt-targets.txt -perm /022 -print) ]]; then
  echo 'Scheduled hunt targets must be owned by root and not writable by other users' >&2; exit 1
fi
# Limit to one hunt worker per host and at most five subjects per invocation.
install -d -m 0700 -o root -g root /run/nyra-sentinel
exec 9>/run/nyra-sentinel/hunt.lock
flock -n 9 || { echo 'Investigation already running' >&2; exit 0; }
count=0
while read -r kind subject extra; do
  [[ -z "${kind:-}" || "${kind:0:1}" == '#' ]] && continue
  [[ -z "${extra:-}" && -n "${subject:-}" ]] || { echo 'Invalid target syntax' >&2; exit 1; }
  case "$kind" in ip|domain|incident) ;; *) echo 'Invalid target kind' >&2; exit 1;; esac
  (( count += 1 ))
  if (( count > 5 )); then echo 'Too many targets (max 5)' >&2; exit 1; fi
  docker compose --profile agent run --rm -T agent "--$kind" "$subject"
done < configs/hunt-targets.txt
