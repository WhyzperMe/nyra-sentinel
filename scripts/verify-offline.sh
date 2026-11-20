#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
python3 scripts/static-validation.py
python3 scripts/check-phase3-offline.py
python3 scripts/check-phase4-offline.py
python3 scripts/check-phase5-offline.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m py_compile scripts/*.py
for script in scripts/*.sh; do bash -n "$script"; done
if command -v node >/dev/null 2>&1; then
  node --check web/app.js
  node --check tests/browser_smoke.cjs
elif command -v node.exe >/dev/null 2>&1; then
  node.exe --check web/app.js
  node.exe --check tests/browser_smoke.cjs
else
  echo 'WARN Node unavailable: JS syntax not checked'
fi
printf '\nOffline checks passed. Rust/Docker/OPNsense integration remain separate release gates.\n'
