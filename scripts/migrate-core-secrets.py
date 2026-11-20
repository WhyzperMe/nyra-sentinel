#!/usr/bin/env python3
"""One-time migration from Phase 4 .env tokens to root:10001 secret files.

Run as root, stop containers beforehand; refuses overwrite, avoids printing secrets.
"""
import os
import pathlib
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
env_path = root / '.env'
secrets = root / 'secrets'
keys = ('SENTINEL_API_TOKEN', 'SENTINEL_INGEST_TOKEN')
if os.geteuid() != 0:
    sys.exit('Run as root after stopping the Compose stack')
if not env_path.is_file() or env_path.is_symlink():
    sys.exit('Expected a regular .env file')
raw = env_path.read_text()
lines = raw.splitlines(keepends=True)
tokens = {}
kept = []
for line in lines:
    matched = False
    for key in keys:
        if line.startswith(key + '='):
            if key in tokens:
                sys.exit('Duplicate token variable; refusing migration')
            value = line.split('=', 1)[1].strip()
            if len(value) < 32 or any(c.isspace() for c in value):
                sys.exit('Invalid token in .env')
            tokens[key] = value
            matched = True
    if not matched:
        kept.append(line)
if set(tokens) != set(keys):
    sys.exit('Expected both legacy tokens; nothing modified')
if any((secrets / name).exists() for name in ('api_token', 'ingest_token')):
    sys.exit('Destination secret already exists; refusing overwrite')
if secrets.is_symlink():
    sys.exit('Refusing symlinked secrets directory')
secrets.mkdir(mode=0o750, exist_ok=True)
if not secrets.is_dir() or secrets.stat().st_uid != 0:
    sys.exit('Secrets directory must be a regular root-owned directory')
for key, filename in zip(keys, ('api_token', 'ingest_token')):
    dest = secrets / filename
    fd = os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o640)
    with os.fdopen(fd, 'w') as fh:
        fh.write(tokens[key] + '\n')
    os.chown(dest, 0, 10001)
fd, tmp = tempfile.mkstemp(prefix='.env.migrating.', dir=env_path.parent)
try:
    with os.fdopen(fd, 'w') as fh:
        fh.writelines(kept)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, env_path)
finally:
    if os.path.exists(tmp):
        os.unlink(tmp)
print('Core tokens moved to secret files; rotate them if previous .env was ever exposed.')
