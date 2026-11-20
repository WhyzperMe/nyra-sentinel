#!/usr/bin/env python3
"""NYRA Sentinel operational CLI: standard-library-only, no LLM required.

Backups use SQLite's live online backup API; NEVER copy a running WAL database.
Restore must be performed offline and refuses leftover WAL/SHM files.
"""
import argparse
from contextlib import closing
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / 'data/sqlite/sentinel.sqlite'
DEFAULT_BACKUPS = ROOT / 'backups'


def fail(message):
    raise SystemExit('ERROR: ' + message)


def utc_stamp():
    return dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def integrity(path):
    uri = path.resolve().as_uri() + '?mode=ro&immutable=1'
    with closing(sqlite3.connect(uri, uri=True, timeout=10)) as conn:
        conn.execute('PRAGMA foreign_keys=ON')
        outcome = conn.execute('PRAGMA integrity_check').fetchone()[0]
        if outcome != 'ok':
            fail('SQLite integrity_check failed: ' + str(outcome))
        issues = conn.execute('PRAGMA foreign_key_check').fetchall()
        if issues:
            fail('SQLite foreign_key_check found inconsistencies')
        required = {'raw_events', 'security_events', 'investigations'}
        present = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not required.issubset(present):
            fail('backup does not look like a NYRA Sentinel database')
        versions = ([r[0] for r in conn.execute(
            "SELECT version FROM _sqlx_migrations WHERE success = 1 ORDER BY version")]
            if '_sqlx_migrations' in present else [])
        return versions


def fsync_dir(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def require_regular(path):
    if path.is_symlink() or not path.is_file():
        fail(f'not a regular, non-symlink file: {path}')


def require_no_sidecars(path):
    for suffix in ('-wal', '-shm', '-journal'):
        candidate = path.with_name(path.name + suffix)
        if candidate.exists() or candidate.is_symlink():
            fail(f'SQLite sidecar exists: {candidate}. Stop writers and checkpoint safely first.')


def cmd_backup(args):
    db, dest = Path(args.db), Path(args.dir)
    if not 10 <= args.timeout <= 3600:
        fail('backup timeout must be between 10 and 3600 seconds')
    require_regular(db)
    if dest.is_symlink():
        fail('backup directory may not be a symlink')
    dest.mkdir(mode=0o700, parents=True, exist_ok=True)
    if dest.stat().st_mode & 0o077:
        fail('backup directory must have mode 0700 (chmod 700)')
    base = f'sentinel-{utc_stamp()}-{secrets.token_hex(4)}.sqlite'
    target = dest / base
    manifest = target.with_suffix('.json')
    if shutil.disk_usage(dest).free < db.stat().st_size * 2:
        fail('insufficient space for database snapshot and SQLite working files')
    fd, tmp = tempfile.mkstemp(dir=dest, prefix='.backup-', suffix='.sqlite')
    manifest_tmp = Path(tmp).with_suffix('.json')
    linked_target = False
    linked_manifest = False
    committed = False
    try:
        with os.fdopen(fd, 'wb'):
            pass
        # Source connection may be actively writing. Online Backup API yields a
        # transactionally consistent snapshot even when the database uses WAL.
        src_uri = db.resolve().as_uri() + '?mode=ro'
        deadline = time.monotonic() + args.timeout

        def check_deadline(_status, _remaining, _total):
            if time.monotonic() >= deadline:
                fail('online backup timed out')

        with closing(sqlite3.connect(src_uri, uri=True, timeout=5)) as src:
            with closing(sqlite3.connect(tmp, timeout=5)) as dst:
                src.backup(dst, pages=256, progress=check_deadline, sleep=0.05)
                if dst.execute('PRAGMA journal_mode=DELETE').fetchone()[0] != 'delete':
                    fail('could not create standalone SQLite snapshot')
        require_no_sidecars(Path(tmp))
        versions = integrity(Path(tmp))
        with open(tmp, 'rb') as fh:
            os.fsync(fh.fileno())
        metadata = {'format': 1, 'product': 'NYRA Sentinel', 'file': base,
                    'sha256': sha256(Path(tmp)), 'bytes': Path(tmp).stat().st_size,
                    'created_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
                    'migration_versions': versions}
        mfd = os.open(manifest_tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(mfd, 'w') as fh:
            json.dump(metadata, fh, indent=2)
            fh.write('\n')
            fh.flush()
            os.fsync(fh.fileno())
        os.link(tmp, target)
        linked_target = True
        os.link(manifest_tmp, manifest)
        linked_manifest = True
        fsync_dir(dest)
        committed = True
        print(f'Backup verified: {target}\nSHA256: {metadata["sha256"]}\nManifest: {manifest}')
    finally:
        if not committed:
            if linked_manifest:
                manifest.unlink(missing_ok=True)
            if linked_target:
                target.unlink(missing_ok=True)
        manifest_tmp.unlink(missing_ok=True)
        Path(tmp).unlink(missing_ok=True)


def validated_backup(path):
    require_regular(path)
    require_no_sidecars(path)
    manifest = path.with_suffix('.json')
    require_regular(manifest)
    if manifest.stat().st_size > 64 * 1024:
        fail('backup manifest exceeds size limit')
    info = json.loads(manifest.read_text())
    if not isinstance(info, dict) or info.get('format') != 1 or info.get('product') != 'NYRA Sentinel' or info.get('file') != path.name:
        fail('invalid backup manifest or filename mismatch')
    actual = sha256(path)
    if actual != info.get('sha256') or path.stat().st_size != info.get('bytes'):
        fail('backup hash or size mismatch')
    versions = integrity(path)
    if versions != info.get('migration_versions'):
        fail('migration mismatch in manifest')
    return info


def cmd_verify(args):
    info = validated_backup(Path(args.backup))
    print('PASS checksum, SQLite integrity, FK integrity and migration metadata:', info['sha256'])


def cmd_restore(args):
    if not args.offline_confirm:
        fail('restore requires --offline-confirm after stopping all Sentinel containers')
    db, backup = Path(args.db), Path(args.backup)
    if db.is_symlink() or db.parent.is_symlink():
        fail('destination DB path may not be a symlink')
    info = validated_backup(backup)
    if db.resolve() == backup.resolve() or (db.exists() and os.path.samefile(db, backup)):
        fail('the restore destination must differ from the backup')
    require_no_sidecars(db)
    if db.exists():
        require_regular(db)
    db.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if shutil.disk_usage(db.parent).free < info['bytes']:
        fail('insufficient space to stage the restore')
    ownership = db.stat() if db.exists() else db.parent.stat()
    fd, staged = tempfile.mkstemp(prefix='.restore-', suffix='.sqlite', dir=db.parent)
    try:
        with os.fdopen(fd, 'wb') as out, backup.open('rb') as inp:
            shutil.copyfileobj(inp, out)
            out.flush()
            if os.geteuid() == 0:
                os.fchown(out.fileno(), ownership.st_uid, ownership.st_gid)
            os.fsync(out.fileno())
        if sha256(Path(staged)) != info['sha256']:
            fail('staged restore checksum mismatch')
        integrity(Path(staged))
        require_no_sidecars(db)
        if db.exists():
            previous = db.with_name(db.name + '.pre-restore-' + utc_stamp() + '-' + secrets.token_hex(3))
            os.link(db, previous)
            fsync_dir(db.parent)
            print('Original preserved at:', previous)
        os.replace(staged, db)
        fsync_dir(db.parent)
        print('Offline restore complete:', db)
    finally:
        if os.path.exists(staged):
            os.unlink(staged)


def retention_counts(conn, cutoff_epoch, raw_cutoff):
    # Do not delete evidence from deterministic detections, audited tool calls,
    # or any report (including reports created before evidence provenance existed).
    eligible = '''
      FROM security_events e
      WHERE COALESCE(e.event_epoch, (SELECT unixepoch(r.ingested_at) FROM raw_events r WHERE r.event_id=e.raw_event_id)) < ?
        AND e.row_id <= COALESCE((SELECT last_row_id FROM detection_cursor WHERE pipeline='default'),0)
        AND NOT EXISTS (SELECT 1 FROM detection_evidence d WHERE d.security_event_id=e.event_id)
        AND NOT EXISTS (SELECT 1 FROM harness_tool_evidence h WHERE h.security_event_id=e.event_id)
        AND NOT EXISTS (SELECT 1 FROM response_proposals p WHERE p.evidence_event_id=e.event_id)
        AND NOT EXISTS (SELECT 1 FROM investigations i, json_each(i.evidence_json) j WHERE j.value=e.event_id)
    '''
    events = conn.execute('SELECT COUNT(*) ' + eligible, (cutoff_epoch,)).fetchone()[0]
    # An orphan raw event is only purgeable once any security event is gone.
    raws = conn.execute('''SELECT COUNT(*) FROM raw_events r
       WHERE CAST(strftime('%s',r.ingested_at) AS INTEGER) < ?
       AND NOT EXISTS (SELECT 1 FROM security_events e WHERE e.raw_event_id=r.event_id)''', (raw_cutoff,)).fetchone()[0]
    return eligible, events, raws


def cmd_retention(args):
    db = Path(args.db)
    require_regular(db)
    if args.event_days < 7 or args.raw_days < args.event_days:
        fail('event retention >=7 days, raw retention >= event retention required')
    now = int(dt.datetime.now(dt.timezone.utc).timestamp())
    event_cutoff = now - args.event_days * 86400
    raw_cutoff = now - args.raw_days * 86400
    with sqlite3.connect(db, timeout=30) as conn:
        conn.execute('PRAGMA foreign_keys=ON')
        conn.execute('PRAGMA busy_timeout=30000')
        if not args.dry_run and not args.confirm:
            fail('retention changes require --confirm (or use --dry-run)')
        conn.execute('BEGIN' if args.dry_run else 'BEGIN IMMEDIATE')
        eligible, events, raws = retention_counts(conn, event_cutoff, raw_cutoff)
        if args.dry_run:
            print(f'DRY RUN: {events} old unreferenced normalized events; {raws} orphan raw events before event deletion')
            return
        conn.execute('DELETE FROM security_events WHERE event_id IN (SELECT e.event_id ' + eligible + ' LIMIT 50000)', (event_cutoff,))
        e_deleted = conn.execute('SELECT changes()').fetchone()[0]
        conn.execute('''DELETE FROM raw_events WHERE row_id IN (
          SELECT r.row_id FROM raw_events r
          WHERE CAST(strftime('%s',r.ingested_at) AS INTEGER) < ?
          AND NOT EXISTS (SELECT 1 FROM security_events e WHERE e.raw_event_id=r.event_id)
          LIMIT 50000)''', (raw_cutoff,))
        r_deleted = conn.execute('SELECT changes()').fetchone()[0]
        # Never prune a report's auditable history. Expired standalone sessions
        # can be removed only if not referenced by investigations.
        conn.execute('''DELETE FROM asset_dns_buckets WHERE rowid IN (
          SELECT rowid FROM asset_dns_buckets WHERE bucket_start_epoch < ? LIMIT 50000)''',
          (now - max(args.event_days, 30) * 86400,))
        conn.execute('''DELETE FROM harness_tool_audit WHERE row_id IN (
          SELECT a.row_id FROM harness_tool_audit a WHERE unixepoch(a.created_at) < ?
            AND NOT EXISTS (SELECT 1 FROM investigations i WHERE i.trace_id=a.trace_id)
            AND NOT EXISTS (SELECT 1 FROM harness_tool_evidence e WHERE e.audit_row_id=a.row_id)
          ORDER BY a.row_id LIMIT 50000)''', (now-30*86400,))
        conn.execute('''DELETE FROM harness_sessions WHERE trace_id IN (
          SELECT s.trace_id FROM harness_sessions s WHERE s.expires_epoch < ?
            AND NOT EXISTS (SELECT 1 FROM investigations i WHERE i.trace_id=s.trace_id)
            AND NOT EXISTS (SELECT 1 FROM harness_tool_audit a WHERE a.trace_id=s.trace_id)
            AND NOT EXISTS (SELECT 1 FROM harness_tool_evidence e WHERE e.trace_id=s.trace_id)
          ORDER BY s.expires_epoch LIMIT 50000)''', (now-30*86400,))
        conn.execute('''DELETE FROM crowdsec_decisions WHERE id IN (
          SELECT id FROM crowdsec_decisions WHERE active=0 AND last_changed < ?
          ORDER BY last_changed LIMIT 50000)''',
          (dt.datetime.fromtimestamp(event_cutoff, dt.timezone.utc).isoformat().replace('+00:00','Z'),))
        conn.execute('''DELETE FROM asset_domains WHERE rowid IN (
          SELECT rowid FROM asset_domains WHERE last_seen_epoch < ? ORDER BY last_seen_epoch LIMIT 50000)''',
          (now - max(args.event_days, 90) * 86400,))
        if conn.execute('PRAGMA foreign_key_check').fetchone() is not None:
            fail('retention rolled back because foreign_key_check found inconsistencies')
        conn.commit()
        print(f'Retention committed: security_events={e_deleted}, raw_events={r_deleted}; max 50000 per table per run')


def cmd_doctor(args):
    problems = []
    for label, path in [('Compose', ROOT/'compose.yaml'), ('Vector config', ROOT/'vector/vector.yaml'),
                         ('Rust manifest', ROOT/'Cargo.toml'), ('Cargo lockfile', ROOT/'Cargo.lock')]:
        ok = path.is_file() and path.stat().st_size > 0
        print(('PASS' if ok else 'FAIL'), label)
        if not ok: problems.append(label)
    if (ROOT/'.env').is_file():
        if any(line.lstrip().removeprefix('export ').startswith(('SENTINEL_API_TOKEN=', 'SENTINEL_INGEST_TOKEN='))
               for line in (ROOT/'.env').read_text().splitlines()):
            print('FAIL legacy plaintext core tokens in .env (run scripts/migrate-core-secrets.py)')
            problems.append('legacy plaintext tokens')
    else:
        print('FAIL .env missing (run init on a fresh deployment)')
        problems.append('.env')
    found_tokens = set()
    for name in ('api_token','ingest_token','harness_read_token','harness_report_token','response_approval_token','response_executor_token'):
        p = ROOT/'secrets'/name
        try:
            value = p.read_text().rstrip('\r\n') if p.is_file() and not p.is_symlink() and p.stat().st_size <= 258 else ''
            is_ok = (32 <= len(value) <= 256 and all(33 <= ord(c) <= 126 for c in value)
                     and value not in found_tokens and not (p.stat().st_mode & 0o037)
                     and p.stat().st_gid == 10001 and bool(p.stat().st_mode & 0o040))
            found_tokens.add(value)
        except PermissionError:
            print('FAIL cannot read secret', name, '(run sudo doctor)')
            problems.append('secret ' + name)
            continue
        print(('PASS' if is_ok else 'FAIL'), 'secret:', name)
        if not is_ok: problems.append('secret ' + name)
    openssl = shutil.which('openssl')
    for label, command in (
        ('Vector CA and server certificate', ['verify', '-CAfile', 'pki/vector/ca.crt',
                                             '-purpose', 'sslserver', 'pki/vector/server.crt']),
        ('Vector certificate valid for the next seven days', ['x509', '-noout', '-checkend', '604800',
                                                               '-in', 'pki/vector/server.crt']),
    ):
        result = subprocess.run([openssl, *command], cwd=ROOT, capture_output=True, timeout=10) if openssl else None
        print(('PASS' if result and result.returncode == 0 else 'FAIL'), label)
        if not result or result.returncode != 0:
            problems.append(label)
    if not args.offline:
        result = subprocess.run(['docker','compose','config','--quiet'],
                                cwd=ROOT, check=False) if shutil.which('docker') else None
        if result is None or result.returncode:
            print('FAIL Docker Compose unavailable or deployment configuration invalid')
            problems.append('Docker Compose')
        else:
            print('PASS Docker Compose configuration')
    if problems:
        fail(f'{len(problems)} deployment prerequisites failed')
    print('Local configuration checks passed.')


def cmd_status(_args):
    subprocess.run(['docker', 'compose', 'ps', 'sentinel', 'vector'], cwd=ROOT, check=True)
    subprocess.run(['docker', 'compose', 'exec', '-T', 'sentinel', 'sentinel-server', 'healthcheck'],
                   cwd=ROOT, check=True, stdin=subprocess.DEVNULL, timeout=15)
    print('Sentinel storage health check passed.')


def main():
    parser = argparse.ArgumentParser(description='Whyzper.Me NYRA Sentinel maintenance and recovery CLI')
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init', help='Create new homelab PKI and initial secrets (root required)')
    init.add_argument('vm_ip', help='Private IPv4 address of the Debian Sentinel VM')
    doctor = sub.add_parser('doctor', help='Check local deployment prerequisites')
    doctor.add_argument('--offline', action='store_true')
    sub.add_parser('status', help='Show core Compose services and check Sentinel storage health')
    backup = sub.add_parser('backup', help='Online consistent SQLite backup with SHA256 manifest')
    backup.add_argument('--db', default=str(DEFAULT_DB))
    backup.add_argument('--dir', default=str(DEFAULT_BACKUPS))
    backup.add_argument('--timeout', type=int, metavar='SECONDS', default=300)
    verify = sub.add_parser('verify', help='Verify SQLite backup hash, integrity and schema')
    verify.add_argument('backup')
    restore = sub.add_parser('restore', help='Restore backup only after stopping the service')
    restore.add_argument('backup')
    restore.add_argument('--db', default=str(DEFAULT_DB))
    restore.add_argument('--offline-confirm', action='store_true')
    retention = sub.add_parser('retention', help='Evidence-preserving, bounded telemetry cleanup')
    retention.add_argument('--db', default=str(DEFAULT_DB))
    retention.add_argument('--event-days', type=int, default=30)
    retention.add_argument('--raw-days', type=int, default=45)
    retention.add_argument('--dry-run', action='store_true')
    retention.add_argument('--confirm', action='store_true')
    args = parser.parse_args()
    if args.command == 'init':
        cmd = ['bash', str(ROOT/'scripts/bootstrap.sh'), args.vm_ip]
        raise SystemExit(subprocess.run(cmd, cwd=ROOT, check=False).returncode)
    {'doctor': cmd_doctor, 'status': cmd_status, 'backup': cmd_backup, 'verify': cmd_verify,
     'restore': cmd_restore, 'retention': cmd_retention}[args.command](args)

if __name__ == '__main__':
    try:
        main()
    except (OSError, sqlite3.Error, ValueError, subprocess.SubprocessError) as error:
        fail(str(error))
