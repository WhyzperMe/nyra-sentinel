#!/usr/bin/env python3
"""Offline structural and migration/replay checks; does not replace cargo test."""
import pathlib
import sqlite3
import sys
root = pathlib.Path(__file__).resolve().parents[1]
try:
    import yaml
except ImportError:
    print('PyYAML unavailable: skipping YAML checks (pip install pyyaml)', file=sys.stderr)
else:
    compose = yaml.safe_load((root/'compose.yaml').read_text())
    vector = yaml.safe_load((root/'vector/vector.yaml').read_text())
    assert {'sentinel','vector','agent','ollama'} <= set(compose['services'])
    assert 'agent' in compose['services']['agent']['profiles']
    assert 'ollama' in compose['services']['ollama']['profiles']
    assert vector['sources']['opnsense_syslog']['tls']['verify_certificate'] is True
    assert vector['sinks']['collector']['buffer']['type'] == 'disk'
    assert vector['secret']['sentinel']['type'] == 'directory'
    assert vector['sinks']['collector']['auth']['token'] == 'SECRET[sentinel.ingest_token]'
    assert 'uuid_v4()' in vector['transforms']['with_delivery_id']['source']
    print('PASS YAML structure and security settings')
c = sqlite3.connect(':memory:')
for migration in sorted((root/'migrations').glob('*.sql')):
    c.executescript(migration.read_text())
    print('PASS migration', migration.name)
def insert(uid, native, delivery):
    c.execute('''INSERT INTO raw_events (event_id,source,source_native_id,ingested_at,raw_json,payload_sha256,parser_version,delivery_id)
               VALUES (?,?,?,'2026-11-20T19:00:00Z','{}',?,2,?) ON CONFLICT DO NOTHING''',
              (uid,'opnsense-syslog',native, '0'*64, delivery))
insert('a',None,'550e8400-e29b-41d4-a716-446655440000')
insert('b',None,'550e8400-e29b-41d4-a716-446655440000')
insert('c',None,'a7b1578a-3d6d-4bc9-988a-c4f35948c673')
assert c.execute('SELECT COUNT(*) FROM raw_events').fetchone()[0] == 2
print('PASS unique delivery replay and distinct identical-message identities')
c.execute('INSERT INTO ingestion_checkpoints (source,cursor,updated_at) VALUES (?,?,?)', ('adguard-querylog','2026-11-20T19:00:00Z','2026-11-20T19:00:00Z'))
assert c.execute("SELECT cursor FROM ingestion_checkpoints WHERE source='adguard-querylog'").fetchone()[0] == '2026-11-20T19:00:00Z'
print('PASS source checkpoints')
print('Static checks passed (Rust binary and real network not tested).')
