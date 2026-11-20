#!/usr/bin/env python3
"""Executable offline regression tests; do not misrepresent as a compiled Rust test."""
from pathlib import Path
import sqlite3
import yaml

ROOT = Path(__file__).resolve().parents[1]
conn = sqlite3.connect(':memory:')
conn.execute('PRAGMA foreign_keys=ON')
for migration in sorted((ROOT/'migrations').glob('*.sql')):
    conn.executescript(migration.read_text())
assert conn.execute('PRAGMA foreign_keys').fetchone()[0] == 1
for table in ('harness_sessions','harness_tool_evidence','investigations','harness_tool_audit'):
    assert conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()
print('PASS Phase-5 migration applies after all four historical migrations')

# Two subjects with the same raw content MUST remain separate (phase 2 invariant).
for raw, event in [('raw-a','event-a'),('raw-b','event-b')]:
    conn.execute("INSERT INTO raw_events(event_id,source,ingested_at,raw_json,payload_sha256,parser_version) VALUES (?,'test','2026-01-01T00:00:00Z','{}',?,2)",(raw,'a'*64))
    conn.execute("INSERT INTO security_events(event_id,raw_event_id,source,category,event_epoch) VALUES (?,?,'test','dns.query',1767225600)",(event,raw))

trace='550e8400-e29b-41d4-a716-446655440000'
conn.execute("INSERT INTO harness_sessions(trace_id,expires_epoch) VALUES (?, CAST(strftime('%s','now') AS INTEGER)+900)",(trace,))
for _ in range(24):
    changed=conn.execute("UPDATE harness_sessions SET tool_calls=tool_calls+1 WHERE trace_id=? AND expires_epoch>CAST(strftime('%s','now') AS INTEGER) AND tool_calls<24",(trace,)).rowcount
    assert changed==1
assert conn.execute("UPDATE harness_sessions SET tool_calls=tool_calls+1 WHERE trace_id=? AND tool_calls<24",(trace,)).rowcount==0
print('PASS session atomic 24-call budget and fixed expiration schema')

conn.execute("INSERT INTO harness_tool_audit(trace_id,tool_name,args_sha256,status) VALUES (?,'get_ip_history',?,'ok')",(trace,'a'*64))
audit_id=conn.execute('SELECT last_insert_rowid()').fetchone()[0]
conn.execute('INSERT INTO harness_tool_evidence(audit_row_id,trace_id,security_event_id) VALUES (?,?,?)',(audit_id,trace,'event-a'))
assert conn.execute("SELECT 1 FROM harness_tool_evidence WHERE trace_id=? AND security_event_id='event-a'",(trace,)).fetchone()
assert not conn.execute("SELECT 1 FROM harness_tool_evidence WHERE trace_id=? AND security_event_id='event-b'",(trace,)).fetchone()
try:
    conn.execute('INSERT INTO harness_tool_evidence(audit_row_id,trace_id,security_event_id) VALUES (?,?,?)',(audit_id,trace,'non-existent'))
except sqlite3.IntegrityError:
    pass
else:
    raise AssertionError('forged event was accepted')
print('PASS provenance lookup rejects real but unqueried events and nonexistent events')

compose=yaml.safe_load((ROOT/'compose.yaml').read_text())
s=compose['services']
assert 'sentinel' in s and 'agent' in s and 'vector' in s and 'ollama' in s
assert set(s['agent']['networks'])=={'investigation_api','local_model'}
assert set(s['vector']['networks'])=={'telemetry_ingest','syslog_ingress'}
assert compose['networks']['telemetry_ingest']['internal'] is True
assert compose['networks']['syslog_ingress']['driver_opts']['com.docker.network.bridge.enable_ip_masquerade'] == 'false'
assert 'source_egress' not in s['agent']['networks']
assert all(compose['networks'][n]['internal'] for n in ('telemetry_ingest','investigation_api','local_model'))
assert s['sentinel']['environment']['SENTINEL_API_TOKEN_FILE']=='/run/secrets/api_token'
assert 'SENTINEL_API_TOKEN' not in s['sentinel']['environment']
assert s['vector']['entrypoint']==['vector']
assert './secrets/ingest_token:/run/secrets/ingest_token:ro' in s['vector']['volumes']
assert 'mod model;' not in (ROOT/'src/agent/mod.rs').read_text()
assert 'COPY Cargo.toml Cargo.lock rust-toolchain.toml' in (ROOT/'Dockerfile').read_text()
assert 'cargo build --frozen --release --bins' in (ROOT/'Dockerfile').read_text()
assert 'if [ -f Cargo.lock ]' not in (ROOT/'Dockerfile').read_text()
print('PASS isolated container trust zones, secret file delivery, fail-closed Docker build')
print('All Phase-5 OFFLINE checks passed. Rust and Docker build still require toolchains.')
