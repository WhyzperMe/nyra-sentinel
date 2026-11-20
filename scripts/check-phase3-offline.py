#!/usr/bin/env python3
"""Real SQLite upgrade, timestamp backfill, FK and replay-schema regression checks."""
import hashlib
import pathlib
import sqlite3
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
MIGRATIONS = sorted((ROOT / 'migrations').glob('*.sql'))
assert len(MIGRATIONS) >= 3
cx = sqlite3.connect(':memory:')
cx.execute('PRAGMA foreign_keys=ON')
for sql in MIGRATIONS[:2]:
    cx.executescript(sql.read_text())

# Phase 2 pre-existing data: a timezone offset must migrate to an absolute epoch.
cx.execute("INSERT INTO raw_events(event_id,source,ingested_at,raw_json,payload_sha256,parser_version) VALUES ('old-raw','test','2026-11-20T19:00:00Z','{}',?,2)", ('0'*64,))
cx.execute("INSERT INTO security_events(event_id,raw_event_id,source,event_ts,category,action,source_ip,details_json) VALUES ('old-sec','old-raw','test','2026-11-20T21:00:00+02:00','firewall.filterlog','block','203.0.113.7','{}')")
cx.commit()
for sql in MIGRATIONS[2:]:
    cx.executescript(sql.read_text())
epoch = cx.execute("SELECT event_epoch FROM security_events WHERE event_id='old-sec'").fetchone()[0]
assert epoch == 1795201200, epoch  # 2026-11-20 19:00:00 UTC
assert cx.execute("SELECT last_row_id FROM detection_cursor WHERE pipeline='default'").fetchone()[0] == 0
print('PASS Phase 2 -> Phase 3 upgrade; normalized UTC epoch backfill')

# Foreign keys prevent an alert from citing invented evidence.
cx.execute("INSERT INTO incidents(id,subject_kind,subject_value,severity,first_seen_epoch,last_seen_epoch,detection_count,title) VALUES ('i1','ip','203.0.113.7','medium',1,1,1,'Test')")
fp = hashlib.sha256(b'v1\x00repeated_firewall_blocks\x00203.0.113.7\x001').hexdigest()
cx.execute("INSERT INTO detections(id,fingerprint,rule_id,rule_version,severity,classification,entity_kind,entity_value,incident_id,window_start_epoch,first_seen_epoch,last_seen_epoch,observed_count,title,explanation) VALUES ('d1',?,'repeated_firewall_blocks',1,'medium','deterministic','ip','203.0.113.7','i1',300,300,301,3,'Test','No compromise claim')", (fp,))
cx.execute("INSERT INTO detection_evidence(detection_id,security_event_id) VALUES ('d1','old-sec')")
assert cx.execute('SELECT COUNT(*) FROM detection_evidence').fetchone()[0] == 1
try:
    cx.execute("INSERT INTO detection_evidence(detection_id,security_event_id) VALUES ('d1','not-a-real-event')")
except sqlite3.IntegrityError:
    print('PASS evidence foreign key rejects nonexistent security event')
else:
    raise AssertionError('Foreign key not enforced')
try:
    cx.execute("INSERT INTO detections(id,fingerprint,rule_id,rule_version,severity,classification,entity_kind,entity_value,incident_id,window_start_epoch,first_seen_epoch,last_seen_epoch,observed_count,title,explanation) VALUES ('d2',?,'repeated_firewall_blocks',1,'medium','deterministic','ip','203.0.113.7','i1',300,300,301,3,'Test','Test')",(fp,))
except sqlite3.IntegrityError:
    print('PASS unique fingerprint rejects duplicate alert')
else:
    raise AssertionError('Duplicate fingerprint accepted')
assert cx.execute('PRAGMA foreign_key_check').fetchall() == []
print('PASS referential integrity and idempotency keys')

# Query semantics used by the Rust engine: no future/unprocessed row contributes.
cx.execute("INSERT INTO security_events(event_id,raw_event_id,source,event_ts,category,action,source_ip,details_json,event_epoch) VALUES ('now-sec','old-raw','test','2026-11-20T19:00:01Z','firewall.filterlog','block','203.0.113.7','{}',?)",(epoch+1,))
first_id=cx.execute("SELECT row_id FROM security_events WHERE event_id='old-sec'").fetchone()[0]
count=cx.execute("SELECT COUNT(*) FROM security_events WHERE source_ip=? AND category='firewall.filterlog' AND action IN ('block','reject') AND event_epoch BETWEEN ? AND ? AND row_id<=?",('203.0.113.7',epoch,epoch+10,first_id)).fetchone()[0]
assert count == 1
print('PASS bounded time-window query excludes not-yet-processed event rows')
print('Phase 3 offline checks passed. No Rust build, Vector runtime, or network test was executed.')
