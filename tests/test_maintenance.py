import pathlib
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CTL = ROOT / 'scripts/sentinelctl.py'

class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.dir.name)
        self.db = self.root / 'sentinel.sqlite'
        conn = sqlite3.connect(self.db)
        conn.execute('PRAGMA foreign_keys=ON')
        for migration in sorted((ROOT / 'migrations').glob('*.sql')):
            conn.executescript(migration.read_text())
        conn.close()
        self.backups = self.root / 'backups'
    def tearDown(self):
        self.dir.cleanup()
    def runctl(self, *args, ok=True):
        proc = subprocess.run([sys.executable, str(CTL), *map(str,args)], capture_output=True, text=True)
        if ok and proc.returncode:
            self.fail(f'{proc.stdout}\n{proc.stderr}')
        return proc
    def test_online_backup_verify_restore_and_tamper(self):
        src = sqlite3.connect(self.db)
        src.execute('PRAGMA journal_mode=WAL')
        src.execute("INSERT INTO source_health(source,status) VALUES ('test','ok')")
        src.commit()  # leave the original WAL-connection OPEN throughout backup
        self.runctl('backup','--db',self.db,'--dir',self.backups)
        files = list(self.backups.glob('*.sqlite'))
        self.assertEqual(len(files), 1)
        target = files[0]
        self.runctl('verify',target)
        self.assertEqual(sqlite3.connect(target).execute('SELECT COUNT(*) FROM source_health').fetchone()[0],1)
        self.assertNotEqual(self.runctl('restore',target,'--db',self.db,ok=False).returncode,0)
        src.close()
        # Disable SQLite WAL to ensure the offline restore may proceed.
        for suffix in ('-wal','-shm'):
            pathlib.Path(str(self.db)+suffix).unlink(missing_ok=True)
        self.runctl('restore',target,'--db',self.db,'--offline-confirm')
        self.assertEqual(sqlite3.connect(self.db).execute('SELECT COUNT(*) FROM source_health').fetchone()[0],1)
        preserved = list(self.root.glob('sentinel.sqlite.pre-restore-*'))
        self.assertEqual(len(preserved), 1)
        self.assertEqual(self.db.stat().st_uid, preserved[0].stat().st_uid)
        self.assertEqual(self.db.stat().st_mode & 0o777, 0o600)
        fresh = self.root / 'fresh' / 'sentinel.sqlite'
        self.runctl('restore',target,'--db',fresh,'--offline-confirm')
        with sqlite3.connect(fresh) as restored:
            self.assertEqual(restored.execute('SELECT source,status FROM source_health').fetchall(), [('test','ok')])
        os.link(target, self.root / 'backup-hardlink')
        self.assertNotEqual(self.runctl('restore',target,'--db',self.root/'backup-hardlink',
                                        '--offline-confirm',ok=False).returncode,0)
        with target.open('ab') as fh: fh.write(b'tamper')
        self.assertNotEqual(self.runctl('verify',target,ok=False).returncode,0)
    def test_retention_preserves_detection_evidence(self):
        with sqlite3.connect(self.db) as c:
            c.execute('PRAGMA foreign_keys=ON')
            c.execute("INSERT INTO raw_events(event_id,source,ingested_at,raw_json,payload_sha256,parser_version) VALUES ('r1','test','2020-01-01T00:00:00Z','{}',?,2)",('0'*64,))
            c.execute("INSERT INTO raw_events(event_id,source,ingested_at,raw_json,payload_sha256,parser_version) VALUES ('r2','test','2020-01-01T00:00:00Z','{}',?,2)",('0'*64,))
            c.execute("INSERT INTO security_events(event_id,raw_event_id,source,category,event_epoch) VALUES ('e1','r1','test','dns.query',1577836800)")
            c.execute("INSERT INTO security_events(event_id,raw_event_id,source,category,event_epoch) VALUES ('e2','r2','test','dns.query',1577836800)")
            c.execute("UPDATE detection_cursor SET last_row_id=100 WHERE pipeline='default'")
            c.execute("INSERT INTO incidents(id,subject_kind,subject_value,severity,first_seen_epoch,last_seen_epoch,title) VALUES ('i1','ip','192.0.2.1','low',1,1,'sample')")
            c.execute("INSERT INTO detections(id,fingerprint,rule_id,rule_version,severity,classification,entity_kind,entity_value,incident_id,window_start_epoch,first_seen_epoch,last_seen_epoch,observed_count,title,explanation) VALUES ('d1','fingerprint','rule',1,'low','deterministic','ip','192.0.2.1','i1',1,1,1,1,'sample','evidence')")
            c.execute("INSERT INTO detection_evidence(detection_id,security_event_id) VALUES ('d1','e1')")
        self.runctl('retention','--db',self.db,'--event-days',30,'--raw-days',45,'--dry-run')
        self.runctl('retention','--db',self.db,'--event-days',30,'--raw-days',45,'--confirm')
        with sqlite3.connect(self.db) as c:
            self.assertEqual([x[0] for x in c.execute('SELECT event_id FROM security_events')],['e1'])
            self.assertEqual([x[0] for x in c.execute('SELECT event_id FROM raw_events')],['r1'])
            self.assertEqual(c.execute('PRAGMA foreign_key_check').fetchall(),[])
    def test_migrations_apply_from_empty_database(self):
        with sqlite3.connect(self.db) as c:
            c.execute('PRAGMA foreign_keys=ON')
            self.assertIn('harness_sessions',[r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")])
            c.execute("INSERT INTO harness_sessions(trace_id,expires_epoch) VALUES ('trace',2000000000)")
            c.execute("INSERT INTO harness_tool_audit(trace_id,tool_name,args_sha256,status) VALUES ('trace','query',?,'ok')",('0'*64,))
            with self.assertRaises(sqlite3.IntegrityError):
                c.execute("INSERT INTO harness_tool_evidence(audit_row_id,trace_id,security_event_id) VALUES (1,'trace','fake')")

    def test_retention_preserves_expired_standalone_audit_evidence(self):
        with sqlite3.connect(self.db) as c:
            c.execute('PRAGMA foreign_keys=ON')
            c.execute("INSERT INTO raw_events(event_id,source,ingested_at,raw_json,payload_sha256,parser_version) VALUES ('r','test','2020-01-01T00:00:00Z','{}',?,2)", ('0'*64,))
            c.execute("INSERT INTO security_events(event_id,raw_event_id,source,category,event_epoch) VALUES ('e','r','test','dns.query',1577836800)")
            c.execute("UPDATE detection_cursor SET last_row_id=100 WHERE pipeline='default'")
            c.execute("INSERT INTO harness_sessions(trace_id,created_epoch,expires_epoch) VALUES ('trace',1,2)")
            c.execute("INSERT INTO harness_tool_audit(trace_id,tool_name,args_sha256,status,created_at) VALUES ('trace','query',?,'ok','2020-01-01T00:00:00Z')", ('0'*64,))
            c.execute("INSERT INTO harness_tool_evidence(audit_row_id,trace_id,security_event_id) VALUES (1,'trace','e')")
        for _ in range(2):
            self.runctl('retention','--db',self.db,'--confirm')
        with sqlite3.connect(self.db) as c:
            for table in ('raw_events','security_events','harness_tool_audit','harness_tool_evidence','harness_sessions'):
                self.assertEqual(c.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0], 1)

if __name__ == '__main__':
    unittest.main()
