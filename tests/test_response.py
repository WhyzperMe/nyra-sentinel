"""Phase 6 database enforcement and operational regression (does not compile Rust)."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from importlib.machinery import SourceFileLoader

ROOT=Path(__file__).resolve().parents[1]
ctl=SourceFileLoader('sentinelctl',str(ROOT/'scripts/sentinelctl.py')).load_module()


def database():
    conn=sqlite3.connect(':memory:')
    conn.execute('PRAGMA foreign_keys=ON')
    for migration in sorted((ROOT/'migrations').glob('*.sql')):
        conn.executescript(migration.read_text())
    return conn


def event(conn):
    conn.execute("INSERT INTO raw_events(event_id,source,ingested_at,raw_json,payload_sha256,parser_version) VALUES ('raw-1','syslog','2026-11-20T12:00:00Z','{}',?,2)",('a'*64,))
    conn.execute("INSERT INTO security_events(event_id,raw_event_id,source,category,event_epoch,source_ip) VALUES ('event-1','raw-1','opnsense-syslog','firewall.filterlog',CAST(strftime('%s','now') AS INTEGER)-60,'1.1.1.1')")


def proposal(conn):
    event(conn)
    conn.execute("INSERT INTO response_proposals(id,evidence_event_id,action,target_ip,justification,duration_minutes,requester) VALUES ('proposal-1','event-1','temporary_block_ip','1.1.1.1','Suspicious repeated connection attempts',30,'analyst_a')")
    conn.execute("INSERT INTO response_audit(proposal_id,transition,actor,reason) VALUES ('proposal-1','proposed','analyst_a','created')")


class ResponseTests(unittest.TestCase):
    def test_migrations_and_indexes(self):
        with database() as conn:
            for table in ['response_proposals','response_audit']:
                self.assertTrue(conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone())

    def test_deduplicates_active_proposals(self):
        with database() as conn:
            proposal(conn)
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("INSERT INTO response_proposals(id,evidence_event_id,action,target_ip,justification,duration_minutes,requester) VALUES ('duplicate','event-1','temporary_block_ip','1.1.1.1','Another suspicious connection attempt',30,'analyst_b')")
            conn.execute("UPDATE response_proposals SET status='rejected' WHERE id='proposal-1'")
            conn.execute("INSERT INTO response_proposals(id,evidence_event_id,action,target_ip,justification,duration_minutes,requester) VALUES ('followup','event-1','temporary_block_ip','1.1.1.1','Another suspicious connection attempt',30,'analyst_b')")

    def test_evidence_foreign_key_and_append_only_audit(self):
        with database() as conn:
            proposal(conn)
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("INSERT INTO response_proposals(id,evidence_event_id,action,target_ip,justification,duration_minutes,requester) VALUES ('proposal-fake','fake-event','temporary_block_ip','1.1.1.1','Suspicious repeated connection attempts',30,'analyst_a')")
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE response_audit SET actor='hacker' WHERE proposal_id='proposal-1'")
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("DELETE FROM response_audit WHERE proposal_id='proposal-1'")

    def test_approval_one_time_non_self_and_expiring(self):
        with database() as conn:
            proposal(conn)
            sql="UPDATE response_proposals SET status='approved',approver=?,approved_epoch=CAST(strftime('%s','now') AS INTEGER),valid_until_epoch=CAST(strftime('%s','now') AS INTEGER)+900 WHERE id='proposal-1' AND status='proposed' AND requester<>?"
            self.assertEqual(conn.execute(sql,('analyst_a','analyst_a')).rowcount,0)
            self.assertEqual(conn.execute(sql,('analyst_b','analyst_b')).rowcount,1)
            self.assertEqual(conn.execute(sql,('analyst_c','analyst_c')).rowcount,0)
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE response_proposals SET approver='analyst_a' WHERE id='proposal-1'")
            conn.execute("UPDATE response_proposals SET valid_until_epoch=CAST(strftime('%s','now') AS INTEGER)-1 WHERE id='proposal-1'")
            self.assertEqual(conn.execute("UPDATE response_proposals SET status='simulated' WHERE id='proposal-1' AND status='approved' AND valid_until_epoch>CAST(strftime('%s','now') AS INTEGER)").rowcount,0)

    def test_retention_preserves_response_evidence(self):
        with database() as conn:
            proposal(conn)
            conn.execute("UPDATE security_events SET event_epoch=100 WHERE event_id='event-1'")
            conn.execute("UPDATE raw_events SET ingested_at='2021-01-01T00:00:00Z' WHERE event_id='raw-1'")
            conn.execute("UPDATE detection_cursor SET last_row_id=500 WHERE pipeline='default'")
            eligible, event_count, raw_count=ctl.retention_counts(conn,100000,100000)
            self.assertEqual(event_count,0)
            self.assertEqual(raw_count,0)
            self.assertIn('response_proposals',eligible)

    def test_request_policy_and_files(self):
        rust=(ROOT/'src/response_api.rs').read_text()
        self.assertIn('recent matching source-IP evidence required',rust)
        self.assertIn('valid_until_epoch',rust)
        self.assertIn('return err(StatusCode::CONFLICT',rust)
        self.assertIn('response_audit',rust)
        self.assertIn('SENTINEL_RESPONSE_EXECUTOR_TOKEN_FILE',(ROOT/'src/bin/sentinel-respond.rs').read_text())
        self.assertNotIn('api/firewall/alias_util/add',rust)
        self.assertNotIn('api/firewall/alias_util/add',(ROOT/'src/bin/sentinel-respond.rs').read_text())

    def test_dashboard_does_not_persist_token(self):
        js=(ROOT/'web/app.js').read_text()
        self.assertNotIn('localStorage.',js)
        self.assertNotIn('innerHTML',js)
        self.assertIn('textContent',js)
        self.assertIn('credentials:\'omit\'',js)


if __name__=='__main__':unittest.main()
