"""Upgrade regression with historical rows, not just a fresh empty schema."""
import pathlib
import sqlite3
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MIGRATIONS = sorted((ROOT/'migrations').glob('*.sql'))

class UpgradeTests(unittest.TestCase):
    def test_phase4_data_survives_phase5_and_is_not_backfilled_as_verified(self):
        c = sqlite3.connect(':memory:')
        c.execute('PRAGMA foreign_keys=ON')
        for migration in MIGRATIONS[:4]:
            c.executescript(migration.read_text())
        c.execute("INSERT INTO raw_events(event_id,source,ingested_at,raw_json,payload_sha256,parser_version) VALUES ('old-raw','legacy','2026-11-01T00:00:00Z','{}',?,2)",('0'*64,))
        c.execute("INSERT INTO security_events(event_id,raw_event_id,source,category,event_epoch) VALUES ('old-event','old-raw','legacy','firewall.filterlog',1793491200)")
        c.execute("INSERT INTO harness_tool_audit(trace_id,tool_name,args_sha256,status) VALUES ('old-trace','get_ip_history',?,'ok')",('0'*64,))
        c.execute("INSERT INTO investigations(id,trace_id,subject_kind,subject_value,model,status,summary,report_json,evidence_json,tool_calls) VALUES ('old-report','old-trace','ip','192.0.2.1','old','incomplete','unverified','{}','[\"old-event\"]',1)")
        for migration in MIGRATIONS[4:]:
            c.executescript(migration.read_text())
        self.assertEqual(c.execute('SELECT COUNT(*) FROM investigations').fetchone()[0],1)
        self.assertEqual(c.execute('SELECT COUNT(*) FROM security_events').fetchone()[0],1)
        self.assertEqual(c.execute('SELECT COUNT(*) FROM harness_tool_audit').fetchone()[0],1)
        self.assertEqual(c.execute('SELECT COUNT(*) FROM harness_tool_evidence').fetchone()[0],0)
        self.assertEqual(c.execute('PRAGMA foreign_key_check').fetchall(),[])
        c.close()

    def test_phase6_audit_history_and_existing_state_survive(self):
        with sqlite3.connect(':memory:') as c:
            c.execute('PRAGMA foreign_keys=ON')
            for migration in MIGRATIONS[:6]:
                c.executescript(migration.read_text())
            c.execute("INSERT INTO raw_events(event_id,source,ingested_at,raw_json,payload_sha256,parser_version) VALUES ('r','legacy','2026-11-01T00:00:00Z','{}',?,2)", ('0'*64,))
            c.execute("INSERT INTO security_events(event_id,raw_event_id,source,category) VALUES ('e','r','legacy','firewall.filterlog')")
            c.execute("INSERT INTO response_proposals(id,evidence_event_id,action,target_ip,justification,duration_minutes,requester) VALUES ('p','e','temporary_block_ip','8.8.8.8','Synthetic retained Phase-6 evidence',10,'legacy')")
            c.execute("INSERT INTO response_audit(proposal_id,transition,actor) VALUES ('p','proposed','legacy')")
            c.executescript(MIGRATIONS[6].read_text())
            self.assertEqual(c.execute('SELECT actor,credential_role FROM response_audit').fetchone(),
                             ('legacy', 'legacy_unknown'))
            with self.assertRaises(sqlite3.IntegrityError):
                c.execute("UPDATE response_audit SET credential_role='operator'")
            self.assertEqual(c.execute('PRAGMA foreign_key_check').fetchall(), [])

if __name__=='__main__': unittest.main()
