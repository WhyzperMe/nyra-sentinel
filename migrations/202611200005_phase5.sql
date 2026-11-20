-- Phase 5: server-owned, bounded investigation sessions and verifiable tool evidence.
-- No destructive changes to existing telemetry or investigations.
CREATE TABLE IF NOT EXISTS harness_sessions (
    trace_id TEXT PRIMARY KEY,
    subject_kind TEXT NOT NULL DEFAULT 'unknown' CHECK(subject_kind IN ('ip','domain','incident','unknown')),
    subject_value TEXT NOT NULL DEFAULT '',
    created_epoch INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),
    expires_epoch INTEGER NOT NULL,
    tool_calls INTEGER NOT NULL DEFAULT 0 CHECK(tool_calls BETWEEN 0 AND 24),
    CHECK(expires_epoch > created_epoch)
);
CREATE INDEX IF NOT EXISTS idx_harness_sessions_expiry ON harness_sessions(expires_epoch);

CREATE TABLE IF NOT EXISTS harness_tool_evidence (
    audit_row_id INTEGER NOT NULL REFERENCES harness_tool_audit(row_id) ON DELETE CASCADE,
    trace_id TEXT NOT NULL REFERENCES harness_sessions(trace_id) ON DELETE RESTRICT,
    security_event_id TEXT NOT NULL REFERENCES security_events(event_id) ON DELETE RESTRICT,
    PRIMARY KEY(audit_row_id, security_event_id)
);
CREATE INDEX IF NOT EXISTS idx_harness_evidence_trace ON harness_tool_evidence(trace_id, security_event_id);
CREATE INDEX IF NOT EXISTS idx_harness_evidence_event ON harness_tool_evidence(security_event_id);

-- Investigations in older versions carry evidence_json only; this migration deliberately
-- does NOT backfill provenance from those self-declared references.
