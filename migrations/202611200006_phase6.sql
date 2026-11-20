-- Phase 6: defensive response PROPOSALS and approvals.
-- Deliberately NO firewall writes. A separate and explicitly enabled executor is required
-- before any live action; the built-in gateway only simulates and records outcomes.
CREATE TABLE IF NOT EXISTS response_proposals (
    id TEXT PRIMARY KEY,
    incident_id TEXT REFERENCES incidents(id) ON DELETE RESTRICT,
    evidence_event_id TEXT NOT NULL REFERENCES security_events(event_id) ON DELETE RESTRICT,
    action TEXT NOT NULL CHECK(action='temporary_block_ip'),
    target_ip TEXT NOT NULL CHECK(length(target_ip) BETWEEN 3 AND 45),
    justification TEXT NOT NULL CHECK(length(justification) BETWEEN 20 AND 1024),
    duration_minutes INTEGER NOT NULL CHECK(duration_minutes BETWEEN 5 AND 1440),
    requester TEXT NOT NULL CHECK(length(requester) BETWEEN 3 AND 64),
    status TEXT NOT NULL DEFAULT 'proposed'
        CHECK(status IN ('proposed','approved','rejected','simulated','rolled_back','expired')),
    approver TEXT,
    approved_epoch INTEGER,
    valid_until_epoch INTEGER,
    created_epoch INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),
    updated_epoch INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),
    CHECK(approver IS NULL OR requester != approver)
);
CREATE INDEX IF NOT EXISTS idx_response_created ON response_proposals(created_epoch DESC,id);
-- Only one simultaneously pending/approved proposal per external target.
CREATE UNIQUE INDEX IF NOT EXISTS idx_response_one_active_target ON response_proposals(target_ip)
    WHERE status IN ('proposed','approved');
CREATE INDEX IF NOT EXISTS idx_response_status ON response_proposals(status,valid_until_epoch);
CREATE INDEX IF NOT EXISTS idx_response_target ON response_proposals(target_ip,created_epoch DESC);
CREATE TABLE IF NOT EXISTS response_audit (
    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
    proposal_id TEXT NOT NULL REFERENCES response_proposals(id) ON DELETE RESTRICT,
    transition TEXT NOT NULL CHECK(transition IN ('proposed','approved','rejected','simulated','rolled_back','expired')),
    actor TEXT NOT NULL CHECK(length(actor) BETWEEN 3 AND 64),
    reason TEXT NOT NULL DEFAULT '',
    created_epoch INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);
CREATE INDEX IF NOT EXISTS idx_response_audit_proposal ON response_audit(proposal_id,row_id);
CREATE TRIGGER IF NOT EXISTS response_audit_no_update BEFORE UPDATE ON response_audit
BEGIN SELECT RAISE(ABORT,'response audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS response_audit_no_delete BEFORE DELETE ON response_audit
BEGIN SELECT RAISE(ABORT,'response audit is append-only'); END;
