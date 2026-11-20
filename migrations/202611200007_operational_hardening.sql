ALTER TABLE response_audit ADD COLUMN credential_role TEXT NOT NULL DEFAULT 'legacy_unknown'
    CHECK(credential_role IN ('legacy_unknown','operator','approver','executor','system'));

CREATE INDEX idx_response_evidence_event ON response_proposals(evidence_event_id);
CREATE INDEX idx_crowdsec_inactive_last_changed ON crowdsec_decisions(last_changed) WHERE active=0;
CREATE INDEX idx_security_events_epoch ON security_events(event_epoch);
CREATE INDEX idx_asset_domains_retention ON asset_domains(last_seen_epoch);
