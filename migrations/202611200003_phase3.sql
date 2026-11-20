-- Phase 3: additive, backward-compatible telemetry -> detection materialization.
-- Use an epoch integer: prior RFC3339 timestamps may use Z, +00:00 or offsets.
ALTER TABLE security_events ADD COLUMN event_epoch INTEGER;
UPDATE security_events SET event_epoch = CAST(strftime('%s', event_ts) AS INTEGER)
 WHERE event_ts IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sec_src_category_epoch ON security_events(source_ip, category, event_epoch);
CREATE INDEX IF NOT EXISTS idx_sec_src_action_epoch ON security_events(source_ip, action, event_epoch);
CREATE INDEX IF NOT EXISTS idx_sec_dns_client_epoch ON security_events(source_ip, event_epoch) WHERE category='dns.query';
CREATE INDEX IF NOT EXISTS idx_sec_fw_src_epoch ON security_events(source_ip,event_epoch) WHERE category='firewall.filterlog';

CREATE TABLE IF NOT EXISTS detection_cursor (
    pipeline TEXT PRIMARY KEY,
    last_row_id INTEGER NOT NULL DEFAULT 0 CHECK(last_row_id>=0),
    processed_events INTEGER NOT NULL DEFAULT 0 CHECK(processed_events>=0),
    skipped_events INTEGER NOT NULL DEFAULT 0 CHECK(skipped_events>=0),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
INSERT OR IGNORE INTO detection_cursor(pipeline) VALUES ('default');

CREATE TABLE IF NOT EXISTS assets (
    asset_key TEXT PRIMARY KEY,
    first_seen_epoch INTEGER NOT NULL,
    last_seen_epoch INTEGER NOT NULL,
    total_dns_queries INTEGER NOT NULL DEFAULT 0 CHECK(total_dns_queries>=0),
    total_firewall_blocks INTEGER NOT NULL DEFAULT 0 CHECK(total_firewall_blocks>=0),
    total_outbound_passes INTEGER NOT NULL DEFAULT 0 CHECK(total_outbound_passes>=0)
);
CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(last_seen_epoch DESC);

CREATE TABLE IF NOT EXISTS asset_domains (
    asset_key TEXT NOT NULL REFERENCES assets(asset_key),
    domain TEXT NOT NULL,
    first_seen_epoch INTEGER NOT NULL,
    last_seen_epoch INTEGER NOT NULL,
    query_count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(asset_key,domain)
);
CREATE INDEX IF NOT EXISTS idx_asset_domains_last ON asset_domains(asset_key,last_seen_epoch DESC);

CREATE TABLE IF NOT EXISTS asset_dns_buckets (
    asset_key TEXT NOT NULL REFERENCES assets(asset_key),
    bucket_start_epoch INTEGER NOT NULL,
    query_count INTEGER NOT NULL DEFAULT 0 CHECK(query_count>=0),
    PRIMARY KEY(asset_key,bucket_start_epoch)
);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    subject_kind TEXT NOT NULL CHECK(subject_kind IN ('ip','domain')),
    subject_value TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed')),
    severity TEXT NOT NULL CHECK(severity IN ('low','medium','high')),
    first_seen_epoch INTEGER NOT NULL,
    last_seen_epoch INTEGER NOT NULL,
    detection_count INTEGER NOT NULL DEFAULT 0,
    title TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_incidents_subject ON incidents(subject_kind,subject_value,last_seen_epoch DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_latest ON incidents(last_seen_epoch DESC);

CREATE TABLE IF NOT EXISTS detections (
    id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    rule_id TEXT NOT NULL,
    rule_version INTEGER NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('low','medium','high')),
    classification TEXT NOT NULL CHECK(classification IN ('deterministic','statistical')),
    entity_kind TEXT NOT NULL CHECK(entity_kind IN ('ip','domain')),
    entity_value TEXT NOT NULL,
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE RESTRICT,
    window_start_epoch INTEGER NOT NULL,
    first_seen_epoch INTEGER NOT NULL,
    last_seen_epoch INTEGER NOT NULL,
    observed_count INTEGER NOT NULL CHECK(observed_count>=0),
    title TEXT NOT NULL,
    explanation TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_detections_latest ON detections(last_seen_epoch DESC, id);
CREATE INDEX IF NOT EXISTS idx_detections_rule ON detections(rule_id,last_seen_epoch DESC);
CREATE INDEX IF NOT EXISTS idx_detections_incident ON detections(incident_id,last_seen_epoch DESC);

CREATE TABLE IF NOT EXISTS detection_evidence (
    detection_id TEXT NOT NULL REFERENCES detections(id) ON DELETE CASCADE,
    security_event_id TEXT NOT NULL REFERENCES security_events(event_id) ON DELETE RESTRICT,
    PRIMARY KEY(detection_id,security_event_id)
);
CREATE INDEX IF NOT EXISTS idx_detection_evidence_event ON detection_evidence(security_event_id);
