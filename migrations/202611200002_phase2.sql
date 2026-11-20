-- Additive migration: existing Phase 1 database rows remain intact.
ALTER TABLE raw_events ADD COLUMN delivery_id TEXT;
ALTER TABLE raw_events ADD COLUMN parse_status TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE raw_events ADD COLUMN parse_error TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS ux_raw_delivery ON raw_events(delivery_id) WHERE delivery_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_raw_native ON raw_events(source, source_native_id) WHERE source_native_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS security_events (
    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    raw_event_id TEXT NOT NULL REFERENCES raw_events(event_id) ON DELETE RESTRICT,
    source TEXT NOT NULL,
    event_ts TEXT,
    category TEXT NOT NULL,
    action TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    source_port INTEGER,
    destination_port INTEGER,
    protocol TEXT,
    interface TEXT,
    direction TEXT,
    rule_tracker TEXT,
    domain TEXT,
    dns_qtype TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    parser_version INTEGER NOT NULL DEFAULT 2
);
CREATE INDEX IF NOT EXISTS idx_security_events_source ON security_events(source, row_id DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_src ON security_events(source_ip, row_id DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_dst ON security_events(destination_ip, row_id DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_domain ON security_events(domain, row_id DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_category ON security_events(category, row_id DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_ts ON security_events(event_ts);

CREATE TABLE IF NOT EXISTS ingestion_checkpoints (
    source TEXT PRIMARY KEY,
    cursor TEXT,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS source_health (
    source TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    last_attempt TEXT,
    last_success TEXT,
    last_error TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_batch_inserted INTEGER NOT NULL DEFAULT 0,
    last_batch_duplicates INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS crowdsec_decisions (
    id TEXT PRIMARY KEY,
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    stable_hash TEXT NOT NULL,
    scope TEXT,
    value TEXT,
    action TEXT,
    scenario TEXT,
    origin TEXT,
    raw_json TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    last_changed TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_crowdsec_active ON crowdsec_decisions(active, id);
