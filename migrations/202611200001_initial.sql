CREATE TABLE IF NOT EXISTS raw_events (
    row_id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id             TEXT NOT NULL UNIQUE,
    source               TEXT NOT NULL,
    source_native_id     TEXT,
    event_ts             TEXT,
    ingested_at          TEXT NOT NULL,
    hostname             TEXT,
    appname              TEXT,
    severity             TEXT,
    facility             TEXT,
    message              TEXT,
    transport_peer_ip    TEXT,
    raw_json             TEXT NOT NULL,
    payload_sha256       TEXT NOT NULL,
    parser_version       INTEGER NOT NULL,
    CHECK (length(payload_sha256) = 64),
    CHECK (parser_version > 0)
);
CREATE INDEX IF NOT EXISTS idx_raw_events_ts ON raw_events(event_ts);
CREATE INDEX IF NOT EXISTS idx_raw_events_hostname ON raw_events(hostname, row_id DESC);
CREATE INDEX IF NOT EXISTS idx_raw_events_source ON raw_events(source, row_id DESC);
CREATE INDEX IF NOT EXISTS idx_raw_events_ingested ON raw_events(ingested_at);
