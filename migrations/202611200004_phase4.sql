-- Phase 4: add analysis provenance and independently auditable tool executions.
-- All writes are metadata/reports; no API write access to firewall or third-party sources.
CREATE TABLE IF NOT EXISTS harness_tool_audit (
  row_id INTEGER PRIMARY KEY AUTOINCREMENT,
  trace_id TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  args_sha256 TEXT NOT NULL CHECK(length(args_sha256)=64),
  status TEXT NOT NULL CHECK(status IN ('ok','rejected','failed')),
  result_count INTEGER NOT NULL DEFAULT 0,
  elapsed_ms INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_harness_audit_trace ON harness_tool_audit(trace_id,row_id);
CREATE INDEX IF NOT EXISTS idx_harness_audit_created ON harness_tool_audit(created_at);
CREATE TABLE IF NOT EXISTS investigations (
  id TEXT PRIMARY KEY,
  trace_id TEXT NOT NULL UNIQUE,
  subject_kind TEXT NOT NULL CHECK(subject_kind IN ('ip','domain','incident')),
  subject_value TEXT NOT NULL,
  model TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('hypothesis','incomplete')),
  summary TEXT NOT NULL,
  report_json TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  tool_calls INTEGER NOT NULL CHECK(tool_calls>=0 AND tool_calls<=24),
  prompt_version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_investigations_created ON investigations(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_investigations_subject ON investigations(subject_kind,subject_value,created_at DESC);
