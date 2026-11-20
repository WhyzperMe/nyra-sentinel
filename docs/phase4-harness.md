# Phase 4 — NYRA Harness bridge, API policy and investigation semantics

## Security boundaries

- **Collector** (`sentinel-server`): database + upstream polling + detection; no model dependency.
- **Agent** (`sentinel-agent`): only scoped read-token and report-token files; no SQLite mount,
  raw-event API token, ingest token, firewall credentials, SSH keys or Docker socket.
- **Model** (Ollama): receives curated tool results; it does not receive credentials and cannot
  directly make HTTP requests. Tool calls are mediated by the separate agent and server.
- **Operator**: configures runtime and reviews hypotheses; only a future distinct approved
  execution gateway would modify the firewall (not implemented).

## Threat model and limits

| Surface | Control | Remaining limitation |
|---|---|---|
| Prompt-injected logs | Never expose raw payloads to model, explicit system policy, fixed schema | Structured domain/IP strings can still be hostile; model can reason badly |
| Model proposing arbitrary tools | Hardcoded allowlist in agent + independently validated server dispatch | No guarantee the narrative is correct |
| Runaway research | 8 tool requests, 5 model rounds, 50 rows/query, 168 hours max, 48 KiB response | Operator can launch many separate jobs; orchestration limits needed if automated |
| Secret exposure | Distinct read and report credentials; separate container mounts | Docker host root / containers share an administrative trust boundary |
| Malicious SQL/payload | All queries fixed and parametrized; raw JSON never returned | Database corruption requires backups and monitoring |
| Forged evidence | UUIDs taken from structured results and checked by server FK lookups | Narrative may cite wrong ID or misinterpret real evidence |
| Audit loss | Tool audit rows, investigation trace IDs | A malicious local DB admin can alter records; no external WORM storage |
| Resource exhaustion | Bounded responses, requests, SQLite indexed filters | Additional auth rate limits, quotas and timeout tuning recommended at proxy |

## Read-only tool API

All below use `POST /api/v1/harness/query` (no general-purpose SQL tool) with a scoped read token.
Query syntax:

```json
{
  "trace_id": "550e8400-e29b-41d4-a716-446655440000",
  "tool": "get_ip_history",
  "arguments": {"ip": "203.0.113.7", "hours": 24, "limit": 25}
}
```

Tools: `search_events`, `get_event_details`, `get_ip_history`, `get_domain_history`,
`get_dns_activity`, `get_firewall_activity`, `get_crowdsec_decisions`, `get_asset_profile`,
`get_source_health`, `correlate_events`, `get_network_baseline`, `get_incident`,
`get_detections`. Queries return only selected normalized fields, not arbitrary log strings,
`details_json`, credentials or raw SQL. Numeric epoch timestamps are UTC.

`POST /api/v1/harness/reports` is separate and requires the **report-only token**.
It accepts a compact report, status `hypothesis` or `incomplete`, validated subject,
collected `evidence_ids` (zero to 64 known security-event UUIDs) and tool count (0–24).
The model cannot create a `confirmed` incident via this endpoint. The server records
unverified reports and tool audit rows under the same trace ID.

`GET /api/v1/harness/reports` is available to the agent read token or operator API token.

## Evidence quality and model usage

- A CrowdSec decision means a mitigation exists; not proof of exploitation.
- A blocked packet means a firewall action occurred; not proof of compromise.
- A DNS anomaly means activity differs from a local baseline; it is not a malware verdict.
- A public IP attached to an asset may be NAT/shared/ephemeral; avoid assumptions.
- Ingest gaps, stale source health or empty feeds must be explicitly acknowledged.
- Do not paste entire log files, private credentials or real VPN configs into the model prompt.

## Future extension

To add a tool: declare its JSON schema in `src/agent/tools.rs`, implement a bounded,
read-only parametrized query in `src/harness_api.rs`, add cross-layer validation,
update this document, then introduce unit/regression tests. **Never allow the model to
select an arbitrary URL, executable, shell command, database query or OPNsense API path.**

Phase 4 is an opt-in CLI investigation workflow, not a persistent autonomous hunting
scheduler. Operators can run it from an external scheduler with quotas and approval;
it should not be presented as a perpetual autonomous SOC service.

## Optional scheduled investigations

Copy `configs/hunt-targets.example` to `configs/hunt-targets.txt` (ignored by Git),
`sudo chown root:root configs/hunt-targets.txt && sudo chmod 600 configs/hunt-targets.txt`,
review a maximum of five explicitly authorized subjects, then run
`sudo ./scripts/scheduled-hunt.sh`. The host script uses `flock` to prohibit overlap;
it only launches `sentinel-agent` read-only investigations. Configure a trusted cron
schedule only after real-model tests succeed. Protect cron outputs (reports may include
private telemetry). The Docker CLI has high host privileges; run from a trusted
administrator context and never expose the Docker socket to the model container.
