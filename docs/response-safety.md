# Defensive response trust boundary

The response workflow records proposals, approvals, rejection, simulation and simulation rollback.

## Workflow

- Proposal: operator API token; IP must be parseable and routable-public by conservative checks (private, loopback, CGNAT, multicast, benchmark and documentation ranges excluded). Mandatory security event must show the *same* source IP, be at most seven days old and exist in SQLite. Duration 5–1440 minutes and human-readable reason 20–1024 characters.
- Human decision: separate approval token, a different submitted handle, explicit `APPROVED <uuid>` or `REJECTED <uuid>` confirmation and a reason. The decision and corresponding audit row commit in one transaction.
- Approval: 15-minute **execution permit**, not a 15-minute firewall block. A background expiry task marks unused approvals `expired`. A simulation may happen only during permit validity.
- Simulation-only response gateway: separate binary, short network timeout and a separately mounted executor token. Only `simulate` and `rollback` commands are supported. Result explicitly says `live_firewall_change=false`.
- Audit: role and submitted handle are recorded separately. SQLite triggers prevent ordinary application updates and deletes. A database administrator can modify or remove those triggers, so maintain restricted filesystem access and separate backups.

The response-policy target list is intentionally restrictive. IPv4/IPv6 special ranges must be reviewed against deployment-specific networks before introducing a future live executor.

Actor labels are self-asserted handles. Separate bearer tokens identify credential roles. The same person can hold both tokens, so this deployment provides role separation without an enforceable two-person guarantee.

## API (private only)

| Endpoint | Required secret | Action |
|---|---|---|
| `POST /api/v1/response/proposals` | operator | create proposal |
| `GET /api/v1/response/proposals` | operator | list proposals |
| `GET /api/v1/response/proposals/{id}` | operator | proposal + audit |
| `POST /api/v1/response/proposals/{id}/approve` | approval | one-time approve |
| `POST /api/v1/response/proposals/{id}/reject` | approval | one-time reject |
| `POST /api/v1/response/proposals/{id}/simulate` | executor | simulate only |
| `POST /api/v1/response/proposals/{id}/rollback` | executor | undo simulated state |

The dashboard keeps the approval token in the decision dialog and clears it when the dialog closes. The API is published on host loopback. Connect through SSH or a suitably authenticated reverse proxy.

## Before enabling any future live OPNsense implementation

1. Verify the OPNsense version and supported `firewall/alias_util` API endpoints on a test firewall; have an administrator create a dedicated, isolated deny alias and inspect the corresponding rules. Never create/modify arbitrary firewall rules from LLM output.
2. Use a *different privileged gateway process* with its own service account, mTLS and host-level egress restrictions to the firewall management interface only. It must not receive agent or database privileges.
3. Enforce identity-backed two-person approval, target CIDR allow/deny policies, maximum TTL, idempotent execution keys, remote read-back confirmation and permit expiry.
4. Implement time-limited rollback including restart and network-outage recovery, reconciliation of out-of-band changes and emergency manual cleanup.
5. Run negative tests against gateway/self/gateway-subnet blocking, replay, stolen tokens, unknown aliases, unexpected API schema and partial failure. Build integration tests with simulated response provider plus an explicitly isolated OPNsense lab.
6. Fail closed if OPNsense permissions, rule precedence, alias lifecycle or rollback cannot be verified.

The built-in gateway never sends any request to the firewall API. A status of `simulated` means **no network or security policy change occurred**.
