## Scope and motivation

## Security impact
- [ ] No new privileged capabilities or unrestricted tool execution
- [ ] No secrets or raw sensitive telemetry in logs, tests, or CI artifacts
- [ ] Audit, token scopes and input limits reviewed

## Verification
- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --locked --all-targets -- -D warnings`
- [ ] `cargo test --locked --all-targets`
- [ ] `python3 scripts/check-phase4-offline.py`
- [ ] `python3 scripts/check-phase5-offline.py`
- [ ] `python3 -m unittest discover -s tests -p "test_*.py" -v`
- [ ] Docker Compose config and image build

## Rollback / migrations
