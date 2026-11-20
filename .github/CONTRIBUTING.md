# Contributing

NYRA Sentinel is an open-source project maintained under the **Whyzper.Me** identity.
Contributions should preserve collector independence from AI and the immutable read-only
tool interface. Please open an issue for API/schema changes and add regression tests.

## Developer flow

1. Install Rust specified in `rust-toolchain.toml`, Python 3 and Docker Compose.
2. Use the supplied `Cargo.lock` for builds. Review and commit any changes to it with the corresponding dependency update.
3. Run `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`,
   `cargo test --locked --all-targets`.
4. Install PyYAML and run `bash scripts/verify-offline.sh`. Install `cargo-audit` before running the release preflight.
5. Review any migration for old database compatibility and rollback safety.
6. Provide docs and safe fixtures; never use private user telemetry in CI or issues.

Open pull requests against `develop` if maintained, otherwise `main`.
Use Conventional Commits where reasonable (`feat:`, `fix:`, `docs:`, `test:`).
For use of MIT OR Apache-2.0, see both LICENSE files. Contributors agree their changes
can be distributed under either license.
