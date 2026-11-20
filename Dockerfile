FROM rust:1.100.0-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
RUN cargo fetch --locked
COPY src src
COPY migrations migrations
COPY web web
RUN --mount=type=cache,target=/build/target,sharing=locked \
    cargo build --frozen --release --bins \
    && install -D -t /out target/release/sentinel-server target/release/sentinel-agent target/release/sentinel-respond

FROM debian:13-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/ /usr/local/bin/
USER 10001:10001
EXPOSE 8080/tcp
ENTRYPOINT ["/usr/local/bin/sentinel-server"]
