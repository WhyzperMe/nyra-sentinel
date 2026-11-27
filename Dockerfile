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

FROM debian:13-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/ /usr/local/bin/
USER 10001:10001
EXPOSE 8080/tcp
ENTRYPOINT ["/usr/local/bin/sentinel-server"]
