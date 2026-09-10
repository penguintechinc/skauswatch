# syntax=docker/dockerfile:1.7
#
# skauswatch-svc-ingest — multi-protocol SIEM log ingest (syslog UDP/TCP/TLS,
# OTLP gRPC/HTTP, HTTPS OCSF/JSON), normalizing to OCSF and buffering
# through NATS JetStream ahead of the unified OpenSearch lake. Multi-stage:
# compiled against the full workspace in a Rust builder image, shipped as a
# single binary in a minimal non-root Debian runtime.
#
# Workspace build — context MUST be the repo root:
#   docker build -f services/svc-ingest/Dockerfile -t <tag> .

FROM rust:1.97-slim-bookworm@sha256:99e09cb2284e2ddbb73a995deee3e91783fd04d177602ccf6eab326d778ee777 AS builder

# aws-lc-sys (rustls' default crypto provider, pulled in transitively by
# reqwest/sqlx-tls/tonic) needs cmake + a C/C++ compiler + perl for assembly
# codegen, plus libclang for bindgen. git is needed for the
# penguin-licensing workspace dependency (pinned git rev). protox (proto
# codegen for skauswatch-proto) is pure Rust — no protoc needed.
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
        clang \
        libclang-dev \
        perl \
        pkg-config \
        g++ \
        make \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Full workspace manifests + source. Every service path-depends on
# crates/skauswatch-*, so cargo needs real source (not stub files) to
# resolve the workspace at all — a manifests-only pre-copy layer doesn't
# buy anything here. Real incremental-build caching comes from the
# BuildKit cache mounts below (registry + target dir), which persist
# independently of whether this COPY layer's hash changes.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY services/ services/
COPY proto/ proto/

# rust-toolchain.toml (repo root) pins rustup channel "1.97.0" exactly, but
# this builder image ships rustc 1.97.1 directly — the base image digest
# above *is* the toolchain pin. Deliberately not copied into the build
# context: doing so makes the rustup shim re-download 1.97.0 over the
# network on every build, which both defeats the point of pinning the base
# image by digest and makes the build non-hermetic.
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=skauswatch-cargo-registry,sharing=locked \
    --mount=type=cache,target=/build/target,id=skauswatch-cargo-target-svc-ingest,sharing=locked \
    cargo build --release --locked -p skauswatch-svc-ingest \
    && cp target/release/skauswatch-svc-ingest /tmp/skauswatch-svc-ingest

# --- Runtime -----------------------------------------------------------
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

ARG VERSION=0.0.0-dev
LABEL org.opencontainers.image.title="skauswatch-svc-ingest" \
      org.opencontainers.image.description="SkausWatch svc-ingest — multi-protocol SIEM log ingest (syslog/OTLP/HTTPS), OCSF normalization, NATS JetStream buffer, unified OpenSearch lake" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.vendor="Penguin Tech Inc" \
      org.opencontainers.image.source="https://github.com/penguintechinc/skauswatch" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

# ca-certificates: TLS roots for outbound reqwest/sqlx-tls/OpenSearch/Vault
# calls (rustls only — workspace deny.toml bans openssl-sys).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r appuser -g 1000 \
    && useradd -r -g appuser -u 1000 --no-create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /app \
    && chown appuser:appuser /app

WORKDIR /app

COPY --from=builder --chown=appuser:appuser /tmp/skauswatch-svc-ingest /app/skauswatch-svc-ingest

USER appuser

# Receiver mode: 8443 (HTTPS OCSF/JSON), 5140 (syslog UDP+TCP, unprivileged
# default), 6514 (syslog TLS), 4317 (OTLP gRPC), 4318 (OTLP HTTP). Writer
# mode exposes none of these — see docs/v2-port/ingest-module-spec.md §9a.
EXPOSE 8443 5140/udp 5140/tcp 6514 4317 4318

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/app/skauswatch-svc-ingest", "healthcheck"]

ENTRYPOINT ["/app/skauswatch-svc-ingest"]
