# syntax=docker/dockerfile:1.7
#
# skauswatch-manager — REST /api/v1 + gRPC control-plane server.
# Multi-stage: compiled against the full workspace in a Rust builder image,
# shipped as a single static-ish binary in a minimal non-root Debian runtime.
#
# Workspace build — context MUST be the repo root:
#   docker build -f services/manager/Dockerfile -t <tag> .

FROM rust:1.97-slim-bookworm@sha256:99e09cb2284e2ddbb73a995deee3e91783fd04d177602ccf6eab326d778ee777 AS builder

# aws-lc-sys (rustls' default crypto provider, pulled in transitively by
# reqwest/sqlx-tls everywhere in the workspace) needs cmake + a C/C++
# compiler + perl for its assembly codegen, plus libclang for bindgen. git is
# needed for the penguin-licensing workspace dependency (pinned git rev).
# protox (proto codegen) and yara-x are pure Rust — no protoc/libyara needed.
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
# crates/skauswatch-*, so cargo needs real source (not stub files) to resolve
# the workspace at all — a manifests-only pre-copy layer doesn't buy anything
# here. Real incremental-build caching comes from the BuildKit cache mounts
# below (registry + target dir), which persist independently of whether this
# COPY layer's hash changes.
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
    --mount=type=cache,target=/build/target,id=skauswatch-cargo-target-manager,sharing=locked \
    cargo build --release --locked -p skauswatch-manager \
    && cp target/release/skauswatch-manager /tmp/skauswatch-manager

# --- Runtime -----------------------------------------------------------
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

ARG VERSION=0.0.0-dev
LABEL org.opencontainers.image.title="skauswatch-manager" \
      org.opencontainers.image.description="SkausWatch manager service — REST /api/v1 + gRPC control plane (Rust port)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.vendor="Penguin Tech Inc" \
      org.opencontainers.image.source="https://github.com/penguintechinc/skauswatch" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

# ca-certificates: TLS roots for outbound reqwest/sqlx-tls/AWS SDK calls.
# rustls only (workspace deny.toml bans openssl-sys) — nothing else needed.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 appuser \
    && useradd --system --uid 10001 --gid appuser --no-create-home --shell /usr/sbin/nologin appuser

COPY --from=builder --chown=appuser:appuser /tmp/skauswatch-manager /usr/local/bin/skauswatch-manager

USER appuser

# REST /api/v1 (API_PORT, default 5000) + gRPC control plane (GRPC_PORT, default 50051)
EXPOSE 5000 50051

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["skauswatch-manager", "healthcheck"]

ENTRYPOINT ["skauswatch-manager"]
