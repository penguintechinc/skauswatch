# syntax=docker/dockerfile:1.7
#
# endpoint-agent — process/file/network collector agent that reports to the
# manager service (Rust port of v1's Go endpoint-agent). Client agent, not a
# server: no listening port, health is a one-shot `--healthcheck` config/
# init check (this binary uses a plain `--healthcheck` flag, not the
# `healthcheck` subcommand the server/worker images use — see main.rs).
#
# Workspace build — context MUST be the repo root:
#   docker build -f services/endpoint-agent/Dockerfile -t <tag> .

FROM rust:1.97-slim-bookworm@sha256:99e09cb2284e2ddbb73a995deee3e91783fd04d177602ccf6eab326d778ee777 AS builder

# aws-lc-sys (rustls' default crypto provider, pulled in transitively by
# reqwest) needs cmake + a C/C++ compiler + perl for its assembly codegen,
# plus libclang for bindgen. git is needed for the penguin-licensing
# workspace dependency (pinned git rev). sysinfo/netstat2/walkdir (host
# collectors) are pure Rust.
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
    --mount=type=cache,target=/build/target,id=skauswatch-cargo-target-endpoint-agent,sharing=locked \
    cargo build --release --locked -p skauswatch-endpoint-agent \
    && cp target/release/endpoint-agent /tmp/endpoint-agent

# --- Runtime -----------------------------------------------------------
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

ARG VERSION=0.0.0-dev
LABEL org.opencontainers.image.title="endpoint-agent" \
      org.opencontainers.image.description="SkausWatch endpoint agent — process/file/network collectors reporting to the manager (Rust port)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.vendor="Penguin Tech Inc" \
      org.opencontainers.image.source="https://github.com/penguintechinc/skauswatch" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

# ca-certificates: TLS roots for outbound reqwest calls to the manager.
# rustls only (workspace deny.toml bans openssl-sys) — nothing else needed.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 appuser \
    && useradd --system --uid 10001 --gid appuser --no-create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /etc/skauswatch \
    && chown appuser:appuser /etc/skauswatch

COPY --from=builder --chown=appuser:appuser /tmp/endpoint-agent /usr/local/bin/endpoint-agent
# Sample config only (no secrets — api_key is populated via ENDPOINT_API_KEY
# env var / mounted Secret, never baked in). Overridden by a mounted
# ConfigMap at the same path in every real deployment (see
# deployments/kubernetes/daemonset.yaml); kept here so a standalone
# `docker run` still starts with sane defaults.
COPY --chown=appuser:appuser config/endpoint-agent.yaml /etc/skauswatch/endpoint-agent.yaml

# Default is non-root. The DaemonSet deployment adds host-level Linux
# capabilities (NET_ADMIN/SYS_ADMIN/SYS_PTRACE) for process/network
# collection — capabilities are grantable to a non-root UID; they do not
# require runAsUser 0. Any need for actual root is a K8s securityContext
# decision requiring the standard root-exception approval (see
# devops-containers.md), not something baked into this image.
USER appuser

# No listening port — client agent only, reports outbound to the manager.

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["endpoint-agent", "--healthcheck"]

ENTRYPOINT ["endpoint-agent"]
