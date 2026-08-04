# syntax=docker/dockerfile:1.7
#
# skauswatch-scanner — consumes the `scanner:tasks` stream and performs
# YARA + ClamAV + ASM (Nuclei/ZAP/OpenVAS) scanning. ClamAV is reached over
# the network (CLAMAV_PORT) — no libclamav is linked or shipped in this
# image. Multi-stage: compiled against the full workspace in a Rust builder
# image, shipped as a single binary in a minimal non-root Debian runtime.
#
# Workspace build — context MUST be the repo root:
#   docker build -f services/scanner/Dockerfile -t <tag> .

FROM rust:1.97-slim-bookworm@sha256:99e09cb2284e2ddbb73a995deee3e91783fd04d177602ccf6eab326d778ee777 AS builder

# aws-lc-sys (rustls' default crypto provider, pulled in transitively by
# reqwest/sqlx-tls) needs cmake + a C/C++ compiler + perl for its assembly
# codegen, plus libclang for bindgen. git is needed for the penguin-licensing
# workspace dependency (pinned git rev). yara-x is pure Rust — no libyara.
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
    --mount=type=cache,target=/build/target,id=skauswatch-cargo-target-scanner,sharing=locked \
    cargo build --release --locked -p skauswatch-scanner \
    && cp target/release/skauswatch-scanner /tmp/skauswatch-scanner

# --- Runtime -----------------------------------------------------------
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

ARG VERSION=0.0.0-dev
LABEL org.opencontainers.image.title="skauswatch-scanner" \
      org.opencontainers.image.description="SkausWatch scanner worker — YARA + ClamAV + ASM scanning (Rust port)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.vendor="Penguin Tech Inc" \
      org.opencontainers.image.source="https://github.com/penguintechinc/skauswatch" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

# ca-certificates: TLS roots for outbound reqwest/sqlx-tls calls.
# rustls only (workspace deny.toml bans openssl-sys) — nothing else needed.
#
# NOT YET DONE HERE, FLAGGED FOR THE DOCKERFILE/CHART OWNER: the ASM
# screenshot-capture stage (src/asm.rs) shells out to a `chromium` binary
# (CHROMIUM_BIN, default "chromium") that this image does not install.
# Until a `chromium`/`chromium-common` (or equivalent headless-capable)
# package is added here, ASM_SCREENSHOT_ENABLED=true will fail every
# capture with a `ScreenshotError::Spawn` (logged, non-fatal to the scan —
# see src/asm.rs module docs) rather than silently doing nothing. Installing
# it pulls in a large dependency tree (GTK/NSS/X11 libs) and needs
# `--no-sandbox` at runtime because this container is rootless
# (capabilities.drop: [ALL], non-root UID — Chromium's own setuid sandbox
# cannot initialize under that securityContext); this is the standard,
# narrower trade-off for headless Chromium in containers and does NOT
# require a `NET CAPABILITY EXCEPTION`-class securityContext change. If any
# Tetragon (or equivalent eBPF) process-execution policy gates this pod, it
# must additionally allow `chromium` spawning its own `--type=renderer/
# zygote/gpu-process` children, or captures will be killed at the LSM/eBPF
# layer instead of failing through src/asm.rs's own error handling.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 appuser \
    && useradd --system --uid 10001 --gid appuser --no-create-home --shell /usr/sbin/nologin appuser

COPY --from=builder --chown=appuser:appuser /tmp/skauswatch-scanner /usr/local/bin/skauswatch-scanner

USER appuser

# Health/metrics HTTP endpoint (HEALTH_PORT, default 8080) — no other
# listener; work is pulled from the `scanner:tasks` stream.
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["skauswatch-scanner", "healthcheck"]

ENTRYPOINT ["skauswatch-scanner"]
