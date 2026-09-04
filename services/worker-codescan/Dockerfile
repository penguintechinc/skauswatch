# syntax=docker/dockerfile:1.7
#
# worker-codescan — consumes the `codescan:tasks` stream with the shared
# consumer-group harness and runs the AI code-review pipeline. Multi-stage:
# compiled against the full workspace in a Rust builder image, shipped as a
# single binary in a minimal non-root Debian runtime.
#
# Workspace build — context MUST be the repo root:
#   docker build -f services/worker-codescan/Dockerfile -t <tag> .

FROM rust:1.97-slim-bookworm@sha256:99e09cb2284e2ddbb73a995deee3e91783fd04d177602ccf6eab326d778ee777 AS builder

# aws-lc-sys (rustls' default crypto provider, pulled in transitively by
# reqwest/sqlx-tls) needs cmake + a C/C++ compiler + perl for its assembly
# codegen, plus libclang for bindgen. git is needed for the penguin-licensing
# workspace dependency (pinned git rev).
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
    --mount=type=cache,target=/build/target,id=skauswatch-cargo-target-worker-codescan,sharing=locked \
    cargo build --release --locked -p skauswatch-worker-codescan \
    && cp target/release/worker-codescan /tmp/worker-codescan

# --- Runtime -----------------------------------------------------------
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

# Auto-populated by buildx (docs/v2-port devops-containers.md Multi-Arch
# Builds) — selects the right gitleaks/trivy/syft release asset + checksum
# below for `linux/amd64` and `linux/arm64` alike.
ARG TARGETARCH

ARG VERSION=0.0.0-dev
LABEL org.opencontainers.image.title="worker-codescan" \
      org.opencontainers.image.description="SkausWatch CodeScan code-review worker — consumes codescan:tasks stream (Rust port)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.vendor="Penguin Tech Inc" \
      org.opencontainers.image.source="https://github.com/penguintechinc/skauswatch" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

# ca-certificates: TLS roots for outbound reqwest/sqlx-tls/git-provider calls
# (rustls only — workspace deny.toml bans openssl-sys). curl: fetches the
# pinned scanner-tool release tarballs below (removed again after use, see
# the final `apt-get purge` line, to keep it out of the shipped image).
# python3/python3-pip: semgrep has no standalone static binary — its PyPI
# package installs a thin Python CLI wrapper around a native core, so a
# Python 3 runtime is a genuine dependency here, not just a build tool.
#
# CodeScan Sentinel P2 tool registry
# (docs/v2-port/v2.1-codescan-sentinel.md §3): semgrep (SAST), gitleaks
# (secrets), trivy (IaC/misconfig), syft (SBOM) — see `crate::scanner_tool`
# for how each is invoked. Every one of these is genuinely-absent-tolerant
# (`crate::scanner_tool::ProcessRunner` degrades to `ScanOutcome::Unavailable`,
# never a panic) — installing them here is a completeness/performance
# choice, not a hard runtime dependency of the binary itself.
#
# Pinning: gitleaks/trivy/syft are pinned to an exact release tag with a
# sha256 checksum verified against each project's own published
# `*_checksums.txt` release asset (both linux/amd64 and linux/arm64 — see
# the case statement below). semgrep is pinned to an exact PyPI version
# only, with no hash: its dependency tree is large enough (dozens of
# transitive wheels) that hash-pinning it inline in a single RUN instruction
# isn't practical without a companion `requirements.txt` +
# `pip download --require-hashes` step — flagged here as a known gap rather
# than a fabricated checksum (see `general.md` Red Flags: never fake a
# security control).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        python3 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 appuser \
    && useradd --system --uid 10001 --gid appuser --no-create-home --shell /usr/sbin/nologin appuser \
    && pip3 install --no-cache-dir --break-system-packages "semgrep==1.174.0" \
    && case "${TARGETARCH}" in \
         amd64) \
           GITLEAKS_ARCH="x64"; \
           GITLEAKS_SHA="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"; \
           TRIVY_ARCH="64bit"; \
           TRIVY_SHA="2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"; \
           SYFT_ARCH="amd64"; \
           SYFT_SHA="2a2e837a2c8d59ec9af5472ee22d3b04ee463c4e44476ecf993fd1e5ab6ebc7f" \
           ;; \
         arm64) \
           GITLEAKS_ARCH="arm64"; \
           GITLEAKS_SHA="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"; \
           TRIVY_ARCH="ARM64"; \
           TRIVY_SHA="b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5"; \
           SYFT_ARCH="arm64"; \
           SYFT_SHA="6c0466811541ea03add5213a60a1562f0851e4c0b0ecfdee1a694a9455285900" \
           ;; \
         *) \
           echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; \
           exit 1 \
           ;; \
       esac \
    && curl -fsSL -o /tmp/gitleaks.tar.gz \
         "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_${GITLEAKS_ARCH}.tar.gz" \
    && printf '%s  /tmp/gitleaks.tar.gz\n' "${GITLEAKS_SHA}" > /tmp/gitleaks.sha256 \
    && sha256sum -c /tmp/gitleaks.sha256 \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm -f /tmp/gitleaks.tar.gz /tmp/gitleaks.sha256 \
    && curl -fsSL -o /tmp/trivy.tar.gz \
         "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-${TRIVY_ARCH}.tar.gz" \
    && printf '%s  /tmp/trivy.tar.gz\n' "${TRIVY_SHA}" > /tmp/trivy.sha256 \
    && sha256sum -c /tmp/trivy.sha256 \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm -f /tmp/trivy.tar.gz /tmp/trivy.sha256 \
    && curl -fsSL -o /tmp/syft.tar.gz \
         "https://github.com/anchore/syft/releases/download/v1.51.0/syft_1.51.0_linux_${SYFT_ARCH}.tar.gz" \
    && printf '%s  /tmp/syft.tar.gz\n' "${SYFT_SHA}" > /tmp/syft.sha256 \
    && sha256sum -c /tmp/syft.sha256 \
    && tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft \
    && rm -f /tmp/syft.tar.gz /tmp/syft.sha256 \
    && chmod 0755 /usr/local/bin/gitleaks /usr/local/bin/trivy /usr/local/bin/syft \
    && apt-get purge -y --auto-remove curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder --chown=appuser:appuser /tmp/worker-codescan /usr/local/bin/worker-codescan

USER appuser

# Health/metrics HTTP endpoint (HEALTH_PORT, default 8080) — no other
# listener; work is pulled from the `codescan:tasks` stream.
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["worker-codescan", "healthcheck"]

ENTRYPOINT ["worker-codescan"]
