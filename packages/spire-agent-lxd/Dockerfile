# Multi-stage Dockerfile to build skauswatch-spire-agent .deb package
FROM ghcr.io/spiffe/spire-agent:1.9.4@sha256:66d73a745b3875f7e68f0dd48de9924231aab9a79a632f98f5c9479f95688110 AS spire-src

# Stage 2: Build .deb package. Stays root — apt-get and fpm's dir-to-.deb
# packaging (chown/chmod-ing arbitrary paths into the archive) both need it.
# Nothing from this stage ships in the final image except the built .deb.
FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241 AS builder

ARG SPIRE_VERSION=1.9.4
ARG DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ruby-full \
    rubygems \
    git \
    curl \
    ca-certificates \
    binutils \
    && gem install --no-document fpm \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Create working directory
WORKDIR /build

# Copy SPIRE agent binary from official image
COPY --from=spire-src /opt/spire/bin/spire-agent /tmp/spire-agent

# Create package structure. Explicit paths, not brace expansion — RUN uses
# /bin/sh (dash on Debian), which doesn't support `{a,b,c}` brace expansion;
# it was silently creating one literal directory named with braces instead
# of five real ones.
RUN mkdir -p \
    /tmp/package/usr/local/bin \
    /tmp/package/etc/spire-agent \
    /tmp/package/var/lib/spire-agent \
    /tmp/package/run/spire/sockets \
    /tmp/package/lib/systemd/system

# Copy binary
RUN cp /tmp/spire-agent /tmp/package/usr/local/bin/spire-agent && \
    chmod 755 /tmp/package/usr/local/bin/spire-agent

# Copy enroll script
COPY enroll.sh /tmp/package/usr/local/bin/spire-enroll
RUN chmod 755 /tmp/package/usr/local/bin/spire-enroll

# Copy systemd service file
COPY files/spire-agent.service /tmp/package/lib/systemd/system/spire-agent.service

# Copy config template
COPY files/agent.conf.template /tmp/package/etc/spire-agent/agent.conf.template

# Create pre/post install scripts
RUN mkdir -p /tmp/scripts

# Pre-install script
RUN cat > /tmp/scripts/before-install.sh <<'EOF' && chmod 755 /tmp/scripts/before-install.sh
#!/bin/sh
if ! id -u spire > /dev/null 2>&1; then
  useradd -r -s /bin/false -d /var/lib/spire-agent spire || true
fi
EOF

# Post-install script
RUN cat > /tmp/scripts/after-install.sh <<'EOF' && chmod 755 /tmp/scripts/after-install.sh
#!/bin/sh
systemctl daemon-reload || true
if systemctl is-enabled spire-agent > /dev/null 2>&1; then
  systemctl restart spire-agent || true
fi
EOF

# Build .deb package
RUN fpm \
    --input-type dir \
    --output-type deb \
    --name skauswatch-spire-agent \
    --version ${SPIRE_VERSION} \
    --architecture $(dpkg --print-architecture) \
    --maintainer "PenguinTech <justin@penguintech.io>" \
    --description "SPIFFE/SPIRE Agent for SkausWatch cluster enrollment" \
    --url "https://github.com/penguintechinc/skauswatch" \
    --before-install /tmp/scripts/before-install.sh \
    --after-install /tmp/scripts/after-install.sh \
    --depends libcap2 \
    --deb-no-default-config-files \
    -C /tmp/package \
    -p /build/skauswatch-spire-agent_${SPIRE_VERSION}_$(dpkg --print-architecture).deb \
    .

# Stage 3: minimal, non-root image holding only the built .deb — this is
# what `docker buildx build --output type=oci,dest=...` (see this package's
# Makefile) and `docker create`+`docker cp` both export/extract from, so the
# .deb has to be baked in at build time here rather than produced by a
# runtime CMD.
FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN mkdir -p /dist
COPY --from=builder --chown=appuser:appuser /build/*.deb /dist/
USER appuser
WORKDIR /dist
CMD ["sh", "-c", "ls -la /dist/"]
