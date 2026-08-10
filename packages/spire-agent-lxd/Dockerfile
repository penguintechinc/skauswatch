# Multi-stage Dockerfile to build skauswatch-spire-agent .deb package
FROM ghcr.io/spiffe/spire-server:1.9.4@sha256:9a8c6c4e8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a AS spire-src

# Stage 2: Build .deb package
FROM debian:bookworm-slim@sha256:c5b1261d6d3e43071626931fc004f70149b8de4d4b2151b85a4506f1e2d361d0

ARG SPIRE_VERSION=1.9.4
ARG DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ruby-full \
    rubygems \
    git \
    curl \
    ca-certificates \
    && gem install --no-document fpm \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Create working directory
WORKDIR /build

# Copy SPIRE agent binary from official image
COPY --from=spire-src /opt/spire/bin/spire-agent /tmp/spire-agent

# Create package structure
RUN mkdir -p /tmp/package/{usr/local/bin,etc/spire-agent,var/lib/spire-agent,run/spire/sockets,lib/systemd/system}

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

# Output .deb to /dist for multi-arch extraction
RUN mkdir -p /dist && \
    cp /build/*.deb /dist/

CMD ["sh", "-c", "cp /build/*.deb /dist/ && ls -la /dist/"]
