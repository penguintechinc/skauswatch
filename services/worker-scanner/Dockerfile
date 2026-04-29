# Multi-stage Dockerfile for SkausWatch Worker-Scanner Service
# Base: Debian 12 (bookworm) - Python 3.13

# ============================================================================
# Stage 1: Builder - Install dependencies and download tools
# ============================================================================
FROM python:3.13-slim-bookworm@sha256:bb73517d48bd32016e15eade0c009b2724ec3a025a9975b5cd9b251d0dcadb33 AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Download and install Nuclei binary (latest stable)
# Use the GitHub releases API to get the latest version for linux amd64
RUN NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') && \
    curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o nuclei.zip && \
    unzip nuclei.zip nuclei -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm nuclei.zip

# gowitness (HTTP screenshot tool) - fetch latest release dynamically
# Tag format is bare "X.Y.Z" (no v prefix), asset is gowitness-X.Y.Z-linux-amd64
RUN GOWITNESS_VERSION=$(curl -s https://api.github.com/repos/sensepost/gowitness/releases/latest | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/' | tr -d 'v') && \
    curl -fsSL "https://github.com/sensepost/gowitness/releases/download/${GOWITNESS_VERSION}/gowitness-${GOWITNESS_VERSION}-linux-amd64" \
    -o /usr/local/bin/gowitness && chmod +x /usr/local/bin/gowitness

# Masscan, Xvfb, xfreerdp for ASM scanning
# Note: xfreerdp3-x11 is only in Debian trixie+; bookworm ships freerdp2-x11
# vncsnapshot was removed from Debian after bullseye; not available in bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    masscan \
    xvfb \
    freerdp2-x11 \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ============================================================================
# Stage 2: Runtime - Minimal production image
# ============================================================================
FROM python:3.13-slim-bookworm@sha256:bb73517d48bd32016e15eade0c009b2724ec3a025a9975b5cd9b251d0dcadb33

# Labels
LABEL maintainer="Penguin Tech Inc"
LABEL description="SkausWatch Worker-Scanner Service"
LABEL version="1.0.0"

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user with UID 1000 to match K8s securityContext runAsUser: 1000
RUN groupadd -g 1000 scanner && useradd -u 1000 -g scanner -d /app -s /sbin/nologin scanner

WORKDIR /app

# Copy Nuclei binary from builder
COPY --from=builder /usr/local/bin/nuclei /usr/local/bin/nuclei

# Copy gowitness binary from builder
COPY --from=builder /usr/local/bin/gowitness /usr/local/bin/gowitness

# masscan needs raw socket capability - set during build, NET_RAW cap required at runtime via docker-compose
RUN apt-get update && apt-get install -y --no-install-recommends \
    masscan \
    xvfb \
    freerdp2-x11 \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && setcap cap_net_raw+ep /usr/bin/masscan

# Copy Python packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY . .

# Set ownership
RUN chown -R scanner:scanner /app

# Create writable directories for scanner user
RUN mkdir -p /home/scanner/.config/nuclei && \
    mkdir -p /app/databases && \
    mkdir -p /tmp/celerybeat && \
    chown -R scanner:scanner /home/scanner && \
    chown -R scanner:scanner /app/databases && \
    chown -R scanner:scanner /tmp/celerybeat

USER scanner

# Environment defaults
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WORKER_SCANNER_PORT=5004

EXPOSE 5004

# Healthcheck — use env var so K8s port overrides work
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f "http://localhost:${WORKER_SCANNER_PORT:-5004}/health" || exit 1

# Shell-form CMD so ${WORKER_SCANNER_PORT} is expanded at runtime
CMD gunicorn --bind "0.0.0.0:${WORKER_SCANNER_PORT:-5004}" --workers 2 --threads 4 --timeout 120 --access-logfile - "app:create_app()"
