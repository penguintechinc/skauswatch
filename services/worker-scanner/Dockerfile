# Multi-stage Dockerfile for SkausWatch Worker-Scanner Service
# Base: Debian 12 (bookworm) - Python 3.13

# ============================================================================
# Stage 1: Builder - Install dependencies and download tools
# ============================================================================
FROM python:3.13-slim-bookworm AS builder

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

# gowitness (HTTP screenshot tool)
ARG GOWITNESS_VERSION=2.5.1
RUN curl -fsSL https://github.com/sensepost/gowitness/releases/download/${GOWITNESS_VERSION}/gowitness-linux-amd64 \
    -o /usr/local/bin/gowitness && chmod +x /usr/local/bin/gowitness

# Masscan, Xvfb, xfreerdp, vncsnapshot for ASM scanning
RUN apt-get update && apt-get install -y --no-install-recommends \
    masscan \
    xvfb \
    xfreerdp3-x11 \
    vncsnapshot \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ============================================================================
# Stage 2: Runtime - Minimal production image
# ============================================================================
FROM python:3.13-slim-bookworm

# Labels
LABEL maintainer="Penguin Tech Inc"
LABEL description="SkausWatch Worker-Scanner Service"
LABEL version="1.0.0"

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r scanner && useradd -r -g scanner -d /app -s /sbin/nologin scanner

WORKDIR /app

# Copy Nuclei binary from builder
COPY --from=builder /usr/local/bin/nuclei /usr/local/bin/nuclei

# Copy gowitness binary from builder
COPY --from=builder /usr/local/bin/gowitness /usr/local/bin/gowitness

# masscan needs raw socket capability - set during build, NET_RAW cap required at runtime via docker-compose
RUN apt-get update && apt-get install -y --no-install-recommends \
    masscan \
    xvfb \
    xfreerdp3-x11 \
    vncsnapshot \
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
    WORKER_SCANNER_PORT=5001

EXPOSE 5001

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:5001/api/v1/scanner/healthz || exit 1

# Run with gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--workers", "2", "--threads", "4", "--timeout", "120", "--access-logfile", "-", "app:create_app()"]
