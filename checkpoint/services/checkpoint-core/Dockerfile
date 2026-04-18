FROM python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb AS builder
WORKDIR /app

# Install build dependencies for python-ldap (requires libldap/libsasl headers)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsasl2-dev \
    libldap2-dev \
    libssl-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb

WORKDIR /app

# Runtime LDAP/SASL shared libraries (not dev headers)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsasl2-2 \
    libldap-2.5-0 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.13 /usr/local/lib/python3.13
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application source
COPY . .

# Expose web API, gRPC, LDAP, and LDAPS ports
EXPOSE 8080 50051 389 636

# Health check using stdlib — no curl needed
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

# Run as non-root by default (override to root in K8s if LDAP ports 389/636 are needed
# and NET_BIND_SERVICE capability is not available)
RUN useradd -r -u 1001 checkpoint
USER checkpoint

CMD ["python3", "-m", "hypercorn", "main:app", "--bind", "0.0.0.0:8080"]
