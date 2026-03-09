# Build context: icebox/services/
# This Dockerfile is built from the icebox/services/ directory so it can
# COPY shared crypto/ and models/ from flask-backend.
#
# Build command (from icebox/services/):
#   docker build -f sync-worker/Dockerfile -t icebox-sync:latest .
#
# Or from repo root:
#   docker build \
#     -f .worktrees/icebox/icebox/services/sync-worker/Dockerfile \
#     -t icebox-sync:latest \
#     .worktrees/icebox/icebox/services/

FROM python:3.13-slim-bookworm AS builder

WORKDIR /app

# Build-time deps for native extensions (psycopg2-binary, cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY sync-worker/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --user -r requirements.txt

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM python:3.13-slim-bookworm

WORKDIR /app

# Runtime shared libraries needed by psycopg2 and cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Shared code from flask-backend — crypto module and PyDAL table definitions
COPY flask-backend/crypto /app/crypto
COPY flask-backend/models /app/models

# Sync-worker application source
COPY sync-worker/ /app/

# Non-root user
RUN useradd -r -u 1000 -s /sbin/nologin worker
USER worker

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python3 -c "import asyncio, aioredis, os; \
        asyncio.run(aioredis.from_url(os.getenv('REDIS_URL','redis://localhost')).ping())" \
    || exit 1

CMD ["python3", "-u", "main.py"]
