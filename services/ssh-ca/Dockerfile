# Multi-stage build for SkausWatch SSH CA Service
# Stage 1: Build stage
FROM python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb AS builder

# Set build arguments
ARG BUILD_DATE
ARG VERSION
ARG VCS_REF

# Add metadata
LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="SkausWatch SSH CA" \
      org.label-schema.description="SkausWatch SSH CA Service - SSH Certificate Authority management" \
      org.label-schema.version=$VERSION \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.schema-version="1.0" \
      maintainer="SkausWatch Team <support@skauswatch.io>"

# Install system dependencies for building
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    pkg-config \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip and install build tools
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy dependency files
COPY requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Runtime stage
FROM python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb AS runtime

# Set runtime arguments
ARG BUILD_DATE
ARG VERSION
ARG VCS_REF

# Add metadata
LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="SkausWatch SSH CA" \
      org.label-schema.description="SkausWatch SSH CA Service - SSH Certificate Authority management" \
      org.label-schema.version=$VERSION \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.schema-version="1.0" \
      maintainer="SkausWatch Team <support@skauswatch.io>"

# Install runtime system dependencies including SSH utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    netcat-traditional \
    openssh-client \
    openssl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd -r skauswatch && \
    useradd -r -g skauswatch -d /app -s /bin/bash skauswatch

# Create application directories with strict permissions for SSH key operations
RUN mkdir -p /app/logs /app/certs /app/keys /app/data /app/ssh-ca && \
    chown -R skauswatch:skauswatch /app && \
    chmod 700 /app/keys /app/ssh-ca && \
    chmod 750 /app/certs

# Copy virtual environment from builder stage
COPY --from=builder --chown=skauswatch:skauswatch /opt/venv /opt/venv

# Set environment variables
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/app" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SERVICE_NAME="ssh-ca" \
    SERVICE_PORT="8002" \
    LOG_LEVEL="INFO" \
    ENVIRONMENT="production" \
    SSH_CA_DIR="/app/ssh-ca" \
    SSH_KEYS_DIR="/app/keys"

# Switch to non-root user
USER skauswatch

# Set working directory
WORKDIR /app

# Copy application code with proper ownership
COPY --chown=skauswatch:skauswatch . .

# Create entrypoint script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Wait for dependencies\n\
echo "Waiting for database..."\n\
while ! nc -z ${DATABASE_HOST:-postgres} ${DATABASE_PORT:-5432}; do\n\
  sleep 1\n\
done\n\
echo "Database is ready!"\n\
\n\
echo "Waiting for Redis..."\n\
while ! nc -z ${REDIS_HOST:-redis} ${REDIS_PORT:-6379}; do\n\
  sleep 1\n\
done\n\
echo "Redis is ready!"\n\
\n\
# Initialize SSH CA if needed\n\
if [ "$ENVIRONMENT" != "development" ] && [ ! -f "$SSH_CA_DIR/ssh_ca_key" ]; then\n\
  echo "Initializing SSH CA infrastructure..."\n\
  python -m skauswatch.services.ssh_ca.cli init-ca\n\
fi\n\
\n\
# Run database migrations\n\
if [ "$ENVIRONMENT" != "development" ]; then\n\
  echo "Running database migrations..."\n\
  python -m alembic upgrade head\n\
fi\n\
\n\
# Start the application\n\
echo "Starting SkausWatch SSH CA Service on port $SERVICE_PORT..."\n\
exec uvicorn skauswatch.services.ssh_ca.main:app \\\n\
  --host 0.0.0.0 \\\n\
  --port $SERVICE_PORT \\\n\
  --log-level ${LOG_LEVEL,,} \\\n\
  --access-log \\\n\
  --use-colors false\n\
' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:$SERVICE_PORT/health || exit 1

# Expose port
EXPOSE $SERVICE_PORT

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]