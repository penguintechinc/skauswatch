# Multi-stage build for SkausWatch SSH CA Service
# Stage 1: Build stage
FROM python:3.13-slim-bookworm@sha256:bb73517d48bd32016e15eade0c009b2724ec3a025a9975b5cd9b251d0dcadb33 AS builder

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
FROM python:3.13-slim-bookworm@sha256:bb73517d48bd32016e15eade0c009b2724ec3a025a9975b5cd9b251d0dcadb33 AS runtime

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

# Install runtime system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r skauswatch && \
    useradd -r -g skauswatch -d /app -s /bin/bash skauswatch

# Create application directories
RUN mkdir -p /app/logs && \
    chown -R skauswatch:skauswatch /app

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
    LOG_LEVEL="INFO"

# Switch to non-root user
USER skauswatch

# Set working directory
WORKDIR /app

# Copy application code with proper ownership
COPY --chown=skauswatch:skauswatch . .

# Health check using native Python
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD python3 -c "import urllib.request, os; urllib.request.urlopen('http://localhost:' + os.environ.get('API_PORT', '5002') + '/healthz')" || exit 1

# Expose port
EXPOSE 5002

CMD ["sh", "-c", "python3 -m hypercorn async_ssh_processor:app --bind 0.0.0.0:${API_PORT:-5002}"]