# Multi-stage build for SkausWatch AAA Monitor Service
# Stage 1: Build stage
FROM python:3.13-slim-bookworm@sha256:bb73517d48bd32016e15eade0c009b2724ec3a025a9975b5cd9b251d0dcadb33 AS builder

# Set build arguments
ARG BUILD_DATE
ARG VERSION
ARG VCS_REF

# Add metadata
LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="SkausWatch AAA Monitor" \
      org.label-schema.description="SkausWatch AAA Monitor Service - Authentication, Authorization, and Accounting monitoring" \
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
      org.label-schema.name="SkausWatch AAA Monitor" \
      org.label-schema.description="SkausWatch AAA Monitor Service - Authentication, Authorization, and Accounting monitoring" \
      org.label-schema.version=$VERSION \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.schema-version="1.0" \
      maintainer="SkausWatch Team <support@skauswatch.io>"

# Install runtime system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -g 1000 skauswatch && \
    useradd -u 1000 -g skauswatch -d /workspace -s /bin/bash skauswatch

# Create workspace and log directories
RUN mkdir -p /workspace/logs /workspace/audit /workspace/data /workspace/models && \
    chown -R skauswatch:skauswatch /workspace

# Copy virtual environment from builder stage
COPY --from=builder --chown=skauswatch:skauswatch /opt/venv /opt/venv

# Set environment variables
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/workspace" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SERVICE_NAME="aaa-monitor"

# Switch to non-root user
USER skauswatch

# Set working directory
WORKDIR /workspace

# Copy application code as a Python package (enables relative imports)
COPY --chown=skauswatch:skauswatch . /workspace/aaa_monitor/

# Health check using native Python
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:5003/health')" || exit 1

# Expose port
EXPOSE 5003

CMD ["python3", "-m", "aaa_monitor.main", "--host", "0.0.0.0", "--port", "5003"]