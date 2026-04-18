# SkausWatch Manager Service
# Multi-stage build for production deployment

FROM python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy gRPC directory
COPY grpc/ ./grpc/

# Generate gRPC stubs if proto files exist
RUN mkdir -p ./grpc/generated && \
    touch ./grpc/generated/__init__.py && \
    if ls ./grpc/protos/*.proto 1> /dev/null 2>&1; then \
        python -m grpc_tools.protoc \
            -I./grpc/protos \
            --python_out=./grpc/generated \
            --grpc_python_out=./grpc/generated \
            ./grpc/protos/*.proto; \
    fi

# Production image
FROM python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb

LABEL maintainer="Penguin Tech Inc <support@penguintech.io>"
LABEL description="SkausWatch Manager Service"

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    wget \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash appuser

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy generated gRPC stubs
COPY --from=builder /build/grpc/generated ./grpc/generated/

# Copy application code
COPY . .

# Set ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    QUART_ENV=production \
    API_PORT=5000 \
    GRPC_PORT=50051

# Expose ports
EXPOSE 5000 50051

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:5000/healthz || exit 1

# Run the application
CMD ["python", "main.py"]
