# Multi-stage build for worker-s3 service
FROM python:3.13-slim-bookworm@sha256:bb73517d48bd32016e15eade0c009b2724ec3a025a9975b5cd9b251d0dcadb33 as base

# Install system dependencies including ClamAV, yara, and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    clamav-daemon \
    libmagic1 \
    yara \
    libyara-dev \
    && rm -rf /var/lib/apt/lists/*

# Create required directories for ClamAV
RUN mkdir -p /var/run/clamav && \
    chmod 755 /var/run/clamav

# Configure ClamAV daemon
RUN sed -i 's/^#TCPSocket 3310/TCPSocket 3310/' /etc/clamav/clamd.conf && \
    sed -i 's/^#Foreground yes/Foreground true/' /etc/clamav/clamd.conf && \
    sed -i 's/^Foreground no/Foreground true/' /etc/clamav/clamd.conf

# Set working directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Copy entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Create non-root user and set permissions
RUN useradd -r -u 999 appuser && \
    chown -R appuser:appuser /app

# Switch to non-root user for execution
USER appuser

# Expose ClamAV TCP port
EXPOSE 3310

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import socket; s = socket.socket(); s.connect(('localhost', 3310)); s.close()" || exit 1

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command
CMD ["python3", "main.py"]
