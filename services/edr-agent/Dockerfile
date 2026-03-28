# SkausWatch EDR Agent
# Multi-stage build for minimal production image

FROM golang:1.24-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod tidy && go mod download

# Copy source code
COPY . .

# Build the agent
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s" \
    -o edr-agent \
    ./cmd/edr-agent

# Production image
FROM debian:bookworm-slim@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb

LABEL maintainer="Penguin Tech Inc <support@penguintech.io>"
LABEL description="SkausWatch EDR Agent"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /sbin/nologin edr

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/edr-agent /app/

# Copy default config
COPY --from=builder /build/config/edr-agent.yaml /etc/skauswatch/edr-agent.yaml

# Set ownership
RUN chown -R edr:edr /app /etc/skauswatch

USER edr

# Environment variables
ENV EDR_MANAGER_URL=http://manager:5000 \
    EDR_DEBUG=false

ENTRYPOINT ["/app/edr-agent"]
