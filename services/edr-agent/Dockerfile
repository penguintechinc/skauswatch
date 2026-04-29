# SkausWatch EDR Agent
# Multi-stage build for minimal production image

FROM golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac AS builder

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
FROM debian:bookworm-slim@sha256:f9c6a2fd2ddbc23e336b6257a5245e31f996953ef06cd13a59fa0a1df2d5c252

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
