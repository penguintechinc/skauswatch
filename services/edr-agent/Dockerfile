# SkausWatch EDR Agent
# Multi-stage build for minimal production image

FROM golang:1.24-alpine@sha256:97e88f65eef97e6c16f5a2a5e4a69f2a1c6b9e7d63e8f5d6c5e4f3a2b1c0d9e AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache gcc musl-dev

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
FROM alpine:3.19@sha256:13b7e62e8df80264dbb747995705a986f08c7cb5e0c6e3f96d5117d861d213fa

LABEL maintainer="Penguin Tech Inc <support@penguintech.io>"
LABEL description="SkausWatch EDR Agent"

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -g '' edr

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
