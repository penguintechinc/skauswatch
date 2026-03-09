#!/bin/bash
# Alpha Test Cleanup
# Stops services and cleans up test artifacts

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common/config.sh"

log_info "Cleaning up alpha test environment..."

# Stop Docker Compose services
log_info "Stopping Docker Compose services..."
docker compose -f docker-compose.yml -f docker-compose.smoke.yml down -v 2>/dev/null || true

# Remove test containers if they exist
log_info "Removing test containers..."
docker rm -f darwin-flask-smoke darwin-webui project-template-postgres project-template-redis 2>/dev/null || true

# Clean up Docker images (optional - comment out if you want to keep them)
# log_info "Removing test Docker images..."
# docker rmi -f darwin-flask-smoke darwin-webui 2>/dev/null || true

log_success "Alpha test environment cleaned up"
log_info "Test logs preserved in: $LOG_DIR"
