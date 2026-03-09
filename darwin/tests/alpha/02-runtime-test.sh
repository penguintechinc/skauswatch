#!/bin/bash
# Alpha Test 02: Runtime Verification
# Verifies all services start and pass health checks

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common/config.sh"

TEST_NAME="Alpha Runtime Test"
log_info "Starting $TEST_NAME"

# Initialize results file
echo "[]" > "$LOG_DIR/results.json"

# Test 1: Start all services
log_info "Test 1/5: Starting all services..."
docker compose -f docker-compose.yml -f docker-compose.smoke.yml up -d > "$LOG_DIR/docker-up.log" 2>&1

if [ $? -eq 0 ]; then
    log_success "Services started"
    save_test_result "services-start" "PASS"
else
    log_error "Failed to start services"
    save_test_result "services-start" "FAIL"
    exit 1
fi

# Wait a bit for services to initialize
sleep 10

# Test 2: Check container status
log_info "Test 2/5: Checking container status..."
CONTAINERS=("darwin-flask-smoke" "darwin-webui" "project-template-postgres" "project-template-redis")
ALL_RUNNING=true

for container in "${CONTAINERS[@]}"; do
    if docker ps --filter "name=$container" --filter "status=running" | grep -q "$container"; then
        log_success "Container running: $container"
    else
        log_error "Container not running: $container"
        ALL_RUNNING=false
    fi
done

if [ "$ALL_RUNNING" = true ]; then
    save_test_result "containers-running" "PASS"
else
    save_test_result "containers-running" "FAIL"
    docker compose logs > "$LOG_DIR/docker-logs.log" 2>&1
    exit 1
fi

# Test 3: PostgreSQL health check
log_info "Test 3/5: Checking PostgreSQL health..."
if docker exec project-template-postgres pg_isready -U app_user -d app_db > /dev/null 2>&1; then
    log_success "PostgreSQL is healthy"
    save_test_result "postgres-health" "PASS"
else
    log_error "PostgreSQL health check failed"
    save_test_result "postgres-health" "FAIL"
    exit 1
fi

# Test 4: Redis health check
log_info "Test 4/5: Checking Redis health..."
if docker exec project-template-redis redis-cli -a password ping 2>/dev/null | grep -q "PONG"; then
    log_success "Redis is healthy"
    save_test_result "redis-health" "PASS"
else
    log_error "Redis health check failed"
    save_test_result "redis-health" "FAIL"
    exit 1
fi

# Test 5: Wait for application health endpoints
log_info "Test 5/5: Waiting for application health endpoints..."

# Wait for Flask backend
if wait_for_service "$ALPHA_FLASK_URL/healthz" 60; then
    save_test_result "flask-health" "PASS"
else
    save_test_result "flask-health" "FAIL"
    docker logs darwin-flask-smoke > "$LOG_DIR/flask-logs.log" 2>&1
    exit 1
fi

# Wait for WebUI (may not have /healthz, so check root)
if wait_for_service "$ALPHA_WEBUI_URL" 60; then
    save_test_result "webui-health" "PASS"
else
    save_test_result "webui-health" "FAIL"
    docker logs darwin-webui > "$LOG_DIR/webui-logs.log" 2>&1
    exit 1
fi

print_summary
log_success "$TEST_NAME completed successfully"
