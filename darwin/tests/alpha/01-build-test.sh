#!/bin/bash
# Alpha Test 01: Build Verification
# Verifies all containers build successfully

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common/config.sh"

TEST_NAME="Alpha Build Test"
log_info "Starting $TEST_NAME"

# Initialize results file
echo "[]" > "$LOG_DIR/results.json"

# Test 1: Build flask-backend
log_info "Test 1/3: Building flask-backend..."
if docker compose -f docker-compose.yml -f docker-compose.smoke.yml build flask-backend > "$LOG_DIR/build-flask.log" 2>&1; then
    log_success "flask-backend build succeeded"
    save_test_result "flask-backend-build" "PASS"
else
    log_error "flask-backend build failed"
    save_test_result "flask-backend-build" "FAIL" "See $LOG_DIR/build-flask.log"
    exit 1
fi

# Test 2: Build webui
log_info "Test 2/3: Building webui..."
if docker compose build webui > "$LOG_DIR/build-webui.log" 2>&1; then
    log_success "webui build succeeded"
    save_test_result "webui-build" "PASS"
else
    log_error "webui build failed"
    save_test_result "webui-build" "FAIL" "See $LOG_DIR/build-webui.log"
    exit 1
fi

# Test 3: Verify images exist
log_info "Test 3/3: Verifying Docker images..."
FLASK_IMAGE=$(docker images -q darwin-flask-backend 2>/dev/null)
WEBUI_IMAGE=$(docker images -q darwin-webui 2>/dev/null)

if [ -n "$FLASK_IMAGE" ] && [ -n "$WEBUI_IMAGE" ]; then
    log_success "All Docker images created successfully"
    log_info "  - Flask backend: $FLASK_IMAGE"
    log_info "  - WebUI: $WEBUI_IMAGE"
    save_test_result "verify-images" "PASS"
else
    log_error "Some Docker images are missing"
    [ -z "$FLASK_IMAGE" ] && log_error "  - Flask backend image not found"
    [ -z "$WEBUI_IMAGE" ] && log_error "  - WebUI image not found"
    save_test_result "verify-images" "FAIL"
    exit 1
fi

print_summary
log_success "$TEST_NAME completed successfully"
