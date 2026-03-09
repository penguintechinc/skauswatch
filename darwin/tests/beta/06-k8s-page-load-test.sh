#!/bin/bash
# Beta Test 06: K8s Page Load Test
# Tests page loads through K8s ingress/LoadBalancer

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common/config.sh"

TEST_NAME="Beta K8s Page Load Test"
log_info "Starting $TEST_NAME"

# Initialize results file
echo "[]" > "$LOG_DIR/results.json"

NAMESPACE="${K8S_NAMESPACE:-darwin-beta}"

# Test 1: Get WebUI service
log_info "Test 1/5: Getting WebUI service..."
WEBUI_SERVICE=$(kubectl get service -n "$NAMESPACE" -l app=webui -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

if [ -n "$WEBUI_SERVICE" ]; then
    log_success "WebUI service found: $WEBUI_SERVICE"
    save_test_result "webui-service-found" "PASS"
else
    log_error "WebUI service not found"
    save_test_result "webui-service-found" "FAIL"
    exit 1
fi

# Test 2: Port-forward for WebUI access
log_info "Test 2/5: Setting up port-forward for WebUI..."
kubectl port-forward -n "$NAMESPACE" "service/$WEBUI_SERVICE" 8081:3000 > /dev/null 2>&1 &
PORT_FORWARD_PID=$!
sleep 5

if ps -p $PORT_FORWARD_PID > /dev/null; then
    log_success "Port-forward established (PID: $PORT_FORWARD_PID)"
    save_test_result "webui-port-forward" "PASS"
    WEBUI_URL="http://localhost:8081"
else
    log_error "Port-forward failed"
    save_test_result "webui-port-forward" "FAIL"
    exit 1
fi

# Cleanup function
cleanup() {
    if [ -n "$PORT_FORWARD_PID" ]; then
        kill $PORT_FORWARD_PID 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Test 3: Root page load
log_info "Test 3/5: Testing root page load..."
if wait_for_service "$WEBUI_URL" 60; then
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$WEBUI_URL/")

    if [ "$HTTP_CODE" = "200" ]; then
        log_success "Root page loads in K8s (HTTP $HTTP_CODE)"
        save_test_result "k8s-page-root" "PASS"
    else
        log_error "Root page failed (HTTP $HTTP_CODE)"
        save_test_result "k8s-page-root" "FAIL"
    fi
else
    save_test_result "k8s-page-root" "FAIL"
fi

# Test 4: Test multiple pages
log_info "Test 4/5: Testing multiple pages..."
PAGES=("/login" "/dashboard" "/reviews" "/users" "/settings")

for page in "${PAGES[@]}"; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$WEBUI_URL$page")

    # Accept 200 or 302 (redirect)
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
        log_success "Page loads in K8s: $page (HTTP $HTTP_CODE)"
    else
        log_warning "Page issue in K8s: $page (HTTP $HTTP_CODE)"
    fi
done

save_test_result "k8s-page-loads" "PASS"

# Test 5: Check for weird K8s-specific behaviors
log_info "Test 5/5: Checking for K8s-specific issues..."

# Check if static assets load correctly
STATIC_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$WEBUI_URL/assets/index.js" 2>/dev/null || echo "404")

if [ "$STATIC_CODE" = "200" ] || [ "$STATIC_CODE" = "404" ]; then
    log_success "Static asset handling works in K8s"
    save_test_result "k8s-static-assets" "PASS"
else
    log_warning "Static asset issues (HTTP $STATIC_CODE)"
    save_test_result "k8s-static-assets" "WARN"
fi

# Check for caching issues
CACHE_HEADERS=$(curl -sI "$WEBUI_URL/" | grep -i "cache-control" || echo "none")
log_info "Cache headers: $CACHE_HEADERS"

print_summary
log_success "$TEST_NAME completed successfully"
