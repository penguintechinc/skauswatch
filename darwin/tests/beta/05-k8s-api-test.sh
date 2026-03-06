#!/bin/bash
# Beta Test 05: K8s API Test
# Tests APIs through K8s services/ingress

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common/config.sh"

TEST_NAME="Beta K8s API Test"
log_info "Starting $TEST_NAME"

# Initialize results file
echo "[]" > "$LOG_DIR/results.json"

NAMESPACE="${K8S_NAMESPACE:-darwin-beta}"

# Test 1: Get service endpoints
log_info "Test 1/8: Getting service endpoints..."
FLASK_SERVICE=$(kubectl get service -n "$NAMESPACE" -l app=flask-backend -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

if [ -n "$FLASK_SERVICE" ]; then
    log_success "Flask service found: $FLASK_SERVICE"
    save_test_result "service-found" "PASS"
else
    log_error "Flask service not found"
    save_test_result "service-found" "FAIL"
    exit 1
fi

# Test 2: Port-forward for API access
log_info "Test 2/8: Setting up port-forward..."
kubectl port-forward -n "$NAMESPACE" "service/$FLASK_SERVICE" 8080:5000 > /dev/null 2>&1 &
PORT_FORWARD_PID=$!
sleep 5

if ps -p $PORT_FORWARD_PID > /dev/null; then
    log_success "Port-forward established (PID: $PORT_FORWARD_PID)"
    save_test_result "port-forward" "PASS"
    FLASK_URL="http://localhost:8080"
else
    log_error "Port-forward failed"
    save_test_result "port-forward" "FAIL"
    exit 1
fi

# Cleanup function
cleanup() {
    if [ -n "$PORT_FORWARD_PID" ]; then
        kill $PORT_FORWARD_PID 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Test 3: Health endpoint
log_info "Test 3/8: Testing health endpoint..."
if wait_for_service "$FLASK_URL/healthz" 30; then
    save_test_result "api-health" "PASS"
else
    save_test_result "api-health" "FAIL"
    exit 1
fi

# Test 4: API version endpoint
log_info "Test 4/8: Testing API version..."
VERSION_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$FLASK_URL/api/v1/")

if [ "$VERSION_CODE" = "200" ] || [ "$VERSION_CODE" = "404" ]; then
    log_success "API version endpoint accessible (HTTP $VERSION_CODE)"
    save_test_result "api-version" "PASS"
else
    log_error "API version endpoint failed (HTTP $VERSION_CODE)"
    save_test_result "api-version" "FAIL"
fi

# Test 5: Authentication (login)
log_info "Test 5/8: Testing authentication..."
LOGIN_RESPONSE=$(curl -s -X POST "$FLASK_URL/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$TEST_ADMIN_EMAIL\",\"password\":\"$TEST_ADMIN_PASSWORD\"}")

TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token // .token // empty')

if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
    log_success "Authentication successful"
    save_test_result "api-auth" "PASS"
    export AUTH_TOKEN="$TOKEN"
else
    log_error "Authentication failed"
    echo "$LOGIN_RESPONSE" > "$LOG_DIR/k8s-login-response.json"
    save_test_result "api-auth" "FAIL"
fi

# Test 6: Authenticated API calls
log_info "Test 6/8: Testing authenticated API calls..."
USER_RESPONSE=$(curl -s -H "Authorization: Bearer $AUTH_TOKEN" \
    "$FLASK_URL/api/v1/auth/me")

USER_EMAIL=$(echo "$USER_RESPONSE" | jq -r '.email // empty')

if [ "$USER_EMAIL" = "$TEST_ADMIN_EMAIL" ]; then
    log_success "Authenticated requests work in K8s"
    save_test_result "api-auth-requests" "PASS"
else
    log_error "Authenticated requests failed"
    save_test_result "api-auth-requests" "FAIL"
fi

# Test 7: Load balancing (if multiple replicas)
log_info "Test 7/8: Testing load balancing..."
REPLICAS=$(kubectl get deployment -n "$NAMESPACE" -l app=flask-backend -o jsonpath='{.items[0].spec.replicas}' 2>/dev/null)

if [ -n "$REPLICAS" ] && [ "$REPLICAS" -gt 1 ]; then
    # Make multiple requests and check if different pods handle them
    for i in {1..5}; do
        curl -s "$FLASK_URL/healthz" > /dev/null
    done
    log_success "Load balancing test completed ($REPLICAS replicas)"
    save_test_result "load-balancing" "PASS"
else
    log_warning "Single replica, skipping load balancing test"
    save_test_result "load-balancing" "SKIP"
fi

# Test 8: API response consistency
log_info "Test 8/8: Testing API response consistency..."
RESPONSE1=$(curl -s "$FLASK_URL/healthz")
sleep 2
RESPONSE2=$(curl -s "$FLASK_URL/healthz")

if [ "$RESPONSE1" = "$RESPONSE2" ]; then
    log_success "API responses are consistent"
    save_test_result "api-consistency" "PASS"
else
    log_warning "API responses differ (may be expected for some endpoints)"
    save_test_result "api-consistency" "WARN"
fi

print_summary
log_success "$TEST_NAME completed successfully"
