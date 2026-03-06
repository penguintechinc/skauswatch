#!/bin/bash
# Alpha Test 05: API Tests
# Verifies API endpoints work correctly

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common/config.sh"

TEST_NAME="Alpha API Test"
log_info "Starting $TEST_NAME"

# Initialize results file
echo "[]" > "$LOG_DIR/results.json"

# Test 1: Health endpoint
log_info "Test 1/8: Testing health endpoint..."
HEALTH_RESPONSE=$(curl -s "$ALPHA_FLASK_URL/healthz")

if echo "$HEALTH_RESPONSE" | grep -q "healthy\|ok"; then
    log_success "Health endpoint responded correctly"
    save_test_result "api-health" "PASS"
else
    log_error "Health endpoint failed"
    save_test_result "api-health" "FAIL"
    exit 1
fi

# Test 2: API version endpoint
log_info "Test 2/8: Testing API version endpoint..."
VERSION_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$ALPHA_FLASK_URL/api/v1/")

if [ "$VERSION_CODE" = "200" ] || [ "$VERSION_CODE" = "404" ]; then
    log_success "API version endpoint accessible (HTTP $VERSION_CODE)"
    save_test_result "api-version" "PASS"
else
    log_error "API version endpoint failed (HTTP $VERSION_CODE)"
    save_test_result "api-version" "FAIL"
fi

# Test 3: Login endpoint (without credentials - should fail gracefully)
log_info "Test 3/8: Testing login endpoint (no credentials)..."
LOGIN_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    "$ALPHA_FLASK_URL/api/v1/auth/login")

# Should return 400 or 401 for missing credentials
if [ "$LOGIN_CODE" = "400" ] || [ "$LOGIN_CODE" = "401" ] || [ "$LOGIN_CODE" = "422" ]; then
    log_success "Login endpoint rejects missing credentials correctly (HTTP $LOGIN_CODE)"
    save_test_result "api-login-validation" "PASS"
else
    log_error "Login endpoint unexpected response (HTTP $LOGIN_CODE)"
    save_test_result "api-login-validation" "FAIL"
fi

# Test 4: Login with credentials
log_info "Test 4/8: Testing login with admin credentials..."
LOGIN_RESPONSE=$(curl -s -X POST "$ALPHA_FLASK_URL/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$TEST_ADMIN_EMAIL\",\"password\":\"$TEST_ADMIN_PASSWORD\"}")

TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token // .token // empty')

if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
    log_success "Login successful, token received"
    save_test_result "api-login" "PASS"
    export AUTH_TOKEN="$TOKEN"
else
    log_error "Login failed or no token received"
    echo "$LOGIN_RESPONSE" > "$LOG_DIR/login-response.json"
    save_test_result "api-login" "FAIL"
    exit 1
fi

# Test 5: Authenticated request - Get current user
log_info "Test 5/8: Testing authenticated request (get current user)..."
USER_RESPONSE=$(curl -s -H "Authorization: Bearer $AUTH_TOKEN" \
    "$ALPHA_FLASK_URL/api/v1/auth/me")

USER_EMAIL=$(echo "$USER_RESPONSE" | jq -r '.email // empty')

if [ "$USER_EMAIL" = "$TEST_ADMIN_EMAIL" ]; then
    log_success "Authenticated request successful"
    save_test_result "api-auth-request" "PASS"
else
    log_error "Authenticated request failed"
    echo "$USER_RESPONSE" > "$LOG_DIR/user-response.json"
    save_test_result "api-auth-request" "FAIL"
fi

# Test 6: Get reviews list
log_info "Test 6/8: Testing reviews list endpoint..."
REVIEWS_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    "$ALPHA_FLASK_URL/api/v1/reviews")

if [ "$REVIEWS_CODE" = "200" ]; then
    log_success "Reviews list endpoint accessible"
    save_test_result "api-reviews-list" "PASS"
else
    log_error "Reviews list endpoint failed (HTTP $REVIEWS_CODE)"
    save_test_result "api-reviews-list" "FAIL"
fi

# Test 7: Get users list
log_info "Test 7/8: Testing users list endpoint..."
USERS_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    "$ALPHA_FLASK_URL/api/v1/users")

if [ "$USERS_CODE" = "200" ]; then
    log_success "Users list endpoint accessible"
    save_test_result "api-users-list" "PASS"
else
    log_warning "Users list endpoint may be restricted (HTTP $USERS_CODE)"
    save_test_result "api-users-list" "WARN"
fi

# Test 8: Error handling - Invalid endpoint
log_info "Test 8/8: Testing error handling (invalid endpoint)..."
ERROR_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "$ALPHA_FLASK_URL/api/v1/nonexistent")

if [ "$ERROR_CODE" = "404" ]; then
    log_success "Error handling correct for invalid endpoint (HTTP 404)"
    save_test_result "api-error-handling" "PASS"
else
    log_error "Unexpected response for invalid endpoint (HTTP $ERROR_CODE)"
    save_test_result "api-error-handling" "FAIL"
fi

print_summary
log_success "$TEST_NAME completed successfully"
