#!/bin/bash
# Common test configuration and utilities

# Colors for output
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;34m'
export NC='\033[0m' # No Color

# Test configuration
export TEST_TIMEOUT=300
export API_TIMEOUT=30
export PAGE_LOAD_TIMEOUT=60

# Service URLs (local Docker)
export ALPHA_FLASK_URL="http://localhost:5000"
export ALPHA_WEBUI_URL="http://localhost:3000"

# Service URLs (K8s beta)
export BETA_FLASK_URL="https://darwin.penguintech.io/api"
export BETA_WEBUI_URL="https://darwin.penguintech.io"

# Database configuration
export DB_TYPE="postgres"
export DB_NAME="app_db"
export DB_USER="app_user"
export DB_PASS="password"

# Test user credentials
export TEST_ADMIN_EMAIL="admin@example.com"
export TEST_ADMIN_PASSWORD="admin123"
export TEST_USER_EMAIL="testuser@example.com"
export TEST_USER_PASSWORD="testpass123"

# Logging
export LOG_DIR="/tmp/darwin-tests-$(date +%s)"
mkdir -p "$LOG_DIR"

# Utility functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_DIR/test.log"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_DIR/test.log"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_DIR/test.log"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_DIR/test.log"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Wait for service to be ready
wait_for_service() {
    local url=$1
    local timeout=${2:-$TEST_TIMEOUT}
    local elapsed=0

    log_info "Waiting for service: $url"

    while [ $elapsed -lt $timeout ]; do
        if curl -s -f -o /dev/null "$url"; then
            log_success "Service is ready: $url"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done

    log_error "Service not ready after ${timeout}s: $url"
    return 1
}

# Wait for K8s pod to be ready
wait_for_pod() {
    local pod_label=$1
    local namespace=${2:-default}
    local timeout=${3:-$TEST_TIMEOUT}

    log_info "Waiting for pod: $pod_label in namespace: $namespace"

    kubectl wait --for=condition=Ready \
        pod -l "$pod_label" \
        -n "$namespace" \
        --timeout="${timeout}s"

    if [ $? -eq 0 ]; then
        log_success "Pod is ready: $pod_label"
        return 0
    else
        log_error "Pod not ready: $pod_label"
        return 1
    fi
}

# Make API request with authentication
api_request() {
    local method=$1
    local endpoint=$2
    local base_url=$3
    local token=${4:-""}
    local data=${5:-""}

    local curl_opts="-s -w \n%{http_code}"

    if [ -n "$token" ]; then
        curl_opts="$curl_opts -H \"Authorization: Bearer $token\""
    fi

    if [ -n "$data" ]; then
        curl_opts="$curl_opts -H \"Content-Type: application/json\" -d '$data'"
    fi

    eval curl $curl_opts -X "$method" "$base_url$endpoint"
}

# Get authentication token
get_auth_token() {
    local base_url=$1
    local email=${2:-$TEST_ADMIN_EMAIL}
    local password=${3:-$TEST_ADMIN_PASSWORD}

    local response=$(curl -s -X POST "$base_url/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$email\",\"password\":\"$password\"}")

    echo "$response" | jq -r '.access_token // empty'
}

# Save test result
save_test_result() {
    local test_name=$1
    local status=$2
    local message=${3:-""}
    local timestamp=$(date -Iseconds)

    echo "{
        \"test\": \"$test_name\",
        \"status\": \"$status\",
        \"message\": \"$message\",
        \"timestamp\": \"$timestamp\"
    }" >> "$LOG_DIR/results.json"
}

# Print test summary
print_summary() {
    local total_tests=$(jq -s 'length' "$LOG_DIR/results.json")
    local passed_tests=$(jq -s '[.[] | select(.status == "PASS")] | length' "$LOG_DIR/results.json")
    local failed_tests=$(jq -s '[.[] | select(.status == "FAIL")] | length' "$LOG_DIR/results.json")

    echo ""
    echo "========================================="
    echo "Test Summary"
    echo "========================================="
    echo "Total Tests:  $total_tests"
    echo -e "Passed:       ${GREEN}$passed_tests${NC}"
    echo -e "Failed:       ${RED}$failed_tests${NC}"
    echo "========================================="
    echo "Detailed results: $LOG_DIR/results.json"
    echo "Test logs: $LOG_DIR/test.log"
    echo "========================================="
}
