#!/bin/bash
set -e

# S3 Scan API Health Check Test
# Tests that all S3 scan API endpoints respond with 200 status code

source "$(dirname "$0")/run_all.sh" --source-only

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0

# Function to test endpoint
test_endpoint() {
  local method=$1
  local endpoint=$2
  # Accepted for call-site readability (e.g. "List buckets") but not
  # currently rendered in output.
  # shellcheck disable=SC2034
  local description=$3

  echo -n "Testing $method $endpoint ... "

  response=$(curl -s -w "\n%{http_code}" \
    -X "$method" \
    -H "Authorization: Bearer ${AUTH_TOKEN}" \
    -H "Content-Type: application/json" \
    "${API_BASE}${endpoint}")

  # Extract status code (last line)
  http_code=$(echo "$response" | tail -n1)
  body=$(echo "$response" | head -n-1)

  if [ "$http_code" = "200" ]; then
    echo -e "${GREEN}PASS${NC} (HTTP $http_code)"
    ((PASSED++))
    return 0
  else
    echo -e "${RED}FAIL${NC} (HTTP $http_code)"
    echo "Response: $body"
    ((FAILED++))
    return 1
  fi
}

echo ""
echo "========================================"
echo "S3 Scan API Health Check"
echo "========================================"
echo "Environment: $ENVIRONMENT"
echo "API Base: $API_BASE"
echo ""

# Test all endpoints
test_endpoint "GET" "/api/v1/s3-scan/buckets" "List buckets"
test_endpoint "GET" "/api/v1/s3-scan/jobs" "List jobs"
test_endpoint "GET" "/api/v1/s3-scan/results" "List results"
test_endpoint "GET" "/api/v1/s3-scan/statistics" "Get statistics"

echo ""
echo "========================================"
echo "Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}"
echo "========================================"
echo ""

if [ $FAILED -gt 0 ]; then
  exit 1
fi

exit 0
