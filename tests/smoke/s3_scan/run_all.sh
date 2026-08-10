#!/bin/bash
set -e

# S3 Scan Smoke Test Runner
# Orchestrates all smoke tests with environment configuration and authentication

# Handle --source-only flag for sourcing
if [[ "$1" == "--source-only" ]]; then
  SOURCE_ONLY=true
else
  SOURCE_ONLY=false
fi

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Determine environment (default to alpha)
ENVIRONMENT="${1:-alpha}"
if [ "$SOURCE_ONLY" = true ]; then
  # When sourcing, don't consume the first argument
  ENVIRONMENT="${ENVIRONMENT:-alpha}"
fi

# Validate environment
if [ "$ENVIRONMENT" != "alpha" ] && [ "$ENVIRONMENT" != "beta" ]; then
  if [ "$SOURCE_ONLY" = false ]; then
    echo -e "${RED}ERROR${NC}: Invalid environment '$ENVIRONMENT'. Must be 'alpha' or 'beta'."
    exit 1
  fi
fi

# Load environment configuration
CONFIG_FILE="$SCRIPT_DIR/config/${ENVIRONMENT}.env"
if [ ! -f "$CONFIG_FILE" ]; then
  if [ "$SOURCE_ONLY" = false ]; then
    echo -e "${RED}ERROR${NC}: Configuration file not found: $CONFIG_FILE"
    exit 1
  fi
fi

# Export all variables from config
set -a
# shellcheck disable=SC1090 # path picked at runtime by $ENVIRONMENT (alpha|beta)
source "$CONFIG_FILE"
set +a

# Validate required environment variables
required_vars=(
  "ENVIRONMENT"
  "API_BASE"
  "WEBUI_BASE"
  "MINIO_ENDPOINT"
  "MINIO_ACCESS_KEY"
  "MINIO_SECRET_KEY"
  "TEST_USER_EMAIL"
  "TEST_USER_PASSWORD"
)

# If sourcing, export the variables for use by sourcing scripts
if [ "$SOURCE_ONLY" = true ]; then
  export ENVIRONMENT
  export API_BASE
  export WEBUI_BASE
  export MINIO_ENDPOINT
  export MINIO_ACCESS_KEY
  export MINIO_SECRET_KEY
  export TEST_USER_EMAIL
  export TEST_USER_PASSWORD

  # Authenticate and get token if not already set
  if [ -z "$AUTH_TOKEN" ]; then
    echo -n "Authenticating as $TEST_USER_EMAIL ... " >&2

    # Attempt login
    login_response=$(curl -s \
      -X POST \
      -H "Content-Type: application/json" \
      -d "{
        \"email\": \"${TEST_USER_EMAIL}\",
        \"password\": \"${TEST_USER_PASSWORD}\"
      }" \
      "${API_BASE}/api/v1/auth/login" 2>/dev/null || true)

    AUTH_TOKEN=$(echo "$login_response" | grep -o '"access_token":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [ -z "$AUTH_TOKEN" ]; then
      AUTH_TOKEN=$(echo "$login_response" | grep -o '"token":"[^"]*"' | head -1 | cut -d'"' -f4)
    fi

    if [ -z "$AUTH_TOKEN" ]; then
      echo -e "${RED}FAILED${NC}" >&2
      echo "Login response: $login_response" >&2
      exit 1
    fi

    echo -e "${GREEN}OK${NC}" >&2
  fi

  export AUTH_TOKEN
  return 0 2>/dev/null || true
fi

# Validate required variables for runner
for var in "${required_vars[@]}"; do
  if [ -z "${!var}" ]; then
    echo -e "${RED}ERROR${NC}: Missing required environment variable: $var"
    exit 1
  fi
done

# ============================================================================
# MAIN RUNNER LOGIC (when not sourcing)
# ============================================================================

echo ""
echo "========================================"
echo "S3 Scan Smoke Test Suite"
echo "========================================"
echo -e "Environment: ${BLUE}$ENVIRONMENT${NC}"
echo -e "API Base: ${BLUE}$API_BASE${NC}"
echo -e "WebUI Base: ${BLUE}$WEBUI_BASE${NC}"
echo ""

# Authenticate
echo -n "Authenticating as $TEST_USER_EMAIL ... "

login_response=$(curl -s \
  -X POST \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"${TEST_USER_EMAIL}\",
    \"password\": \"${TEST_USER_PASSWORD}\"
  }" \
  "${API_BASE}/api/v1/auth/login")

AUTH_TOKEN=$(echo "$login_response" | grep -o '"access_token":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$AUTH_TOKEN" ]; then
  AUTH_TOKEN=$(echo "$login_response" | grep -o '"token":"[^"]*"' | head -1 | cut -d'"' -f4)
fi

if [ -z "$AUTH_TOKEN" ]; then
  echo -e "${RED}FAILED${NC}"
  echo "Login response: $login_response"
  exit 1
fi

echo -e "${GREEN}OK${NC}"
echo ""

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Array to store results
declare -a TEST_RESULTS

# Function to run a test script
run_test() {
  local test_script=$1
  local test_name=$2

  ((TOTAL_TESTS++))

  echo -n "[$TOTAL_TESTS] Running $test_name ... "

  if [ ! -f "$test_script" ]; then
    echo -e "${RED}SKIP${NC} (file not found)"
    return 1
  fi

  if [ ! -x "$test_script" ]; then
    echo -e "${YELLOW}Making executable${NC}"
    chmod +x "$test_script"
  fi

  # Run test and capture output
  test_output=$(mktemp)
  trap 'rm -f "$test_output"' EXIT

  if bash "$test_script" > "$test_output" 2>&1; then
    echo -e "${GREEN}PASS${NC}"
    ((PASSED_TESTS++))
    TEST_RESULTS+=("✓ $test_name")

    # Show last summary line
    tail -3 "$test_output" | head -1
  else
    echo -e "${RED}FAIL${NC}"
    ((FAILED_TESTS++))
    TEST_RESULTS+=("✗ $test_name")

    # Show error details
    echo ""
    tail -20 "$test_output" | sed 's/^/    /'
    echo ""
  fi

  rm -f "$test_output"
}

# Run all test scripts
export AUTH_TOKEN
export ENVIRONMENT
export API_BASE
export WEBUI_BASE
export MINIO_ENDPOINT
export MINIO_ACCESS_KEY
export MINIO_SECRET_KEY
export TEST_USER_EMAIL
export TEST_USER_PASSWORD

run_test "$SCRIPT_DIR/test_api_health.sh" "API Health Check"
run_test "$SCRIPT_DIR/test_bucket_crud.sh" "Bucket CRUD Operations"
run_test "$SCRIPT_DIR/test_file_upload.sh" "File Upload & Detection"

# Print summary
echo ""
echo "========================================"
echo "Test Summary"
echo "========================================"
for result in "${TEST_RESULTS[@]}"; do
  echo "$result"
done
echo ""
echo -e "Total: $TOTAL_TESTS | ${GREEN}Passed: $PASSED_TESTS${NC} | ${RED}Failed: $FAILED_TESTS${NC}"
echo "========================================"
echo ""

# Exit with appropriate code
if [ $FAILED_TESTS -gt 0 ]; then
  exit 1
fi

exit 0
