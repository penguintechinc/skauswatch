#!/bin/bash
set -e

# S3 Scan Bucket Configuration CRUD Test
# Tests creating, reading, updating, deleting bucket configurations

source "$(dirname "$0")/run_all.sh" --source-only

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
CLEANUP_IDS=()

# Function to test and assert
test_assert() {
  local description=$1
  local actual=$2
  local expected=$3

  echo -n "  $description ... "
  if [ "$actual" = "$expected" ]; then
    echo -e "${GREEN}PASS${NC}"
    ((PASSED++))
    return 0
  else
    echo -e "${RED}FAIL${NC}"
    echo "    Expected: $expected"
    echo "    Actual: $actual"
    ((FAILED++))
    return 1
  fi
}

# Function to cleanup bucket configs
cleanup() {
  echo ""
  echo "Cleaning up created bucket configs..."
  for id in "${CLEANUP_IDS[@]}"; do
    echo -n "  Deleting bucket config $id ... "
    delete_response=$(curl -s -w "\n%{http_code}" \
      -X DELETE \
      -H "Authorization: Bearer ${AUTH_TOKEN}" \
      "${API_BASE}/api/v1/s3-scan/buckets/${id}")

    delete_code=$(echo "$delete_response" | tail -n1)
    if [ "$delete_code" = "204" ] || [ "$delete_code" = "200" ]; then
      echo -e "${GREEN}done${NC}"
    else
      echo -e "${YELLOW}warning${NC} (HTTP $delete_code)"
    fi
  done
}

# Set trap to cleanup on exit
trap cleanup EXIT

echo ""
echo "========================================"
echo "S3 Scan Bucket CRUD Operations"
echo "========================================"
echo "Environment: $ENVIRONMENT"
echo "API Base: $API_BASE"
echo ""

# Generate unique bucket name
BUCKET_NAME="smoke-test-bucket-$(date +%s)"

echo "1. Creating bucket config..."
create_response=$(curl -s -w "\n%{http_code}" \
  -X POST \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"$BUCKET_NAME\",
    \"endpoint\": \"${MINIO_ENDPOINT}\",
    \"access_key\": \"${MINIO_ACCESS_KEY}\",
    \"secret_key\": \"${MINIO_SECRET_KEY}\",
    \"bucket_name\": \"test-bucket\",
    \"use_ssl\": false,
    \"skip_verify_ssl\": true
  }" \
  "${API_BASE}/api/v1/s3-scan/buckets")

create_code=$(echo "$create_response" | tail -n1)
create_body=$(echo "$create_response" | head -n-1)

test_assert "  HTTP 201 Created" "$create_code" "201"

# Extract bucket ID from response
BUCKET_ID=$(echo "$create_body" | grep -o '"id":"[^"]*' | head -1 | cut -d'"' -f4)
if [ -z "$BUCKET_ID" ]; then
  BUCKET_ID=$(echo "$create_body" | grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)
fi

if [ ! -z "$BUCKET_ID" ]; then
  CLEANUP_IDS+=("$BUCKET_ID")
  test_assert "  Bucket ID present in response" "true" "true"
  echo "  Bucket ID: $BUCKET_ID"
else
  test_assert "  Bucket ID present in response" "false" "true"
  echo "  Response: $create_body"
fi

echo ""
echo "2. Retrieving bucket config..."
get_response=$(curl -s -w "\n%{http_code}" \
  -X GET \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  "${API_BASE}/api/v1/s3-scan/buckets/${BUCKET_ID}")

get_code=$(echo "$get_response" | tail -n1)
get_body=$(echo "$get_response" | head -n-1)

test_assert "  HTTP 200 OK" "$get_code" "200"
test_assert "  Bucket name matches" "$(echo "$get_body" | grep -o "\"name\":\"[^\"]*" | cut -d'"' -f4)" "$BUCKET_NAME"

echo ""
echo "3. Updating bucket config..."
NEW_BUCKET_NAME="${BUCKET_NAME}-updated"
update_response=$(curl -s -w "\n%{http_code}" \
  -X PATCH \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"$NEW_BUCKET_NAME\",
    \"bucket_name\": \"test-bucket-updated\"
  }" \
  "${API_BASE}/api/v1/s3-scan/buckets/${BUCKET_ID}")

update_code=$(echo "$update_response" | tail -n1)
update_body=$(echo "$update_response" | head -n-1)

test_assert "  HTTP 200 OK" "$update_code" "200"
test_assert "  Name updated" "$(echo "$update_body" | grep -o "\"name\":\"[^\"]*" | cut -d'"' -f4)" "$NEW_BUCKET_NAME"

echo ""
echo "4. Testing bucket connection..."
if [ ! -z "$BUCKET_ID" ]; then
  test_response=$(curl -s -w "\n%{http_code}" \
    -X POST \
    -H "Authorization: Bearer ${AUTH_TOKEN}" \
    "${API_BASE}/api/v1/s3-scan/buckets/${BUCKET_ID}/test")

  test_code=$(echo "$test_response" | tail -n1)
  test_body=$(echo "$test_response" | head -n-1)

  if [ "$test_code" = "200" ] || [ "$test_code" = "202" ]; then
    test_assert "  Connection test initiated" "true" "true"
  else
    test_assert "  Connection test initiated" "$test_code" "200"
    echo "  Response: $test_body"
  fi
else
  echo "  ${YELLOW}Skipping${NC} - No bucket ID available"
fi

echo ""
echo "5. Listing all buckets..."
list_response=$(curl -s -w "\n%{http_code}" \
  -X GET \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  "${API_BASE}/api/v1/s3-scan/buckets")

list_code=$(echo "$list_response" | tail -n1)
list_body=$(echo "$list_response" | head -n-1)

test_assert "  HTTP 200 OK" "$list_code" "200"
test_assert "  Response contains array" "$(echo "$list_body" | grep -c '\[' || echo 0)" "1"

echo ""
echo "========================================"
echo "Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}"
echo "========================================"
echo ""

if [ $FAILED -gt 0 ]; then
  exit 1
fi

exit 0
