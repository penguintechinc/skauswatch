#!/bin/bash
set -e

# S3 Scan File Upload and Malware Detection Test
# Tests ad-hoc file upload, scanning, and results verification

source "$(dirname "$0")/run_all.sh" --source-only

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
CLEANUP_SCAN_IDS=()

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

# Function to test substring
test_contains() {
  local description=$1
  local haystack=$2
  local needle=$3

  echo -n "  $description ... "
  if echo "$haystack" | grep -q "$needle"; then
    echo -e "${GREEN}PASS${NC}"
    ((PASSED++))
    return 0
  else
    echo -e "${RED}FAIL${NC}"
    echo "    Expected to contain: $needle"
    echo "    Actual: $haystack"
    ((FAILED++))
    return 1
  fi
}

# Function to poll for scan completion
poll_scan_status() {
  local scan_id=$1
  local max_attempts=60
  local attempt=0

  echo -n "  Polling for scan completion (timeout 60s) ... "

  while [ $attempt -lt $max_attempts ]; do
    status_response=$(curl -s \
      -H "Authorization: Bearer ${AUTH_TOKEN}" \
      "${API_BASE}/api/v1/s3-scan/results/${scan_id}")

    status=$(echo "$status_response" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [ "$status" = "COMPLETED" ] || [ "$status" = "completed" ]; then
      echo -e "${GREEN}done${NC}"
      echo "$status_response"
      return 0
    fi

    ((attempt++))
    sleep 1
  done

  echo -e "${RED}timeout${NC}"
  echo "    Last response: $status_response"
  return 1
}

# Function to cleanup uploaded files
cleanup() {
  if [ ${#CLEANUP_SCAN_IDS[@]} -gt 0 ]; then
    echo ""
    echo "Cleaning up scan records..."
    for _ in "${CLEANUP_SCAN_IDS[@]}"; do
      # Note: Scan records may not have delete endpoint, so this is best-effort
      : # Placeholder for potential cleanup
    done
  fi
}

# Set trap to cleanup on exit
trap cleanup EXIT

echo ""
echo "========================================"
echo "S3 Scan File Upload & Detection Test"
echo "========================================"
echo "Environment: $ENVIRONMENT"
echo "API Base: $API_BASE"
echo ""

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Test 1: Upload EICAR malware test file
echo "1. Uploading EICAR test file (should be detected as malware)..."
if [ ! -f "$SCRIPT_DIR/fixtures/eicar.com" ]; then
  echo -e "${RED}ERROR${NC}: EICAR test file not found at $SCRIPT_DIR/fixtures/eicar.com"
  ((FAILED++))
else
  eicar_response=$(curl -s -w "\n%{http_code}" \
    -X POST \
    -H "Authorization: Bearer ${AUTH_TOKEN}" \
    -F "file=@$SCRIPT_DIR/fixtures/eicar.com" \
    "${API_BASE}/api/v1/s3-scan/upload")

  eicar_code=$(echo "$eicar_response" | tail -n1)
  eicar_body=$(echo "$eicar_response" | head -n-1)

  if [ "$eicar_code" = "200" ] || [ "$eicar_code" = "202" ]; then
    ((PASSED++))
    echo "  ${GREEN}PASS${NC} (HTTP $eicar_code)"

    # Extract scan ID
    EICAR_SCAN_ID=$(echo "$eicar_body" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    if [ -z "$EICAR_SCAN_ID" ]; then
      EICAR_SCAN_ID=$(echo "$eicar_body" | grep -o '"scan_id":"[^"]*"' | head -1 | cut -d'"' -f4)
    fi
    if [ -z "$EICAR_SCAN_ID" ]; then
      EICAR_SCAN_ID=$(echo "$eicar_body" | grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)
    fi

    if [ ! -z "$EICAR_SCAN_ID" ]; then
      CLEANUP_SCAN_IDS+=("$EICAR_SCAN_ID")
      echo "  Scan ID: $EICAR_SCAN_ID"
    fi
  else
    echo -e "  ${RED}FAIL${NC} (HTTP $eicar_code)"
    echo "  Response: $eicar_body"
    ((FAILED++))
  fi
fi

echo ""
echo "2. Polling EICAR scan for completion..."
if [ ! -z "$EICAR_SCAN_ID" ]; then
  eicar_result=$(poll_scan_status "$EICAR_SCAN_ID")

  if [ $? -eq 0 ]; then
    test_assert "  Scan completed successfully" "true" "true"

    # Check is_malware flag
    is_malware=$(echo "$eicar_result" | grep -o '"is_malware":[^,}]*' | cut -d':' -f2)
    test_assert "  is_malware=true" "$is_malware" "true"

    # Check threat_name contains EICAR
    threat_name=$(echo "$eicar_result" | grep -o '"threat_name":"[^"]*"' | cut -d'"' -f4)
    test_contains "  threat_name contains EICAR" "$threat_name" "EICAR"
  else
    echo -e "  ${RED}Scan did not complete${NC}"
    ((FAILED++))
  fi
else
  echo -e "  ${YELLOW}Skipping${NC} - No scan ID from upload"
fi

echo ""
echo "3. Uploading clean test file..."

# Create a temporary clean file
CLEAN_FILE=$(mktemp)
echo "This is a clean text file for testing." > "$CLEAN_FILE"
trap 'rm -f "$CLEAN_FILE"' EXIT

clean_response=$(curl -s -w "\n%{http_code}" \
  -X POST \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -F "file=@$CLEAN_FILE" \
  "${API_BASE}/api/v1/s3-scan/upload")

clean_code=$(echo "$clean_response" | tail -n1)
clean_body=$(echo "$clean_response" | head -n-1)

if [ "$clean_code" = "200" ] || [ "$clean_code" = "202" ]; then
  test_assert "  Upload successful" "true" "true"

  # Extract scan ID
  CLEAN_SCAN_ID=$(echo "$clean_body" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
  if [ -z "$CLEAN_SCAN_ID" ]; then
    CLEAN_SCAN_ID=$(echo "$clean_body" | grep -o '"scan_id":"[^"]*"' | head -1 | cut -d'"' -f4)
  fi
  if [ -z "$CLEAN_SCAN_ID" ]; then
    CLEAN_SCAN_ID=$(echo "$clean_body" | grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)
  fi

  if [ ! -z "$CLEAN_SCAN_ID" ]; then
    CLEANUP_SCAN_IDS+=("$CLEAN_SCAN_ID")
    echo "  Scan ID: $CLEAN_SCAN_ID"
  fi
else
  echo -e "  ${RED}FAIL${NC} (HTTP $clean_code)"
  echo "  Response: $clean_body"
  ((FAILED++))
fi

echo ""
echo "4. Polling clean file scan for completion..."
if [ ! -z "$CLEAN_SCAN_ID" ]; then
  clean_result=$(poll_scan_status "$CLEAN_SCAN_ID")

  if [ $? -eq 0 ]; then
    test_assert "  Scan completed successfully" "true" "true"

    # Check is_malware flag
    is_malware=$(echo "$clean_result" | grep -o '"is_malware":[^,}]*' | cut -d':' -f2)
    test_assert "  is_malware=false" "$is_malware" "false"
  else
    echo -e "  ${RED}Scan did not complete${NC}"
    ((FAILED++))
  fi
else
  echo -e "  ${YELLOW}Skipping${NC} - No scan ID from upload"
fi

echo ""
echo "========================================"
echo "Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}"
echo "========================================"
echo ""

if [ $FAILED -gt 0 ]; then
  exit 1
fi

exit 0
