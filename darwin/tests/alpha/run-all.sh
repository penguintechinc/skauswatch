#!/bin/bash
# Alpha Test Suite - Master Runner
# Runs all alpha tests in sequence

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common/config.sh"

log_info "========================================="
log_info "Darwin Alpha Test Suite"
log_info "========================================="
log_info "Test logs will be saved to: $LOG_DIR"
log_info ""

# Array of test scripts
TESTS=(
    "01-build-test.sh"
    "02-runtime-test.sh"
    "03-mock-data-test.sh"
    "04-page-load-test.sh"
    "05-api-test.sh"
)

FAILED_TESTS=()

# Run each test
for test in "${TESTS[@]}"; do
    log_info "Running: $test"

    if bash "$SCRIPT_DIR/$test"; then
        log_success "$test completed"
    else
        log_error "$test failed"
        FAILED_TESTS+=("$test")
    fi

    echo ""
done

# Print overall summary
log_info "========================================="
log_info "Alpha Test Suite Complete"
log_info "========================================="

if [ ${#FAILED_TESTS[@]} -eq 0 ]; then
    log_success "All tests passed! ✓"
    exit 0
else
    log_error "Failed tests:"
    for test in "${FAILED_TESTS[@]}"; do
        echo "  - $test"
    done
    exit 1
fi
