#!/bin/bash
# Beta Test Suite - Master Runner
# Runs all beta tests in sequence

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common/config.sh"

log_info "========================================="
log_info "Darwin Beta Test Suite (K8s)"
log_info "========================================="
log_info "Test logs will be saved to: $LOG_DIR"
log_info ""

# Check K8s connectivity
log_info "Checking Kubernetes connectivity..."
if kubectl cluster-info > /dev/null 2>&1; then
    CONTEXT=$(kubectl config current-context)
    log_success "Connected to K8s context: $CONTEXT"
else
    log_error "Cannot connect to Kubernetes cluster"
    exit 1
fi

echo ""

# Array of test scripts
TESTS=(
    "01-kustomize-deploy-test.sh"
    "02-kubectl-deploy-test.sh"
    "03-helm-deploy-test.sh"
    "04-k8s-runtime-test.sh"
    "05-k8s-api-test.sh"
    "06-k8s-page-load-test.sh"
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
log_info "Beta Test Suite Complete"
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
