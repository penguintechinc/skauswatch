#!/bin/bash
# Beta Test 02: kubectl Direct Deployment Test
# Tests deployment using direct kubectl manifests

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common/config.sh"

TEST_NAME="Beta kubectl Deployment Test"
log_info "Starting $TEST_NAME"

# Initialize results file
echo "[]" > "$LOG_DIR/results.json"

# Configuration
NAMESPACE="darwin-kubectl-test"

# Test 1: Check kubectl is installed
log_info "Test 1/5: Checking kubectl installation..."
if command_exists kubectl; then
    KUBECTL_VERSION=$(kubectl version --client --short 2>&1 | head -1)
    log_success "kubectl installed: $KUBECTL_VERSION"
    save_test_result "kubectl-installed" "PASS"
else
    log_error "kubectl not found"
    save_test_result "kubectl-installed" "FAIL"
    exit 1
fi

# Test 2: Create namespace
log_info "Test 2/5: Creating namespace $NAMESPACE..."
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - > /dev/null 2>&1

if kubectl get namespace "$NAMESPACE" > /dev/null 2>&1; then
    log_success "Namespace ready: $NAMESPACE"
    save_test_result "namespace-create" "PASS"
else
    log_error "Failed to create namespace"
    save_test_result "namespace-create" "FAIL"
    exit 1
fi

# Test 3: Apply manifests
log_info "Test 3/5: Applying kubectl manifests..."
if [ -d "k8s/manifests" ]; then
    if kubectl apply -f k8s/manifests/ -n "$NAMESPACE" > "$LOG_DIR/kubectl-apply.log" 2>&1; then
        log_success "Manifests applied successfully"
        save_test_result "kubectl-apply" "PASS"
    else
        log_error "Failed to apply manifests"
        save_test_result "kubectl-apply" "FAIL"
        exit 1
    fi
else
    log_warning "No k8s/manifests directory found"
    save_test_result "kubectl-apply" "SKIP"
fi

# Test 4: Wait for pods to be ready
log_info "Test 4/5: Waiting for pods to be ready..."
if kubectl wait --for=condition=Ready \
    pods --all \
    -n "$NAMESPACE" \
    --timeout=300s > /dev/null 2>&1; then
    log_success "All pods ready"
    save_test_result "pods-ready" "PASS"
else
    log_error "Some pods not ready"
    kubectl get pods -n "$NAMESPACE" > "$LOG_DIR/pods-status.log"
    save_test_result "pods-ready" "FAIL"
    exit 1
fi

# Test 5: Check service endpoints
log_info "Test 5/5: Checking service endpoints..."
ENDPOINTS=$(kubectl get endpoints -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}')

if [ -n "$ENDPOINTS" ]; then
    log_success "Service endpoints ready: $ENDPOINTS"
    save_test_result "endpoints-ready" "PASS"
else
    log_error "No service endpoints found"
    save_test_result "endpoints-ready" "FAIL"
    exit 1
fi

# Save cluster state
kubectl get all -n "$NAMESPACE" > "$LOG_DIR/cluster-state.log"

print_summary
log_success "$TEST_NAME completed successfully"
