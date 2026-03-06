#!/bin/bash
# Beta Test 01: Kustomize Deployment Test
# Tests deployment using Kustomize overlays

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common/config.sh"

TEST_NAME="Beta Kustomize Deployment Test"
log_info "Starting $TEST_NAME"

# Initialize results file
echo "[]" > "$LOG_DIR/results.json"

# Configuration
NAMESPACE="darwin-beta"
OVERLAY="dev"  # Can be: dev, staging, prod

# Test 1: Check Kustomize is installed
log_info "Test 1/6: Checking Kustomize installation..."
if command_exists kustomize; then
    KUSTOMIZE_VERSION=$(kustomize version --short 2>&1)
    log_success "Kustomize installed: $KUSTOMIZE_VERSION"
    save_test_result "kustomize-installed" "PASS"
else
    log_error "Kustomize not found"
    save_test_result "kustomize-installed" "FAIL"
    exit 1
fi

# Test 2: Build Kustomize manifests
log_info "Test 2/6: Building Kustomize manifests..."
if kustomize build "k8s/kustomize/overlays/$OVERLAY" > "$LOG_DIR/kustomize-manifests.yaml" 2>&1; then
    log_success "Kustomize build successful"
    save_test_result "kustomize-build" "PASS"
else
    log_error "Kustomize build failed"
    save_test_result "kustomize-build" "FAIL"
    exit 1
fi

# Test 3: Create namespace if needed
log_info "Test 3/6: Creating namespace $NAMESPACE..."
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - > /dev/null 2>&1

if kubectl get namespace "$NAMESPACE" > /dev/null 2>&1; then
    log_success "Namespace ready: $NAMESPACE"
    save_test_result "namespace-create" "PASS"
else
    log_error "Failed to create namespace"
    save_test_result "namespace-create" "FAIL"
    exit 1
fi

# Test 4: Apply Kustomize manifests
log_info "Test 4/6: Applying Kustomize manifests..."
if kubectl apply -k "k8s/kustomize/overlays/$OVERLAY" -n "$NAMESPACE" > "$LOG_DIR/kubectl-apply.log" 2>&1; then
    log_success "Manifests applied successfully"
    save_test_result "kustomize-apply" "PASS"
else
    log_error "Failed to apply manifests"
    save_test_result "kustomize-apply" "FAIL"
    exit 1
fi

# Test 5: Wait for deployments to be ready
log_info "Test 5/6: Waiting for deployments to be ready..."
DEPLOYMENTS=$(kubectl get deployments -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}')

ALL_READY=true
for deployment in $DEPLOYMENTS; do
    log_info "Waiting for deployment: $deployment"

    if kubectl wait --for=condition=available \
        deployment/"$deployment" \
        -n "$NAMESPACE" \
        --timeout=300s > /dev/null 2>&1; then
        log_success "Deployment ready: $deployment"
    else
        log_error "Deployment not ready: $deployment"
        ALL_READY=false
    fi
done

if [ "$ALL_READY" = true ]; then
    save_test_result "deployments-ready" "PASS"
else
    save_test_result "deployments-ready" "FAIL"
    kubectl get pods -n "$NAMESPACE" > "$LOG_DIR/pods-status.log"
    exit 1
fi

# Test 6: Verify services are created
log_info "Test 6/6: Verifying services..."
SERVICES=$(kubectl get services -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}')

if [ -n "$SERVICES" ]; then
    log_success "Services created: $SERVICES"
    save_test_result "services-created" "PASS"
else
    log_error "No services found"
    save_test_result "services-created" "FAIL"
    exit 1
fi

# Save cluster state for debugging
kubectl get all -n "$NAMESPACE" > "$LOG_DIR/cluster-state.log"

print_summary
log_success "$TEST_NAME completed successfully"
