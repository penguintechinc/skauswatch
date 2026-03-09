#!/bin/bash
# Beta Test 03: Helm v3 Deployment Test
# Tests deployment using Helm charts

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common/config.sh"

TEST_NAME="Beta Helm Deployment Test"
log_info "Starting $TEST_NAME"

# Initialize results file
echo "[]" > "$LOG_DIR/results.json"

# Configuration
NAMESPACE="darwin-helm-test"
RELEASE_NAME="darwin"

# Test 1: Check Helm is installed
log_info "Test 1/7: Checking Helm installation..."
if command_exists helm; then
    HELM_VERSION=$(helm version --short 2>&1)
    log_success "Helm installed: $HELM_VERSION"
    save_test_result "helm-installed" "PASS"
else
    log_error "Helm not found"
    save_test_result "helm-installed" "FAIL"
    exit 1
fi

# Test 2: Create namespace
log_info "Test 2/7: Creating namespace $NAMESPACE..."
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - > /dev/null 2>&1

if kubectl get namespace "$NAMESPACE" > /dev/null 2>&1; then
    log_success "Namespace ready: $NAMESPACE"
    save_test_result "namespace-create" "PASS"
else
    log_error "Failed to create namespace"
    save_test_result "namespace-create" "FAIL"
    exit 1
fi

# Test 3: Lint Helm charts
log_info "Test 3/7: Linting Helm charts..."
ALL_CHARTS_VALID=true

for chart_dir in k8s/helm/*/; do
    chart_name=$(basename "$chart_dir")
    log_info "Linting chart: $chart_name"

    if helm lint "$chart_dir" > "$LOG_DIR/helm-lint-$chart_name.log" 2>&1; then
        log_success "Chart valid: $chart_name"
    else
        log_error "Chart invalid: $chart_name"
        ALL_CHARTS_VALID=false
    fi
done

if [ "$ALL_CHARTS_VALID" = true ]; then
    save_test_result "helm-lint" "PASS"
else
    save_test_result "helm-lint" "FAIL"
    exit 1
fi

# Test 4: Install flask-backend chart
log_info "Test 4/7: Installing flask-backend chart..."
if helm install "$RELEASE_NAME-flask" k8s/helm/flask-backend \
    -n "$NAMESPACE" \
    --wait \
    --timeout 5m > "$LOG_DIR/helm-install-flask.log" 2>&1; then
    log_success "Flask backend chart installed"
    save_test_result "helm-install-flask" "PASS"
else
    log_error "Flask backend chart installation failed"
    save_test_result "helm-install-flask" "FAIL"
    exit 1
fi

# Test 5: Install webui chart
log_info "Test 5/7: Installing webui chart..."
if helm install "$RELEASE_NAME-webui" k8s/helm/webui \
    -n "$NAMESPACE" \
    --wait \
    --timeout 5m > "$LOG_DIR/helm-install-webui.log" 2>&1; then
    log_success "WebUI chart installed"
    save_test_result "helm-install-webui" "PASS"
else
    log_error "WebUI chart installation failed"
    save_test_result "helm-install-webui" "FAIL"
    exit 1
fi

# Test 6: Verify Helm releases
log_info "Test 6/7: Verifying Helm releases..."
RELEASES=$(helm list -n "$NAMESPACE" -q)

if echo "$RELEASES" | grep -q "$RELEASE_NAME"; then
    log_success "Helm releases verified: $RELEASES"
    save_test_result "helm-releases" "PASS"
else
    log_error "Helm releases not found"
    save_test_result "helm-releases" "FAIL"
    exit 1
fi

# Test 7: Check deployment status
log_info "Test 7/7: Checking deployment status..."
if kubectl wait --for=condition=available \
    deployments --all \
    -n "$NAMESPACE" \
    --timeout=300s > /dev/null 2>&1; then
    log_success "All deployments ready"
    save_test_result "deployments-ready" "PASS"
else
    log_error "Some deployments not ready"
    kubectl get deployments -n "$NAMESPACE" > "$LOG_DIR/deployments-status.log"
    save_test_result "deployments-ready" "FAIL"
    exit 1
fi

# Save Helm and cluster state
helm list -n "$NAMESPACE" -o yaml > "$LOG_DIR/helm-releases.yaml"
kubectl get all -n "$NAMESPACE" > "$LOG_DIR/cluster-state.log"

print_summary
log_success "$TEST_NAME completed successfully"
