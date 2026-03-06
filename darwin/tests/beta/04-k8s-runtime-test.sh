#!/bin/bash
# Beta Test 04: K8s Runtime Test
# Verifies K8s-specific runtime behaviors

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common/config.sh"

TEST_NAME="Beta K8s Runtime Test"
log_info "Starting $TEST_NAME"

# Initialize results file
echo "[]" > "$LOG_DIR/results.json"

# Use the namespace from the deployment method you chose
NAMESPACE="${K8S_NAMESPACE:-darwin-beta}"

# Test 1: Service Discovery
log_info "Test 1/7: Testing service discovery (DNS)..."
FLASK_POD=$(kubectl get pods -n "$NAMESPACE" -l app=flask-backend -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

if [ -n "$FLASK_POD" ]; then
    # Try to resolve service DNS from within a pod
    if kubectl exec -n "$NAMESPACE" "$FLASK_POD" -- nslookup flask-backend > /dev/null 2>&1; then
        log_success "Service DNS resolution works"
        save_test_result "service-discovery" "PASS"
    else
        log_error "Service DNS resolution failed"
        save_test_result "service-discovery" "FAIL"
    fi
else
    log_warning "No flask-backend pod found for DNS test"
    save_test_result "service-discovery" "SKIP"
fi

# Test 2: Persistent Volume Mounts
log_info "Test 2/7: Checking persistent volume mounts..."
POSTGRES_POD=$(kubectl get pods -n "$NAMESPACE" -l app=postgres -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

if [ -n "$POSTGRES_POD" ]; then
    PV_MOUNTED=$(kubectl exec -n "$NAMESPACE" "$POSTGRES_POD" -- df -h | grep -c "/var/lib/postgresql/data" || echo "0")

    if [ "$PV_MOUNTED" -gt 0 ]; then
        log_success "Persistent volumes mounted correctly"
        save_test_result "pv-mounts" "PASS"
    else
        log_error "Persistent volumes not mounted"
        save_test_result "pv-mounts" "FAIL"
    fi
else
    log_warning "No postgres pod found for PV test"
    save_test_result "pv-mounts" "SKIP"
fi

# Test 3: ConfigMaps and Secrets
log_info "Test 3/7: Verifying ConfigMaps and Secrets..."
CONFIGMAPS=$(kubectl get configmaps -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}')
SECRETS=$(kubectl get secrets -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}')

if [ -n "$CONFIGMAPS" ] && [ -n "$SECRETS" ]; then
    log_success "ConfigMaps and Secrets present"
    save_test_result "config-secrets" "PASS"
else
    log_error "ConfigMaps or Secrets missing"
    save_test_result "config-secrets" "FAIL"
fi

# Test 4: Resource Limits
log_info "Test 4/7: Checking resource limits..."
PODS_WITH_LIMITS=$(kubectl get pods -n "$NAMESPACE" -o json | \
    jq '[.items[] | select(.spec.containers[].resources.limits != null)] | length')

TOTAL_PODS=$(kubectl get pods -n "$NAMESPACE" -o json | jq '.items | length')

if [ "$PODS_WITH_LIMITS" -gt 0 ]; then
    log_success "Resource limits configured ($PODS_WITH_LIMITS/$TOTAL_PODS pods)"
    save_test_result "resource-limits" "PASS"
else
    log_warning "No resource limits configured"
    save_test_result "resource-limits" "WARN"
fi

# Test 5: Health Checks in K8s
log_info "Test 5/7: Verifying health checks..."
PODS_WITH_PROBES=$(kubectl get pods -n "$NAMESPACE" -o json | \
    jq '[.items[] | select(.spec.containers[].livenessProbe != null or .spec.containers[].readinessProbe != null)] | length')

if [ "$PODS_WITH_PROBES" -gt 0 ]; then
    log_success "Health probes configured ($PODS_WITH_PROBES pods)"
    save_test_result "health-probes" "PASS"
else
    log_error "No health probes configured"
    save_test_result "health-probes" "FAIL"
fi

# Test 6: Pod Restart Behavior
log_info "Test 6/7: Checking pod restart policy..."
RESTART_POLICIES=$(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].spec.restartPolicy}')

if echo "$RESTART_POLICIES" | grep -q "Always"; then
    log_success "Restart policies configured correctly"
    save_test_result "restart-policy" "PASS"
else
    log_warning "Unexpected restart policies: $RESTART_POLICIES"
    save_test_result "restart-policy" "WARN"
fi

# Test 7: Check for CrashLoopBackOff or Error states
log_info "Test 7/7: Checking for pod errors..."
ERROR_PODS=$(kubectl get pods -n "$NAMESPACE" --field-selector=status.phase!=Running,status.phase!=Succeeded -o jsonpath='{.items[*].metadata.name}')

if [ -z "$ERROR_PODS" ]; then
    log_success "No pods in error state"
    save_test_result "pod-health" "PASS"
else
    log_error "Pods in error state: $ERROR_PODS"
    kubectl describe pods -n "$NAMESPACE" $ERROR_PODS > "$LOG_DIR/error-pods.log"
    save_test_result "pod-health" "FAIL"
fi

# Save detailed pod information
kubectl describe pods -n "$NAMESPACE" > "$LOG_DIR/pods-describe.log"
kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' > "$LOG_DIR/k8s-events.log"

print_summary
log_success "$TEST_NAME completed successfully"
