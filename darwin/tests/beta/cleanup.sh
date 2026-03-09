#!/bin/bash
# Beta Test Cleanup
# Removes K8s test deployments

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common/config.sh"

log_info "Cleaning up beta test environment..."

# Namespaces to clean up
NAMESPACES=(
    "darwin-beta"
    "darwin-kubectl-test"
    "darwin-helm-test"
)

for ns in "${NAMESPACES[@]}"; do
    if kubectl get namespace "$ns" > /dev/null 2>&1; then
        log_info "Deleting namespace: $ns"
        kubectl delete namespace "$ns" --wait=true 2>/dev/null || true
    fi
done

# Clean up Helm releases
log_info "Cleaning up any remaining Helm releases..."
helm list --all-namespaces -q | grep "^darwin" | while read -r release; do
    ns=$(helm list --all-namespaces -o json | jq -r ".[] | select(.name==\"$release\") | .namespace")
    log_info "Uninstalling Helm release: $release (namespace: $ns)"
    helm uninstall "$release" -n "$ns" 2>/dev/null || true
done

log_success "Beta test environment cleaned up"
log_info "Test logs preserved in: $LOG_DIR"
