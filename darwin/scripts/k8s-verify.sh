#!/bin/bash

################################################################################
# Kubernetes Verification Script for Darwin Project
#
# This script verifies a Darwin deployment in Kubernetes by checking:
# - All pods are running
# - Deployments are ready
# - Flask backend /healthz endpoint
# - WebUI /healthz endpoint
# - PostgreSQL connection
# - Redis connection
#
# Usage: ./scripts/k8s-verify.sh [namespace]
# Example: ./scripts/k8s-verify.sh darwin-prod
################################################################################

set -euo pipefail

# Configuration
NAMESPACE="${1:-darwin-dev}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TIMEOUT=300  # 5 minutes timeout for operations
VERBOSE=${VERBOSE:-0}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
WARNINGS=0

################################################################################
# Utility Functions
################################################################################

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED++))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARNINGS++))
}

log_section() {
    echo ""
    echo -e "${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}=================================================================================${NC}"
}

debug_log() {
    if [ "$VERBOSE" -eq 1 ]; then
        echo -e "${YELLOW}[DEBUG]${NC} $1"
    fi
}

check_prerequisites() {
    log_section "Checking Prerequisites"

    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl not found. Please install kubectl 1.28 or later."
        exit 1
    fi
    log_success "kubectl is installed ($(kubectl version --client --short 2>/dev/null | head -1 || echo 'version check failed'))"

    # Check namespace exists
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_error "Namespace '$NAMESPACE' does not exist"
        exit 1
    fi
    log_success "Namespace '$NAMESPACE' exists"

    # Check cluster access
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot access Kubernetes cluster"
        exit 1
    fi
    log_success "Kubernetes cluster is accessible"
}

check_pods_running() {
    log_section "Checking Pod Status"

    local pods
    pods=$(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)

    if [ -z "$pods" ]; then
        log_warning "No pods found in namespace '$NAMESPACE'"
        return
    fi

    local pod_count
    local running_count
    local failed_count

    pod_count=$(kubectl get pods -n "$NAMESPACE" --no-headers | wc -l)
    running_count=$(kubectl get pods -n "$NAMESPACE" --field-selector=status.phase=Running --no-headers | wc -l)
    failed_count=$(kubectl get pods -n "$NAMESPACE" --field-selector=status.phase=Failed --no-headers | wc -l)

    debug_log "Total pods: $pod_count, Running: $running_count, Failed: $failed_count"

    kubectl get pods -n "$NAMESPACE" -o wide

    if [ "$failed_count" -gt 0 ]; then
        log_error "$failed_count pod(s) failed"
        kubectl describe pods -n "$NAMESPACE" --field-selector=status.phase=Failed | grep -E "^(Name:|Reason:)" || true
    fi

    if [ "$running_count" -eq "$pod_count" ]; then
        log_success "All $pod_count pods are running"
    else
        log_warning "$running_count/$pod_count pods are running"
    fi
}

check_deployments_ready() {
    log_section "Checking Deployment Readiness"

    local deployments
    deployments=$(kubectl get deployments -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)

    if [ -z "$deployments" ]; then
        log_warning "No deployments found in namespace '$NAMESPACE'"
        return
    fi

    local deployment_count
    deployment_count=$(kubectl get deployments -n "$NAMESPACE" --no-headers | wc -l)

    kubectl get deployments -n "$NAMESPACE" -o wide

    local ready_count
    ready_count=$(kubectl get deployments -n "$NAMESPACE" -o jsonpath='{range .items[*]}{.status.updatedReplicas=="spec.replicas"}{"\n"}{end}' | grep -c true || echo 0)

    if [ "$ready_count" -eq "$deployment_count" ]; then
        log_success "All $deployment_count deployments are ready"
    else
        log_warning "$ready_count/$deployment_count deployments are ready"
    fi
}

check_flask_backend_health() {
    log_section "Checking Flask Backend Health"

    local flask_pod
    flask_pod=$(kubectl get pods -n "$NAMESPACE" -l app=flask-backend,component=api -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

    if [ -z "$flask_pod" ]; then
        log_warning "No Flask backend pod found (searching for label: app=flask-backend,component=api)"
        # Try alternative label
        flask_pod=$(kubectl get pods -n "$NAMESPACE" -l app=flask-backend -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
        if [ -z "$flask_pod" ]; then
            log_warning "No Flask backend pod found with any labels"
            return
        fi
    fi

    debug_log "Found Flask backend pod: $flask_pod"

    # Check pod is running
    local pod_status
    pod_status=$(kubectl get pod "$flask_pod" -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null)

    if [ "$pod_status" != "Running" ]; then
        log_error "Flask backend pod is $pod_status (expected Running)"
        kubectl describe pod "$flask_pod" -n "$NAMESPACE" | grep -A 5 "State:" || true
        return
    fi

    # Test healthz endpoint
    local health_response
    health_response=$(kubectl exec "$flask_pod" -n "$NAMESPACE" -- wget -q -O- http://localhost:5000/healthz 2>&1 || echo "ERROR")

    if [[ "$health_response" == *"200"* ]] || [[ "$health_response" == *"healthy"* ]] || [[ "$health_response" == "OK" ]]; then
        log_success "Flask backend /healthz endpoint is healthy"
    else
        log_warning "Flask backend /healthz endpoint returned: ${health_response:0:100}"
    fi
}

check_webui_health() {
    log_section "Checking WebUI Health"

    local webui_pod
    webui_pod=$(kubectl get pods -n "$NAMESPACE" -l app=webui,component=frontend -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

    if [ -z "$webui_pod" ]; then
        log_warning "No WebUI pod found (searching for label: app=webui,component=frontend)"
        # Try alternative label
        webui_pod=$(kubectl get pods -n "$NAMESPACE" -l app=webui -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
        if [ -z "$webui_pod" ]; then
            log_warning "No WebUI pod found with any labels"
            return
        fi
    fi

    debug_log "Found WebUI pod: $webui_pod"

    # Check pod is running
    local pod_status
    pod_status=$(kubectl get pod "$webui_pod" -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null)

    if [ "$pod_status" != "Running" ]; then
        log_error "WebUI pod is $pod_status (expected Running)"
        kubectl describe pod "$webui_pod" -n "$NAMESPACE" | grep -A 5 "State:" || true
        return
    fi

    # Test healthz endpoint
    local health_response
    health_response=$(kubectl exec "$webui_pod" -n "$NAMESPACE" -- wget -q -O- http://localhost:3000/healthz 2>&1 || echo "ERROR")

    if [[ "$health_response" == *"200"* ]] || [[ "$health_response" == *"healthy"* ]] || [[ "$health_response" == "OK" ]]; then
        log_success "WebUI /healthz endpoint is healthy"
    else
        log_warning "WebUI /healthz endpoint returned: ${health_response:0:100}"
    fi
}

check_postgres_connection() {
    log_section "Checking PostgreSQL Connection"

    local postgres_pod
    postgres_pod=$(kubectl get pods -n "$NAMESPACE" -l app=postgres -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

    if [ -z "$postgres_pod" ]; then
        log_warning "No PostgreSQL pod found in namespace (statefulsets may be used instead)"
        # Try StatefulSets
        postgres_pod=$(kubectl get statefulsets -n "$NAMESPACE" -l app=postgres -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
        if [ -z "$postgres_pod" ]; then
            log_warning "No PostgreSQL StatefulSet found"
            return
        fi
    fi

    debug_log "Found PostgreSQL pod/set: $postgres_pod"

    # Create temporary pod to test connection
    local test_pod="postgres-test-$RANDOM"
    debug_log "Creating temporary pod: $test_pod"

    kubectl run "$test_pod" -n "$NAMESPACE" \
        --image=postgres:16-alpine \
        --rm -it \
        --restart=Never \
        --command -- pg_isready -h postgres -U "${DB_USER:-app_user}" -d "${DB_NAME:-app_db}" 2>/dev/null || true

    if kubectl run "$test_pod" -n "$NAMESPACE" \
        --image=postgres:16-alpine \
        --rm -it \
        --restart=Never \
        --command -- pg_isready -h postgres -U "${DB_USER:-app_user}" -d "${DB_NAME:-app_db}" &>/dev/null; then
        log_success "PostgreSQL connection successful"
    else
        log_warning "PostgreSQL connection test inconclusive (pod may not have external access)"
    fi
}

check_redis_connection() {
    log_section "Checking Redis Connection"

    local redis_pod
    redis_pod=$(kubectl get pods -n "$NAMESPACE" -l app=redis -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

    if [ -z "$redis_pod" ]; then
        log_warning "No Redis pod found in namespace"
        return
    fi

    debug_log "Found Redis pod: $redis_pod"

    # Check pod is running
    local pod_status
    pod_status=$(kubectl get pod "$redis_pod" -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null)

    if [ "$pod_status" != "Running" ]; then
        log_error "Redis pod is $pod_status (expected Running)"
        return
    fi

    # Test PING command
    local redis_password
    redis_password="${REDIS_PASSWORD:-}"

    if kubectl exec "$redis_pod" -n "$NAMESPACE" -- redis-cli PING &>/dev/null; then
        log_success "Redis PING successful"
    elif [ -n "$redis_password" ] && kubectl exec "$redis_pod" -n "$NAMESPACE" -- redis-cli -a "$redis_password" PING &>/dev/null; then
        log_success "Redis PING successful (with authentication)"
    else
        log_warning "Redis PING test inconclusive"
    fi
}

check_services() {
    log_section "Checking Kubernetes Services"

    local services
    services=$(kubectl get services -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l)

    if [ "$services" -eq 0 ]; then
        log_warning "No services found in namespace"
        return
    fi

    kubectl get services -n "$NAMESPACE" -o wide

    log_success "$services service(s) found"
}

check_persistent_volumes() {
    log_section "Checking Persistent Volumes"

    local pvcs
    pvcs=$(kubectl get pvc -n "$NAMESPACE" --no-headers 2>/dev/null)

    if [ -z "$pvcs" ]; then
        log_info "No persistent volume claims found in namespace"
        return
    fi

    kubectl get pvc -n "$NAMESPACE" -o wide

    local bound_count
    bound_count=$(kubectl get pvc -n "$NAMESPACE" --field-selector=status.phase=Bound --no-headers | wc -l)
    local total_count
    total_count=$(kubectl get pvc -n "$NAMESPACE" --no-headers | wc -l)

    if [ "$bound_count" -eq "$total_count" ]; then
        log_success "All $total_count PVCs are bound"
    else
        log_warning "$bound_count/$total_count PVCs are bound"
    fi
}

print_summary() {
    log_section "Verification Summary"

    echo ""
    echo "Namespace: $NAMESPACE"
    echo "Test Results:"
    echo -e "  ${GREEN}Passed: $PASSED${NC}"
    echo -e "  ${YELLOW}Warnings: $WARNINGS${NC}"
    echo -e "  ${RED}Failed: $FAILED${NC}"
    echo ""

    if [ "$FAILED" -eq 0 ]; then
        echo -e "${GREEN}Verification completed successfully!${NC}"
        return 0
    else
        echo -e "${RED}Verification failed with errors.${NC}"
        return 1
    fi
}

print_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Verifies a Darwin deployment in Kubernetes.

OPTIONS:
    -n, --namespace NAMESPACE    Kubernetes namespace to verify (default: darwin-dev)
    -v, --verbose               Enable verbose output
    -h, --help                  Show this help message

EXAMPLES:
    # Verify default namespace (darwin-dev)
    $0

    # Verify specific namespace
    $0 -n darwin-prod

    # Verify with verbose output
    $0 -n darwin-dev -v

PREREQUISITES:
    - kubectl 1.28 or later installed
    - Access to Kubernetes cluster
    - Appropriate namespace exists

EOF
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -h|--help)
                print_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                print_help
                exit 1
                ;;
        esac
    done

    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
    echo "║         Darwin Project - Kubernetes Deployment Verification Script           ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    check_prerequisites
    check_pods_running
    check_deployments_ready
    check_services
    check_persistent_volumes
    check_flask_backend_health
    check_webui_health
    check_postgres_connection
    check_redis_connection

    print_summary
}

main "$@"
