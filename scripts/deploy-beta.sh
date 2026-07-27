#!/bin/bash

# Skauswatch Beta Deployment Script
# Comprehensive Kubernetes deployment with build, push, and rollback support
# Usage: ./scripts/deploy-beta.sh [OPTIONS]

set -euo pipefail

# === Configuration ===
RELEASE_NAME="skauswatch"
NAMESPACE="skauswatch"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART_PATH="${PROJECT_ROOT}/k8s/helm"
KUSTOMIZE_PATH="${PROJECT_ROOT}/k8s/kustomize/overlays/beta"

# Registry and cluster configuration
IMAGE_REGISTRY="ghcr.io/penguintechinc/skauswatch"
KUBE_CONTEXT="dal2-beta"
APP_HOST="skauswatch.penguintech.cloud"

# Services configuration — one entry per Helm chart + Dockerfile
SERVICES=(
  "monitor:services/monitor"
  "endpoint-agent:services/endpoint-agent"
  "manager:services/manager"
  "pki:services/pki"
  "sshca:services/sshca"
  "webui:services/webui"
  "worker-codescan:services/worker-codescan"
  "s3scan:services/s3scan"
  "scanner:services/scanner"
)

# Image defaults
# Resolve latest CI-built beta tag from ghcr.io
resolve_latest_beta_tag() {
    local svc="manager"
    local tag
    tag=$(gh api "users/penguintechinc/packages/container/skauswatch-${svc}/versions" \
        --jq '.[].metadata.container.tags[] | select(startswith("beta-"))' 2>/dev/null | sort -r | head -1)
    echo "${tag:-beta-latest}"
}

DEFAULT_TAG="$(resolve_latest_beta_tag)"
IMAGE_TAG="${DEFAULT_TAG}"
SKIP_BUILD=false
DRY_RUN=false
ROLLBACK=false
SPECIFIC_SERVICE=""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# === Color Output Functions ===
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_header() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# === Helper Functions ===

print_usage() {
    cat << 'EOF'
Skauswatch Beta Deployment Script

USAGE:
    ./scripts/deploy-beta.sh [OPTIONS]

OPTIONS:
    --tag TAG               Docker image tag (default: epoch timestamp)
    --service SERVICE       Deploy specific service only (flask-backend, go-backend, webui)
    --skip-build            Skip docker build and push (use existing image)
    --dry-run               Show what would be deployed without making changes
    --rollback              Rollback to previous release
    --help                  Show this help message

EXAMPLES:
    # Deploy all services with custom tag
    ./scripts/deploy-beta.sh --tag v1.2.3

    # Deploy only flask-backend
    ./scripts/deploy-beta.sh --service flask-backend --tag v1.2.3

    # Dry-run deployment
    ./scripts/deploy-beta.sh --tag v1.2.3 --dry-run

    # Rollback to previous version
    ./scripts/deploy-beta.sh --rollback

ENVIRONMENT VARIABLES:
    KUBE_CONTEXT        Kubernetes context (default: dal2-beta)
    IMAGE_REGISTRY      Container registry (default: registry-dal2.penguintech.io)

EOF
}

# Check prerequisites
check_prerequisites() {
    log_header "Checking Prerequisites"

    local missing_tools=()

    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        missing_tools+=("kubectl")
    fi

    # Check helm
    if ! command -v helm &> /dev/null; then
        missing_tools+=("helm")
    fi

    # Check docker (if not skipping build)
    if [ "$SKIP_BUILD" = false ]; then
        if ! command -v docker &> /dev/null; then
            missing_tools+=("docker")
        fi
    fi

    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        return 1
    fi

    log_success "All required tools found"

    # Check kubectl access
    log_info "Verifying Kubernetes context: ${KUBE_CONTEXT}"
    if ! kubectl config get-contexts | grep -q "${KUBE_CONTEXT}"; then
        log_error "Kubernetes context '${KUBE_CONTEXT}' not found"
        log_info "Available contexts:"
        kubectl config get-contexts
        return 1
    fi

    log_success "Using Kubernetes context: ${KUBE_CONTEXT}"

    # Check namespace exists
    if ! kubectl --context "${KUBE_CONTEXT}" get namespace "${NAMESPACE}" &> /dev/null; then
        log_warning "Namespace '${NAMESPACE}' does not exist, creating..."
        kubectl --context "${KUBE_CONTEXT}" create namespace "${NAMESPACE}"
        log_success "Created namespace: ${NAMESPACE}"
    fi

    log_success "Prerequisites check completed"
}

# Copy wildcard TLS secret to namespace
copy_wildcard_tls_secret() {
    local secret_name="penguintech-cloud-wildcard-tls"
    if kubectl --context "${KUBE_CONTEXT}" get secret "${secret_name}" -n "${NAMESPACE}" &>/dev/null; then
        log_success "Wildcard TLS secret already present in namespace"
        return 0
    fi
    log_info "Copying wildcard TLS secret to namespace ${NAMESPACE}..."
    # Try common source namespaces
    for src_ns in current-beta icecharts killkrill; do
        if kubectl --context "${KUBE_CONTEXT}" get secret "${secret_name}" -n "${src_ns}" &>/dev/null; then
            kubectl --context "${KUBE_CONTEXT}" get secret "${secret_name}" -n "${src_ns}" -o json \
                | python3 -c "import sys,json; d=json.load(sys.stdin); d['metadata']={'name':d['metadata']['name'],'namespace':'${NAMESPACE}'}; print(json.dumps(d))" \
                | kubectl --context "${KUBE_CONTEXT}" apply -f -
            log_success "Copied ${secret_name} from ${src_ns}"
            return 0
        fi
    done
    log_warning "Could not copy ${secret_name} — TLS may not work until secret is created manually"
}

# Build and push Docker images
build_and_push_images() {
    log_header "Beta Image Strategy"
    log_info "Beta images are built by CI from ghcr.io — local build skipped"
    log_info "Using tag: ${IMAGE_TAG}"
    log_info "If images are missing, trigger CI: gh workflow run build.yml --ref release/v1.0.x"
    log_success "Using CI-built images from ${IMAGE_REGISTRY}"
}

# Deploy using Helm
do_deploy_helm() {
    log_header "Deploying Applications (Helm)"

    for service_spec in "${SERVICES[@]}"; do
        IFS=':' read -r service_name service_path <<< "$service_spec"

        # Skip if specific service requested and this isn't it
        if [ -n "$SPECIFIC_SERVICE" ] && [ "$SPECIFIC_SERVICE" != "$service_name" ]; then
            continue
        fi

        local chart_path="${CHART_PATH}/${service_name}"
        local release_name="${RELEASE_NAME}-${service_name}"
        local values_file="${chart_path}/values-beta.yaml"

        if [ ! -d "$chart_path" ]; then
            log_warning "Helm chart not found for $service_name at $chart_path, skipping"
            continue
        fi

        log_info "Deploying ${service_name} with Helm release: ${release_name}"

        local helm_cmd=(
            "helm" "upgrade" "--install"
            "${release_name}"
            "${chart_path}"
            "--kube-context" "${KUBE_CONTEXT}"
            "--namespace" "${NAMESPACE}"
            "--create-namespace"
            "--values" "${values_file}"
            "--set" "image.tag=${IMAGE_TAG}"
            "--set" "image.registry=${IMAGE_REGISTRY}"
        )

        if [ "$DRY_RUN" = true ]; then
            helm_cmd+=("--dry-run" "--debug")
        fi

        if "${helm_cmd[@]}"; then
            log_success "Helm deployment successful: ${release_name}"
        else
            log_error "Helm deployment failed: ${release_name}"
            return 1
        fi
    done

    log_success "Helm deployment completed"
}

# Deploy using Kustomize
do_deploy_kustomize() {
    log_header "Deploying Applications (Kustomize)"

    log_info "Building Kustomize manifests from: ${KUSTOMIZE_PATH}"

    # Build Kustomize output
    local kustomize_output
    kustomize_output=$(kustomize build "${KUSTOMIZE_PATH}")

    if [ -z "$kustomize_output" ]; then
        log_error "Failed to build Kustomize manifests"
        return 1
    fi

    if [ "$DRY_RUN" = true ]; then
        log_info "Dry-run mode: Showing Kustomize output"
        echo "$kustomize_output"
        return 0
    fi

    # Apply the manifests
    log_info "Applying Kustomize manifests to cluster"
    echo "$kustomize_output" | kubectl apply -f -

    log_success "Kustomize deployment completed"
}

# Verify deployment
verify_deployment() {
    log_header "Verifying Deployment"

    if [ "$DRY_RUN" = true ]; then
        log_warning "Skipping verification in dry-run mode"
        return 0
    fi

    local max_retries=30
    local retry_count=0

    while [ $retry_count -lt $max_retries ]; do
        log_info "Checking deployment status (attempt $((retry_count + 1))/$max_retries)..."

        local deployments
        deployments=$(kubectl --context "${KUBE_CONTEXT}" get deployments -n "${NAMESPACE}" -o jsonpath='{.items[*].metadata.name}')

        if [ -z "$deployments" ]; then
            log_warning "No deployments found in namespace: ${NAMESPACE}"
            sleep 10
            ((retry_count++))
            continue
        fi

        local all_ready=true
        for deployment in $deployments; do
            local ready=$(kubectl --context "${KUBE_CONTEXT}" get deployment "$deployment" -n "${NAMESPACE}" -o jsonpath='{.status.conditions[?(@.type=="Available")].status}')
            if [ "$ready" != "True" ]; then
                all_ready=false
                log_info "  Waiting for deployment: $deployment"
            else
                log_success "  Deployment ready: $deployment"
            fi
        done

        if [ "$all_ready" = true ]; then
            log_success "All deployments are ready"
            return 0
        fi

        sleep 10
        ((retry_count++))
    done

    log_warning "Deployment verification timed out after $((max_retries * 10)) seconds"
    log_info "Check deployment status with: kubectl get deployments -n ${NAMESPACE}"
    return 1
}

# Rollback deployment
do_rollback() {
    log_header "Rolling Back Deployment"

    for service_spec in "${SERVICES[@]}"; do
        IFS=':' read -r service_name service_path <<< "$service_spec"

        local release_name="${RELEASE_NAME}-${service_name}"

        log_info "Rolling back Helm release: ${release_name}"

        if helm rollback "${release_name}" --kube-context "${KUBE_CONTEXT}" -n "${NAMESPACE}"; then
            log_success "Rolled back: ${release_name}"
        else
            log_warning "Failed to rollback: ${release_name}"
        fi
    done

    log_success "Rollback completed"
}

# Display deployment information
show_deployment_info() {
    log_header "Deployment Information"

    echo "Release Name:       ${RELEASE_NAME}"
    echo "Namespace:          ${NAMESPACE}"
    echo "Kubernetes Context: ${KUBE_CONTEXT}"
    echo "App Host:           ${APP_HOST}"
    echo "Image Registry:     ${IMAGE_REGISTRY}"
    echo "Image Tag:          ${IMAGE_TAG}"
    echo "Chart Path:         ${CHART_PATH}"
    echo "Kustomize Path:     ${KUSTOMIZE_PATH}"
    echo ""
}

# === Main Execution ===

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --tag)
            IMAGE_TAG="$2"
            shift 2
            ;;
        --service)
            SPECIFIC_SERVICE="$2"
            shift 2
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --rollback)
            ROLLBACK=true
            shift
            ;;
        --help|-h)
            print_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# Main execution flow
main() {
    log_header "Skauswatch Beta Deployment"

    show_deployment_info

    # Check prerequisites
    if ! check_prerequisites; then
        log_error "Prerequisites check failed"
        exit 1
    fi

    # Copy wildcard TLS secret
    copy_wildcard_tls_secret

    # Handle rollback
    if [ "$ROLLBACK" = true ]; then
        if ! do_rollback; then
            log_error "Rollback failed"
            exit 1
        fi
        log_success "Deployment rollback completed successfully"
        exit 0
    fi

    # Build and push images (unless skipped)
    if [ "$SKIP_BUILD" = false ]; then
        if ! build_and_push_images; then
            log_error "Image build and push failed"
            exit 1
        fi
    else
        log_warning "Skipping Docker build and push (--skip-build)"
    fi

    # Deploy using Helm (preferred method)
    if ! do_deploy_helm; then
        log_error "Helm deployment failed"
        exit 1
    fi

    # Verify deployment
    if ! verify_deployment; then
        log_warning "Deployment verification encountered issues"
    fi

    # Final summary
    log_header "Deployment Summary"
    echo -e "${GREEN}✓ Deployment completed successfully${NC}"
    echo ""
    echo "Access your applications:"
    echo "  WebUI:            https://${APP_HOST}"
    echo "  Flask API:        https://flask-api.penguintech.cloud/api/v1"
    echo "  Go API:           https://go-api.penguintech.cloud/api/v1"
    echo ""
    echo "View deployment logs:"
    echo "  kubectl --context ${KUBE_CONTEXT} logs -n ${NAMESPACE} -l app=skauswatch-manager"
    echo "  kubectl --context ${KUBE_CONTEXT} logs -n ${NAMESPACE} -l app=skauswatch-webui"
    echo "  kubectl --context ${KUBE_CONTEXT} logs -n ${NAMESPACE} -l app=skauswatch-monitor"
    echo ""
    echo "View Helm releases:"
    echo "  helm list -n ${NAMESPACE}"
    echo ""
}

# Execute main
main
