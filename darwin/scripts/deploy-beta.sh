#!/bin/bash
# Deploy to Beta Environment - Darwin
# Builds containers, pushes to registry, and deploys using Helm or Kustomize

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Configuration
KUBE_CONTEXT="${KUBE_CONTEXT:-dal2-beta}"
NAMESPACE="${NAMESPACE:-darwin-beta}"
RELEASE_NAME="darwin"
CHART_PATH="$PROJECT_ROOT/k8s/helm/flask-backend"
VALUES_FILE="$CHART_PATH/values-beta.yaml"
IMAGE_REGISTRY="registry-dal2.penguintech.io"
APP_HOST="darwin.penguintech.cloud"
VERSION=$(cat "$PROJECT_ROOT/.version" 2>/dev/null || echo "v1.0.0")

# Flags
DRY_RUN=0
ROLLBACK=0
BUILD_IMAGES=1
SKIP_LOGIN=0
SERVICE=""
IMAGE_TAG=""
USE_KUSTOMIZE=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_section() { echo ""; echo -e "${BLUE}========================================${NC}"; echo -e "${BLUE}$1${NC}"; echo -e "${BLUE}========================================${NC}"; echo ""; }

check_prerequisites() {
    log_section "Checking Prerequisites"

    for cmd in docker kubectl helm; do
        if ! command -v "$cmd" &>/dev/null; then
            log_error "$cmd is not installed"
            return 1
        fi
        log_info "$cmd: found"
    done

    if ! kubectl config get-contexts "$KUBE_CONTEXT" &>/dev/null; then
        log_error "Context not found: $KUBE_CONTEXT"
        log_info "Available contexts:"
        kubectl config get-contexts
        return 1
    fi
    log_info "Kubernetes context: $KUBE_CONTEXT (verified)"

    if [ "$USE_KUSTOMIZE" -eq 0 ]; then
        if [ ! -d "$CHART_PATH" ]; then
            log_error "Helm chart not found: $CHART_PATH"
            return 1
        fi
        log_info "Helm chart found: $CHART_PATH"

        if [ ! -f "$VALUES_FILE" ]; then
            log_error "Values file not found: $VALUES_FILE"
            return 1
        fi
        log_info "Values file found: $VALUES_FILE"
    fi
}

registry_login() {
    log_section "Docker Registry Authentication"

    if [ "$SKIP_LOGIN" -eq 1 ]; then
        log_info "Skipping registry login (--skip-login)"
        return 0
    fi

    log_info "Attempting login to: $IMAGE_REGISTRY"
    if docker login "$IMAGE_REGISTRY" > /dev/null 2>&1; then
        log_info "Registry login successful"
    else
        log_error "Failed to login to registry"
        log_info "Run: docker login $IMAGE_REGISTRY"
        return 1
    fi
}

build_and_push_images() {
    log_section "Building and Pushing Docker Images"

    local EPOCH
    EPOCH=$(date +%s)

    if [ -z "$IMAGE_TAG" ] || [ "$IMAGE_TAG" = "beta" ]; then
        IMAGE_TAG="beta-${EPOCH}"
    fi

    log_info "Image tag: $IMAGE_TAG"

    # Build and push flask-backend
    if [ -z "$SERVICE" ] || [ "$SERVICE" = "flask-backend" ]; then
        log_info "Building flask-backend image..."
        local FLASK_IMAGE="$IMAGE_REGISTRY/darwin-flask-backend:$IMAGE_TAG"
        local FLASK_LATEST="$IMAGE_REGISTRY/darwin-flask-backend:beta"

        if docker build \
            -t "$FLASK_IMAGE" \
            -t "$FLASK_LATEST" \
            -t "darwin-flask-backend:$IMAGE_TAG" \
            -t "darwin-flask-backend:latest" \
            --build-arg VERSION="$VERSION" \
            --build-arg BUILD_TAG="$IMAGE_TAG" \
            -f "$PROJECT_ROOT/services/flask-backend/Dockerfile" \
            "$PROJECT_ROOT/services/flask-backend"; then
            log_info "flask-backend image built successfully"
        else
            log_error "Failed to build flask-backend image"
            return 1
        fi

        log_info "Pushing flask-backend images..."
        if docker push "$FLASK_IMAGE" && docker push "$FLASK_LATEST"; then
            log_info "flask-backend images pushed successfully"
        else
            log_error "Failed to push flask-backend images"
            return 1
        fi
    fi

    # Build and push webui
    if [ -z "$SERVICE" ] || [ "$SERVICE" = "webui" ]; then
        log_info "Building webui image..."
        local WEBUI_IMAGE="$IMAGE_REGISTRY/darwin-webui:$IMAGE_TAG"
        local WEBUI_LATEST="$IMAGE_REGISTRY/darwin-webui:beta"

        if docker build \
            -t "$WEBUI_IMAGE" \
            -t "$WEBUI_LATEST" \
            -t "darwin-webui:$IMAGE_TAG" \
            -t "darwin-webui:latest" \
            --build-arg VERSION="$VERSION" \
            --build-arg BUILD_TAG="$IMAGE_TAG" \
            -f "$PROJECT_ROOT/services/webui/Dockerfile" \
            "$PROJECT_ROOT/services/webui"; then
            log_info "webui image built successfully"
        else
            log_error "Failed to build webui image"
            return 1
        fi

        log_info "Pushing webui images..."
        if docker push "$WEBUI_IMAGE" && docker push "$WEBUI_LATEST"; then
            log_info "webui images pushed successfully"
        else
            log_error "Failed to push webui images"
            return 1
        fi
    fi
}

deploy_with_helm() {
    log_section "Deploying with Helm"

    local helm_args=(
        "upgrade"
        "--install"
        "$RELEASE_NAME"
        "$CHART_PATH"
        "--kube-context=$KUBE_CONTEXT"
        "--namespace=$NAMESPACE"
        "--values=$CHART_PATH/values.yaml"
        "--values=$VALUES_FILE"
        "--set=image.tag=$IMAGE_TAG"
        "--wait"
        "--timeout=10m"
    )

    # Create namespace if it doesn't exist
    if ! kubectl --context="$KUBE_CONTEXT" get namespace "$NAMESPACE" &>/dev/null; then
        helm_args+=("--create-namespace")
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        helm_args+=("--dry-run=client")
    fi

    log_info "Executing: helm ${helm_args[*]}"
    if helm "${helm_args[@]}"; then
        log_info "Helm deployment successful"
    else
        log_error "Helm deployment failed"
        return 1
    fi
}

deploy_with_kustomize() {
    log_section "Deploying with Kustomize"

    local KUSTOMIZE_PATH="$PROJECT_ROOT/k8s/kustomize/overlays/beta"

    if [ ! -f "$KUSTOMIZE_PATH/kustomization.yaml" ]; then
        log_error "Kustomization file not found: $KUSTOMIZE_PATH/kustomization.yaml"
        return 1
    fi

    log_info "Building Kustomize manifests from: $KUSTOMIZE_PATH"

    # Create namespace if it doesn't exist
    if ! kubectl --context="$KUBE_CONTEXT" get namespace "$NAMESPACE" &>/dev/null; then
        log_info "Creating namespace: $NAMESPACE"
        kubectl --context="$KUBE_CONTEXT" create namespace "$NAMESPACE"
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        log_info "DRY RUN: Showing manifests..."
        if kubectl kustomize "$KUSTOMIZE_PATH" | kubectl --context="$KUBE_CONTEXT" apply -f - --dry-run=client -n "$NAMESPACE"; then
            log_info "DRY RUN completed successfully"
        else
            log_error "Kustomize dry-run failed"
            return 1
        fi
    else
        log_info "Applying Kustomize manifests..."
        if kubectl kustomize "$KUSTOMIZE_PATH" | kubectl --context="$KUBE_CONTEXT" apply -f - -n "$NAMESPACE"; then
            log_info "Kustomize deployment successful"
        else
            log_error "Kustomize deployment failed"
            return 1
        fi
    fi
}

do_rollback() {
    log_section "Rolling Back"

    log_info "Rolling back release: $RELEASE_NAME"
    if helm rollback "$RELEASE_NAME" --kube-context="$KUBE_CONTEXT" -n "$NAMESPACE"; then
        log_info "Rollback successful"
    else
        log_error "Rollback failed"
        return 1
    fi
}

verify_deployment() {
    if [ "$DRY_RUN" -eq 1 ]; then
        return 0
    fi

    log_section "Verifying Deployment"

    # Wait for deployments to be ready
    log_info "Waiting for deployments to be ready..."
    local deployments
    deployments=$(kubectl --context="$KUBE_CONTEXT" -n "$NAMESPACE" get deployments -o jsonpath='{.items[*].metadata.name}')

    for deployment in $deployments; do
        log_info "Waiting for deployment: $deployment"
        if kubectl --context="$KUBE_CONTEXT" -n "$NAMESPACE" rollout status deployment/"$deployment" --timeout=300s; then
            log_info "Deployment ready: $deployment"
        else
            log_warn "Deployment not ready or timed out: $deployment"
        fi
    done

    # Show pod status
    log_info "Pod status:"
    kubectl --context="$KUBE_CONTEXT" -n "$NAMESPACE" get pods -o wide

    # Show services
    log_info "Services:"
    kubectl --context="$KUBE_CONTEXT" -n "$NAMESPACE" get svc -o wide

    # Show ingress if available
    if kubectl --context="$KUBE_CONTEXT" -n "$NAMESPACE" get ingress &>/dev/null; then
        log_info "Ingress:"
        kubectl --context="$KUBE_CONTEXT" -n "$NAMESPACE" get ingress -o wide
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --tag=*)
                IMAGE_TAG="${1#*=}"
                shift
                ;;
            --tag)
                IMAGE_TAG="$2"
                shift 2
                ;;
            --service=*)
                SERVICE="${1#*=}"
                shift
                ;;
            --service)
                SERVICE="$2"
                shift 2
                ;;
            --skip-build)
                BUILD_IMAGES=0
                shift
                ;;
            --skip-login)
                SKIP_LOGIN=1
                shift
                ;;
            --dry-run)
                DRY_RUN=1
                shift
                ;;
            --rollback)
                ROLLBACK=1
                shift
                ;;
            --kustomize)
                USE_KUSTOMIZE=1
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

show_help() {
    cat <<EOF
Usage: $0 [OPTIONS]

Deploy Darwin to beta environment

OPTIONS:
    --tag=TAG                Image tag (default: beta-<timestamp>)
    --tag TAG                Image tag (positional)
    --service=SVC            Build only one service: flask-backend or webui
    --service SVC            Build only one service (positional)
    --skip-build             Skip Docker image building
    --skip-login             Skip Docker registry login
    --dry-run                Show what would be deployed without applying
    --rollback               Rollback to previous Helm release
    --kustomize              Use Kustomize instead of Helm
    -h, --help               Show this help message

ENVIRONMENT VARIABLES:
    KUBE_CONTEXT             Kubernetes context (default: dal2-beta)
    NAMESPACE                Kubernetes namespace (default: darwin-beta)
    IMAGE_REGISTRY           Docker registry (default: registry-dal2.penguintech.io)

EXAMPLES:
    # Deploy all services to beta
    $0

    # Deploy with custom tag
    $0 --tag=my-custom-tag

    # Deploy only flask-backend
    $0 --service=flask-backend

    # Dry run to see what would be deployed
    $0 --dry-run

    # Skip image building (uses existing images)
    $0 --skip-build

    # Use Kustomize instead of Helm
    $0 --kustomize

    # Rollback to previous release
    $0 --rollback

EOF
}

main() {
    log_section "Darwin - Beta Deployment"
    echo -e "${BLUE}Version: $VERSION${NC}"
    echo -e "${BLUE}Registry: $IMAGE_REGISTRY${NC}"
    echo -e "${BLUE}Namespace: $NAMESPACE${NC}"
    echo ""

    parse_args "$@"

    if [ "$ROLLBACK" -eq 1 ]; then
        check_prerequisites || exit 1
        do_rollback || exit 1
        log_section "Rollback Complete"
        exit 0
    fi

    check_prerequisites || exit 1

    if [ "$BUILD_IMAGES" -eq 1 ]; then
        registry_login || exit 1
        build_and_push_images || exit 2
    fi

    if [ "$USE_KUSTOMIZE" -eq 1 ]; then
        deploy_with_kustomize || exit 3
    else
        deploy_with_helm || exit 3
    fi

    verify_deployment

    log_section "Deployment Summary"
    echo -e "${GREEN}✓${NC} Release: $RELEASE_NAME"
    echo -e "${GREEN}✓${NC} Namespace: $NAMESPACE"
    echo -e "${GREEN}✓${NC} Context: $KUBE_CONTEXT"
    echo -e "${GREEN}✓${NC} Image Tag: $IMAGE_TAG"
    echo -e "${GREEN}✓${NC} App Host: https://$APP_HOST"
    log_info "Deployment complete!"
}

main "$@"
