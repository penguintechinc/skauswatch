#!/bin/bash
# Deploy to Beta Environment
# Builds containers, pushes to registry, and deploys to K8s

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REGISTRY="registry-dal2.penguintech.io"
KUBE_CONTEXT="dal2-beta"
KUBE_NAMESPACE="darwin-beta"
PROJECT_NAME="darwin"
VERSION=$(cat .version 2>/dev/null || echo "v1.0.0")
BUILD_TAG="beta-$(date +%s)"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check prerequisites
log_info "Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed"
    exit 1
fi

if ! command -v kubectl &> /dev/null; then
    log_error "kubectl is not installed"
    exit 1
fi

if ! kubectl config get-contexts | grep -q "$KUBE_CONTEXT"; then
    log_error "kubectl context '$KUBE_CONTEXT' not found"
    log_info "Available contexts:"
    kubectl config get-contexts
    exit 1
fi

log_success "Prerequisites check passed"

# Step 1: Build container images
log_info "========================================="
log_info "Step 1: Building container images"
log_info "========================================="

SERVICES=("flask-backend" "webui")

for service in "${SERVICES[@]}"; do
    log_info "Building $service..."

    IMAGE_NAME="$REGISTRY/$PROJECT_NAME-$service:$BUILD_TAG"
    IMAGE_LATEST="$REGISTRY/$PROJECT_NAME-$service:latest"

    if docker build \
        -t "$IMAGE_NAME" \
        -t "$IMAGE_LATEST" \
        --platform linux/amd64,linux/arm64 \
        --build-arg VERSION="$VERSION" \
        --build-arg BUILD_TAG="$BUILD_TAG" \
        -f "services/$service/Dockerfile" \
        "services/$service"; then
        log_success "$service image built: $IMAGE_NAME"
    else
        log_error "Failed to build $service"
        exit 1
    fi
done

# Step 2: Push images to registry
log_info "========================================="
log_info "Step 2: Pushing images to registry"
log_info "========================================="

# Login to registry (assumes credentials are configured)
log_info "Logging into registry: $REGISTRY"
if docker login "$REGISTRY" > /dev/null 2>&1; then
    log_success "Registry login successful"
else
    log_error "Failed to login to registry"
    log_info "Please run: docker login $REGISTRY"
    exit 1
fi

for service in "${SERVICES[@]}"; do
    log_info "Pushing $service..."

    IMAGE_NAME="$REGISTRY/$PROJECT_NAME-$service:$BUILD_TAG"
    IMAGE_LATEST="$REGISTRY/$PROJECT_NAME-$service:latest"

    if docker push "$IMAGE_NAME" && docker push "$IMAGE_LATEST"; then
        log_success "$service images pushed"
    else
        log_error "Failed to push $service images"
        exit 1
    fi
done

# Step 3: Switch to beta K8s context
log_info "========================================="
log_info "Step 3: Configuring K8s context"
log_info "========================================="

CURRENT_CONTEXT=$(kubectl config current-context)
log_info "Current context: $CURRENT_CONTEXT"

if [ "$CURRENT_CONTEXT" != "$KUBE_CONTEXT" ]; then
    log_info "Switching to context: $KUBE_CONTEXT"
    kubectl config use-context "$KUBE_CONTEXT"
    log_success "Switched to $KUBE_CONTEXT"
else
    log_success "Already using $KUBE_CONTEXT"
fi

# Verify connectivity
if kubectl cluster-info > /dev/null 2>&1; then
    log_success "K8s cluster connectivity verified"
else
    log_error "Cannot connect to K8s cluster"
    exit 1
fi

# Step 4: Create namespace if needed
log_info "========================================="
log_info "Step 4: Preparing namespace"
log_info "========================================="

if kubectl get namespace "$KUBE_NAMESPACE" > /dev/null 2>&1; then
    log_success "Namespace exists: $KUBE_NAMESPACE"
else
    log_info "Creating namespace: $KUBE_NAMESPACE"
    kubectl create namespace "$KUBE_NAMESPACE"
    log_success "Namespace created"
fi

# Step 5: Deploy to K8s using kubectl
log_info "========================================="
log_info "Step 5: Deploying to K8s"
log_info "========================================="

# Update image tags in deployment manifests
log_info "Updating deployment manifests with new image tags..."

# Create a temporary directory for modified manifests
TEMP_MANIFESTS=$(mktemp -d)

# Process manifests and update image tags
for manifest in k8s/manifests/*.yaml; do
    if [ -f "$manifest" ]; then
        filename=$(basename "$manifest")
        log_info "Processing $filename..."

        # Replace image references with new tags
        sed -e "s|image:.*/$PROJECT_NAME-flask-backend:.*|image: $REGISTRY/$PROJECT_NAME-flask-backend:$BUILD_TAG|g" \
            -e "s|image:.*/$PROJECT_NAME-webui:.*|image: $REGISTRY/$PROJECT_NAME-webui:$BUILD_TAG|g" \
            "$manifest" > "$TEMP_MANIFESTS/$filename"
    fi
done

# Apply manifests
log_info "Applying K8s manifests..."
if kubectl apply -f "$TEMP_MANIFESTS/" -n "$KUBE_NAMESPACE"; then
    log_success "Manifests applied successfully"
else
    log_error "Failed to apply manifests"
    rm -rf "$TEMP_MANIFESTS"
    exit 1
fi

# Cleanup temp manifests
rm -rf "$TEMP_MANIFESTS"

# Step 6: Wait for deployment rollout
log_info "========================================="
log_info "Step 6: Waiting for deployment rollout"
log_info "========================================="

DEPLOYMENTS=$(kubectl get deployments -n "$KUBE_NAMESPACE" -o jsonpath='{.items[*].metadata.name}')

for deployment in $DEPLOYMENTS; do
    log_info "Waiting for deployment: $deployment"

    if kubectl rollout status deployment/"$deployment" -n "$KUBE_NAMESPACE" --timeout=300s; then
        log_success "Deployment ready: $deployment"
    else
        log_error "Deployment failed: $deployment"
        kubectl describe deployment/"$deployment" -n "$KUBE_NAMESPACE"
        exit 1
    fi
done

# Step 7: Verify deployment
log_info "========================================="
log_info "Step 7: Verifying deployment"
log_info "========================================="

# Check pod status
log_info "Pod status:"
kubectl get pods -n "$KUBE_NAMESPACE"

# Check services
log_info "Services:"
kubectl get services -n "$KUBE_NAMESPACE"

# Get ingress URL
INGRESS_URL=$(kubectl get ingress -n "$KUBE_NAMESPACE" -o jsonpath='{.items[0].spec.rules[0].host}' 2>/dev/null || echo "")

if [ -n "$INGRESS_URL" ]; then
    log_success "Deployment accessible at: https://$INGRESS_URL"
else
    log_warning "No ingress found, check service configuration"
fi

# Final summary
log_info "========================================="
log_success "Beta Deployment Complete!"
log_info "========================================="
log_info "Registry: $REGISTRY"
log_info "Build Tag: $BUILD_TAG"
log_info "Namespace: $KUBE_NAMESPACE"
log_info "Context: $KUBE_CONTEXT"
[ -n "$INGRESS_URL" ] && log_info "URL: https://$INGRESS_URL"
log_info "========================================="
