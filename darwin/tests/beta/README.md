# Beta Test Suite

**Purpose**: Validate Kubernetes deployments (Kustomize, kubectl, Helm v3) against beta environment.

## What Beta Tests Cover

### 1. K8s Deployment Verification
- Kustomize deployments work correctly
- kubectl manifests deploy successfully
- Helm v3 charts install properly
- All pods reach Ready state
- Services are exposed correctly

### 2. K8s-Specific Behaviors
- Service discovery works (DNS)
- Network policies are enforced
- Persistent volumes mount correctly
- ConfigMaps and Secrets are loaded
- Resource limits are respected
- Health checks pass in K8s context

### 3. Mock Data Integration (K8s)
- Mock data populates in K8s-deployed database
- Data persists across pod restarts
- No data loss or corruption

### 4. Page/Tab Load Tests (K8s)
- Pages load through Ingress/LoadBalancer
- TLS termination works correctly
- No weird caching behaviors
- Session persistence across pods
- Tab switching works in K8s environment

### 5. API Tests (K8s)
- APIs accessible through K8s services
- Authentication works with K8s secrets
- Load balancing distributes requests
- API responses are consistent
- No timeout issues
- Authenticated endpoints work correctly

### 6. Deployment Methods
- **Kustomize**: Base + overlays (dev/staging/prod)
- **kubectl**: Direct manifest application
- **Helm v3**: Chart installation with values

## Running Beta Tests

```bash
# Set K8s context first
export KUBECONFIG=~/.kube/config
kubectl config use-context <beta-cluster>

# Run all beta tests
./tests/beta/run-all.sh

# Run individual test suites
./tests/beta/01-kustomize-deploy-test.sh
./tests/beta/02-kubectl-deploy-test.sh
./tests/beta/03-helm-deploy-test.sh
./tests/beta/04-k8s-runtime-test.sh
./tests/beta/05-k8s-api-test.sh
./tests/beta/06-k8s-page-load-test.sh

# Clean up after tests
./tests/beta/cleanup.sh
```

## Test Output

- Results logged to `/tmp/beta-tests-<timestamp>/`
- K8s resource manifests saved
- Pod logs captured
- Screenshots from K8s-deployed app
- JSON reports for CI/CD integration

## Prerequisites

- K8s cluster access (beta environment)
- kubectl configured and authenticated
- Helm v3 installed
- Kustomize installed
- Sufficient cluster resources
- Ingress controller configured
- DNS configured for beta domain
