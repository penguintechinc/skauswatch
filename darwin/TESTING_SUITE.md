# Darwin Testing Suite - Complete Guide

## Overview

Comprehensive alpha (local) and beta (K8s) test suites for validating builds, deployments, integrations, and end-to-end workflows.

`★ Insight ─────────────────────────────────────`
**Two-Tier Testing Strategy:**
- **Alpha** validates local Docker builds before any K8s push
- **Beta** validates K8s-specific behaviors and deployments
- This prevents broken deployments and catches environment-specific bugs early
`─────────────────────────────────────────────────`

## Quick Start

### Alpha Tests (Local Docker)
```bash
# Run all alpha tests
make test-alpha

# Or directly
./tests/alpha/run-all.sh
```

### Beta Tests (Kubernetes)
```bash
# Set K8s context
kubectl config use-context dal2-beta

# Run all beta tests
make test-beta

# Or directly
./tests/beta/run-all.sh
```

### Deploy to Beta
```bash
# Build, push images, deploy to K8s
make deploy-beta

# Or directly
./scripts/deploy-to-beta.sh
```

## Test Suite Structure

```
tests/
├── README.md                    # Complete testing documentation
├── alpha/                       # Local Docker tests
│   ├── 01-build-test.sh        # Container build verification
│   ├── 02-runtime-test.sh      # Service runtime & health checks
│   ├── 03-mock-data-test.sh    # Mock data integration
│   ├── 04-page-load-test.sh    # Page & tab load tests
│   ├── 05-api-test.sh          # API endpoint tests
│   ├── run-all.sh              # Run all alpha tests
│   └── cleanup.sh              # Clean up test environment
├── beta/                        # Kubernetes tests
│   ├── 01-kustomize-deploy-test.sh  # Kustomize deployment
│   ├── 02-kubectl-deploy-test.sh    # kubectl deployment
│   ├── 03-helm-deploy-test.sh       # Helm v3 deployment
│   ├── 04-k8s-runtime-test.sh       # K8s runtime behaviors
│   ├── 05-k8s-api-test.sh           # K8s API tests
│   ├── 06-k8s-page-load-test.sh     # K8s page load tests
│   ├── run-all.sh                   # Run all beta tests
│   └── cleanup.sh                   # Clean up K8s resources
├── common/
│   └── config.sh                # Shared utilities & config
└── mock-data/
    └── populate.sh              # Populate 3-4 items per feature
```

## Alpha Test Coverage

### 01-build-test.sh
- ✅ flask-backend builds successfully
- ✅ webui builds successfully
- ✅ Docker images created
- ✅ No build errors or warnings

### 02-runtime-test.sh
- ✅ All containers start (flask, webui, postgres, redis)
- ✅ Health checks pass
- ✅ PostgreSQL ready
- ✅ Redis ready
- ✅ Flask /healthz endpoint responds
- ✅ WebUI loads

### 03-mock-data-test.sh
- ✅ Mock data populates (3-4 items per feature)
- ✅ User accounts created
- ✅ Reviews created
- ✅ Data relationships valid
- ✅ No orphaned records

### 04-page-load-test.sh
- ✅ Root page loads (HTTP 200)
- ✅ Login page loads
- ✅ Dashboard loads
- ✅ Reviews page loads
- ✅ Users page loads
- ✅ Settings page loads
- ✅ Tab switching works
- ✅ No JavaScript console errors

### 05-api-test.sh
- ✅ Health endpoint responds
- ✅ API version endpoint accessible
- ✅ Login validation (rejects bad credentials)
- ✅ Login success (returns token)
- ✅ Authenticated requests work
- ✅ Reviews list endpoint works
- ✅ Users list endpoint works
- ✅ Error handling (404 for invalid endpoints)

## Beta Test Coverage

### 01-kustomize-deploy-test.sh
- ✅ Kustomize installed
- ✅ Manifests build successfully
- ✅ Namespace created
- ✅ Manifests applied
- ✅ Deployments ready
- ✅ Services created

### 02-kubectl-deploy-test.sh
- ✅ kubectl installed
- ✅ Namespace created
- ✅ Manifests applied
- ✅ Pods ready
- ✅ Service endpoints ready

### 03-helm-deploy-test.sh
- ✅ Helm v3 installed
- ✅ Charts lint successfully
- ✅ flask-backend chart installs
- ✅ webui chart installs
- ✅ Releases verified
- ✅ Deployments ready

### 04-k8s-runtime-test.sh
- ✅ Service discovery (DNS) works
- ✅ Persistent volumes mount correctly
- ✅ ConfigMaps and Secrets loaded
- ✅ Resource limits configured
- ✅ Health probes configured
- ✅ Restart policies correct
- ✅ No pods in error state

### 05-k8s-api-test.sh
- ✅ Service endpoints found
- ✅ Port-forward works
- ✅ Health endpoint responds
- ✅ API version accessible
- ✅ Authentication works in K8s
- ✅ Authenticated requests work
- ✅ Load balancing works (if multiple replicas)
- ✅ API responses consistent

### 06-k8s-page-load-test.sh
- ✅ WebUI service found
- ✅ Port-forward works
- ✅ Root page loads in K8s
- ✅ Multiple pages load
- ✅ Static assets load correctly
- ✅ No weird K8s caching issues

## Available Make Commands

### Alpha Tests
```bash
make test-alpha              # Run all alpha tests
make test-alpha-build        # Build verification
make test-alpha-runtime      # Runtime verification
make test-alpha-mock         # Mock data integration
make test-alpha-pages        # Page load tests
make test-alpha-api          # API tests
make test-alpha-cleanup      # Clean up environment
```

### Beta Tests
```bash
make test-beta               # Run all beta tests
make test-beta-kustomize     # Kustomize deployment
make test-beta-kubectl       # kubectl deployment
make test-beta-helm          # Helm deployment
make test-beta-runtime       # K8s runtime tests
make test-beta-api           # K8s API tests
make test-beta-pages         # K8s page load tests
make test-beta-cleanup       # Clean up K8s resources
```

### Deployment
```bash
make deploy-beta             # Deploy to beta (build, push, deploy)
make mock-data               # Populate mock data
```

## Deployment Workflow

### Beta Deployment Process

The `deploy-beta` script performs the following:

1. **Build**: Multi-arch container images (amd64, arm64)
2. **Tag**: `beta-<timestamp>` and `latest`
3. **Push**: To `registry-dal2.penguintech.io`
4. **Deploy**: To dal2-beta K8s cluster via kubectl
5. **Verify**: Wait for rollout, check pod status
6. **Report**: Display ingress URL and deployment info

```bash
./scripts/deploy-to-beta.sh
```

Configuration:
- Registry: `registry-dal2.penguintech.io`
- K8s Context: `dal2-beta`
- Namespace: `darwin-beta`
- Build Tag: `beta-<epoch>`

## Test Results

All test results are saved to `/tmp/darwin-tests-<timestamp>/`:
- `test.log` - Detailed execution logs
- `results.json` - Structured test results (JSON)
- `build-*.log` - Build logs
- `docker-logs.log` - Container logs
- `kubectl-apply.log` - K8s deployment logs
- `pods-status.log` - Pod status information
- `k8s-events.log` - K8s events

## Mock Data

The mock data script populates:
- **1 admin user** (admin@example.com)
- **3 regular users** (user1@, user2@, user3@)
- **9+ reviews** (3 per user)
- **Valid relationships** (no orphaned records)

Run manually:
```bash
make mock-data
# Or
./tests/mock-data/populate.sh
```

## Prerequisites

### Alpha Tests
- Docker & Docker Compose
- Ports 5000, 3000 available
- 4GB+ RAM
- (Optional) Node.js 18+ for JS error checking
- (Optional) jq for JSON parsing

### Beta Tests
- kubectl configured (dal2-beta context)
- Helm v3 installed
- Kustomize installed
- Access to K8s cluster
- Registry credentials for registry-dal2.penguintech.io

## Typical Workflow

### 1. Local Development
```bash
# Start dev environment
make dev

# Populate mock data
make mock-data

# Run alpha tests
make test-alpha
```

### 2. Deploy to Beta
```bash
# Deploy to beta environment
make deploy-beta
```

### 3. Validate Beta Deployment
```bash
# Run beta tests
make test-beta
```

### 4. Cleanup
```bash
# Clean up alpha environment
make test-alpha-cleanup

# Clean up beta environment
make test-beta-cleanup
```

## CI/CD Integration

Example GitHub Actions:
```yaml
- name: Alpha Tests
  run: make test-alpha

- name: Deploy to Beta
  if: success()
  run: make deploy-beta

- name: Beta Tests
  run: make test-beta

- name: Cleanup
  if: always()
  run: |
    make test-alpha-cleanup
    make test-beta-cleanup
```

## Troubleshooting

### Alpha Test Failures
- **Build fails**: Check `$LOG_DIR/build-*.log`
- **Runtime fails**: Check `$LOG_DIR/docker-logs.log`
- **Mock data fails**: Verify database is healthy
- **API fails**: Check Flask logs with `docker logs darwin-flask-smoke`

### Beta Test Failures
- **Deploy fails**: Check `$LOG_DIR/kubectl-apply.log`
- **Pods not ready**: Check `$LOG_DIR/pods-status.log`
- **Service issues**: Verify ingress and network policies
- **Auth fails**: Check K8s secrets are configured

### Common Issues
- **Port conflicts**: Stop conflicting services
- **No K8s access**: Verify kubectl context and credentials
- **Registry login fails**: Run `docker login registry-dal2.penguintech.io`
- **Resource limits**: Ensure sufficient cluster resources

## Environment Variables

See `tests/common/config.sh` for all configuration:
- `ALPHA_FLASK_URL` (default: http://localhost:5000)
- `ALPHA_WEBUI_URL` (default: http://localhost:3000)
- `BETA_FLASK_URL` (default: https://darwin.penguintech.io/api)
- `BETA_WEBUI_URL` (default: https://darwin.penguintech.io)
- `TEST_ADMIN_EMAIL` (default: admin@example.com)
- `TEST_ADMIN_PASSWORD` (default: admin123)

## Summary

✅ **Alpha Tests**: 5 test scripts, ~25 test cases
✅ **Beta Tests**: 6 test scripts, ~30 test cases
✅ **Mock Data**: Automated population with 3-4 items per feature
✅ **Deployment**: Automated beta deployment to K8s
✅ **Make Integration**: All tests accessible via make commands
✅ **Comprehensive**: Build → Runtime → Integration → E2E

Ready to validate local builds and K8s deployments with confidence! 🚀
