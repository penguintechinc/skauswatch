  # Darwin Test Suite

Comprehensive testing infrastructure for local (alpha) and Kubernetes (beta) environments.

## Test Structure

```
tests/
├── alpha/              # Local Docker Compose tests
│   ├── 01-build-test.sh
│   ├── 02-runtime-test.sh
│   ├── 03-mock-data-test.sh
│   ├── 04-page-load-test.sh
│   ├── 05-api-test.sh
│   ├── run-all.sh
│   └── cleanup.sh
├── beta/               # Kubernetes deployment tests
│   ├── 01-kustomize-deploy-test.sh
│   ├── 02-kubectl-deploy-test.sh
│   ├── 03-helm-deploy-test.sh
│   ├── 04-k8s-runtime-test.sh
│   ├── 05-k8s-api-test.sh
│   ├── 06-k8s-page-load-test.sh
│   ├── run-all.sh
│   └── cleanup.sh
├── common/             # Shared utilities and configuration
│   └── config.sh
└── mock-data/          # Mock data scripts
    └── populate.sh
```

## Quick Start

### Alpha Tests (Local Docker)

```bash
# Run all alpha tests
./tests/alpha/run-all.sh

# Run individual tests
./tests/alpha/01-build-test.sh
./tests/alpha/02-runtime-test.sh
./tests/alpha/03-mock-data-test.sh
./tests/alpha/04-page-load-test.sh
./tests/alpha/05-api-test.sh

# Clean up after testing
./tests/alpha/cleanup.sh
```

### Beta Tests (Kubernetes)

```bash
# Set K8s context first
kubectl config use-context dal2-beta

# Run all beta tests
./tests/beta/run-all.sh

# Run individual tests
./tests/beta/01-kustomize-deploy-test.sh
./tests/beta/02-kubectl-deploy-test.sh
./tests/beta/03-helm-deploy-test.sh
./tests/beta/04-k8s-runtime-test.sh
./tests/beta/05-k8s-api-test.sh
./tests/beta/06-k8s-page-load-test.sh

# Clean up after testing
./tests/beta/cleanup.sh
```

## Test Coverage

### Alpha Tests
- ✅ Container build verification (multi-arch)
- ✅ Service runtime and health checks
- ✅ Database connectivity and data integrity
- ✅ Mock data population (3-4 items per feature)
- ✅ Page load tests (all routes)
- ✅ Tab load tests
- ✅ API endpoint tests (authenticated and unauthenticated)
- ✅ Error handling verification

### Beta Tests
- ✅ Kustomize deployment (overlays: dev/staging/prod)
- ✅ kubectl manifest deployment
- ✅ Helm v3 chart deployment
- ✅ K8s-specific runtime behaviors (DNS, PVs, ConfigMaps)
- ✅ Service discovery and load balancing
- ✅ API tests through K8s services
- ✅ Page loads through Ingress/LoadBalancer
- ✅ Session persistence across pods
- ✅ No weird K8s-specific caching issues

## Test Results

All test results are logged to `/tmp/darwin-tests-<timestamp>/` including:
- `test.log` - Detailed test execution logs
- `results.json` - Structured test results
- Container logs, K8s manifests, and screenshots (where applicable)

## Prerequisites

### Alpha Tests
- Docker and Docker Compose
- Ports 5000 and 3000 available
- 4GB+ RAM available
- (Optional) Node.js 18+ for JavaScript error checking

### Beta Tests
- kubectl configured and authenticated
- Access to K8s cluster (dal2-beta context)
- Helm v3 installed
- Kustomize installed
- Sufficient cluster resources

## Environment Variables

See `tests/common/config.sh` for all configuration options.

Key variables:
- `ALPHA_FLASK_URL` - Flask API URL for local tests (default: http://localhost:5000)
- `ALPHA_WEBUI_URL` - WebUI URL for local tests (default: http://localhost:3000)
- `BETA_FLASK_URL` - Flask API URL for K8s tests
- `BETA_WEBUI_URL` - WebUI URL for K8s tests
- `TEST_ADMIN_EMAIL` - Admin test user email
- `TEST_ADMIN_PASSWORD` - Admin test user password

## Deployment to Beta

To deploy to the beta environment after passing alpha tests:

```bash
./scripts/deploy-to-beta.sh
```

This will:
1. Build multi-arch container images
2. Push to registry-dal2.penguintech.io
3. Deploy to dal2-beta K8s cluster
4. Wait for rollout completion
5. Verify deployment health

## CI/CD Integration

The test suite is designed for CI/CD integration:

```yaml
# Example GitHub Actions workflow
- name: Run Alpha Tests
  run: ./tests/alpha/run-all.sh

- name: Deploy to Beta
  if: success()
  run: ./scripts/deploy-to-beta.sh

- name: Run Beta Tests
  run: ./tests/beta/run-all.sh
```

## Troubleshooting

### Alpha Tests
- **Build failures**: Check `$LOG_DIR/build-*.log`
- **Runtime failures**: Check `$LOG_DIR/docker-logs.log`
- **API failures**: Verify database is healthy and migrations ran

### Beta Tests
- **Deployment failures**: Check `$LOG_DIR/kubectl-apply.log`
- **Pod not ready**: Check `$LOG_DIR/pods-status.log`
- **Service issues**: Verify ingress and network policies

For detailed troubleshooting, check the logs in `/tmp/darwin-tests-<timestamp>/`
