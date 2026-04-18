# Testing Guide - SkausWatch

Comprehensive testing documentation for SkausWatch's 8-service architecture. Tests are organized by category across Python (pytest), Go (go test), TypeScript (Vitest), and browser (Playwright).

## Overview

| Category | Framework | Speed | Marker | Files |
|----------|-----------|-------|--------|-------|
| **Build** | pytest + docker | 5-10 min | `@pytest.mark.build` | `tests/build/` |
| **Smoke** | pytest | <2 min | `@pytest.mark.smoke` | `tests/smoke/` |
| **Unit** | pytest / go test / vitest | 1-3 min | `@pytest.mark.unit` | Per-service `tests/unit/` |
| **API** | pytest (test_client) | 1-2 min | `@pytest.mark.api` | `tests/api/` |
| **Integration** | pytest + httpx | 2-5 min | `@pytest.mark.integration` | `tests/integration/` |
| **Stream** | pytest + fakeredis | 1-2 min | `@pytest.mark.stream` | `tests/streams/` |
| **Security** | pytest | 1-2 min | `@pytest.mark.security` | `tests/security/` |
| **Performance** | pytest + fakeredis | 5-15 min | `@pytest.mark.performance` | `tests/performance/` |
| **E2E** | pytest + httpx | 5-10 min | `@pytest.mark.e2e` | `tests/e2e/` |
| **Lint** | pytest (subprocess) | 1-2 min | `@pytest.mark.lint` | `tests/lint/` |

---

## Quick Start

```bash
# Run everything (no services needed)
./scripts/test-controller.sh all

# Run specific category
./scripts/test-controller.sh unit
./scripts/test-controller.sh smoke
./scripts/test-controller.sh api

# Run per-service
./scripts/test-controller.sh unit manager-new
./scripts/test-controller.sh unit webui
./scripts/test-controller.sh unit edr-agent
```

---

## Test Controller CLI

The unified entry point for all tests:

```bash
./scripts/test-controller.sh <type> [service]
```

**Types:** `build | unit | integration | functional | e2e | security | api | performance | smoke | lint | stream | all`

**Exit codes:** 0 = pass, 1 = fail

---

## Test Categories

### 1. Smoke Tests (`tests/smoke/`)

Fast verification of basic functionality. **Must run <2 minutes.** Required before every commit.

```bash
pytest tests/smoke/ -v -m smoke
```

| File | What it tests |
|------|--------------|
| `test_compose_valid.py` | docker-compose config validation |
| `test_python_imports.py` | Each service's main module imports without error |
| `test_manager_smoke.py` | Quart test client: /healthz, /version, login+me |
| `test_pki_smoke.py` | PKI server basic health |
| `test_go_build.py` | `go build ./...` in edr-agent |
| `test_webui_build.py` | `npm run build` in webui |

### 2. Unit Tests (per-service)

Isolated function/method tests with mocked dependencies.

**Python services** (pytest):
```bash
# All Python service unit tests
pytest services/manager-new/tests/unit/ -v
pytest services/pki-server-new/tests/unit/ -v
pytest services/ssh-ca/tests/unit/ -v
pytest services/aaa-monitor/tests/unit/ -v
pytest services/worker-s3/tests/unit/ -v
pytest services/worker-scanner/tests/unit/ -v
```

**Go service** (go test):
```bash
cd services/edr-agent && go test ./... -v
```

**TypeScript/React** (Vitest):
```bash
cd services/webui && npx vitest run
```

#### Per-Service Test Files

| Service | Test Files | Test Count |
|---------|-----------|------------|
| manager-new | auth, users, alerts, config, s3scan, edr, threat-intel | ~80 |
| pki-server-new | x509, ssh, config | ~100 |
| ssh-ca | ssh_processor | ~46 |
| aaa-monitor | health | ~43 |
| worker-s3 | models, config | ~78 |
| worker-scanner | parsers, validators, job_manager, findings | ~40 |
| edr-agent (Go) | agent, collectors, rest_reporter | ~30 |
| webui (Vitest) | useAuth, Button, RoleGuard, TabNav, ResearchInput, s3scan API | ~80 |

### 3. API Tests (`tests/api/`)

Test every API endpoint using Quart/Flask test_client (no running services needed).

```bash
pytest tests/api/ -v -m api
```

| File | Endpoints Covered |
|------|------------------|
| `test_manager_api.py` | 70+ tests: auth, users, alerts, s3-scan, EDR, approvals, threat-intel, research |
| `test_pki_api.py` | 56 tests: X.509 lifecycle, SSH lifecycle, health |
| `test_worker_scanner_api.py` | 82 tests: targets, jobs, findings, schedules, scanners |

**Shared fixtures** in `conftest.py`: app factory, test client, admin/viewer/maintainer tokens.

### 4. Integration Tests (`tests/integration/`)

Test real service interactions. **Requires `docker-compose.test.yml` infrastructure.**

```bash
# Start test infrastructure
docker compose -f docker-compose.test.yml up -d --wait

# Run integration tests
pytest tests/integration/ -v -m integration

# Tear down
docker compose -f docker-compose.test.yml down
```

| File | Flow Tested |
|------|------------|
| `test_s3_scan_flow.py` | Bucket CRUD → trigger scan → poll results → EICAR detection |
| `test_edr_flow.py` | Agent register → heartbeat → batch events → list agents |
| `test_redis_streams.py` | Publish/consume round-trip, consumer groups, ack, no-duplicate |
| `test_alert_pipeline.py` | Alert CRUD → status update → search → statistics |
| `test_service_health.py` | Health endpoints for all 6 services + Postgres/Redis/MinIO |

Tests **skip gracefully** if services are not running.

### 5. Stream Pipeline Tests (`tests/streams/`)

Test data flow through Redis Streams, Celery, and gRPC.

```bash
pytest tests/streams/ -v -m stream
```

| File | Pipeline |
|------|---------|
| `test_s3_task_pipeline.py` | Manager publishes ScanTaskMessage → worker consumes → publishes result |
| `test_celery_tasks.py` | Celery task dispatch, state transitions, retry behavior |
| `test_grpc_pipeline.py` | gRPC client init, error handling, cert request round-trip |

### 6. Security Tests (`tests/security/`)

Test authentication, authorization, and input validation security.

```bash
pytest tests/security/ -v -m security
```

| File | Attack Vectors |
|------|---------------|
| `test_auth_security.py` | SQL injection, XSS, JWT alg:none, brute force, token replay, bcrypt DoS, mass assignment |
| `test_input_validation.py` | Missing fields, null bytes, oversized payloads, invalid enums, negative integers, SQL chars |

### 7. Performance Tests (`tests/performance/`)

Test throughput and latency under load.

```bash
pytest tests/performance/ -v -m performance
```

| File | Metric |
|------|--------|
| `test_api_load.py` | Login p95<500ms, alerts list p95<200ms, s3-scan results p95<300ms |
| `test_stream_throughput.py` | 1000 msg publish <5s, consume <5s, round-trip p95<50ms |

### 8. E2E Tests (`tests/e2e/`)

Full user journeys requiring the entire stack running.

```bash
pytest tests/e2e/ -v -m e2e
```

| File | Journey |
|------|---------|
| `test_full_scan_pipeline.py` | Login → create bucket → scan → results → create indicator |
| `test_user_management.py` | Admin login → create user → new user login → delete → verify |
| `test_pki_cert_lifecycle.py` | Issue X.509 → list → revoke → CRL → OCSP. Same for SSH |

### 9. Lint Tests (`tests/lint/`)

Verify code formatting and style compliance.

```bash
pytest tests/lint/ -v -m lint
```

| File | Tools |
|------|-------|
| `test_python_lint.py` | black --check, isort --check, flake8 |
| `test_go_lint.py` | gofmt -l, go vet |
| `test_typescript_lint.py` | eslint, tsc --noEmit |

### 10. Build Tests (`tests/build/`)

Verify Docker images build successfully.

```bash
pytest tests/build/ -v -m build
```

Parameterized across all 8 services. Also validates `docker-compose config` for all compose files.

---

## Test Infrastructure

### docker-compose.test.yml

Ephemeral test infrastructure:

| Service | Port | Purpose |
|---------|------|---------|
| postgres-test | 5499 | Test database |
| redis-test | 6399 | Test Redis/Streams |
| minio-test | 9099 | Test S3 storage |

```bash
docker compose -f docker-compose.test.yml up -d --wait
docker compose -f docker-compose.test.yml down
```

### Test Helpers (`tests/helpers/`)

| Module | Functions |
|--------|----------|
| `auth.py` | `create_test_token()`, `create_admin_token()`, `create_viewer_token()` |
| `factories.py` | `make_user()`, `make_alert()`, `make_bucket_config()`, `make_scan_result()` |
| `assertions.py` | `assert_pagination()`, `assert_error()`, `assert_json_keys()` |

### Pytest Markers

Defined in `conftest.py` and `pyproject.toml`:

```
unit, integration, e2e, smoke, api, functional, performance, security, lint, build, stream, slow
```

### Manager Test Client Pattern

All Python API/unit tests follow this pattern:

```python
@pytest.fixture
async def app():
    os.environ["DB_TYPE"] = "sqlite"
    os.environ["DB_NAME"] = ":memory:"
    os.environ["JWT_SECRET_KEY"] = "test-secret"
    os.environ["GRPC_ENABLED"] = "false"
    os.environ["AI_ENABLED"] = "false"
    # Mock Redis StreamManager
    with patch("path.to.RedisStreamManager", AsyncMock()):
        app = create_app()
    return app

@pytest.fixture
async def client(app):
    return app.test_client()
```

### WebUI Test Setup

Vitest with jsdom environment:

```typescript
// vitest.config.ts
export default defineConfig({
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/client/__tests__/setup.ts'],
    include: ['src/client/__tests__/**/*.{test,spec}.{ts,tsx}'],
  },
});
```

---

## CI/CD Integration

Tests run in GitHub Actions (`.github/workflows/build.yml`):

| Group | Jobs | Blocking |
|-------|------|----------|
| **1. Lint** | lint-python, lint-go, lint-typescript, secret-scan | Yes |
| **2. Security** | bandit, gosec, npm audit | Yes |
| **3. Build** | Docker build x 8 services | Yes |
| **4. Container Scan** | Trivy (main branch only) | Yes |
| **5. Tests** | Python unit/api, Go tests, Vitest, security suite | Yes |

---

## Pre-Commit Test Order

1. `pytest tests/lint/ -m lint` (formatting check, <1 min)
2. `pytest tests/smoke/ -m smoke` (basic checks, <2 min)
3. `pytest tests/security/ -m security` (security validation, <2 min)
4. `pytest tests/api/ -m api` (API contracts, <2 min)
5. Per-service unit tests (1-3 min)

**Total pre-commit time: <10 minutes**

---

## Adding New Tests

1. Place test files in the appropriate category directory
2. Use the correct pytest marker (`@pytest.mark.<category>`)
3. Follow the existing test client pattern for the service
4. Add `__init__.py` if creating a new test directory
5. Verify with `python3 -c "import py_compile; py_compile.compile('path/to/test.py', doraise=True)"`

---

**Last Updated**: 2026-03-01
**Maintained by**: Penguin Tech Inc
