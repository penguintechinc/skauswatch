# Testing Guide - SkausWatch

Comprehensive testing documentation for SkausWatch's eight-service architecture with IceBox and Darwin sub-modules, including unit tests, integration tests, PKI testing, SSH CA testing, smoke tests, mock data, and cross-architecture validation.

## Overview

Testing is organized into multiple levels to ensure comprehensive coverage, fast feedback, and production-ready code:

| Test Level | Purpose | Speed | Coverage |
|-----------|---------|-------|----------|
| **Smoke Tests** | Fast verification of basic functionality | <2 min | Build, run, API health, service communication |
| **Unit Tests** | Isolated function/method testing | <1 min | Code logic, edge cases, security validation |
| **Integration Tests** | Service interaction verification | 1-5 min | Inter-service communication, data flow |
| **PKI Tests** | Certificate management validation | 2-5 min | Certificate generation, revocation, OCSP |
| **SSH CA Tests** | SSH certificate authority validation | 2-5 min | SSH cert generation, validation, expiry |
| **E2E Tests** | Critical workflows end-to-end | 5-10 min | User scenarios, business logic |
| **IceBox Tests** | Secrets vault validation | 2-5 min | Encryption, JIT tokens, one-time secrets, API |
| **Performance Tests** | Scalability and throughput validation | 5-15 min | Load, latency, resource usage |

---

## Mock Data Scripts

### Purpose

Mock data scripts populate the development database with realistic test data, enabling:
- Rapid local development without manual data entry
- Consistent test data across the development team
- Documentation of expected data structure and relationships
- Quick feature iteration with pre-populated databases

### Location & Structure

```
scripts/mock-data/
├── seed-all.py             # Orchestrator: runs all seeders in order
├── seed-users.py           # 3-4 users with different roles
├── seed-certificates.py    # 3-4 certificates in various states
├── seed-ssh-keys.py        # 3-4 SSH keys and certificates
├── seed-audit-logs.py      # 3-4 audit log entries
├── seed-[feature].py       # Additional feature-specific seeders
└── README.md               # Instructions for running mock data
```

### Naming Convention

- **Python**: `seed-{feature-name}.py`
- **Shell**: `seed-{feature-name}.sh`
- **Organization**: One seeder per logical entity/feature

### Scope: 3-4 Items Per Service

Each seeder should create **exactly 3-4 representative items** to test all feature variations:

**Example (Users)**:
```python
# seed-users.py
items = [
    {"email": "admin@example.com", "role": "admin", "status": "active"},
    {"email": "maintainer@example.com", "role": "maintainer", "status": "active"},
    {"email": "viewer@example.com", "role": "viewer", "status": "active"},
    {"email": "inactive@example.com", "role": "user", "status": "inactive"},
]
```

**Example (Certificates)**:
```python
# seed-certificates.py
items = [
    {"subject": "cn=server1.example.com", "status": "active", "days_valid": 365},
    {"subject": "cn=server2.example.com", "status": "active", "days_valid": 180},
    {"subject": "cn=expired.example.com", "status": "revoked", "days_valid": 0},
    {"subject": "cn=pending.example.com", "status": "pending", "days_valid": 365},
]
```

### Execution

**Seed all test data**:
```bash
make seed-mock-data          # Via Makefile
python scripts/mock-data/seed-all.py  # Direct execution
```

**Seed specific feature**:
```bash
python scripts/mock-data/seed-users.py
python scripts/mock-data/seed-certificates.py
```

### Implementation Pattern

**Python (PyDAL)**:
```python
#!/usr/bin/env python3
"""Seed mock data for users entity."""

import os
import sys
from dal import DAL

def seed_users():
    db = DAL('sqlite:memory')  # or use DB_TYPE env var

    users = [
        {"email": "admin@example.com", "role": "admin"},
        {"email": "user1@example.com", "role": "user"},
        {"email": "user2@example.com", "role": "user"},
        {"email": "viewer@example.com", "role": "viewer"},
    ]

    for user in users:
        db.users.insert(**user)

    print(f"✓ Seeded {len(users)} users")

if __name__ == "__main__":
    seed_users()
```

**Shell (curl/API)**:
```bash
#!/bin/bash
# seed-certificates.sh

API_URL="${API_URL:-http://localhost:8001}"
TOKEN="${AUTH_TOKEN}"

# Certificate 1
curl -X POST "$API_URL/api/v1/certificates" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"subject": "cn=server1.example.com", "days_valid": 365}'

# Certificate 2
curl -X POST "$API_URL/api/v1/certificates" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"subject": "cn=server2.example.com", "days_valid": 180}'

echo "✓ Seeded 2 certificates"
```

### Makefile Integration

Add to your `Makefile`:

```makefile
.PHONY: seed-mock-data
seed-mock-data:
	@echo "Seeding mock data..."
	@python scripts/mock-data/seed-all.py
	@echo "✓ Mock data seeding complete"

.PHONY: clean-data
clean-data:
	@echo "Clearing mock data..."
	@rm -f data/dev.db
	@echo "✓ Mock data cleared"
```

### When to Create Mock Data Scripts

**Create a mock data script after each new feature/entity completion**:
- After implementing users entity → create `seed-users.py`
- After implementing certificate management → create `seed-certificates.py`
- After implementing SSH keys → create `seed-ssh-keys.py`

---

## Smoke Tests

### Purpose

Smoke tests provide fast verification that basic functionality works after code changes, preventing regressions in core features.

### Requirements (Mandatory)

All projects **MUST** implement smoke tests before committing:

- ✅ **Build Tests**: All containers build successfully without errors
- ✅ **Run Tests**: All containers start and remain healthy
- ✅ **API Health Checks**: All API endpoints respond with 200/healthy status
- ✅ **Service Communication**: Manager can communicate with PKI, SSH CA, AAA Monitor
- ✅ **Database Connectivity**: All services connect to database successfully

### Location & Structure

```
tests/smoke/
├── build/          # Container build verification
│   ├── test-manager-build.sh
│   ├── test-pki-build.sh
│   ├── test-ssh-ca-build.sh
│   └── test-aaa-monitor-build.sh
├── run/            # Container runtime and health
│   ├── test-manager-run.sh
│   ├── test-pki-run.sh
│   ├── test-ssh-ca-run.sh
│   └── test-aaa-monitor-run.sh
├── api/            # API health endpoint validation
│   ├── test-manager-health.sh
│   ├── test-pki-health.sh
│   ├── test-ssh-ca-health.sh
│   ├── test-aaa-monitor-health.sh
│   └── README.md
├── integration/    # Service communication
│   ├── test-service-communication.sh
│   └── README.md
├── run-all.sh      # Execute all smoke tests
└── README.md       # Documentation
```

### Execution

**Run all smoke tests**:
```bash
make smoke-test              # Via Makefile
./tests/smoke/run-all.sh     # Direct execution
```

**Run specific test category**:
```bash
./tests/smoke/build/test-manager-build.sh
./tests/smoke/api/test-manager-health.sh
./tests/smoke/integration/test-service-communication.sh
```

### Speed Requirement

Complete smoke test suite **MUST run in under 2 minutes** to provide fast feedback during development.

### Implementation Examples

**Build Test (Shell)**:
```bash
#!/bin/bash
# tests/smoke/build/test-manager-build.sh

set -e

echo "Testing Manager build..."
cd services/manager

# Attempt to build the container
if docker build -t manager:test .; then
    echo "✓ Manager builds successfully"
    exit 0
else
    echo "✗ Manager build failed"
    exit 1
fi
```

**Health Check Test**:
```bash
#!/bin/bash
# tests/smoke/api/test-manager-health.sh

set -e

echo "Checking Manager API health..."
HEALTH_URL="http://localhost:8000/api/health"

RESPONSE=$(curl -s -w "\n%{http_code}" "$HEALTH_URL")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ Manager API is healthy (HTTP $HTTP_CODE)"
    exit 0
else
    echo "✗ Manager API is unhealthy (HTTP $HTTP_CODE)"
    exit 1
fi
```

**Service Communication Test**:
```bash
#!/bin/bash
# tests/smoke/integration/test-service-communication.sh

set -e

echo "Testing inter-service communication..."

# Manager → PKI Server
curl -s http://localhost:8001/api/health || exit 1

# Manager → SSH CA
curl -s http://localhost:8002/api/health || exit 1

# Manager → AAA Monitor
curl -s http://localhost:8003/api/health || exit 1

echo "✓ All services communicating correctly"
```

---

## Unit Tests

### Purpose

Unit tests verify individual functions and methods in isolation with mocked dependencies.

### Location

```
tests/unit/
├── manager/
│   ├── test_auth.py
│   ├── test_models.py
│   └── test_api.py
├── pki-server/
│   ├── test_certificate_generation.py
│   ├── test_revocation.py
│   └── test_ocsp.py
├── ssh-ca/
│   ├── test_ssh_key_generation.py
│   ├── test_cert_issuance.py
│   └── test_validation.py
└── aaa-monitor/
    ├── test_log_parsing.py
    └── test_threat_detection.py
```

### Execution

```bash
make test-unit              # All unit tests
pytest tests/unit/          # Python
pytest tests/unit/manager   # Service-specific
```

### Requirements

- All dependencies must be mocked
- Network calls must be stubbed
- Database access must be isolated
- Tests must run in parallel when possible

---

## Integration Tests

### Purpose

Integration tests verify that components work together correctly, including real database interactions and inter-service communication.

### Location

```
tests/integration/
├── manager/
│   ├── test_auth_flow.py
│   ├── test_user_creation.py
│   └── test_api_contracts.py
├── pki-server/
│   ├── test_certificate_lifecycle.py
│   ├── test_database_operations.py
│   └── test_ocsp_integration.py
├── ssh-ca/
│   ├── test_ssh_cert_flow.py
│   └── test_database_operations.py
├── services/
│   ├── test_manager_pki_communication.py
│   ├── test_manager_ssh_ca_communication.py
│   └── test_aaa_monitor_integration.py
└── database/
    ├── test_migrations.py
    └── test_queries.py
```

### Execution

```bash
make test-integration       # All integration tests
pytest tests/integration/   # Python
pytest tests/integration/manager  # Service-specific
```

### Requirements

- Use real databases (test instances)
- Test complete workflows
- Verify API contracts
- Test error scenarios

---

## PKI Testing Strategy

### Certificate Generation Testing

```bash
# Test certificate generation
pytest tests/integration/pki-server/test_certificate_lifecycle.py

# Test with different key sizes
pytest tests/integration/pki-server/ -k "key_size"

# Test certificate validation
pytest tests/integration/pki-server/ -k "validation"
```

### Revocation Testing

```bash
# Test certificate revocation
pytest tests/integration/pki-server/test_revocation.py

# Test CRL generation
pytest tests/integration/pki-server/ -k "crl"

# Test OCSP responder
pytest tests/integration/pki-server/test_ocsp_integration.py
```

### OCSP Testing

Mock OCSP client and server interactions:

```python
# tests/integration/pki-server/test_ocsp_integration.py
def test_ocsp_response_format():
    """Verify OCSP response is properly formatted"""
    # Generate certificate
    cert = generate_test_certificate()

    # Request OCSP status
    response = request_ocsp_status(cert)

    # Validate response format
    assert response.status == 'successful'
    assert response.cert_status == 'good'
```

---

## SSH CA Testing Strategy

### SSH Key Generation Testing

```bash
# Test SSH key pair generation
pytest tests/integration/ssh-ca/test_ssh_key_generation.py

# Test with different key types
pytest tests/integration/ssh-ca/ -k "key_type"

# Test key validation
pytest tests/integration/ssh-ca/ -k "validation"
```

### SSH Certificate Issuance Testing

```bash
# Test SSH certificate issuance
pytest tests/integration/ssh-ca/test_ssh_cert_flow.py

# Test certificate signing
pytest tests/integration/ssh-ca/ -k "signing"

# Test with different principals
pytest tests/integration/ssh-ca/ -k "principals"
```

### SSH Certificate Validation Testing

```python
# tests/integration/ssh-ca/test_validation.py
def test_ssh_cert_validation():
    """Verify SSH certificate validates correctly"""
    # Generate CA key
    ca_key = generate_ca_key()

    # Issue certificate
    cert = issue_ssh_cert(ca_key, "user@example.com")

    # Validate certificate
    assert validate_ssh_cert(cert, ca_key)
    assert not validate_ssh_cert(cert, wrong_key)
```

---

## IceBox Sub-Module Tests

### Location

IceBox tests live in the IceBox worktree, separate from core SkausWatch tests:

```
.worktrees/icebox/icebox/
├── services/flask-backend/tests/
│   ├── test_envelope.py           # AES-256-GCM roundtrip, tamper, MEK rotation
│   ├── test_jit_token.py          # HMAC token format, expiry, tamper detection
│   └── test_jit_flow_integration.py  # Full JIT + one-time secret lifecycle
└── tests/smoke/
    └── run-all.sh                 # 6-phase smoke runner
```

### IceBox Smoke Tests

**6-phase smoke runner:**

```bash
# Full smoke run (build + run + API)
icebox/tests/smoke/run-all.sh

# Build only (faster, pre-commit)
icebox/tests/smoke/run-all.sh --build-only

# Skip build (use existing images)
icebox/tests/smoke/run-all.sh --skip-build
```

**Phases:**
1. Build all 5 IceBox containers
2. Start services (flask-backend, pki-server, ssh-ca, sync-worker, webui)
3. Wait for health checks
4. API health validation
5. Core API smoke (secrets CRUD, JIT request, one-time create)
6. Teardown

**Requirements**: IceBox namespace must exist on `--context local-alpha`. Provision with:
```bash
kubectl apply --context local-alpha -k icebox/k8s/kustomize/overlays/alpha
```

### IceBox Unit Tests

```bash
# All IceBox unit tests
cd .worktrees/icebox/icebox/services/flask-backend
pytest tests/ -v

# Envelope encryption tests
pytest tests/test_envelope.py -v
# Covers: AES-256-GCM roundtrip, authentication tag tamper detection, MEK rotation

# JIT token tests
pytest tests/test_jit_token.py -v
# Covers: HMAC token format (jit:{grant_id}:{grantee_id}:{expires}), expiry, tamper

# JIT flow integration test
pytest tests/test_jit_flow_integration.py -v
# Covers: full lifecycle — JIT request → approve → generate token → use → expire
# Also covers: one-time secret create → view → verify view-once enforcement
```

### IceBox WebUI Smoke Tests

IceBox WebUI has 9 pages, each requiring a smoke test:
- `/login` — LoginPageBuilder with ALTCHA CAPTCHA
- `/dashboard` — Secrets summary cards
- `/secrets` — Secrets list and CRUD
- `/jit-access` — JIT access request/approve workflow
- `/cloud-sync` — Cloud integration management
- `/audit` — Audit log viewer
- `/one-time` — One-time secrets
- `/settings` — MEK rotation, license key management
- `/pki` and `/ssh` — IceBox PKI/SSH CA management

Run via Playwright:
```bash
cd .worktrees/icebox/icebox/webui
npx playwright test tests/smoke/
```

---

## End-to-End Tests

### Purpose

E2E tests verify critical user workflows from start to finish, testing the entire application stack.

### Location

```
tests/e2e/
├── certificate-lifecycle.spec.ts
├── ssh-ca-flow.spec.ts
├── user-authentication.spec.ts
└── audit-logging.spec.ts
```

### Execution

```bash
make test-e2e               # All E2E tests
npx playwright test tests/e2e/  # Playwright
```

---

## Performance Tests

### Purpose

Performance tests validate scalability, throughput, and resource usage under load.

### Location

```
tests/performance/
├── load-test.js
├── stress-test.js
└── profile-report.md
```

### Execution

```bash
make test-performance
npm run test:performance
```

---

## Cross-Architecture Testing

### Purpose

Cross-architecture testing ensures the application builds and runs correctly on both amd64 and arm64 architectures, preventing platform-specific bugs.

### When to Test

**Before every final commit**, test on the alternate architecture:
- Developing on amd64 → Build and test arm64 with QEMU
- Developing on arm64 → Build and test amd64 with QEMU

### Setup (First Time)

Enable Docker buildx for multi-architecture builds:

```bash
docker buildx create --name multiarch --driver docker-container
docker buildx use multiarch
```

### Single Architecture Build

```bash
# Test current architecture (native, fast)
docker build -t manager:test services/manager/

# Or explicitly specify architecture
docker build --platform linux/amd64 -t manager:test services/manager/
```

### Cross-Architecture Build (QEMU)

```bash
# Test alternate architecture (uses QEMU emulation)
docker buildx build --platform linux/arm64 -t manager:test services/manager/

# Or test both simultaneously
docker buildx build --platform linux/amd64,linux/arm64 -t manager:test services/manager/
```

### Multi-Architecture Build Script

Create `scripts/build/test-multiarch.sh`:

```bash
#!/bin/bash
# Test both architectures before commit

set -e

SERVICES=("manager-new" "pki-server-new" "ssh-ca" "aaa-monitor" "worker-s3" "worker-scanner" "edr-agent" "webui")
ARCHITECTURES=("linux/amd64" "linux/arm64")

for service in "${SERVICES[@]}"; do
    echo "Testing $service on multiple architectures..."

    for arch in "${ARCHITECTURES[@]}"; do
        echo "  → Building for $arch..."
        docker buildx build \
            --platform "$arch" \
            -t "$service:multiarch-test" \
            "services/$service/" || {
            echo "✗ Build failed for $service on $arch"
            exit 1
        }
    done

    echo "✓ $service builds successfully on amd64 and arm64"
done

echo "✓ All services passed multi-architecture testing"
```

### Makefile Integration

```makefile
.PHONY: test-multiarch
test-multiarch:
	@echo "Testing multi-architecture builds..."
	@bash scripts/build/test-multiarch.sh

.PHONY: build-multiarch
build-multiarch:
	@docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-t $(IMAGE_NAME):$(VERSION) \
		--push .
```

---

## Test Execution Order (Pre-Commit)

Follow this order for efficient testing before commits:

1. **Linters** (fast, <1 min)
2. **Security scans** (fast, <1 min)
3. **Secrets check** (fast, <1 min)
4. **Build & Run** (5-10 min)
5. **Smoke tests** (fast, <2 min) ← Gates further testing
6. **Unit tests** (1-2 min)
7. **Integration tests** (2-5 min)
8. **PKI/SSH CA tests** (2-5 min)
9. **IceBox smoke tests** (if IceBox modified): `icebox/tests/smoke/run-all.sh --build-only`
10. **E2E tests** (5-10 min)
11. **Cross-architecture build** (optional, slow)

## CI/CD Integration

All tests run automatically in GitHub Actions:

- **On PR**: Smoke + Unit + Integration tests
- **On main merge**: All tests + Performance tests
- **Nightly**: Performance + Cross-architecture tests
- **Release**: Full suite + Manual sign-off

See [Workflows](WORKFLOWS.md) for detailed CI/CD configuration.

---

**Last Updated**: 2026-03-07
**Maintained by**: Penguin Tech Inc
