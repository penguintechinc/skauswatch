# SkausWatch Testing Guide

**Audience:** QA | Developers

Testing procedures for SkausWatch, including smoke tests, unit tests, integration tests, and debugging workflows.

## 🏃 Quick Testing

```bash
# Smoke tests (fast, <2 min)
make smoke-test

# Unit tests (isolated)
make test-unit

# Integration tests (with services)
make test-integration

# All tests
make test
```

## 🔥 Smoke Tests

**Purpose:** Fast verification of basic functionality (build, run, health checks).

**Mandatory requirements before every commit:**
- ✅ Build all containers successfully
- ✅ All containers start and remain healthy
- ✅ All API health endpoints respond
- ✅ Service communication working
- ✅ Database connectivity verified

### Run Smoke Tests

```bash
# Via Makefile (recommended)
make smoke-test

# Direct execution
./tests/smoke/run-all.sh

# Specific test
./tests/smoke/build/test-manager-build.sh
./tests/smoke/api/test-manager-health.sh
```

### Smoke Test Structure

```
tests/smoke/
├── build/                  # Container build verification
│   ├── test-manager-build.sh
│   ├── test-pki-build.sh
│   ├── test-sshca-build.sh
│   ├── test-monitor-build.sh
│   ├── test-s3scan-build.sh
│   ├── test-scanner-build.sh
│   ├── test-endpoint-agent-build.sh
│   └── test-webui-build.sh
├── api/                    # API health checks
│   ├── test-manager-health.sh
│   ├── test-pki-health.sh
│   ├── test-sshca-health.sh
│   └── test-monitor-health.sh
├── integration/            # Service communication
│   └── test-service-communication.sh
├── run-all.sh              # Master test runner
└── README.md
```

## 📊 Unit Tests

**Purpose:** Test individual functions/methods in isolation with mocked dependencies.

**Speed:** <1 minute total
**Scope:** No network calls, no database, no external services

### Run Unit Tests

```bash
# All unit tests
make test-unit

# Or via pytest directly
pytest tests/unit/ -v

# Specific service
pytest tests/unit/manager/ -v

# Specific test file
pytest tests/unit/manager/test_auth.py -v

# With coverage
pytest tests/unit/ --cov=services --cov-report=html
```

### Unit Test Structure

```
tests/unit/
├── manager/
│   ├── test_auth.py          # Authentication logic
│   ├── test_models.py        # Data models, validators
│   ├── test_encryption.py    # S3 credential encryption
│   └── test_api.py           # API endpoints
├── pki/
│   ├── test_certificate.py   # Cert generation
│   └── test_revocation.py    # Revocation logic
├── sshca/
│   └── test_ssh_certs.py     # SSH cert issuance
└── monitor/
    └── test_threat_analysis.py
```

### Example Unit Test

```python
# tests/unit/manager/test_encryption.py
import pytest
from services.manager import encryption

def test_encrypt_decrypt_s3_creds():
    """Verify S3 credential encryption/decryption roundtrip"""
    key = encryption.generate_key()
    plaintext = {
        "access_key": "AKIA...",
        "secret_key": "wJal..."
    }

    ciphertext = encryption.encrypt(plaintext, key)
    decrypted = encryption.decrypt(ciphertext, key)

    assert decrypted == plaintext

def test_decrypt_with_wrong_key_raises():
    """Verify decryption fails with wrong key"""
    key1 = encryption.generate_key()
    key2 = encryption.generate_key()
    plaintext = {"access_key": "AKIA..."}

    ciphertext = encryption.encrypt(plaintext, key1)

    with pytest.raises(ValueError):
        encryption.decrypt(ciphertext, key2)
```

## 🔗 Integration Tests

**Purpose:** Test service interactions with real dependencies (DB, Redis, gRPC).

**Speed:** 2-5 minutes
**Scope:** Real database, real Redis, inter-service communication

### Run Integration Tests

```bash
# All integration tests
make test-integration

# Or via pytest
pytest tests/integration/ -v

# Specific service interaction
pytest tests/integration/services/test_manager_pki_communication.py -v

# Database tests
pytest tests/integration/database/ -v
```

### Integration Test Structure

```
tests/integration/
├── manager/
│   ├── test_auth_flow.py      # Full auth workflow
│   ├── test_scan_lifecycle.py # S3 scan end-to-end
│   └── test_user_creation.py  # User CRUD
├── pki/
│   ├── test_certificate_lifecycle.py
│   └── test_ocsp_integration.py
├── sshca/
│   └── test_ssh_cert_flow.py
├── services/
│   ├── test_manager_pki_communication.py
│   ├── test_manager_sshca_communication.py
│   └── test_monitor_integration.py
└── database/
    └── test_migrations.py
```

## 🧪 Mock Data

**Purpose:** Populate development database with realistic test data (3-4 items per entity).

### Run Mock Data Scripts

```bash
# Seed all mock data
make seed-mock-data

# Or directly
python scripts/mock-data/seed-all.py

# Seed specific feature
python scripts/mock-data/seed-users.py
python scripts/mock-data/seed-certificates.py
```

### Mock Data Structure

```
scripts/mock-data/
├── seed-all.py              # Orchestrator
├── seed-users.py            # 3-4 users with different roles
├── seed-certificates.py     # 3-4 certificates in various states
├── seed-ssh-keys.py         # 3-4 SSH keys
├── seed-audit-logs.py       # 3-4 audit log entries
└── README.md
```

## 🚨 Vault Sub-Module Tests

Vault tests run independently in the Vault worktree.

### Vault Unit Tests

```bash
cd .worktrees/vault/vault/services/flask-backend

# All Vault unit tests
pytest tests/ -v

# Envelope encryption (AES-256-GCM)
pytest tests/test_envelope.py -v

# JIT token format and expiry
pytest tests/test_jit_token.py -v

# JIT + one-time secret lifecycle
pytest tests/test_jit_flow_integration.py -v
```

### Vault Smoke Tests

```bash
# Full 6-phase smoke run (build + start + health + API + teardown)
icebox/tests/smoke/run-all.sh

# Build only (faster, for pre-commit)
icebox/tests/smoke/run-all.sh --build-only

# Skip build (use existing images)
icebox/tests/smoke/run-all.sh --skip-build
```

## 📈 Cross-Architecture Testing

**Purpose:** Ensure builds work on both amd64 and arm64.

**When to test:** Before final commit (optional but recommended)

### Setup Buildx

```bash
# Enable Docker buildx
docker buildx create --name multiarch --driver docker-container
docker buildx use multiarch

# Verify
docker buildx ls
```

### Test Alternate Architecture

```bash
# If developing on amd64, test arm64 (uses QEMU emulation)
docker buildx build --platform linux/arm64 -t manager:test services/manager/

# If developing on arm64, test amd64
docker buildx build --platform linux/amd64 -t manager:test services/manager/

# Test both simultaneously
docker buildx build --platform linux/amd64,linux/arm64 \
  -t manager:multiarch services/manager/
```

### Makefile Target

```bash
# Add to Makefile
.PHONY: test-multiarch
test-multiarch:
	@bash scripts/build/test-multiarch.sh
```

## 🐛 Debugging Failed Tests

### View Test Logs

```bash
# All test output
pytest tests/unit/ -v -s

# Stop on first failure
pytest tests/unit/ -x

# Show local variables in tracebacks
pytest tests/unit/ -l

# Show warnings
pytest tests/unit/ -W all
```

### Debug a Specific Test

```bash
# Run with Python debugger
pytest tests/unit/manager/test_auth.py::test_login_success -v --pdb

# Commands in pdb:
# (Pdb) c            - continue execution
# (Pdb) n            - next line
# (Pdb) p variable   - print variable
# (Pdb) l            - list source
# (Pdb) h            - help
```

### Database Debugging

```bash
# Inspect database during test
docker-compose exec postgres psql -U postgres -d skauswatch_dev

# View tables
SELECT * FROM users LIMIT 5;
SELECT * FROM scans WHERE status = 'pending';

# Check for locks
SELECT * FROM pg_stat_activity WHERE state != 'idle';
```

### Service Health During Tests

```bash
# Check service status
curl http://localhost:5000/api/health

# View logs
docker-compose logs -f manager

# Connect to container
docker-compose exec manager bash
```

## 📊 Test Execution Order (Pre-Commit)

Run tests in this order for efficiency:

1. **Linters** (fast, <1 min)
2. **Security scans** (fast, <1 min)
3. **Build & Run** (5-10 min)
4. **Smoke tests** (fast, <2 min) ← Gates further testing
5. **Unit tests** (1-2 min)
6. **Integration tests** (2-5 min)
7. **Vault tests** (if Vault modified)
8. **E2E tests** (optional, 5-10 min)

## 🏆 Testing Checklist

Before committing, verify:

- [ ] All smoke tests pass: `make smoke-test`
- [ ] All unit tests pass: `make test-unit`
- [ ] All integration tests pass: `make test-integration`
- [ ] Linting passes: `flake8 services/`
- [ ] No secrets in code: `grep -r "AKIA\|sk-\|bearer " services/`
- [ ] Mock data seeded: `make seed-mock-data`
- [ ] Service communication verified
- [ ] Cross-architecture tested (optional): `make test-multiarch`

---

**Last Updated:** 2026-03-10
**Maintained by:** Penguin Tech Inc
