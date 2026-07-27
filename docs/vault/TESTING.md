# 🧪 Vault Testing Guide

**Module:** Vault Secrets Vault
**Audience:** Developers | DevOps
**Location:** `.worktrees/vault/`
**Last Updated:** 2026-03-10

---

## 🧪 Test Categories

| Category | Command | What It Tests | When to Run |
|----------|---------|---------------|------------|
| **Unit** | `pytest tests/ -v` | Envelope encryption, JIT tokens, one-time secrets | Every commit |
| **Envelope** | `pytest tests/test_envelope.py -v` | AES-256-GCM roundtrip, tamper detection, MEK rotation | Before crypto changes |
| **JIT Token** | `pytest tests/test_jit_token.py -v` | Token format, expiry, HMAC tamper detection | Before JIT changes |
| **JIT Flow** | `pytest tests/test_jit_flow_integration.py -v` | Full JIT lifecycle: request → approve → token → retrieve → expire | Before JIT flow changes |
| **Smoke** | `bash icebox/tests/smoke/run-all.sh` | 6-phase: build, start, health, auth, secrets, JIT | Pre-commit + before deployment |
| **Security** | `bandit -r . && safety check` | Python security vulnerabilities, dependency CVEs | Pre-commit mandatory |
| **Lint** | `flake8 . && black --check . && isort --check-only .` | Code style, imports, formatting | Pre-commit mandatory |

---

## 🏃 Running Tests

### Unit Tests (All)

```bash
cd /home/penguin/code/skauswatch/.worktrees/vault/vault/services/flask-backend
pytest tests/ -v
```

### Unit Tests (Specific Files)

```bash
# Envelope encryption (AES-256-GCM)
pytest tests/test_envelope.py -v

# JIT token format and HMAC validation
pytest tests/test_jit_token.py -v

# Full JIT workflow integration
pytest tests/test_jit_flow_integration.py -v
```

### Smoke Tests (6-Phase Runner)

```bash
cd /home/penguin/code/skauswatch/.worktrees/vault

# Full smoke test suite (build, start, health, auth, secrets, JIT)
bash icebox/tests/smoke/run-all.sh

# Build only (verify Docker images)
bash icebox/tests/smoke/run-all.sh --build-only

# Skip build, run existing images
bash icebox/tests/smoke/run-all.sh --skip-build
```

### Security & Linting

```bash
cd /home/penguin/code/skauswatch/.worktrees/vault/vault/services/flask-backend

# Security scanning
bandit -r . -ll
safety check
pip-audit

# Linting
flake8 .
black --check .
isort --check-only .

# Auto-fix linting
black .
isort .
```

---

## 🔐 Unit Test Details

### test_envelope.py — AES-256-GCM Encryption

**What it tests:**
- Envelope encryption roundtrip: plaintext → encrypt → decrypt → verify
- Tamper detection: modified ciphertext/IV/tag rejected
- MEK rotation: old DEK re-wrapped with new MEK

**Key test cases:**
```python
def test_envelope_roundtrip()
    # Encrypt secret, decrypt, verify plaintext matches

def test_envelope_tamper_detection()
    # Modify ciphertext/IV/tag, verify decrypt fails

def test_mek_rotation()
    # Re-wrap DEK with new MEK, verify old DEK still decrypts
```

**Run:**
```bash
pytest tests/test_envelope.py -v
```

### test_jit_token.py — JIT Token Format & Validation

**What it tests:**
- Token format: `jit:{grant_id}:{grantee_id}:{expires_epoch}`
- HMAC validation: tokens signed with SHA-256, tamper detected
- Expiry enforcement: expired tokens rejected
- Token generation consistency

**Key test cases:**
```python
def test_jit_token_format()
    # Verify token structure and fields

def test_jit_token_hmac_validation()
    # Generate token, tamper, verify HMAC fails

def test_jit_token_expiry()
    # Create expired token, verify rejection
```

**Run:**
```bash
pytest tests/test_jit_token.py -v
```

### test_jit_flow_integration.py — Full JIT Lifecycle

**What it tests:**
- **Request phase:** User requests JIT access, grant created
- **Approval phase:** Admin approves grant, token generated
- **Retrieval phase:** Grantee uses token to retrieve secret
- **One-time phase:** One-time secret created, retrieved once, cannot re-retrieve
- **Expiry phase:** Expired JIT denies access

**Key test cases:**
```python
def test_jit_request_and_approve()
    # Create grant, approve, verify token issued

def test_jit_secret_retrieval()
    # Retrieve secret with valid JIT token

def test_jit_one_time_secret()
    # Create one-time secret, retrieve once, verify second attempt fails

def test_jit_expiry()
    # Create expired JIT, verify access denied
```

**Run:**
```bash
pytest tests/test_jit_flow_integration.py -v
```

---

## 🌐 Integration Tests

### Cloud Sync Mock Providers

Vault includes mock cloud providers for testing sync operations without external dependencies:

**Supported mocks:**
- AWS S3 (moto)
- Azure Blob Storage (mock)
- Local filesystem fallback

**Test pattern:**
```python
# Mock S3 sync
@mock_aws
def test_sync_to_s3():
    # Publish to Redis Stream
    # sync-worker reads, uploads to mock S3
    # Verify object in mock bucket
```

### Full JIT Approval Workflow

Tests the entire approval pipeline:
1. User requests access to secret
2. Admin receives notification
3. Admin approves/rejects
4. Grantee receives token (if approved)
5. Token used to retrieve secret
6. Audit log recorded

**Run:**
```bash
pytest tests/test_jit_flow_integration.py::test_jit_approval_workflow -v
```

### License Validation Bypass

Tests that license checks are skipped for development domains:

**Bypass domains:**
- `*.nest.localhost.local` (alpha)
- `*.nest.penguintech.cloud` (beta)
- `*.nestdata.app` (prod)

**Test:**
```bash
pytest tests/test_licensing_bypass.py -v
```

---

## 💨 Smoke Test Phases

The 6-phase smoke runner (`icebox/tests/smoke/run-all.sh`) verifies:

| Phase | What It Tests | Success Criteria |
|-------|---------------|------------------|
| **1. Build** | Docker images build | `docker build` exits 0 for all services |
| **2. Start** | Services start without error | All containers reach healthy state |
| **3. Health** | `/health` endpoints respond | HTTP 200 on health checks |
| **4. Auth** | JWT token issuance | Login endpoint returns valid JWT |
| **5. Secrets** | CRUD operations | Create, read, update, delete secret succeeds |
| **6. JIT** | JIT request/approval | Request → approve → token → retrieve succeeds |

**Run all phases:**
```bash
bash icebox/tests/smoke/run-all.sh
```

**Output:**
```
[Phase 1/6] Building Docker images...
✓ flask-backend
✓ sync-worker
✓ pki
✓ sshca
✓ webui

[Phase 2/6] Starting services...
✓ All services healthy

[Phase 3/6] Health checks...
✓ Flask backend: 200 OK
✓ Sync worker: 200 OK
...

[Phase 4/6] Authentication...
✓ JWT token issued

[Phase 5/6] Secrets CRUD...
✓ Create secret
✓ Read secret
✓ Update secret
✓ Delete secret

[Phase 6/6] JIT workflow...
✓ Request JIT access
✓ Approve grant
✓ Retrieve with token

All phases passed ✓
```

---

## 🔒 Security Tests

### Bandit — Python Security Scanning

```bash
cd /home/penguin/code/skauswatch/.worktrees/vault/vault/services/flask-backend

# Full scan (show high/medium severity only)
bandit -r . -ll

# Full output with low severity
bandit -r .
```

**What it detects:**
- Hardcoded passwords/secrets
- SQL injection vulnerabilities
- Insecure deserialization
- Weak cryptography

### Safety Check — Dependency Vulnerabilities

```bash
# Check requirements.txt for known CVEs
safety check

# Detailed report with policy file (optional)
safety check --json
```

### pip-audit — Audit All Python Packages

```bash
# Full audit with remediation advice
pip-audit

# JSON output for CI parsing
pip-audit --format json
```

### Pre-Commit Security Checklist

**MANDATORY before commit:**

```bash
cd /home/penguin/code/skauswatch/.worktrees/vault/vault/services/flask-backend

# Security scan
bandit -r . -ll
safety check
pip-audit

# If any vulnerabilities found, fix them and re-run
```

---

## 📋 Pre-Commit Checklist

**Every commit must pass all checks:**

```bash
cd /home/penguin/code/skauswatch/.worktrees/vault

# 1. Unit tests
cd icebox/services/flask-backend
pytest tests/ -v
[ $? -eq 0 ] && echo "✓ Unit tests passed" || exit 1

# 2. Security scans
bandit -r . -ll
safety check
pip-audit
[ $? -eq 0 ] && echo "✓ Security scan passed" || exit 1

# 3. Linting
flake8 .
black --check .
isort --check-only .
[ $? -eq 0 ] && echo "✓ Linting passed" || exit 1

# 4. Smoke tests
cd ../..
bash icebox/tests/smoke/run-all.sh --skip-build
[ $? -eq 0 ] && echo "✓ Smoke tests passed" || exit 1

echo "All checks passed! Ready to commit."
```

---

## 🐛 Troubleshooting

### Unit Tests Fail with "import errors"

**Problem:** Test imports fail because dependencies are not installed.

**Solution:**
```bash
cd /home/penguin/code/skauswatch/.worktrees/vault/vault/services/flask-backend
pip install -e .  # Install in editable mode
pip install -r requirements-dev.txt  # Dev dependencies
pytest tests/ -v
```

### Smoke Tests Fail at "Health Check"

**Problem:** Services don't become healthy within timeout.

**Solution:**
```bash
# Check service logs
docker logs vault-flask-backend
docker logs vault-sync-worker

# Verify required env vars (PostgreSQL, Redis)
docker compose -f icebox/docker-compose.yml config

# Rebuild from scratch
bash icebox/tests/smoke/run-all.sh --build-only
```

### JIT Token HMAC Fails

**Problem:** Token validation rejects otherwise valid token.

**Cause:** JIT_SECRET environment variable mismatch between test setup and service.

**Solution:**
```bash
# Verify test env setup
cat icebox/services/flask-backend/tests/conftest.py | grep JIT_SECRET

# Regenerate test tokens with current secret
pytest tests/test_jit_token.py -v --tb=short
```

### Envelope Encryption Roundtrip Fails

**Problem:** Decrypted value doesn't match original plaintext.

**Cause:** MEK rotation may have changed the encryption key.

**Solution:**
```bash
# Force use of the same MEK for test
export MEK_VERSION="1"
pytest tests/test_envelope.py::test_envelope_roundtrip -v

# Or reset MEK to baseline
rm -f /tmp/mek-cache
pytest tests/test_envelope.py -v
```

---

## 🔗 Related Documentation

- **Development Setup:** `docs/icebox/DEVELOPMENT.md`
- **Pre-Commit Workflow:** `docs/icebox/PRE_COMMIT.md`
- **Vault Architecture:** `docs/icebox/CLAUDE.md`
- **SkausWatch Core Testing:** `docs/TESTING.md`
- **Test Files:** `.worktrees/vault/vault/services/flask-backend/tests/`
- **Smoke Runner:** `.worktrees/vault/vault/tests/smoke/run-all.sh`

---

**Last Reviewed:** 2026-03-10
**Test Count:** 12+ unit tests + 6-phase smoke suite
**Expected Runtime:** Unit tests ~2min | Smoke tests ~5min
