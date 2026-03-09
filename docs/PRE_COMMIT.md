# Pre-Commit Checklist - SkausWatch

**CRITICAL: This checklist MUST be followed before every commit.**

## Automated Pre-Commit Script

**Run the automated pre-commit script to execute all checks:**

```bash
./scripts/pre-commit/pre-commit.sh
```

This script will:
1. Run all checks in the correct order
2. Log output to `/tmp/pre-commit-skauswatch-<epoch>.log`
3. Provide a summary of pass/fail status
4. Echo the log file location for review

**Individual check scripts** (run separately if needed):
- `./scripts/pre-commit/check-python.sh` - Python linting, typing & security
- `./scripts/pre-commit/check-security.sh` - All security scans (bandit)
- `./scripts/pre-commit/check-secrets.sh` - Secret detection
- `./scripts/pre-commit/check-docker.sh` - Docker build & validation
- `./scripts/pre-commit/check-tests.sh` - Unit tests

## Required Steps (In Order)

Before committing, run in this order (or use `./scripts/pre-commit/pre-commit.sh`):

### Foundation Checks
- [ ] **Linters**: `black --check .`, `flake8 .`, `isort --check .`, `mypy .`
- [ ] **Security scans**: `bandit -r .` (Python security)
- [ ] **No secrets**: Verify no credentials, API keys, or tokens in code

### Build & Integration Verification
- [ ] **Build & Run**: Verify code compiles and containers start successfully
- [ ] **Smoke tests** (mandatory, <2 min): `make smoke-test`
  - All containers build without errors
  - All containers start and remain healthy
  - All API health endpoints respond with 200 status
  - All services communicate successfully
  - Database connectivity verified
  - IceBox: `icebox/tests/smoke/run-all.sh` (6-phase runner; flags: `--build-only`, `--skip-build`)
  - See: [Testing Documentation - Smoke Tests](TESTING.md#smoke-tests)

### Feature Testing & Documentation
- [ ] **Mock data** (for testing features): Ensure 3-4 test items per feature via `make seed-mock-data`
  - Populate development database with realistic test data
  - Required for integration testing and manual QA
  - See: [Testing Documentation - Mock Data Scripts](TESTING.md#mock-data-scripts)

### Comprehensive Testing
- [ ] **Unit tests**: `make test-unit` or `pytest tests/unit/`
  - Network isolated, mocked dependencies
  - Must pass before committing
- [ ] **Integration tests**: `make test-integration` or `pytest tests/integration/`
  - Tests with real database and service communication
  - See: [Testing Documentation - Integration Tests](TESTING.md#integration-tests)
- [ ] **PKI tests** (if modifying PKI Server): `pytest tests/integration/pki-server/`
  - Certificate generation, validation, revocation
  - OCSP responder functionality
  - See: [Testing Documentation - PKI Testing](TESTING.md#pki-testing-strategy)
- [ ] **SSH CA tests** (if modifying SSH CA): `pytest tests/integration/ssh-ca/`
  - SSH key pair generation and validation
  - SSH certificate issuance and validation
  - Certificate expiry and validation
  - See: [Testing Documentation - SSH CA Testing](TESTING.md#ssh-ca-testing-strategy)

### Service-Specific Requirements

**If modifying Manager service**:
- [ ] Manager → PKI Server communication tests passing
- [ ] Manager → SSH CA communication tests passing
- [ ] Manager → AAA Monitor communication tests passing
- [ ] User authentication flow tests passing
- [ ] Role-based access control tests passing

**If modifying PKI Server service**:
- [ ] Certificate generation tests passing
- [ ] Certificate revocation tests passing
- [ ] OCSP responder tests passing
- [ ] CRL generation tests passing
- [ ] Integration with Manager service verified

**If modifying SSH CA service**:
- [ ] SSH key pair generation tests passing
- [ ] SSH certificate issuance tests passing
- [ ] SSH certificate validation tests passing
- [ ] Certificate expiry handling tests passing
- [ ] Integration with Manager service verified

**If modifying AAA Monitor service**:
- [ ] Log parsing tests passing
- [ ] Audit log storage tests passing
- [ ] Threat detection tests passing
- [ ] Integration with Manager service verified

**If modifying IceBox sub-module** (`icebox/services/flask-backend/` or `icebox/webui/`):
- [ ] Python linting: `cd .worktrees/icebox/icebox/services/flask-backend && bandit -r . && flake8 . && black --check . && isort --check . && mypy .`
- [ ] React/TS linting: `cd .worktrees/icebox/icebox/webui && npm run lint`
- [ ] IceBox unit tests: `pytest icebox/services/flask-backend/tests/ -v`
  - `test_envelope.py` — AES-256-GCM roundtrip, tamper detection, MEK rotation
  - `test_jit_token.py` — HMAC token format, expiry, tamper detection
- [ ] IceBox integration tests: `pytest icebox/services/flask-backend/tests/test_jit_flow_integration.py -v`
- [ ] IceBox smoke tests (build-only): `icebox/tests/smoke/run-all.sh --build-only`
- [ ] Verify PKI Server and SSH CA shims still proxy correctly to IceBox endpoints

**If modifying PKI Server or SSH CA shims** (`services/pki-server-new/` or `services/ssh-ca/`):
- [ ] Verify shim proxy still attaches `Deprecation:` and `Link:` headers
- [ ] Verify requests still forward correctly to `$ICEBOX_PKI_URL` / `$ICEBOX_SSH_CA_URL`
- [ ] PKI integration tests: `pytest tests/integration/pki-server/`
- [ ] SSH CA integration tests: `pytest tests/integration/ssh-ca/`

**If modifying Darwin sub-module** (`darwin/` or `services/worker-darwin/`):
- [ ] Darwin unit tests: `cd darwin && pytest tests/ -v`
- [ ] Worker-Darwin linting: `cd services/worker-darwin && bandit -r . && flake8 .`

**If modifying shared libraries (py_libs)**:
- [ ] All dependent services rebuild successfully
- [ ] All validation, security, and crypto functions test passing
- [ ] All service integration tests re-run and pass

### Finalization
- [ ] **Version updates**: Update `.version` if releasing new version
- [ ] **Documentation**: Update docs if adding/changing workflows
- [ ] **Docker builds**: Verify Dockerfile uses debian-slim base (no alpine)
- [ ] **Cross-architecture**: (Optional) Test alternate architecture with QEMU
  - `docker buildx build --platform linux/arm64 .` (if on amd64)
  - `docker buildx build --platform linux/amd64 .` (if on arm64)
  - See: [Testing Documentation - Cross-Architecture Testing](TESTING.md#cross-architecture-testing)

## Language-Specific Commands

### Python (All Services)

```bash
# Linting
black --check .              # Code formatting check
flake8 .                     # Style guide enforcement
isort --check .              # Import sorting check
mypy .                       # Type checking

# Security
bandit -r .                  # Security issue detection
safety check                 # Dependency vulnerability scan

# Build & Run
python -m py_compile *.py    # Syntax check
pip install -r requirements.txt  # Dependencies (service-specific)
python app.py &              # Verify it starts (then kill)

# Tests
pytest                       # Run all tests
pytest tests/unit/ -v        # Unit tests with verbose output
pytest tests/integration/ -v # Integration tests
pytest tests/unit/ --cov=. --cov-report=html  # Coverage report
```

### Docker / Containers

```bash
# Lint Dockerfiles
hadolint Dockerfile

# Verify base image (debian-slim, NOT alpine)
grep -E "^FROM.*slim" Dockerfile

# Build & Run
docker build -t manager:test services/manager/              # Build image
docker run -d --name test-container manager:test           # Start container
docker logs test-container                                 # Check for errors
docker stop test-container && docker rm test-container    # Cleanup

# Docker Compose (all services)
docker-compose build                 # Build all services
docker-compose up -d                 # Start all services
docker-compose logs -f               # Follow logs
docker-compose down                  # Stop all services
```

## Commit Rules

- **NEVER commit automatically** unless explicitly requested by the user
- **NEVER push to remote repositories** under any circumstances
- **ONLY commit when explicitly asked** - never assume commit permission
- **Wait for approval** before running `git commit`

## Security Scanning Requirements

### Before Every Commit

- **Run security audits on all modified packages**:
  - **Python packages**: Run `bandit -r .` on modified Python services
  - **Dependencies**: Run `safety check` for dependency vulnerabilities
- **Do NOT commit if security vulnerabilities are found** - fix all issues first
- **Document vulnerability fixes** in commit message if applicable

### Vulnerability Response

1. Identify affected packages and severity
2. Update to patched versions immediately
3. Test updated dependencies thoroughly
4. Document security fixes in commit messages
5. Verify no new vulnerabilities introduced

## API Testing Requirements

Before committing changes to any service:

- **Create and run API testing scripts** for each modified service
- **Testing scope**: All new endpoints and modified functionality
- **Test files location**: `tests/api/` directory with service-specific subdirectories
  - `tests/api/manager/` - Manager service API tests
  - `tests/api/pki-server/` - PKI server API tests
  - `tests/api/ssh-ca/` - SSH CA API tests
  - `tests/api/aaa-monitor/` - AAA Monitor API tests
  - `tests/api/worker-scanner/` - Worker-Scanner API tests
  - `tests/api/icebox/` - IceBox API tests (when IceBox installed)
- **Run before commit**: Each test script should be executable and pass completely
- **Test coverage**: Health checks, authentication, CRUD operations, error cases
- **Command pattern**: `cd services/<service-name> && pytest tests/api/ -v`

## Service Communication Testing Requirements

**For changes affecting inter-service communication**:

- [ ] Manager → PKI Server communication tests passing
- [ ] Manager → SSH CA communication tests passing
- [ ] Manager → AAA Monitor communication tests passing
- [ ] All services respond to health checks
- [ ] Database consistency verified across services

**Test command**:
```bash
pytest tests/integration/services/ -v -k "communication"
```

## Shared Library Testing Requirements

**If modifying shared libraries (py_libs)**:

- [ ] All input validation functions test passing
- [ ] All security middleware functions test passing
- [ ] All cryptographic operations test passing
- [ ] All dependent services rebuild successfully:
  ```bash
  docker-compose down && docker-compose up -d --build
  ```
- [ ] All service integration tests re-run and pass
- [ ] Cross-service communication still working

## Mock Data Requirements

### Prerequisites

Before testing, ensure development environment is running with mock data:

```bash
make dev                   # Start all services
make seed-mock-data       # Populate with 3-4 test items per feature
```

### What to Test

For all feature changes, verify mock data includes:
- **3-4 representative items** per entity (certificates, SSH keys, users, etc.)
- **Various states/statuses** when applicable (active, inactive, revoked, pending)
- **Empty states vs populated views** where relevant

---

## Example Pre-Commit Workflow

```bash
# 1. Make changes to a service
vi services/manager/auth.py

# 2. Run linters
black services/manager/auth.py
flake8 services/manager/
mypy services/manager/

# 3. Run security scan
bandit -r services/manager/

# 4. Run tests
pytest tests/unit/manager/ -v
pytest tests/integration/manager/ -v

# 5. Run smoke tests
make smoke-test

# 6. Run full pre-commit script
./scripts/pre-commit/pre-commit.sh

# 7. Wait for approval, then commit
git add services/manager/auth.py
git commit -m "Improve authentication logic"
```

---

**Last Updated**: 2026-01-06
**Maintained by**: Penguin Tech Inc
