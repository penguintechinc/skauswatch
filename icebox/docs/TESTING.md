# IceBox — Testing & Validation Guide

## Test Categories

| Type | Runner | Scope | When to Run |
|------|--------|-------|-------------|
| Unit | pytest | Crypto, token logic, validation | Every commit |
| Integration | pytest | JIT flow, one-time secrets, API routes | Before PR |
| Smoke | run-all.sh | Docker builds, container health, K8s manifests | Every commit |
| E2E | Playwright | Full browser flows via deployed cluster | Before release |
| Security | bandit + pip-audit | Python deps + static analysis | Every commit |

## Unit Tests — flask-backend

Located at `icebox/services/flask-backend/tests/`.

### Running

```bash
cd icebox/services/flask-backend
source .venv/bin/activate

# All tests
python3 -m pytest tests/ -v

# Specific module
python3 -m pytest tests/test_envelope.py -v
python3 -m pytest tests/test_jit_token.py -v
python3 -m pytest tests/test_jit_flow_integration.py -v

# With coverage report
python3 -m pytest tests/ --cov=. --cov-report=term-missing --cov-report=html
```

### Test Modules

**`test_envelope.py`** — Envelope encryption (AES-256-GCM DEK/MEK)
- Roundtrip for short, long, empty, and unicode values
- Ciphertext ≠ plaintext, fresh nonce per encryption
- Tampered ciphertext/DEK raises exception (GCM auth tag)
- DEK version starts at 1 and increments
- MEK rotation: re-wrap DEK, old MEK fails after rewrap

**`test_jit_token.py`** — JIT HMAC token format
- Token structure: `jit:{grant_id}:{grantee_id}:{expires_epoch}`
- Expiry detection (past vs future epoch)
- HMAC-SHA256 determinism and tamper detection
- Wrong secret fails verification
- SHA-256 hash storage (64-char hex, not reversible)

**`test_jit_flow_integration.py`** — JIT and one-time secret lifecycle
- Payload validation (missing fields, zero/negative duration)
- Approved duration cannot exceed requested
- Status machine transitions: pending → approved → rejected → expired → revoked
- Token scoped to one secret and one user
- One-time: unviewed retrievable, viewed returns Gone, expired returns Gone
- Token hash stored (SHA-256), not raw URL token

### Environment Variables for Tests

Tests set defaults via `os.environ.setdefault()` at the top of each file.
No external services (Redis, DB) are required — tests use mocks and SQLite `:memory:`.

```bash
# Override if needed
ICEBOX_MEK="test-mek-32-chars-minimum-length!" \
SECRET_KEY="test-secret-key-for-jit-hmac-signing" \
python3 -m pytest tests/ -v
```

## Smoke Tests

The smoke test runner (`icebox/tests/smoke/run-all.sh`) performs 6 phases:

1. **Docker builds** — all 5 images build successfully
2. **Flask-backend health** — container starts, `/healthz` 200, `/api/v1/status` responds
3. **WebUI health** — nginx container starts, `/healthz` 200, `/vault` reachable
4. **Python unit tests** — pytest runs inside the flask-backend container
5. **Kustomize validation** — all 3 overlays (alpha/beta/prod) produce valid YAML
6. **Helm lint** — all 5 charts pass `helm lint`

```bash
# Full smoke suite
./icebox/tests/smoke/run-all.sh

# Build images only (no runtime checks)
./icebox/tests/smoke/run-all.sh --build-only

# Skip builds (test already-built images)
./icebox/tests/smoke/run-all.sh --skip-build
```

Expected output on success:
```
[PASS] docker build icebox-flask-backend
[PASS] docker build icebox-sync-worker
...
[PASS] pytest: all unit tests passed
[PASS] kubectl kustomize overlays/alpha: valid
...
========================================
 IceBox Smoke Test Results
========================================
 Passed:  18
 Failed:  0
 Skipped: 0
========================================
ALL SMOKE TESTS PASSED
```

## Security Tests

```bash
cd icebox/services/flask-backend
source .venv/bin/activate

# Static analysis
bandit -r . -ll

# Dependency vulnerabilities
pip-audit

# Safety check (alternative)
safety check
```

For sync-worker and other Python services, run from their respective directories.

## Alpha Integration Tests (K8s)

Deploy to local alpha first, then test against the running cluster:

```bash
# 1. Clean up any existing deployment
kubectl delete --context local-alpha -k icebox/k8s/kustomize/overlays/alpha 2>/dev/null || true
kubectl get pods --context local-alpha -n icebox --watch  # wait for termination

# 2. Deploy fresh
kubectl apply --context local-alpha -k icebox/k8s/kustomize/overlays/alpha

# 3. Wait for rollout
kubectl --context local-alpha rollout status deployment/icebox-flask-backend -n icebox
kubectl --context local-alpha rollout status deployment/icebox-webui -n icebox

# 4. Run smoke tests against the live cluster
BASE_URL="https://icebox.skauswatch.localhost.local"
curl -sf "${BASE_URL}/healthz"
curl -sf "${BASE_URL}/api/v1/status"
```

## JIT Flow Integration Test (manual)

End-to-end JIT approval cycle against a running IceBox instance:

```bash
BASE="http://localhost:8080"
TOKEN="<valid-jwt-with-jit:request-scope>"
OWNER_TOKEN="<valid-jwt-with-jit:approve-scope>"

# 1. Request JIT access
RESPONSE=$(curl -sf -X POST "${BASE}/api/v1/jit/requests" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"secret_id":"<uuid>","reason":"emergency maintenance","requested_duration_seconds":3600}')

REQUEST_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['id'])")

# 2. Approve
curl -sf -X PATCH "${BASE}/api/v1/jit/requests/${REQUEST_ID}/approve" \
  -H "Authorization: Bearer ${OWNER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"approved_duration_seconds":1800}'

# 3. Get the JIT token from the approval response and use it
# GET /api/v1/secrets/{id}/value with JIT token as Bearer
```

## One-Time Secret Test (manual)

```bash
BASE="http://localhost:8080"
TOKEN="<valid-jwt-with-secrets:write-scope>"

# Create
RESPONSE=$(curl -sf -X POST "${BASE}/api/v1/one-time-secrets" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"value":"top-secret-value","ttl_seconds":300}')

URL_TOKEN=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['url_token'])")

# First retrieval — 200
curl -sf "${BASE}/api/v1/one-time-secrets/${URL_TOKEN}"

# Second retrieval — 410 Gone
curl -v "${BASE}/api/v1/one-time-secrets/${URL_TOKEN}"  # must show 410
```

## Mock Data

For realistic UI/API testing, seed 3–4 test secrets:

```bash
cd icebox/services/flask-backend
python3 - <<'EOF'
import os
os.environ.setdefault("ICEBOX_MEK", "local-dev-mek-change-in-production-!!")
# ... seed script once API is running
# POST /api/v1/secrets x4 with different secret_type values
EOF
```

## Cross-Architecture Testing

Before final commit, validate the arm64 build:

```bash
docker buildx build \
  --platform linux/arm64 \
  -t icebox-flask-backend:arm64-test \
  icebox/services/flask-backend/

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t icebox-webui:multi-arch-test \
  icebox/webui/
```
