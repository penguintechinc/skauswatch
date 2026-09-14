# Vault — Deployment & Usage Guide

**Audience:** DevOps | Developers

## Prerequisites

- SkausWatch v1.x with Vault sub-module (`.worktrees/vault/vault/`)
- Kubernetes cluster (MicroK8s for alpha, remote cluster for beta/prod)
- PostgreSQL 16+ (or SQLite for dev)
- Redis 7+ for cloud sync jobs
- PenguinTech license key with `vault` feature enabled
- kubectl and helm (or kustomize) configured

## Enable Vault in SkausWatch

### 1. Set Environment Variables (SkausWatch Core)

In your SkausWatch deployment (`.env` or K8s Secret), add:

```bash
# Vault Integration
VAULT_ENABLED=true                              # Enable Vault module
VAULT_PKI_URL=http://vault-pki:5101    # PKI shim target
VAULT_SSHCA_URL=http://vault-sshca:5102     # SSH CA shim target
VAULT_MEK=<base64-encoded-32-byte-key>         # Master Encryption Key for DEK wrapping
```

### 2. Deploy Vault Services

#### Option A: Via Helm (Beta/Production)

```bash
# Add Vault charts to deployment
helm upgrade --install vault-flask-backend \
  ./k8s/helm/flask-backend \
  --kube-context dal2-beta \
  --namespace vault \
  --create-namespace \
  --values ./k8s/helm/flask-backend/values-beta.yaml

# Repeat for sync-worker, pki, sshca, webui
# See CONFIGURATION.md for values file structure
```

#### Option B: Via Kustomize (Alpha/Local)

```bash
# Deploy all Vault services to local K8s
kubectl apply --context local-alpha -k ./k8s/kustomize/overlays/alpha

# Verify all pods running
kubectl --context local-alpha get pods -n vault
```

### 3. Initialize Database

```bash
# Run Alembic migrations (once, after first deploy)
kubectl --context local-alpha exec \
  -it deployment/vault-flask-backend -n vault \
  -- alembic upgrade head

# Verify schema
kubectl --context local-alpha exec \
  -it deployment/vault-flask-backend -n vault \
  -- python3 -c "from models.db import db; print([t for t in db.tables])"
```

### 4. Validate License

```bash
# Health check (should return 200 if licensed)
curl -H "Host: vault.skauswatch.localhost.local" \
  https://localhost/api/v1/status

# If 402 Payment Required: check license key and bypass domain config
```

---

## Common Workflows

### Store a Secret

```bash
TOKEN="<jwt-with-secrets:write-scope>"
curl -X POST http://localhost:5100/api/v1/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod-db-password",
    "value": "super-secret-db-pass",
    "secret_type": "database_password",
    "metadata": {"env": "production"}
  }'
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "prod-db-password",
    "secret_type": "database_password",
    "created_at": "2025-01-24T10:00:00Z",
    "updated_at": "2025-01-24T10:00:00Z"
  }
}
```

### Request JIT Access

```bash
TOKEN="<jwt-with-jit:request-scope>"
curl -X POST http://localhost:5100/api/v1/jit/requests \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "secret_id": "550e8400-e29b-41d4-a716-446655440000",
    "reason": "emergency maintenance window",
    "requested_duration_seconds": 3600
  }'
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "id": "660e8400-e29b-41d4-a716-446655440001",
    "status": "pending",
    "secret_id": "550e8400-e29b-41d4-a716-446655440000",
    "grantee_id": "user-uuid-123",
    "requested_duration_seconds": 3600,
    "approved_duration_seconds": null,
    "created_at": "2025-01-24T10:00:00Z"
  }
}
```

### Approve JIT Access (Admin)

```bash
TOKEN="<jwt-with-jit:approve-scope>"
curl -X PATCH http://localhost:5100/api/v1/jit/requests/660e8400-e29b-41d4-a716-446655440001/approve \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "approved_duration_seconds": 1800
  }'
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "id": "660e8400-e29b-41d4-a716-446655440001",
    "status": "approved",
    "jit_token": "jit:660e8400-e29b-41d4-a716-446655440001:user-uuid-123:1737720000",
    "expires_at": "2025-01-24T10:30:00Z"
  }
}
```

### Retrieve Secret via JIT Token

```bash
JIT_TOKEN="jit:660e8400-e29b-41d4-a716-446655440001:user-uuid-123:1737720000"
curl http://localhost:5100/api/v1/secrets/550e8400-e29b-41d4-a716-446655440000/value \
  -H "Authorization: Bearer $JIT_TOKEN"
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "value": "super-secret-db-pass"
  }
}
```

### Create One-Time Secret

```bash
TOKEN="<jwt-with-secrets:write-scope>"
curl -X POST http://localhost:5100/api/v1/one-time-secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "value": "temporary-api-key-for-partner",
    "ttl_seconds": 3600
  }'
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "id": "770e8400-e29b-41d4-a716-446655440002",
    "url_token": "ots:abcd1234efgh5678ijkl9012mnop3456",
    "expires_at": "2025-01-24T11:00:00Z"
  }
}
```

**Share URL:** `https://vault.skauswatch.app/api/v1/one-time-secrets/ots:abcd1234efgh5678ijkl9012mnop3456`

First access returns the secret; second access returns 410 Gone.

---

## Development Workflow

### Start Vault Locally

```bash
# From project root
cd .worktrees/vault/vault

# Copy environment file
cp .env.example .env

# Start all services with docker compose
docker compose up -d

# Run Alembic migrations
cd services/flask-backend
source .venv/bin/activate
alembic upgrade head

# Start Flask dev server
python3 main.py
# API available at http://localhost:5100
```

### Run Tests

```bash
# Unit tests
cd services/flask-backend
python3 -m pytest tests/ -v

# Smoke tests (requires Docker)
../../tests/smoke/run-all.sh

# API integration test (manual)
curl http://localhost:5100/api/v1/status
```

### Linting & Security

```bash
cd services/flask-backend
source .venv/bin/activate

# Code quality
flake8 . && black . && isort . && mypy . --strict
bandit -r . -ll
pip-audit
```

---

## Reference: Worktree Documentation

The Vault worktree includes its own comprehensive docs:

| File | Location |
|------|----------|
| **DEVELOPMENT.md** | `.worktrees/vault/vault/docs/DEVELOPMENT.md` |
| **TESTING.md** | `.worktrees/vault/vault/docs/TESTING.md` |
| **PRE_COMMIT.md** | `.worktrees/vault/vault/docs/PRE_COMMIT.md` |

These files cover local setup, test execution, and pre-commit checklist specific to the worktree.

---

## Next Steps

1. **API Integration:** See [API.md](./API.md) for complete endpoint reference
2. **Architecture Details:** See [ARCHITECTURE.md](./ARCHITECTURE.md) for encryption and design
3. **Configuration:** See [CONFIGURATION.md](./CONFIGURATION.md) for cloud provider setup
4. **Troubleshooting:** See [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) for common issues

---

**Vault v1.0.0** | Production-ready | Limited AGPL-3.0
