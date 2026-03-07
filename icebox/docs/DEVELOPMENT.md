# IceBox — Local Development Setup

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Python | 3.13+ | `sudo apt install python3.13` or `pyenv install 3.13` |
| Docker | 24+ | https://docs.docker.com/engine/install/ |
| MicroK8s | latest | `sudo snap install microk8s --classic` |
| kubectl | 1.28+ | `sudo snap install kubectl --classic` |
| Helm | 3.x | `sudo snap install helm --classic` |
| Redis | 7+ | `sudo apt install redis-server` (or Docker) |

## Repository Layout

```
icebox/
├── services/
│   ├── flask-backend/     REST API (port 8080)
│   ├── sync-worker/       Cloud sync consumer (internal)
│   ├── pki-server/        PKI cert lifecycle (port 8081)
│   └── ssh-ca/            SSH CA (port 8082)
├── webui/                 React+TypeScript frontend (port 80)
├── k8s/
│   ├── helm/              Helm charts (beta/prod deploy)
│   └── kustomize/         Kustomize overlays (alpha/local deploy)
├── tests/
│   └── smoke/             run-all.sh smoke tests
└── docs/                  This directory
```

## Environment Configuration

Copy `.env.example` and fill in values:

```bash
cp icebox/.env.example icebox/.env
```

Minimum required variables for local development:

```bash
# Encryption key — must be ≥32 chars
ICEBOX_MEK=local-dev-mek-change-in-production-!!

# Flask/HMAC signing
SECRET_KEY=local-dev-secret-key-for-hmac-signing
JWT_SECRET_KEY=local-dev-jwt-secret

# Database (SQLite for local dev)
DB_TYPE=sqlite
DB_NAME=icebox_dev.db
DB_HOST=
DB_PORT=
DB_USER=
DB_PASS=

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASS=
REDIS_DB=0

# License (bypass domains — no key needed locally)
LICENSE_SERVER_URL=https://license.penguintech.io
PRODUCT_NAME=icebox
RELEASE_MODE=false
ALLOWED_HOSTS=*
```

## Starting Services Locally

### Option A: Kubernetes (recommended — matches CI)

```bash
# Build images
docker build -t icebox-flask-backend:latest icebox/services/flask-backend/
docker build -t icebox-sync-worker:latest    icebox/services/sync-worker/
docker build -t icebox-pki-server:latest     icebox/services/pki-server/
docker build -t icebox-ssh-ca:latest         icebox/services/ssh-ca/
docker build -t icebox-webui:latest          icebox/webui/

# Load into MicroK8s
microk8s ctr images import <(docker save icebox-flask-backend:latest)
microk8s ctr images import <(docker save icebox-sync-worker:latest)
microk8s ctr images import <(docker save icebox-pki-server:latest)
microk8s ctr images import <(docker save icebox-ssh-ca:latest)
microk8s ctr images import <(docker save icebox-webui:latest)

# Deploy
kubectl apply --context local-alpha -k icebox/k8s/kustomize/overlays/alpha

# Verify
kubectl --context local-alpha get pods -n icebox
```

### Option B: Direct Python (flask-backend only)

```bash
cd icebox/services/flask-backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run Alembic migration (first time)
alembic upgrade head

# Start Quart dev server
python3 main.py
# API available at http://localhost:8080
```

## Database Migrations

Migrations are managed by Alembic. **Never use PyDAL's auto-migrate.**

```bash
cd icebox/services/flask-backend

# Apply all pending migrations
alembic upgrade head

# Check current revision
alembic current

# Create a new migration after model changes
alembic revision --autogenerate -m "description_of_change"

# Roll back one step
alembic downgrade -1
```

## Running Tests

```bash
# Unit tests (no external services needed)
cd icebox/services/flask-backend
source .venv/bin/activate
python3 -m pytest tests/ -v

# With coverage
python3 -m pytest tests/ --cov=. --cov-report=term-missing

# Smoke tests (requires Docker)
./icebox/tests/smoke/run-all.sh
```

## Linting

```bash
cd icebox/services/flask-backend
source .venv/bin/activate

flake8 .
black . --check
isort . --check-only
mypy . --strict
bandit -r . -ll
```

Auto-fix formatting:

```bash
black .
isort .
```

## Common Developer Tasks

### Inspect the running API

```bash
# Health check
curl http://localhost:8080/healthz

# API status
curl http://localhost:8080/api/v1/status

# Create a secret (unauthenticated — returns 401, confirms route exists)
curl -X POST http://localhost:8080/api/v1/secrets \
  -H "Content-Type: application/json" \
  -d '{"name":"test","value":"s3cr3t","secret_type":"api_key"}'
```

### Working with the envelope encryption module

```python
# Quick test in Python REPL
import os; os.environ["ICEBOX_MEK"] = "test-mek-32-chars-minimum-length!"
from crypto.envelope import EnvelopeEncryption
enc = EnvelopeEncryption(mek_source="test-mek-32-chars-minimum-length!")
ct, edek, ver = enc.encrypt("my-secret")
print(enc.decrypt(ct, edek, ver))  # "my-secret"
```

### Port assignments

| Service | Port | Notes |
|---------|------|-------|
| flask-backend | 8080 | REST API |
| pki-server | 8081 | PKI API |
| ssh-ca | 8082 | SSH CA API |
| webui | 80 | nginx (K8s), 3000 dev |
| PostgreSQL | 5432 | default DB |
| Redis | 6379 | streams + cache |

## Troubleshooting

**`ICEBOX_MEK` too short:**
```
ValueError: ICEBOX_MEK must be at least 32 characters
```
Ensure `ICEBOX_MEK` is ≥ 32 chars in your `.env`.

**PyDAL `migrate=False` errors:**
The schema must be initialized by Alembic before the app starts. Run `alembic upgrade head` once before the first start.

**Redis connection refused:**
Start Redis: `sudo systemctl start redis` or `docker run -d -p 6379:6379 redis:7-bookworm`

**JIT token HMAC failures in tests:**
Ensure `SECRET_KEY` env var is set before importing `api.v1.jit`.

**License 402 errors:**
Check `RELEASE_MODE=false` and hostname is not a non-bypass domain. For bypass: deploy under `*.nest.localhost.local` or `*.nest.penguintech.cloud`.
