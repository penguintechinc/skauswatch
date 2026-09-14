# Local Development Guide - SkausWatch

Complete guide to setting up a local development environment for SkausWatch's full ecosystem — 8 core services (Manager, PKI Server, SSH CA, Monitor, S3scan, Scanner, ENDPOINT Agent, and WebUI) plus optional Vault (licensed secrets vault) and CodeScan (AI code review) sub-modules — running the application locally, and following the development workflow.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Initial Setup](#initial-setup)
3. [Starting Development Environment](#starting-development-environment)
4. [Service Architecture](#service-architecture)
5. [Vault Sub-Module (Licensed Secrets Vault)](#vault-sub-module-licensed-secrets-vault)
6. [CodeScan Sub-Module (AI Code Review)](#codescan-sub-module-ai-code-review)
7. [Development Workflow](#development-workflow)
8. [Common Tasks](#common-tasks)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

- **macOS 12+**, **Linux (Ubuntu 20.04+)**, or **Windows 10+ with WSL2**
- **Docker Desktop** 4.0+ (or Docker Engine 20.10+)
- **Docker Compose** 2.0+
- **Git** 2.30+
- **Python** 3.13+ (for shared libraries and service development)
- **PostgreSQL** 16+ (or use Docker version)
- **Redis** 7+ (or use Docker version)

### Optional Tools

- **Docker Buildx** (for multi-architecture builds)
- **Helm** (for Kubernetes deployments)
- **kubectl** (for Kubernetes clusters)

### Installation

**macOS (Homebrew)**:
```bash
brew install docker docker-compose git python postgresql redis
brew install --cask docker
```

**Ubuntu/Debian**:
```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose git python3.13 postgresql redis-server
sudo usermod -aG docker $USER  # Allow docker without sudo
newgrp docker                   # Activate group change
```

**Verify Installation**:
```bash
docker --version              # Docker 20.10+
docker-compose --version      # Docker Compose 2.0+
git --version
python3 --version             # Python 3.13+
postgres --version            # PostgreSQL 16+
redis-cli --version           # Redis 7+
```

---

## Initial Setup

### Clone Repository

```bash
git clone https://github.com/penguintechinc/skauswatch.git
cd SkausWatch
```

### Install Dependencies

```bash
# Install all project dependencies
make setup
```

This runs:
1. Python virtual environment setup
2. **Penguin-libs package installation** (centralized common libraries)
3. Per-service dependency installation
4. Pre-commit hooks installation
5. Database initialization

#### Penguin-Libs (Centralized Packages)

SkausWatch uses published packages from the [penguin-libs monorepo](https://github.com/penguintechinc/penguin-libs) for common functionality.

**Python Packages (PyPI):**
- `penguin-libs>=0.1.0` - Validation, HTTP, gRPC utilities
- `penguin-licensing>=0.1.0` - License server client
- `penguintechinc-utils>=0.1.0` - Sanitized logging, Flask utils

**React Packages (GitHub Packages):**
- `@penguintechinc/react-libs@^1.1.1` - UI components

**Installation is automatic via `make setup`**, but for manual installation:

Python services:
```bash
pip install penguin-libs penguin-licensing penguintechinc-utils
```

React/WebUI service:
```bash
cd services/webui

# Create .npmrc for GitHub Packages access
cat > .npmrc << EOF
@penguintechinc:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=\${GITHUB_TOKEN}
EOF

# Set GitHub token (required for @penguintechinc packages)
export GITHUB_TOKEN=your_github_personal_access_token

# Install dependencies
npm install
```

**GitHub Token Setup:**
1. Go to https://github.com/settings/tokens
2. Generate new token with `read:packages` scope
3. Set `GITHUB_TOKEN` environment variable
4. Run `npm install`

**Application-Specific Libraries:**
See `shared/README.md` for utilities kept in `shared/` (performance, database, go_libs, node_libs)

### Environment Configuration

Copy and customize environment files:

```bash
# Copy example environment files
cp .env.example .env
cp .env.local.example .env.local  # Optional: local overrides
```

**Key Environment Variables**:

```bash
# Database Configuration
DB_TYPE=postgres              # postgres, mysql, sqlite
DB_HOST=localhost
DB_PORT=5432
DB_NAME=skauswatch_dev
DB_USER=postgres
DB_PASSWORD=postgres

# Manager Service (Port 5000)
MANAGER_PORT=5000
MANAGER_DEBUG=true
MANAGER_SECRET_KEY=your-secret-key-for-dev

# PKI Server (Port 5001)
PKI_PORT=5001
PKI_DEBUG=true

# SSH CA Server (Port 5002)
SSHCA_PORT=5002
SSHCA_DEBUG=true

# Monitor (Port 5003)
MONITOR_PORT=5003
MONITOR_DEBUG=true

# Redis Cache
REDIS_URL=redis://localhost:6379/0
REDIS_PORT=6379

# License (Development - all features available)
RELEASE_MODE=false
LICENSE_KEY=not-required-in-dev

# Worker Scanner
NUCLEI_ENABLED=true
ZAP_ENABLED=false
OPENVAS_ENABLED=false

# Vault integration (when Vault sub-module is installed)
VAULT_PKI_URL=http://localhost:5101
VAULT_SSHCA_URL=http://localhost:5102
```

### Database Initialization

```bash
# Create database and run migrations
make db-init

# Seed with mock data (3-4 items per entity)
make seed-mock-data

# Verify database connection
make db-health
```

---

## Starting Development Environment

### Quick Start (All Core Services)

```bash
# Start all services in one command
make dev

# This runs:
# - PostgreSQL database
# - Redis cache
# - Manager service (port 5000)
# - PKI Server shim (port 5001)
# - SSH CA shim (port 5002)
# - Monitor (port 5003)
# - S3scan (background worker, no HTTP port)
# - Scanner (background worker, no HTTP port)
# - ENDPOINT Agent (DaemonSet in K8s; runs via kubectl in local dev)
# - WebUI (port 3000)

# Access the services:
# Manager API:     http://localhost:5000
# PKI Server API:  http://localhost:5001
# SSH CA API:      http://localhost:5002
# Monitor API: http://localhost:5003
# WebUI:           http://localhost:3000
```

### Individual Service Management

**Start specific services**:
```bash
# Start only Manager service
docker-compose up -d manager

# Start Manager, PKI, and database
docker-compose up -d postgres redis manager pki

# Start without detaching (see logs)
docker-compose up manager
```

**View service logs**:
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f manager

# Last 100 lines, follow new entries
docker-compose logs -f --tail=100 pki
```

**Stop services**:
```bash
# Stop all services (keep data)
docker-compose down

# Stop and remove volumes (clean slate)
docker-compose down -v

# Restart services
docker-compose restart

# Rebuild and restart (apply code changes)
docker-compose down && docker-compose up -d --build
```

---

## Service Architecture

### Eight-Service Design

| Service | Purpose | Port | Language |
|---------|---------|------|----------|
| **Manager** (`manager-new`) | Configuration and management plane | 5000 | Python 3.13 + Quart |
| **PKI Server** (`pki`) | Shim proxy → Vault PKI (v1.x) | 5001 | Python 3.13 + Quart |
| **SSH CA** (`sshca`) | Shim proxy → Vault SSH CA (v1.x) | 5002 | Python 3.13 + Quart |
| **Monitor** (`monitor`) | Audit logging and threat analysis | 5003 | Python 3.13 + FastAPI |
| **S3scan** (`s3scan`) | ClamAV + YARA + TI scan workers | — | Python 3.13 |
| **Scanner** (`scanner`) | Nuclei, ZAP, OpenVAS scanner | — | Python 3.13 |
| **ENDPOINT Agent** (`endpoint-agent`) | Endpoint detection & response | — | Go 1.24 (DaemonSet) |
| **WebUI** (`webui`) | Frontend dashboard | 3000 | Node.js + React |

> **Note on PKI Server and SSH CA**: In v1.x these services are shim proxies that forward certificate operations to the Vault sub-module when Vault is installed and `VAULT_PKI_URL` / `VAULT_SSHCA_URL` are configured. When Vault is not present they return appropriate 501/503 responses with `Deprecation:` headers indicating that full PKI and SSH CA functionality requires the Vault module.

### Shared Components

All services use shared security libraries:
- **py_libs**: Input validation, security middleware, crypto operations
- **Database layer**: SQLAlchemy (init) + PyDAL (operations)
- **Authentication**: Flask-Security-Too / Quart-Security RBAC

### Service Dependencies

```
Manager ─────────── PKI Server (shim → Vault)
   │                   │
   ├── SSH CA (shim → Vault) ──┤
   │                   │
   ├── Monitor ────┘
   │
   ├── S3scan
   ├── Scanner
   └── WebUI
              │
         Shared Libraries
         (py_libs / penguin-libs)
         │
   ┌─────┴──────────────┐
   │                    │
PostgreSQL Database   Redis Cache
```

---

## Vault Sub-Module (Licensed Secrets Vault)

Vault is an optional licensed secrets vault sub-module that provides full PKI, SSH CA, envelope-encrypted secrets storage, JIT access controls, and cloud sync. It lives in a separate worktree.

**Location:** `.worktrees/vault/vault/`
**Branch:** `vault-module` (branched from `v1.x`)
**License requirement:** Vault feature flag must be present in your `LICENSE_KEY`

### Prerequisites

- Vault feature enabled in license: `VAULT_MEK` env var must be set (AES-256 master encryption key)
- The `vault-module` worktree must be checked out:

```bash
git worktree add .worktrees/vault vault-module
```

### Required Environment Variables (Vault)

```bash
VAULT_MEK=<32-byte-hex-or-base64-key>   # Master encryption key — REQUIRED
VAULT_DB_HOST=localhost
VAULT_DB_PORT=5432
VAULT_DB_NAME=vault_dev
VAULT_DB_USER=vault
VAULT_DB_PASS=vault
REDIS_URL=redis://localhost:6379/1        # Vault uses DB 1 by convention
VAULT_PORT=5100                          # Vault Flask backend
```

### First-Time Database Migration

Run the Alembic migration before starting Vault for the first time:

```bash
cd .worktrees/vault/vault
docker compose exec flask-backend alembic upgrade head
```

### Starting Vault

```bash
cd .worktrees/vault/vault
docker compose up -d
```

This starts:
- Vault Flask backend (port 5100)
- Vault PKI service (port 5101)
- Vault SSH CA service (port 5102)
- Vault WebUI (port 5110)
- Vault sync-worker (background)

### Connecting Core Services to Vault

Set these env vars in core SkausWatch services so PKI Server and SSH CA shims forward to Vault:

```bash
VAULT_PKI_URL=http://localhost:5101
VAULT_SSHCA_URL=http://localhost:5102
```

These are already included in the `.env.example`. Restart the core services after setting them:

```bash
docker compose restart pki sshca
```

### K8s Deploy (Alpha)

```bash
kubectl apply --context local-alpha -k icebox/k8s/kustomize/overlays/alpha
```

---

## CodeScan Sub-Module (AI Code Review)

CodeScan provides AI-powered code review and ASM surface scanning as an optional sub-module.

**Location:** `codescan/` in the project root
**Worker service:** `services/worker-codescan/`

See `darwin/README.md` for full setup instructions including API key configuration and scan profile setup.

---

## Development Workflow

### 1. Start Development Environment

```bash
make dev                      # Start all services
make seed-mock-data          # Populate with test data
```

### 2. Make Code Changes

Edit files in your favorite editor. Services with auto-reload:

- **Python (Quart/FastAPI)**: Reload on file save (DEBUG=true, auto-reload via uvicorn/Hypercorn)
- **Shared Libraries**: Services restart on changes (`py_libs` / `penguin-libs`)

For services without auto-reload:
```bash
docker-compose restart <service-name>
```

### 3. Verify Changes

```bash
# Quick syntax checks
python -m py_compile services/manager/*.py

# Run linters
make lint

# Run unit tests (specific service)
cd services/manager && pytest tests/unit/

# Run all tests
make test
```

### 4. Populate Mock Data for Feature Testing

After implementing a new feature, create mock data scripts:

```bash
# Create mock data script for new entity (e.g., Users)
cat > scripts/mock-data/seed-users.py << 'EOF'
from dal import DAL

def seed_users():
    db = DAL('postgresql://user:password@localhost/dbname')

    users = [
        {"email": "admin@example.com", "role": "admin", "status": "active"},
        {"email": "user@example.com", "role": "user", "status": "active"},
        {"email": "viewer@example.com", "role": "viewer", "status": "active"},
        {"email": "inactive@example.com", "role": "user", "status": "inactive"},
    ]

    for user in users:
        db.users.insert(**user)

    print(f"✓ Seeded {len(users)} users")

if __name__ == "__main__":
    seed_users()
EOF

# Run the mock data script
python scripts/mock-data/seed-users.py

# Add to seed-all.py orchestrator
echo "from seed_users import seed_users; seed_users()" >> scripts/mock-data/seed-all.py
```

### 5. Run Pre-Commit Checklist

Before committing, run the comprehensive pre-commit script:

```bash
./scripts/pre-commit/pre-commit.sh
```

**Steps**:
1. ✅ Linters (flake8, black, mypy for Python)
2. ✅ Security scans (bandit)
3. ✅ Secret detection (no API keys, passwords, tokens)
4. ✅ Build & Run (verify containers start)
5. ✅ Smoke tests (services respond to health checks)
6. ✅ Unit tests (isolated component testing)
7. ✅ Integration tests (component interactions)

**Troubleshooting Pre-Commit**: See [Pre-Commit Documentation](PRE_COMMIT.md)

### 6. Testing & Validation

Comprehensive testing guide:

**Quick Test Commands**:
```bash
# Smoke tests only (fast, <2 min)
make smoke-test

# Unit tests only
make test-unit

# Integration tests only
make test-integration

# All tests
make test

# Specific test file
pytest tests/unit/test_auth.py

# With coverage
make test-cov
```

### 7. Create Pull Request

Once tests pass:

```bash
# Push branch
git push origin feature-branch-name

# Create PR via GitHub CLI
gh pr create --title "Brief feature description" \
  --body "Detailed description of changes"
```

### 8. Code Review & Merge

- Address review feedback
- Re-run tests if changes made
- Merge when approved

---

## Common Tasks

### Adding Python Dependency to Service

```bash
# Add to services/<service-name>/requirements.txt
echo "new-package==1.0.0" >> services/manager/requirements.txt

# Rebuild service container
docker-compose up -d --build manager

# Verify import works
docker-compose exec manager python -c "import new_package"
```

### Adding Shared Library Dependency

```bash
# Add to shared/py_libs/setup.py extras
# Edit setup.py and add to install_requires or extras_require

# Reinstall shared libraries
pip install -e "shared/py_libs[all]"

# Rebuild all services (they use shared libs)
docker-compose up -d --build
```

### Adding Environment Variable

```bash
# Add to .env
echo "NEW_VAR=value" >> .env

# Restart services to pick up new variable
docker-compose restart

# Verify it's set
docker-compose exec manager printenv | grep NEW_VAR
```

### Debugging a Service

**View logs in real-time**:
```bash
docker-compose logs -f manager
```

**Access container shell**:
```bash
# Python service
docker-compose exec manager bash
```

**Execute commands in container**:
```bash
# Run Python script
docker-compose exec manager python -c "print('hello')"

# Check service health
docker-compose exec manager curl http://localhost:8000/api/health
```

### Database Operations

**Connect to database**:
```bash
# PostgreSQL
docker-compose exec postgres psql -U postgres -d skauswatch_dev

# View schema
\dt                    # PostgreSQL tables
```

**Reset database**:
```bash
# Full reset (deletes all data)
docker-compose down -v
make db-init
make seed-mock-data
```

**Run migrations**:
```bash
# Migrations run automatically on startup
docker-compose restart manager

# Or manually run migration
docker-compose exec manager python -m migrations
```

### Working with Git Branches

```bash
# Create feature branch
git checkout -b feature/new-feature-name

# Keep branch updated with main
git fetch origin
git rebase origin/main

# Clean commit history before PR
git rebase -i origin/main  # Interactive rebase

# Push branch
git push origin feature/new-feature-name
```

### Database Backups

```bash
# Backup PostgreSQL
docker-compose exec postgres pg_dump -U postgres skauswatch_dev > backup.sql

# Restore from backup
docker-compose exec -T postgres psql -U postgres skauswatch_dev < backup.sql
```

---

## Troubleshooting

### Services Won't Start

**Check if ports are already in use**:
```bash
# Find what's using port 8000
lsof -i :8000

# Kill the process
kill -9 <PID>

# Or use different ports in .env
MANAGER_PORT=8001
```

**Docker daemon not running**:
```bash
# macOS
open /Applications/Docker.app

# Linux
sudo systemctl start docker

# Windows (Docker Desktop)
# Start Docker Desktop from Applications
```

### Database Connection Error

```bash
# Verify database container is running
docker-compose ps postgres

# Check database credentials in .env
cat .env | grep DB_

# Connect to database directly
docker-compose exec postgres psql -U postgres -d postgres

# View logs
docker-compose logs postgres
```

### Manager Service Won't Start

```bash
# Check logs
docker-compose logs manager

# Verify database migration
docker-compose exec manager python -c "from app import db; db.create_all()"

# Reset and rebuild
docker-compose down
docker-compose up -d --build manager
```

### Shared Libraries Import Error

```bash
# Verify py_libs is installed
pip list | grep py_libs

# Reinstall with all extras
pip install -e "shared/py_libs[all]"

# Rebuild all services
docker-compose up -d --build
```

### Git Merge Conflicts

```bash
# View conflicts
git status

# Edit conflicted files (marked with <<<<, ====, >>>>)
# Remove conflict markers and keep desired code

# Mark as resolved
git add <resolved-file>

# Complete merge
git commit -m "Resolve merge conflicts"
```

### Slow Docker Builds

```bash
# Check Docker disk usage
docker system df

# Clean up unused images/containers
docker system prune

# Rebuild without cache (slow, but fresh)
docker-compose build --no-cache manager
```

---

## Tips & Best Practices

### Hot Reload Development

For fastest iteration:
```bash
# Start services once
docker-compose up -d

# Edit Python files → auto-reload (FLASK_DEBUG=true)
# Edit shared libraries → restart services (docker-compose restart)
```

### Environment-Specific Configuration

```bash
# Development settings (auto-loaded)
.env              # Default development config
.env.local        # Local machine overrides (gitignored)

# Production settings (via secret management)
Kubernetes secrets
AWS Secrets Manager
HashiCorp Vault
```

### Code Organization

Keep project clean:
```bash
# Remove old branches
git branch -D old-branch

# Clean local Docker images
docker image prune -a

# Clean unused containers
docker container prune
```

### Performance Tips

```bash
# Use specific services to reduce memory usage
docker-compose up postgres manager  # Skip other services

# Use lightweight testing
make smoke-test  # Instead of full test suite while developing

# Cache Docker layers by building in order of frequency of change
Dockerfile: base → dependencies → code → entrypoint
```

---

## Related Documentation

- **Testing**: [Testing Documentation](TESTING.md)
  - Mock data scripts
  - Smoke tests
  - Unit/integration/E2E tests
  - Performance tests

- **Pre-Commit**: [Pre-Commit Checklist](PRE_COMMIT.md)
  - Linting requirements
  - Security scanning
  - Build verification
  - Test requirements

- **Deployment**: [Kubernetes Guide](../k8s/README.md)
  - Containerization
  - Kubernetes deployment
  - Health checks

- **Standards**: [Development Standards](STANDARDS.md)
  - Architecture decisions
  - Code style
  - API conventions
  - Database patterns

- **Workflows**: [CI/CD Workflows](WORKFLOWS.md)
  - GitHub Actions pipelines
  - Build automation
  - Test automation
  - Release processes

---

**Last Updated**: 2026-03-07
**Maintained by**: Penguin Tech Inc
