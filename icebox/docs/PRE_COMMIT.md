# IceBox — Pre-Commit Checklist

Run these steps before every `git commit` on the `icebox-module` branch.
All checks must pass — do not commit with failures.

---

## Quick Reference

```bash
# All-in-one (recommended)
cd icebox/services/flask-backend && source .venv/bin/activate
flake8 . && black . --check && isort . --check-only && mypy . --strict && bandit -r . -ll
python3 -m pytest tests/ -q
cd ../../..
./icebox/tests/smoke/run-all.sh --build-only   # fast: builds only
```

---

## Step 1 — Linting (Python)

```bash
cd icebox/services/flask-backend
source .venv/bin/activate

flake8 .           # style + errors
black . --check    # formatting (run `black .` to auto-fix)
isort . --check-only  # import order (run `isort .` to auto-fix)
mypy . --strict    # type checking
```

Repeat for `sync-worker/`, `pki-server/`, and `ssh-ca/` if modified.

Expected: zero errors. Fix all before proceeding.

---

## Step 2 — Security Scanning (Python)

```bash
cd icebox/services/flask-backend
source .venv/bin/activate

bandit -r . -ll    # static security analysis (medium + high severity)
pip-audit          # dependency vulnerability check
```

Do not commit if high-severity issues are found. Fix or document mitigations.

---

## Step 3 — Secrets Scan

```bash
# Scan staged changes for accidental secret commits
git diff --cached | grep -iE '(password|secret|api_key|token|mek)\s*[:=]\s*["\x27][^"\x27]{8,}'
```

If any matches appear, review them. `.env` files must not be committed.
Verify `.gitignore` excludes:
- `.env`, `.env.*`
- `*.key`, `*.pem`
- `icebox_dev.db`

---

## Step 4 — Unit Tests

```bash
cd icebox/services/flask-backend
source .venv/bin/activate
python3 -m pytest tests/ -q --tb=short
```

Expected: all tests pass. Zero failures, zero errors.

If tests need the DB initialized, run `alembic upgrade head` first.

---

## Step 5 — Smoke Tests (Build Verification)

```bash
./icebox/tests/smoke/run-all.sh --build-only
```

This builds all 5 Docker images and confirms they compile without errors.
Takes ~3–5 minutes on first run, faster with layer cache.

Expected: all `[PASS]` lines, zero `[FAIL]`.

---

## Step 6 — Smoke Tests (Runtime, Optional but Recommended)

Only required when changing:
- `main.py`, `config.py`, or `requirements.txt`
- Dockerfiles
- K8s Kustomize overlays or Helm charts
- nginx configuration

```bash
./icebox/tests/smoke/run-all.sh
```

Expected: all phases pass including container health checks and Kustomize validation.

---

## Step 7 — K8s Manifest Validation (if K8s files changed)

```bash
kubectl kustomize icebox/k8s/kustomize/overlays/alpha
kubectl kustomize icebox/k8s/kustomize/overlays/beta
kubectl kustomize icebox/k8s/kustomize/overlays/prod

helm lint icebox/k8s/helm/flask-backend
helm lint icebox/k8s/helm/sync-worker
helm lint icebox/k8s/helm/pki-server
helm lint icebox/k8s/helm/ssh-ca
helm lint icebox/k8s/helm/webui
```

---

## Step 8 — Version Update

Update the `.version` file if this commit represents a releasable change:

```bash
# from the SkausWatch repo root
./scripts/version/update-version.sh patch   # for bug fixes
./scripts/version/update-version.sh minor   # for new features (IceBox is a minor release)
```

---

## Pre-Commit Checklist (Copy-paste)

```
[ ] flake8 passes (0 errors)
[ ] black --check passes (or auto-fixed and re-staged)
[ ] isort --check-only passes (or auto-fixed and re-staged)
[ ] mypy --strict passes
[ ] bandit -ll passes (no medium/high issues)
[ ] pip-audit passes (no known vulnerabilities)
[ ] Secrets scan: no credentials in staged diff
[ ] pytest tests/ passes (0 failures)
[ ] Smoke builds pass (--build-only)
[ ] Runtime smoke passes (if Dockerfile/main.py changed)
[ ] K8s manifests valid (if k8s/ files changed)
[ ] Helm charts lint clean (if k8s/ files changed)
[ ] .version updated (if feature/fix commit)
[ ] No TODO/FIXME left in changed files
[ ] No hardcoded secrets or credentials
```

---

## What NOT to Commit

- `.env` files or any file containing real credentials
- `icebox_dev.db` (SQLite dev database)
- `__pycache__/`, `*.pyc`, `.pytest_cache/`
- `*.egg-info/`, `.venv/`
- `alembic/versions/` files with `migrate=True` in comments
- Any PyDAL DAL() call with `migrate=True` (must always be `False`)
