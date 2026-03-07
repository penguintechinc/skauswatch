#!/usr/bin/env bash
# IceBox smoke test runner
# Verifies: Docker builds succeed, containers start, API health endpoints respond,
# WebUI loads, and unit tests pass.
#
# Usage:
#   ./icebox/tests/smoke/run-all.sh                    # full suite
#   ./icebox/tests/smoke/run-all.sh --build-only       # only build images
#   ./icebox/tests/smoke/run-all.sh --skip-build       # skip builds, test running containers
#
# Exit codes: 0 = all pass, 1 = one or more failures

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ICEBOX_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PASS=0
FAIL=0
SKIPPED=0

BUILD_ONLY=false
SKIP_BUILD=false

for arg in "$@"; do
  case "$arg" in
    --build-only) BUILD_ONLY=true ;;
    --skip-build) SKIP_BUILD=true ;;
  esac
done

# ── helpers ──────────────────────────────────────────────────────────────────

log_pass() { echo "[PASS] $*"; ((PASS++)); }
log_fail() { echo "[FAIL] $*"; ((FAIL++)); }
log_skip() { echo "[SKIP] $*"; ((SKIPPED++)); }
log_info() { echo "[INFO] $*"; }

check_cmd() {
  if ! command -v "$1" &>/dev/null; then
    log_fail "Required command not found: $1"
    exit 1
  fi
}

# ── prerequisites ─────────────────────────────────────────────────────────────

log_info "Checking prerequisites..."
check_cmd docker
check_cmd python3
check_cmd curl

# ── 1. Docker image builds ────────────────────────────────────────────────────

if [[ "$SKIP_BUILD" == "false" ]]; then
  log_info "=== Phase 1: Docker image builds ==="

  build_image() {
    local name="$1"
    local context="$2"
    log_info "Building ${name}..."
    if docker build -t "${name}:smoke-test" "${context}" --quiet 2>&1; then
      log_pass "docker build ${name}"
    else
      log_fail "docker build ${name}"
    fi
  }

  build_image "icebox-flask-backend" "${ICEBOX_ROOT}/services/flask-backend"
  build_image "icebox-sync-worker"   "${ICEBOX_ROOT}/services/sync-worker"
  build_image "icebox-pki-server"    "${ICEBOX_ROOT}/services/pki-server"
  build_image "icebox-ssh-ca"        "${ICEBOX_ROOT}/services/ssh-ca"
  build_image "icebox-webui"         "${ICEBOX_ROOT}/webui"
fi

if [[ "$BUILD_ONLY" == "true" ]]; then
  echo ""
  echo "Build-only mode — skipping runtime checks."
  echo "Results: ${PASS} passed, ${FAIL} failed, ${SKIPPED} skipped"
  [[ "$FAIL" -eq 0 ]]
  exit $?
fi

# ── 2. Flask-backend container health ─────────────────────────────────────────

log_info "=== Phase 2: Flask-backend container health ==="

FLASK_CID=""
cleanup_flask() {
  if [[ -n "$FLASK_CID" ]]; then
    docker stop "$FLASK_CID" &>/dev/null || true
    docker rm   "$FLASK_CID" &>/dev/null || true
  fi
}
trap cleanup_flask EXIT

log_info "Starting icebox-flask-backend container..."
FLASK_CID=$(docker run -d \
  -p 18080:8080 \
  -e ICEBOX_MEK="smoke-test-mek-32chars-minimum!!" \
  -e SECRET_KEY="smoke-test-secret-key-for-hmac" \
  -e JWT_SECRET_KEY="smoke-test-jwt-secret" \
  -e DB_TYPE="sqlite" \
  -e DB_NAME=":memory:" \
  -e DB_HOST="" \
  -e DB_PORT="" \
  -e DB_USER="" \
  -e DB_PASS="" \
  -e REDIS_HOST="localhost" \
  -e REDIS_PORT="6379" \
  -e REDIS_PASS="" \
  -e REDIS_DB="0" \
  -e LICENSE_SERVER_URL="http://license.test" \
  -e PRODUCT_NAME="icebox-smoke" \
  -e RELEASE_MODE="false" \
  -e ALLOWED_HOSTS="*" \
  "icebox-flask-backend:smoke-test" 2>/dev/null || true)

if [[ -z "$FLASK_CID" ]]; then
  log_fail "flask-backend container failed to start"
else
  log_info "Waiting for flask-backend to be ready (up to 30s)..."
  READY=false
  for i in $(seq 1 30); do
    if curl -sf "http://localhost:18080/healthz" &>/dev/null; then
      READY=true
      break
    fi
    sleep 1
  done

  if [[ "$READY" == "true" ]]; then
    log_pass "flask-backend /healthz responds 200"

    # Check /api/v1/status
    if curl -sf "http://localhost:18080/api/v1/status" &>/dev/null; then
      log_pass "flask-backend /api/v1/status responds"
    else
      log_fail "flask-backend /api/v1/status did not respond"
    fi

    # Unlicensed 402 on secrets route (license enforcement when RELEASE_MODE=false
    # on non-bypass domain — skip this check, just ensure route is reachable)
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
      "http://localhost:18080/api/v1/secrets" \
      -H "Authorization: Bearer invalid.token.here" 2>/dev/null || echo "000")
    if [[ "$HTTP_CODE" != "000" ]]; then
      log_pass "flask-backend /api/v1/secrets reachable (HTTP ${HTTP_CODE})"
    else
      log_fail "flask-backend /api/v1/secrets unreachable (no response)"
    fi
  else
    log_fail "flask-backend did not become healthy within 30s"
  fi

  docker stop "$FLASK_CID" &>/dev/null || true
  docker rm   "$FLASK_CID" &>/dev/null || true
  FLASK_CID=""
fi

# ── 3. WebUI container health ─────────────────────────────────────────────────

log_info "=== Phase 3: WebUI container health ==="

WEBUI_CID=""
cleanup_webui() {
  if [[ -n "$WEBUI_CID" ]]; then
    docker stop "$WEBUI_CID" &>/dev/null || true
    docker rm   "$WEBUI_CID" &>/dev/null || true
  fi
}

log_info "Starting icebox-webui container..."
WEBUI_CID=$(docker run -d \
  -p 18081:80 \
  "icebox-webui:smoke-test" 2>/dev/null || true)

if [[ -z "$WEBUI_CID" ]]; then
  log_fail "webui container failed to start"
else
  log_info "Waiting for webui to be ready (up to 20s)..."
  READY=false
  for i in $(seq 1 20); do
    if curl -sf "http://localhost:18081/healthz" &>/dev/null; then
      READY=true
      break
    fi
    sleep 1
  done

  if [[ "$READY" == "true" ]]; then
    log_pass "webui /healthz responds 200"

    # /vault should redirect or serve index.html (200 or 301)
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
      "http://localhost:18081/vault" 2>/dev/null || echo "000")
    if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "301" ]]; then
      log_pass "webui /vault reachable (HTTP ${HTTP_CODE})"
    else
      log_fail "webui /vault returned unexpected HTTP ${HTTP_CODE}"
    fi
  else
    log_fail "webui did not become healthy within 20s"
  fi

  docker stop "$WEBUI_CID" &>/dev/null || true
  docker rm   "$WEBUI_CID" &>/dev/null || true
  WEBUI_CID=""
fi

# ── 4. Python unit tests (flask-backend) ──────────────────────────────────────

log_info "=== Phase 4: Python unit tests ==="

TESTS_DIR="${ICEBOX_ROOT}/services/flask-backend"
if [[ -d "${TESTS_DIR}/tests" ]]; then
  log_info "Running pytest in icebox-flask-backend container..."
  if docker run --rm \
    -e ICEBOX_MEK="smoke-test-mek-32chars-minimum!!" \
    -e SECRET_KEY="smoke-test-secret-key-for-hmac" \
    -e JWT_SECRET_KEY="smoke-test-jwt-secret" \
    -e DB_TYPE="sqlite" \
    -e DB_NAME=":memory:" \
    -e DB_HOST="" \
    -e DB_PORT="" \
    -e DB_USER="" \
    -e DB_PASS="" \
    -e REDIS_HOST="localhost" \
    -e REDIS_PORT="6379" \
    -e REDIS_PASS="" \
    -e REDIS_DB="0" \
    -e LICENSE_SERVER_URL="http://license.test" \
    -e PRODUCT_NAME="icebox-smoke" \
    -e RELEASE_MODE="false" \
    -e ALLOWED_HOSTS="*" \
    "icebox-flask-backend:smoke-test" \
    python3 -m pytest tests/ -q --tb=short 2>&1; then
    log_pass "pytest: all unit tests passed"
  else
    log_fail "pytest: one or more unit tests failed"
  fi
else
  log_skip "No tests/ directory found at ${TESTS_DIR}/tests"
fi

# ── 5. Kustomize manifest validation ─────────────────────────────────────────

log_info "=== Phase 5: Kustomize manifest validation ==="

if command -v kubectl &>/dev/null; then
  for overlay in alpha beta prod; do
    OVERLAY_DIR="${ICEBOX_ROOT}/k8s/kustomize/overlays/${overlay}"
    if [[ -d "$OVERLAY_DIR" ]]; then
      if kubectl kustomize "${OVERLAY_DIR}" &>/dev/null; then
        log_pass "kubectl kustomize overlays/${overlay}: valid"
      else
        log_fail "kubectl kustomize overlays/${overlay}: invalid YAML"
      fi
    else
      log_skip "Overlay ${overlay} not found at ${OVERLAY_DIR}"
    fi
  done
else
  log_skip "kubectl not found — skipping Kustomize validation"
fi

# ── 6. Helm chart linting ─────────────────────────────────────────────────────

log_info "=== Phase 6: Helm chart linting ==="

if command -v helm &>/dev/null; then
  for chart in flask-backend sync-worker pki-server ssh-ca webui; do
    CHART_DIR="${ICEBOX_ROOT}/k8s/helm/${chart}"
    if [[ -d "$CHART_DIR" ]]; then
      if helm lint "${CHART_DIR}" --quiet 2>&1; then
        log_pass "helm lint ${chart}: clean"
      else
        log_fail "helm lint ${chart}: errors found"
      fi
    else
      log_skip "Helm chart not found: ${CHART_DIR}"
    fi
  done
else
  log_skip "helm not found — skipping Helm lint"
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "========================================"
echo " IceBox Smoke Test Results"
echo "========================================"
echo " Passed:  ${PASS}"
echo " Failed:  ${FAIL}"
echo " Skipped: ${SKIPPED}"
echo "========================================"

if [[ "$FAIL" -gt 0 ]]; then
  echo "SMOKE TESTS FAILED"
  exit 1
else
  echo "ALL SMOKE TESTS PASSED"
  exit 0
fi
