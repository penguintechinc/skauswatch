#!/usr/bin/env bash
# SkausWatch Test Controller
# Unified CLI for all test types
# Usage: ./scripts/test-controller.sh <type> [service]

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Colors
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
RESET='\033[0m'

usage() {
    echo -e "${BLUE}SkausWatch Test Controller${RESET}"
    echo ""
    echo "Usage: $0 <type> [service]"
    echo ""
    echo -e "${GREEN}Test Types:${RESET}"
    echo "  build         Docker build tests (all services)"
    echo "  unit          Unit tests (pytest + go test + vitest)"
    echo "  integration   Integration tests (requires test infra)"
    echo "  functional    Functional tests (Playwright browser tests)"
    echo "  e2e           End-to-end tests (requires full stack)"
    echo "  security      Security tests (auth, input validation)"
    echo "  api           API endpoint tests"
    echo "  performance   Performance/load tests"
    echo "  smoke         Smoke tests (pre-commit, <2 min)"
    echo "  lint          Lint checks (black, isort, flake8, eslint, gofmt)"
    echo "  streams       Stream/pipeline tests"
    echo "  all           Run all test types"
    echo ""
    echo -e "${GREEN}Service Filter (optional):${RESET}"
    echo "  manager-new, pki-server-new, ssh-ca, aaa-monitor,"
    echo "  worker-s3, worker-scanner, webui, edr-agent"
    echo ""
    echo -e "${GREEN}Examples:${RESET}"
    echo "  $0 unit                    # All unit tests"
    echo "  $0 unit manager-new        # Only manager-new unit tests"
    echo "  $0 smoke                   # Pre-commit smoke tests"
    echo "  $0 lint                    # All linting"
    echo "  $0 all                     # Everything"
    exit 1
}

# Validate arguments
[[ $# -lt 1 ]] && usage

TYPE="$1"
SERVICE="${2:-}"
EXIT_CODE=0

log_info() { echo -e "${BLUE}[test-controller]${RESET} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${RESET} $1"; }
log_fail() { echo -e "${RED}[FAIL]${RESET} $1"; }
log_skip() { echo -e "${YELLOW}[SKIP]${RESET} $1"; }

run_cmd() {
    local desc="$1"
    shift
    log_info "$desc"
    if "$@"; then
        log_pass "$desc"
    else
        log_fail "$desc"
        EXIT_CODE=1
    fi
}

# --- Test Type Runners ---

run_build() {
    log_info "Running build tests..."
    run_cmd "Docker build tests" pytest tests/build/ -v -m build 2>/dev/null || \
        log_skip "No build tests found at tests/build/"
}

run_unit() {
    log_info "Running unit tests..."

    if [[ -n "$SERVICE" ]]; then
        case "$SERVICE" in
            edr-agent)
                run_cmd "Go unit tests ($SERVICE)" bash -c "cd services/edr-agent && go test ./... -v"
                ;;
            webui)
                run_cmd "Vitest unit tests ($SERVICE)" bash -c "cd services/webui && npx vitest run"
                ;;
            *)
                if [[ -d "services/$SERVICE/tests/unit" ]]; then
                    run_cmd "Python unit tests ($SERVICE)" pytest "services/$SERVICE/tests/unit/" -v -m unit
                else
                    log_skip "No unit tests found for $SERVICE"
                fi
                ;;
        esac
    else
        # Run all unit tests
        # Python (root-level + service-level)
        local python_paths=()
        [[ -d tests/unit ]] && python_paths+=(tests/unit/)
        for svc_dir in services/*/tests/unit; do
            [[ -d "$svc_dir" ]] && python_paths+=("$svc_dir/")
        done
        if [[ ${#python_paths[@]} -gt 0 ]]; then
            run_cmd "Python unit tests" pytest "${python_paths[@]}" -v -m unit
        fi

        # Go
        if [[ -f services/edr-agent/go.mod ]]; then
            run_cmd "Go unit tests" bash -c "cd services/edr-agent && go test ./... -v"
        fi

        # TypeScript
        if [[ -f services/webui/package.json ]] && grep -q vitest services/webui/package.json 2>/dev/null; then
            run_cmd "Vitest unit tests" bash -c "cd services/webui && npx vitest run"
        fi
    fi
}

run_integration() {
    log_info "Running integration tests..."

    # Check if test infra is up
    if ! docker compose -f docker-compose.test.yml ps --status running 2>/dev/null | grep -q "running"; then
        log_info "Starting test infrastructure..."
        docker compose -f docker-compose.test.yml up -d --wait 2>/dev/null || \
            log_skip "docker-compose.test.yml not available"
    fi

    run_cmd "Integration tests" pytest tests/integration/ -v -m integration
}

run_functional() {
    log_info "Running functional tests (Playwright)..."
    if [[ -f services/webui/playwright.config.ts ]]; then
        run_cmd "Playwright functional tests" bash -c "cd services/webui && npx playwright test tests/functional/"
    else
        log_skip "No Playwright config found at services/webui/playwright.config.ts"
    fi
}

run_e2e() {
    log_info "Running E2E tests..."
    # Python E2E
    if [[ -d tests/e2e ]]; then
        run_cmd "Python E2E tests" pytest tests/e2e/ -v -m e2e
    fi
    # Browser E2E
    if [[ -f services/webui/playwright.config.ts ]] && [[ -d services/webui/tests/e2e ]]; then
        run_cmd "Browser E2E tests" bash -c "cd services/webui && npx playwright test tests/e2e/"
    fi
}

run_security() {
    log_info "Running security tests..."
    if [[ -d tests/security ]]; then
        run_cmd "Security tests" pytest tests/security/ -v -m security
    else
        log_skip "No security tests found at tests/security/"
    fi
}

run_api() {
    log_info "Running API tests..."
    if [[ -d tests/api ]]; then
        run_cmd "API tests" pytest tests/api/ -v -m api
    else
        log_skip "No API tests found at tests/api/"
    fi
}

run_performance() {
    log_info "Running performance tests..."
    if [[ -d tests/performance ]]; then
        run_cmd "Performance tests" pytest tests/performance/ -v -m performance
    else
        log_skip "No performance tests found at tests/performance/"
    fi
}

run_smoke() {
    log_info "Running smoke tests (<2 min)..."

    local smoke_paths=()
    [[ -d tests/smoke ]] && smoke_paths+=(tests/smoke/)
    for svc_dir in services/*/tests/smoke; do
        [[ -d "$svc_dir" ]] && smoke_paths+=("$svc_dir/")
    done

    if [[ ${#smoke_paths[@]} -gt 0 ]]; then
        run_cmd "Smoke tests" pytest "${smoke_paths[@]}" -v -m smoke
    else
        log_skip "No smoke tests found"
    fi
}

run_lint() {
    log_info "Running lint checks..."

    # Python
    run_cmd "black (check)" black --check services/ tests/ || true
    run_cmd "isort (check)" isort --check-only services/ tests/ || true
    run_cmd "flake8" flake8 services/ tests/ --max-line-length=120 --exclude=__pycache__,.git,node_modules || true

    # Go
    if [[ -f services/edr-agent/go.mod ]]; then
        run_cmd "gofmt (check)" bash -c "test -z \"\$(cd services/edr-agent && gofmt -l .)\"" || true
        run_cmd "go vet" bash -c "cd services/edr-agent && go vet ./..." || true
    fi

    # TypeScript
    if [[ -f services/webui/package.json ]]; then
        if grep -q '"lint"' services/webui/package.json 2>/dev/null; then
            run_cmd "eslint" bash -c "cd services/webui && npm run lint" || true
        fi
        if grep -q '"typecheck"' services/webui/package.json 2>/dev/null; then
            run_cmd "tsc typecheck" bash -c "cd services/webui && npm run typecheck" || true
        fi
    fi

    # Lint test files (pytest-based)
    if [[ -d tests/lint ]]; then
        run_cmd "Lint tests" pytest tests/lint/ -v -m lint
    fi
}

run_streams() {
    log_info "Running stream/pipeline tests..."
    if [[ -d tests/streams ]]; then
        run_cmd "Stream tests" pytest tests/streams/ -v -m stream
    else
        log_skip "No stream tests found at tests/streams/"
    fi
}

run_all() {
    log_info "Running ALL test types..."
    run_lint
    run_smoke
    run_unit
    run_api
    run_security
    run_streams
    run_integration
    run_functional
    run_e2e
    run_build
    run_performance
}

# --- Main Dispatch ---

case "$TYPE" in
    build)       run_build ;;
    unit)        run_unit ;;
    integration) run_integration ;;
    functional)  run_functional ;;
    e2e)         run_e2e ;;
    security)    run_security ;;
    api)         run_api ;;
    performance) run_performance ;;
    smoke)       run_smoke ;;
    lint)        run_lint ;;
    streams)     run_streams ;;
    all)         run_all ;;
    *)           echo -e "${RED}Unknown test type: $TYPE${RESET}"; usage ;;
esac

echo ""
if [[ $EXIT_CODE -eq 0 ]]; then
    echo -e "${GREEN}All tests passed!${RESET}"
else
    echo -e "${RED}Some tests failed!${RESET}"
fi

exit $EXIT_CODE
