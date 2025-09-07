#!/bin/bash
set -euo pipefail

# SkausWatch Quality Checks Script
# This script runs all code quality checks manually for testing and CI/CD

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_section() {
    echo -e "${CYAN}[SECTION]${NC} $1"
    echo "$(printf '=%.0s' {1..60})"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Track results
declare -A results
total_checks=0
passed_checks=0

# Function to run a check and track results
run_check() {
    local check_name="$1"
    local check_command="$2"
    local optional="${3:-false}"
    
    total_checks=$((total_checks + 1))
    log_info "Running: $check_name"
    
    if eval "$check_command"; then
        results["$check_name"]="PASSED"
        passed_checks=$((passed_checks + 1))
        log_success "$check_name passed"
    else
        if [[ "$optional" == "true" ]]; then
            results["$check_name"]="SKIPPED"
            log_warning "$check_name skipped (optional)"
        else
            results["$check_name"]="FAILED"
            log_error "$check_name failed"
        fi
    fi
    echo
}

# Change to project root
cd "$PROJECT_ROOT"

# Display header
echo "$(printf '=%.0s' {1..60})"
echo -e "${CYAN}SkausWatch Code Quality Checks${NC}"
echo "$(printf '=%.0s' {1..60})"
echo

# Check if pre-commit is available
if ! command_exists pre-commit; then
    log_error "pre-commit not found. Please run scripts/setup-pre-commit.sh first."
    exit 1
fi

# 1. Pre-commit hooks (all files)
log_section "Running all pre-commit hooks"
run_check "Pre-commit hooks" "pre-commit run --all-files"

# 2. Python-specific checks (if Python files exist)
if find . -name "*.py" -not -path "./node_modules/*" -not -path "./.next/*" -not -path "./out/*" -not -path "./.venv/*" -not -path "./venv/*" | grep -q .; then
    log_section "Python Code Quality Checks"
    
    # Black formatting check
    if command_exists black; then
        run_check "Black formatting" "black --check --diff ."
    fi
    
    # isort import sorting check
    if command_exists isort; then
        run_check "isort import sorting" "isort --check-only --diff ."
    fi
    
    # Ruff linting
    if command_exists ruff; then
        run_check "Ruff linting" "ruff check ."
        run_check "Ruff formatting" "ruff format --check ."
    fi
    
    # MyPy type checking
    if command_exists mypy; then
        run_check "MyPy type checking" "mypy --config-file pyproject.toml ." "true"
    fi
    
    # Bandit security scanning
    if command_exists bandit; then
        run_check "Bandit security scan" "bandit -r . -x tests/,migrations/,venv/,.venv/,node_modules/ -ll" "true"
    fi
fi

# 3. JavaScript/TypeScript checks (if JS/TS files exist)
if find . -name "*.js" -o -name "*.jsx" -o -name "*.ts" -o -name "*.tsx" -not -path "./node_modules/*" -not -path "./.next/*" -not -path "./out/*" | grep -q .; then
    log_section "JavaScript/TypeScript Code Quality Checks"
    
    # ESLint
    if command_exists npx && [[ -f "package.json" ]]; then
        run_check "ESLint" "npx eslint . --ext .js,.jsx,.ts,.tsx"
    fi
    
    # Prettier formatting check
    if command_exists npx; then
        run_check "Prettier formatting" "npx prettier --check ." "true"
    fi
    
    # TypeScript type checking
    if command_exists npx && [[ -f "tsconfig.json" ]]; then
        run_check "TypeScript compilation" "npx tsc --noEmit"
    fi
    
    # Next.js build (if it's a Next.js project)
    if [[ -f "next.config.js" ]] && command_exists npx; then
        run_check "Next.js build" "npx next build" "true"
    fi
fi

# 4. Docker checks (if Dockerfile exists)
if find . -name "Dockerfile*" -not -path "./node_modules/*" | grep -q .; then
    log_section "Docker Quality Checks"
    
    # Hadolint
    if command_exists hadolint; then
        run_check "Hadolint Dockerfile linting" "find . -name 'Dockerfile*' -not -path './node_modules/*' | xargs -r hadolint"
    fi
    
    # Docker Compose validation
    if command_exists docker-compose && [[ -f "docker-compose.yml" ]]; then
        run_check "Docker Compose validation" "docker-compose config --quiet" "true"
    fi
fi

# 5. Shell script checks (if shell scripts exist)
if find . -name "*.sh" -not -path "./node_modules/*" | grep -q .; then
    log_section "Shell Script Quality Checks"
    
    # ShellCheck
    if command_exists shellcheck; then
        run_check "ShellCheck" "find . -name '*.sh' -not -path './node_modules/*' | xargs -r shellcheck"
    fi
fi

# 6. YAML checks (if YAML files exist)
if find . -name "*.yml" -o -name "*.yaml" -not -path "./node_modules/*" -not -path "./.next/*" | grep -q .; then
    log_section "YAML Quality Checks"
    
    # yamllint
    if command_exists yamllint; then
        run_check "YAML linting" "yamllint ."
    fi
fi

# 7. Markdown checks (if Markdown files exist)
if find . -name "*.md" -not -path "./node_modules/*" -not -path "./.next/*" | grep -q .; then
    log_section "Markdown Quality Checks"
    
    # markdownlint
    if command_exists markdownlint; then
        run_check "Markdown linting" "markdownlint --config .markdownlint.json *.md docs/**/*.md" "true"
    fi
fi

# 8. Security checks
log_section "Security Checks"

# Secrets detection
if command_exists detect-secrets; then
    run_check "Secrets detection" "detect-secrets scan --baseline .secrets.baseline"
fi

# GitGuardian (if available)
if command_exists ggshield; then
    run_check "GitGuardian secrets scan" "ggshield secret scan path ." "true"
fi

# 9. Git checks
log_section "Git Quality Checks"

# Check for merge conflicts
run_check "Merge conflict check" "! grep -r '<<<<<<< ' . --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.next --exclude-dir=out || false"

# Check for large files
run_check "Large files check" "find . -type f -size +10M -not -path './node_modules/*' -not -path './.git/*' -not -path './.next/*' -not -path './out/*' | grep -q . && echo 'Large files found' && exit 1 || true"

# 10. Dependencies checks (if applicable)
log_section "Dependencies Security Checks"

# npm audit (if package.json exists)
if [[ -f "package.json" ]] && command_exists npm; then
    run_check "npm security audit" "npm audit --audit-level=high" "true"
fi

# Python safety check (if requirements files exist)
if command_exists safety && (find . -name "*requirements*.txt" -o -name "pyproject.toml" | grep -q .); then
    run_check "Python safety check" "safety check" "true"
fi

# Display results summary
echo
echo "$(printf '=%.0s' {1..60})"
log_section "Quality Checks Summary"

for check in "${!results[@]}"; do
    status="${results[$check]}"
    case $status in
        "PASSED")
            echo -e "${GREEN}✓${NC} $check"
            ;;
        "FAILED")
            echo -e "${RED}✗${NC} $check"
            ;;
        "SKIPPED")
            echo -e "${YELLOW}⚠${NC} $check (skipped)"
            ;;
    esac
done

echo
echo "$(printf '=%.0s' {1..60})"
if [[ $passed_checks -eq $total_checks ]]; then
    log_success "All quality checks passed! ($passed_checks/$total_checks)"
    exit 0
else
    failed_checks=$((total_checks - passed_checks))
    log_error "Some quality checks failed. ($passed_checks/$total_checks passed, $failed_checks failed)"
    
    echo
    log_info "To fix issues:"
    echo "  - Run individual tools to see detailed error messages"
    echo "  - Some issues can be auto-fixed with: pre-commit run --all-files"
    echo "  - Review the configuration files for tool-specific settings"
    echo "  - Check the logs above for specific failure details"
    
    exit 1
fi