#!/bin/bash
set -euo pipefail

# SkausWatch Pre-commit Setup Script
# This script installs and configures pre-commit hooks for code quality

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check Python version
check_python_version() {
    if command_exists python3; then
        local python_version
        python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        local major minor
        major=$(echo "$python_version" | cut -d. -f1)
        minor=$(echo "$python_version" | cut -d. -f2)
        
        if [[ $major -ge 3 && $minor -ge 8 ]]; then
            log_success "Python version $python_version is supported"
            return 0
        else
            log_error "Python version $python_version is not supported. Minimum required: 3.8"
            return 1
        fi
    else
        log_error "python3 command not found"
        return 1
    fi
}

# Function to check Node.js version
check_node_version() {
    if command_exists node; then
        local node_version
        node_version=$(node --version | sed 's/v//')
        local major
        major=$(echo "$node_version" | cut -d. -f1)
        
        if [[ $major -ge 18 ]]; then
            log_success "Node.js version $node_version is supported"
            return 0
        else
            log_error "Node.js version $node_version is not supported. Minimum required: 18"
            return 1
        fi
    else
        log_error "node command not found"
        return 1
    fi
}

# Function to install pre-commit
install_pre_commit() {
    log_info "Installing pre-commit..."
    
    if command_exists pip3; then
        pip3 install --user pre-commit
    elif command_exists pip; then
        pip install --user pre-commit
    else
        log_error "pip or pip3 not found. Please install Python package manager."
        exit 1
    fi
    
    # Add ~/.local/bin to PATH if not already there
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        log_warning "Adding ~/.local/bin to PATH for current session"
        export PATH="$HOME/.local/bin:$PATH"
        log_info "Add 'export PATH=\"\$HOME/.local/bin:\$PATH\"' to your shell profile for permanent access"
    fi
}

# Function to install Node.js dependencies
install_node_dependencies() {
    log_info "Installing Node.js dependencies..."
    cd "$PROJECT_ROOT"
    
    if [[ -f "package.json" ]]; then
        if command_exists npm; then
            npm install
        elif command_exists yarn; then
            yarn install
        else
            log_error "Neither npm nor yarn found"
            return 1
        fi
    else
        log_warning "package.json not found, skipping Node.js dependencies"
    fi
}

# Function to setup git hooks
setup_git_hooks() {
    log_info "Setting up git hooks..."
    cd "$PROJECT_ROOT"
    
    # Ensure we're in a git repository
    if [[ ! -d ".git" ]]; then
        log_error "Not in a git repository. Please run 'git init' first."
        exit 1
    fi
    
    # Install pre-commit hooks
    if command_exists pre-commit; then
        pre-commit install
        pre-commit install --hook-type commit-msg
        pre-commit install --hook-type pre-push
        log_success "Pre-commit hooks installed"
    else
        log_error "pre-commit command not found after installation"
        exit 1
    fi
}

# Function to run initial check
run_initial_check() {
    log_info "Running initial pre-commit check on all files..."
    cd "$PROJECT_ROOT"
    
    if command_exists pre-commit; then
        # Run pre-commit on all files (may fail on first run)
        if pre-commit run --all-files; then
            log_success "All pre-commit checks passed"
        else
            log_warning "Some pre-commit checks failed. This is normal on first run."
            log_info "Files have been automatically fixed where possible."
            log_info "Review the changes and commit them, then run the checks again."
        fi
    fi
}

# Function to create or update gitignore
update_gitignore() {
    log_info "Updating .gitignore with pre-commit cache entries..."
    cd "$PROJECT_ROOT"
    
    local gitignore_entries=(
        ".pre-commit-cache/"
        ".ruff_cache/"
        ".mypy_cache/"
        "__pycache__/"
        "*.pyc"
        ".pytest_cache/"
        "htmlcov/"
        ".coverage"
        ".coverage.*"
    )
    
    for entry in "${gitignore_entries[@]}"; do
        if ! grep -Fxq "$entry" .gitignore 2>/dev/null; then
            echo "$entry" >> .gitignore
            log_info "Added $entry to .gitignore"
        fi
    done
}

# Function to setup secrets baseline
setup_secrets_baseline() {
    log_info "Setting up secrets detection baseline..."
    cd "$PROJECT_ROOT"
    
    if [[ -f ".secrets.baseline" ]]; then
        log_info "Secrets baseline already exists"
    else
        log_warning "No secrets baseline found. Creating empty baseline."
        log_info "Run 'detect-secrets scan --baseline .secrets.baseline' to generate initial baseline"
    fi
}

# Function to display post-installation information
show_post_install_info() {
    log_success "Pre-commit setup completed successfully!"
    echo
    log_info "What was installed:"
    echo "  - Pre-commit hooks for code quality"
    echo "  - Python tools: black, isort, ruff, mypy, bandit"
    echo "  - JavaScript tools: prettier, eslint"
    echo "  - Additional tools: hadolint, shellcheck, yamllint, markdownlint"
    echo "  - Security tools: detect-secrets, gitguardian"
    echo
    log_info "Usage:"
    echo "  - Hooks run automatically on git commit"
    echo "  - Manual run: pre-commit run --all-files"
    echo "  - Update hooks: pre-commit autoupdate"
    echo "  - Skip hooks: git commit --no-verify"
    echo
    log_info "Configuration files created:"
    echo "  - .pre-commit-config.yaml (main configuration)"
    echo "  - .secrets.baseline (secrets detection)"
    echo "  - pyproject.toml (Python tool settings)"
    echo "  - ruff.toml (Python linting rules)"
    echo "  - .markdownlint.json (Markdown rules)"
    echo "  - .yamllint.yml (YAML linting rules)"
    echo
    log_info "Next steps:"
    echo "  1. Review and commit the configuration files"
    echo "  2. Run: scripts/run-quality-checks.sh"
    echo "  3. Fix any issues reported by the tools"
    echo "  4. Commit your changes to trigger the hooks"
}

# Main execution
main() {
    log_info "Starting SkausWatch pre-commit setup..."
    echo
    
    # Check prerequisites
    log_info "Checking prerequisites..."
    check_python_version || exit 1
    check_node_version || exit 1
    
    # Install pre-commit if not present
    if ! command_exists pre-commit; then
        install_pre_commit
    else
        log_success "pre-commit already installed"
    fi
    
    # Install Node.js dependencies
    install_node_dependencies
    
    # Setup git hooks
    setup_git_hooks
    
    # Update .gitignore
    update_gitignore
    
    # Setup secrets baseline
    setup_secrets_baseline
    
    # Run initial check
    run_initial_check
    
    # Show completion information
    show_post_install_info
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi