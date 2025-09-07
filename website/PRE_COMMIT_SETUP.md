# Pre-commit Setup for SkausWatch

This document describes the comprehensive pre-commit hooks setup for code quality in the SkausWatch project.

## Overview

The pre-commit configuration includes hooks for:

- **General file fixes** (trailing whitespace, large files, etc.)
- **Python code quality** (black, isort, ruff, mypy, bandit)
- **JavaScript/TypeScript quality** (prettier, eslint)
- **Infrastructure linting** (hadolint for Docker, shellcheck for shell scripts)
- **Documentation quality** (yamllint, markdownlint)
- **Security scanning** (detect-secrets, gitguardian)
- **Git commit message linting** (commitizen)

## Quick Start

1. **Install and setup pre-commit:**
   ```bash
   ./scripts/setup-pre-commit.sh
   ```

2. **Run quality checks manually:**
   ```bash
   ./scripts/run-quality-checks.sh
   ```

3. **Commit your code** - hooks run automatically

## Files Created

### Configuration Files

| File | Purpose |
|------|---------|
| `.pre-commit-config.yaml` | Main pre-commit configuration |
| `.secrets.baseline` | Baseline for secrets detection |
| `pyproject.toml` | Python tools configuration |
| `ruff.toml` | Detailed Python linting rules |
| `.markdownlint.json` | Markdown linting rules |
| `.yamllint.yml` | YAML linting configuration |

### Scripts

| File | Purpose |
|------|---------|
| `scripts/setup-pre-commit.sh` | Installation and setup script |
| `scripts/run-quality-checks.sh` | Manual quality checks runner |

## Pre-commit Hooks Detail

### General File Hooks
- `trailing-whitespace`: Removes trailing whitespace
- `end-of-file-fixer`: Ensures files end with newline
- `check-yaml/json/xml/toml`: Validates file formats
- `check-added-large-files`: Prevents large files (>10MB)
- `check-merge-conflict`: Detects merge conflict markers
- `mixed-line-ending`: Ensures consistent line endings (LF)

### Python Quality Tools
- **Black**: Code formatting (line length: 100)
- **isort**: Import sorting (black profile)
- **Ruff**: Fast linting and formatting
- **MyPy**: Static type checking
- **Bandit**: Security vulnerability scanning

### JavaScript/TypeScript Tools
- **Prettier**: Code formatting
- **ESLint**: Linting with Next.js configuration

### Infrastructure Tools
- **Hadolint**: Dockerfile linting
- **ShellCheck**: Shell script analysis
- **Docker Compose**: Configuration validation

### Documentation Tools
- **yamllint**: YAML file linting
- **markdownlint**: Markdown formatting

### Security Tools
- **detect-secrets**: Prevents secrets in commits
- **GitGuardian**: Additional secrets scanning

### Git Tools
- **Commitizen**: Commit message format enforcement

## Tool Configuration

### Python Tools (pyproject.toml)
- Black: 100 character line length, Python 3.8+ target
- isort: Black-compatible profile
- Ruff: Comprehensive rule set with project-specific ignores
- MyPy: Strict type checking with test exemptions
- Bandit: Security scanning excluding test directories

### Ruff Configuration (ruff.toml)
- Target: Python 3.8+
- Line length: 100 characters
- Comprehensive rule selection covering:
  - Code style (E, W, F)
  - Import organization (I)
  - Security (S)
  - Performance (PERF)
  - Modern Python practices (UP)
  - Documentation (D with Google style)

### Markdown Rules (.markdownlint.json)
- ATX-style headers
- 100 character line length
- Allows HTML elements for enhanced formatting
- Fenced code blocks preferred

### YAML Rules (.yamllint.yml)
- 100 character line length
- 2-space indentation
- Sequence indentation enabled
- Truthy values: true/false, yes/no

## Usage

### Automatic Usage
Hooks run automatically on:
- `git commit` (most hooks)
- `git push` (commitizen branch check)

### Manual Usage
```bash
# Run all hooks on all files
pre-commit run --all-files

# Run specific hook
pre-commit run black

# Run quality checks script
./scripts/run-quality-checks.sh

# Update hook versions
pre-commit autoupdate

# Skip hooks (emergency only)
git commit --no-verify
```

### CI/CD Integration
The quality checks script can be used in CI/CD:
```yaml
# GitHub Actions example
- name: Run quality checks
  run: ./scripts/run-quality-checks.sh
```

## Troubleshooting

### Common Issues

1. **Hook installation fails**
   - Ensure Python 3.8+ and Node.js 18+ are installed
   - Run `./scripts/setup-pre-commit.sh` for guided setup

2. **Type checking errors (MyPy)**
   - Add type annotations or ignore with `# type: ignore`
   - Some errors in tests/ are expected and configured to be less strict

3. **Secrets detection false positives**
   - Update `.secrets.baseline` with: `detect-secrets scan --baseline .secrets.baseline`
   - Use `# pragma: allowlist secret` for false positives

4. **Import sorting conflicts**
   - isort is configured to work with Black
   - Both will auto-fix on commit

5. **Long line length**
   - Tools are configured for 100 characters
   - Black will auto-format where possible

### Excluding Files
Add patterns to exclude files in `.pre-commit-config.yaml`:
```yaml
- id: hook-name
  exclude: ^(path/to/exclude/|another/path/)
```

### Disabling Specific Rules
For Ruff, add rules to ignore in `ruff.toml`:
```toml
ignore = [
    "E501",  # Line too long
    "F401",  # Unused import
]
```

## Maintenance

### Regular Tasks
- **Monthly**: Run `pre-commit autoupdate` to get latest hook versions
- **Before releases**: Run full quality checks with `./scripts/run-quality-checks.sh`
- **After tool updates**: Review and update configuration files

### Adding New Hooks
1. Add to `.pre-commit-config.yaml`
2. Update configuration files as needed
3. Test with `pre-commit run --all-files`
4. Document in this README

## Benefits

- **Consistent code quality** across all contributors
- **Early issue detection** before code review
- **Automated formatting** reduces manual work
- **Security scanning** prevents credential leaks
- **Documentation quality** ensures readable docs
- **Infrastructure validation** catches config issues

## Performance

The hooks are designed to be fast:
- Ruff replaces slower tools like flake8
- Hooks only run on changed files (except manual runs)
- Caching is enabled for all tools
- Most hooks complete in seconds

For large repositories, consider:
- Using `pre-commit run --files changed_file.py` for specific files
- Excluding large directories in hook configurations
- Running full checks in CI rather than locally