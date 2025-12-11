# SkausWatch Development Standards and Conventions

This document defines the development standards, code quality expectations, and CI/CD requirements for SkausWatch.

## Table of Contents

1. [Code Quality Standards](#code-quality-standards)
2. [Version Management](#version-management)
3. [Testing Requirements](#testing-requirements)
4. [Security Standards](#security-standards)
5. [Documentation Standards](#documentation-standards)
6. [Git Workflow](#git-workflow)
7. [Commit Guidelines](#commit-guidelines)

## Code Quality Standards

### Python Code Style

**Framework**: PEP 8 with strict enforcement

**Tools**:
- **black**: Code formatter (line length: 88 characters)
- **isort**: Import organization
- **flake8**: Linting (configured for errors E9, F63, F7, F82)
- **mypy**: Type checking (with ignore-missing-imports)

**Requirements**:
- All code must pass `black --check`
- All imports must be organized by `isort`
- No `flake8` errors in critical categories
- Type hints recommended for public functions

**Example Pre-commit Check**:
```bash
black services/ shared/
isort services/ shared/
flake8 services/ shared/ --count --select=E9,F63,F7,F82
```

### Python Docstrings

**Standard**: PEP 257

**Minimum Requirements**:
- All public modules, functions, and classes must have docstrings
- Docstrings must describe purpose, parameters, and return values
- First line is a summary (imperative mood)
- Multi-line docstrings include detailed description after summary

**Example**:
```python
def validate_license(license_key: str) -> bool:
    """Validate license key format and authenticity.

    Args:
        license_key: License key in format PENG-XXXX-XXXX-XXXX-XXXX-ABCD

    Returns:
        True if license is valid, False otherwise

    Raises:
        ValueError: If license_key format is invalid
    """
```

### Type Hints

**Standard**: PEP 484

**Requirements**:
- Type hints for function parameters and returns
- Type hints for class attributes
- Use `Optional[T]` for nullable values
- Use `Union[T1, T2]` for multiple possible types
- Use `List`, `Dict`, `Set` from typing for generics (Python < 3.9)

**Example**:
```python
from typing import Optional, List, Dict

def fetch_configuration(user_id: int) -> Optional[Dict[str, str]]:
    """Fetch user configuration."""
    pass
```

## Version Management

### Version File Format

**Location**: `.version` at project root

**Format**: `MAJOR.MINOR.PATCH.EPOCH64`

**Constraints**:
- MAJOR: Non-negative integer (0-999)
- MINOR: Non-negative integer (0-999)
- PATCH: Non-negative integer (0-999)
- EPOCH64: 13-digit Unix timestamp in milliseconds

**Examples**:
- `1.0.0.1702742400000` - Release version
- `2.1.5.1702742500000` - Patch release
- `0.0.0.1702742600000` - Development (skips release)

### Version Increment Rules

- **Major**: Breaking API changes, major feature additions
- **Minor**: New features, backward compatible
- **Patch**: Bug fixes, minor improvements
- **Epoch64**: Automatic on build (Unix timestamp * 1000)

### Version Update Workflow

1. Make code changes in feature branch
2. Update `.version` file with new semantic version
3. Commit changes with message: `chore: bump version to X.Y.Z`
4. Push to main branch
5. Workflow automatically creates release

## Testing Requirements

### Unit Tests

**Framework**: pytest with async support

**Coverage**: Minimum 70% code coverage

**Requirements**:
- All business logic must have unit tests
- Edge cases and error conditions tested
- Async functions tested with `pytest-asyncio`
- Fixtures for common test data

**Command**:
```bash
pytest tests/ -v --cov=services --cov=shared --cov-report=html
```

### Integration Tests

**Scope**:
- Database interactions
- External service calls
- Multi-component workflows

**Requirements**:
- Use test database (PostgreSQL in containers)
- Mock external services
- Clean up test data after each test

### Test Organization

```
tests/
├── unit/
│   ├── test_auth.py
│   ├── test_models.py
│   └── test_utils.py
├── integration/
│   ├── test_database.py
│   └── test_api.py
└── conftest.py  # Pytest fixtures
```

## Security Standards

### Bandit Security Scanning

**Scope**: All Python code in `services/` and `shared/`

**Severity**: Medium level (`-ll`)

**Common Issues Detected**:
- SQL injection vulnerabilities
- Hardcoded credentials
- Insecure hashing (MD5, SHA1)
- Use of exec/eval
- Insecure random generation
- Hardcoded passwords in code
- Use of assert for validation

**Fix Examples**:

Bandit Issue: Hardcoded password
```python
# BAD
password = "admin123"

# GOOD
password = os.environ.get('APP_PASSWORD')
```

Bandit Issue: Use of assert
```python
# BAD
assert user is not None, "User must exist"

# GOOD
if user is None:
    raise ValueError("User must exist")
```

### Secret Management

**Rules**:
- Never commit credentials, tokens, or keys
- Use environment variables for sensitive data
- Use `.env` files (added to `.gitignore`)
- Use GitHub Secrets for CI/CD

**Environment Variables**:
```bash
LICENSE_KEY=PENG-XXXX-XXXX-XXXX-XXXX-ABCD
LICENSE_SERVER_URL=https://license.penguintech.io
DATABASE_PASSWORD=secure_password_here
```

### Dependency Security

**Requirements**:
- Regular `pip-audit` checks
- Address high/critical vulnerabilities immediately
- Review security advisories for dependencies
- Keep dependencies updated

**Command**:
```bash
pip-audit
```

## Documentation Standards

### Code Comments

**Rule**: Comments explain WHY, not WHAT

**Good Comments**:
```python
# Use exponential backoff to handle rate limiting from license server
retry_delay = base_delay * (2 ** attempt)
```

**Bad Comments**:
```python
# Multiply base_delay by 2^attempt
retry_delay = base_delay * (2 ** attempt)
```

### Module Documentation

**Requirement**: Each module must have a docstring

**Example**:
```python
"""Authentication and authorization module.

This module handles user authentication, session management, and
role-based access control for SkausWatch services.

Classes:
    AuthManager: Main authentication handler
    Session: User session management

Functions:
    validate_credentials: Verify user credentials
    create_session: Initialize new user session
"""
```

### Function Documentation

**Standard**: Docstring for all public functions

**Format**:
```python
def process_audit_logs(user_id: int, start_date: str) -> List[Dict]:
    """Process audit logs for a user within date range.

    Retrieves audit logs for the specified user, validates entries,
    and applies AI analysis for threat detection.

    Args:
        user_id: Internal user identifier
        start_date: ISO format date (YYYY-MM-DD)

    Returns:
        List of processed audit log entries with threat scores

    Raises:
        ValueError: If start_date is invalid format
        PermissionError: If user lacks audit log access

    Example:
        >>> logs = process_audit_logs(123, "2024-01-01")
        >>> for log in logs:
        ...     print(log['threat_score'])
    """
```

## Git Workflow

### Branch Naming

**Format**: `type/description`

**Types**:
- `feature/`: New feature
- `bugfix/`: Bug fixes
- `chore/`: Maintenance, dependencies
- `docs/`: Documentation only
- `refactor/`: Code refactoring

**Examples**:
```
feature/license-enforcement
bugfix/ssh-ca-certificate-expiry
chore/update-dependencies
docs/api-endpoints
refactor/auth-module
```

### Main Branch Protection

**Rules**:
- Require pull request reviews (minimum 1)
- Require status checks to pass (CI/CD)
- Dismiss stale pull request approvals
- Require branches to be up-to-date before merge
- No forced pushes to main

## Commit Guidelines

### Commit Message Format

**Standard**: Conventional Commits

**Format**: `type(scope): subject`

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `chore`: Build, dependencies, tooling
- `docs`: Documentation
- `refactor`: Code refactoring
- `test`: Test additions or modifications
- `perf`: Performance improvements

**Scope**: Optional, but recommended (module or feature name)

**Subject**: Imperative, present tense, lowercase, no period

**Examples**:
```
feat(auth): implement two-factor authentication
fix(pki): correct certificate expiry calculation
chore(deps): update dependencies to latest versions
docs(api): add endpoint authentication examples
```

### Detailed Commit Message

For complex changes, include body and footer:

```
feat(license): add offline mode support

Implement local caching of license validation to support
offline operation. Cache is refreshed on each network connection.

Adds:
- Local SQLite cache for license status
- Automatic sync when online detected
- Cache expiry after 7 days

Fixes #123
Related to #456
```

## Deployment Standards

### Pre-Deployment Checklist

- [ ] All tests passing locally and in CI
- [ ] Code coverage above 70%
- [ ] Bandit security scan complete (no critical issues)
- [ ] Version updated in `.version` file
- [ ] Documentation updated for new features
- [ ] No hardcoded credentials or sensitive data
- [ ] Pull request reviewed and approved
- [ ] Changelog/release notes prepared

### Release Process

1. Create feature/bugfix branch
2. Make changes following standards above
3. Ensure all tests pass: `pytest tests/ -v`
4. Ensure linting passes: `black` and `isort`
5. Create pull request with detailed description
6. Address code review feedback
7. Get approval from maintainer
8. Merge to main
9. Update `.version` file
10. Push to main (triggers release workflow)
11. Verify release created on GitHub

## Continuous Integration

### Required Checks

All pull requests must pass:
1. **Bandit**: Security scan (informational, no blocking)
2. **Black**: Code formatting
3. **isort**: Import sorting
4. **flake8**: Linting
5. **pytest**: Unit tests with 70%+ coverage
6. **mypy**: Type checking

### Build Artifacts

- Security reports (JSON)
- Coverage reports (HTML, XML)
- Docker images (multi-architecture)

## Performance Expectations

### Code Performance

- API endpoints: < 200ms response time
- Database queries: < 100ms
- License validation: < 50ms

### Build Performance

- Build time: < 10 minutes
- Test suite: < 5 minutes
- Lint check: < 1 minute

## Related Documents

- [Workflows Documentation](WORKFLOWS.md)
- [Project README](../README.md)
- [Version Management](../CLAUDE.md#version-management-system)
