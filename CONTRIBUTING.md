# Contributing to SkausWatch

Thank you for your interest in contributing to SkausWatch! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Security Issues](#security-issues)

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

### Our Pledge

We are committed to making participation in this project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

## Getting Started

### Prerequisites

- Python 3.13 or higher
- Docker and Docker Compose
- Git
- A GitHub account

### Development Setup

1. **Fork and Clone**
   ```bash
   # Fork the repository on GitHub
   git clone https://github.com/penguintechinc/skauswatch.git
   cd SkausWatch
   ```

2. **Set up Development Environment**
   ```bash
   # Create virtual environment
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   
   # Install development dependencies
   pip install -e ".[dev]"
   ```

3. **Install Pre-commit Hooks**
   ```bash
   pre-commit install
   ```

4. **Start Development Services**
   ```bash
   docker-compose up -d
   ```

5. **Verify Setup**
   ```bash
   # Run tests to ensure everything works
   pytest
   
   # Check code quality
   ruff check .
   black --check .
   mypy .
   ```

## Development Workflow

### Branch Naming Convention

Use descriptive branch names with prefixes:

- `feature/` - New features
- `bugfix/` - Bug fixes
- `hotfix/` - Critical fixes for production
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Test improvements

Examples:
- `feature/ssh-ca-certificate-validation`
- `bugfix/pki-server-memory-leak`
- `docs/api-documentation-update`

### Commit Message Format

Follow the [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only changes
- `style`: Changes that don't affect code meaning (formatting, etc.)
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `perf`: Performance improvements
- `test`: Adding missing tests or correcting existing tests
- `build`: Changes affecting build system or external dependencies
- `ci`: Changes to CI configuration files and scripts

Examples:
```
feat(ssh-ca): add certificate validation endpoint

fix(pki-server): resolve memory leak in certificate cleanup

docs: update API documentation for manager service
```

## Coding Standards

### Python Code Style

We use several tools to maintain code quality:

- **Black**: Code formatting (88 character line length)
- **Ruff**: Fast Python linter
- **MyPy**: Static type checking
- **isort**: Import sorting

### Code Quality Requirements

- All code must pass pre-commit hooks
- Type hints are required for all functions and methods
- Docstrings are required for all public functions, classes, and modules
- Code coverage must be maintained above 90%

### Docstring Format

Use Google-style docstrings:

```python
def example_function(param1: str, param2: int = 0) -> bool:
    """Brief description of function.
    
    Longer description if needed, explaining the purpose and behavior
    of the function.
    
    Args:
        param1: Description of param1.
        param2: Description of param2. Defaults to 0.
        
    Returns:
        Description of return value.
        
    Raises:
        ValueError: Description of when this exception is raised.
        
    Example:
        >>> example_function("test", 42)
        True
    """
    return True
```

### File Structure

- Keep modules focused and cohesive
- Use `__init__.py` files to define package interfaces
- Place tests in parallel directory structure under `tests/`
- Keep configuration files in appropriate directories

## Testing

### Test Structure

```
tests/
├── unit/           # Unit tests
├── integration/    # Integration tests
├── e2e/           # End-to-end tests
└── fixtures/      # Test fixtures and data
```

### Writing Tests

- Write tests for all new functionality
- Maintain high test coverage (minimum 90%)
- Use descriptive test names
- Follow AAA pattern (Arrange, Act, Assert)
- Use pytest fixtures for common setup

Example test:

```python
import pytest
from skauswatch.services.manager import ManagerService

class TestManagerService:
    def test_create_service_returns_valid_instance(self):
        """Test that ManagerService creates a valid instance."""
        # Arrange
        config = {"database_url": "sqlite:///:memory:"}
        
        # Act
        service = ManagerService(config)
        
        # Assert
        assert service is not None
        assert service.config == config
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test categories
pytest -m unit
pytest -m integration
pytest -m e2e

# Run with coverage
pytest --cov=skauswatch --cov-report=html

# Run tests in parallel
pytest -n auto
```

## Documentation

### API Documentation

- All APIs must be documented using FastAPI's automatic documentation
- Include comprehensive examples in docstrings
- Document error responses and status codes

### Code Documentation

- Write clear, concise docstrings
- Document complex algorithms and business logic
- Keep documentation up-to-date with code changes

### User Documentation

- Update relevant documentation when adding features
- Provide examples and use cases
- Keep README.md and other docs current

## Pull Request Process

### Before Submitting

1. Ensure all tests pass
2. Update documentation as needed
3. Add entries to CHANGELOG.md
4. Verify pre-commit hooks pass
5. Test your changes locally

### Pull Request Requirements

1. **Title**: Use clear, descriptive title
2. **Description**: Include:
   - What changes were made and why
   - How to test the changes
   - Any breaking changes
   - Screenshots (if applicable)
3. **Checklist**: Complete the PR template checklist
4. **Reviews**: Wait for at least one approval from maintainers
5. **CI**: Ensure all CI checks pass

### Pull Request Template

```markdown
## Description

Brief description of changes...

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing

- [ ] Tests pass locally
- [ ] Added tests for new functionality
- [ ] Updated documentation

## Checklist

- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Added comments for complex code
- [ ] Updated CHANGELOG.md
```

## Issue Reporting

### Before Creating an Issue

1. Search existing issues to avoid duplicates
2. Check the documentation
3. Ensure you're using the latest version

### Issue Template

```markdown
**Bug Description**
Clear description of the bug...

**To Reproduce**
Steps to reproduce:
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected Behavior**
What you expected to happen...

**Environment**
- OS: [e.g., Ubuntu 22.04]
- Python: [e.g., 3.13.0]
- Version: [e.g., 0.1.0]

**Additional Context**
Any other context about the problem...
```

### Feature Requests

- Clearly describe the feature and its use case
- Explain why it would be valuable
- Consider implementation complexity
- Provide examples if applicable

## Security Issues

**DO NOT** create public issues for security vulnerabilities.

Please report security issues privately:

1. Email: security@skauswatch.io
2. Use GitHub's security advisory feature
3. See [SECURITY.md](SECURITY.md) for full details

## Release Process

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Incompatible API changes
- **MINOR**: Backwards-compatible functionality additions
- **PATCH**: Backwards-compatible bug fixes

### Release Checklist

- [ ] Update version in `pyproject.toml`
- [ ] Update CHANGELOG.md
- [ ] Create and test release candidate
- [ ] Update documentation
- [ ] Create GitHub release
- [ ] Publish to package registries

## Getting Help

- **Documentation**: Check the [docs/](docs/) directory
- **Discussions**: Use GitHub Discussions for questions
- **Chat**: Join our development chat (link TBD)
- **Issues**: Create an issue for bugs or feature requests

## Recognition

Contributors are recognized in:

- CHANGELOG.md for significant contributions
- GitHub contributors list
- Release notes for major contributions

Thank you for contributing to SkausWatch! Your efforts help make this project better for everyone.