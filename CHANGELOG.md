# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project structure setup
- Core service directories and shared components
- Development environment configuration
- Docker Compose setup for local development
- Pre-commit hooks configuration
- Testing and code quality tools setup

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [0.1.0] - 2024-12-09

### Added
- Initial project setup
- Project structure with microservices architecture
- Base configuration files:
  - `pyproject.toml` with Python 3.13 support
  - `.gitignore` with comprehensive exclusions
  - `.pre-commit-config.yaml` with code quality checks
  - `docker-compose.yml` for development environment
  - `requirements-dev.txt` for development dependencies
- Service directories:
  - Manager Service (`services/manager/`)
  - PKI Server Service (`services/pki-server/`)
  - SSH CA Service (`services/ssh-ca/`)
  - AAA Monitor Service (`services/aaa-monitor/`)
- Shared components:
  - Models (`shared/models/`)
  - Utils (`shared/utils/`)
  - Security (`shared/security/`)
- Deployment configuration directory (`deployment/`)
- Documentation structure (`docs/`, `website/`)
- Project documentation:
  - Comprehensive README.md
  - CONTRIBUTING.md with development guidelines
  - SECURITY.md with security policy
  - This CHANGELOG.md

### Technical Details
- Python 3.13+ requirement
- FastAPI-based microservices architecture
- PostgreSQL 16 database
- Redis for caching and message queues
- Prometheus and Grafana for monitoring
- Celery for background task processing
- Pre-commit hooks for code quality
- Comprehensive testing setup with pytest
- Docker containerization support
- Development environment automation

---

## Template for Future Releases

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- New features

### Changed
- Changes in existing functionality

### Deprecated
- Soon-to-be removed features

### Removed
- Removed features

### Fixed
- Bug fixes

### Security
- Security improvements and fixes
```

---

## Release Guidelines

### Version Numbering
- **MAJOR** version when you make incompatible API changes
- **MINOR** version when you add functionality in a backwards compatible manner
- **PATCH** version when you make backwards compatible bug fixes

### Categories
- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** in case of vulnerabilities or security improvements

### Release Process
1. Update version in `pyproject.toml`
2. Update this CHANGELOG.md
3. Create a git tag with the version number
4. Build and publish releases
5. Update documentation if needed