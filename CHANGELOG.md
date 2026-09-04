# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - Unreleased

Full platform rewrite. Tracked on branch `release/v2.0.x`; `release/v1.0.x` is
feature-frozen (security fixes only) until v2.0.0 ships.

### Added
- Rust rewrite of all backend services (core, Vault, CodeScan) — single Cargo
  workspace; axum REST, tonic gRPC, sqlx (PostgreSQL), Redis/Valkey Streams
  worker harness replacing Celery
- `penguin-licensing` Rust crate (penguin-libs): PostHog-compatible feature
  flags + license entitlement via license.penguintech.io, fail-safe caching,
  axum feature/tier gating middleware
- Feature flags (`skauswatch.*`, default OFF) wrapping every feature area,
  including module gates `skauswatch.vault` and `skauswatch.codescan`
- Unified React frontend: Vault and CodeScan UIs merged into `services/webui`
  as entitlement-gated lazy-loaded modules (`/vault/*`, `/codescan/*`)

### Changed
- Migrations: Alembic replaced by `sqlx migrate`
- Containers: per-service multi-stage Dockerfiles (`rust:1.97-slim-bookworm`
  builder → `debian:bookworm-slim` runtime, non-root uid 10001, digest-pinned,
  native `<binary> healthcheck` subcommand — no curl)
- CI: single `build.yml` image matrix (12 services + webui, multi-arch,
  env-aware `beta`/`gamma`/`v{semver}` tags + rolling `:beta-latest`); the
  redundant `beta.yml`/`publish.yml` build workflows were consolidated into it
- Build tooling: `Makefile` is now cargo/npm-based (Python `make` targets gone)
- Supply chain: git-credential AEAD nonces use aes-gcm's `AeadCore` (dropping a
  direct `rand` dependency); `cargo deny` policy allows the workspace's own
  `AGPL-3.0-only` and documents three transitive advisory exceptions
- **Modules renamed to descriptive names** — `edr`→`endpoint`, `icebox`→`vault`,
  `darwin`→`codescan`, `worker-scanner`→`scanner`, `aaa-monitor`→`monitor`,
  `pki-server`→`pki`, `ssh-ca`→`sshca`, `log-receiver`→`logs`. Full mapping and
  path/flag/topic details in [`docs/MIGRATION.md`](docs/MIGRATION.md).
  (SkausWatch never shipped to production, so wire/schema/name changes are free —
  no data migration, no fielded-agent compatibility constraint.)

### Deprecated
- Old pre-rename REST paths (`/api/v1/{edr,icebox,darwin,aaa}/*`) — mounted as
  aliases with `Deprecation`/`Sunset` headers; removed in a later release. Old
  feature-flag keys read as fallbacks during transition. See `docs/MIGRATION.md`.

### Removed
- All Python services and the Go EDR (endpoint) agent implementation (ported to Rust)
- Legacy `services/manager/`, `services/pki/`, `services/flask-backend/`,
  vendored `darwin/shared/`, py4web remnants
- Standalone Vault and CodeScan webuis; Kustomize/raw K8s manifests (Helm only)

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
  - PKI Server Service (`services/pki/`)
  - SSH CA Service (`services/sshca/`)
  - Monitor Service (`services/monitor/`)
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