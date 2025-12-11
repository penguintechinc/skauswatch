# SkausWatch GitHub Workflows Documentation

This document describes all GitHub Actions workflows configured for the SkausWatch project.

## Overview

SkausWatch uses GitHub Actions for continuous integration, security scanning, and automated releases. All workflows follow the `.WORKFLOW compliance` standards, including version monitoring through the `.version` file and consistent security scanning.

## Workflows

### 1. Build and Security Scan (`build.yml`)

**Trigger**: Push or pull request to `main` or `develop` branches on changes to:
- `services/**`
- `shared/**`
- `deployment/**`
- `.version`
- `.github/workflows/build.yml`

**Jobs**:

#### Security Scan (Bandit)
- **Tool**: Python Bandit (security scanner)
- **Purpose**: Identifies common security issues in Python code
- **Severity Level**: `-ll` (medium and above)
- **Output**: JSON report uploaded as artifact
- **Failure Policy**: Does not block build (informational)

#### Lint Python Code
- **Tools**:
  - `black`: Code formatter
  - `isort`: Import sorter
  - `flake8`: Style and error checker
  - `mypy`: Type checker
- **Scopes**: `services/` and `shared/` directories
- **Failure Policy**: Blocks build on flake8 errors (E9, F63, F7, F82)

#### Build Services
- **Requires**: Successful security scan and lint
- **Docker Building**: Builds multi-architecture images (amd64, arm64)
- **Metadata Injection**: Version and epoch64 timestamp
- **Cache**: Uses GitHub Actions cache for faster builds
- **Push**: Only to registry (no push on pull requests)

#### Run Tests
- **Requires**: Successful lint
- **Framework**: pytest with async support
- **Coverage**: Generates coverage reports (XML format)
- **Upload**: Coverage uploaded to Codecov

### 2. Create Release on Version Change (`version-release.yml`)

**Trigger**: Push to `main` branch when `.version` file changes

**Jobs**:

#### Create Pre-Release
1. **Version Detection**:
   - Reads `.version` file
   - Validates semantic versioning (Major.Minor.Patch)
   - Strips build metadata if present

2. **Release Validation**:
   - Skips if version is 0.0.0 (default)
   - Skips if release already exists
   - Uses GitHub CLI for validation

3. **Release Creation**:
   - Generates release notes from template
   - Creates pre-release tag
   - Includes commit SHA and branch information

**Configuration**: Requires GitHub write permissions

## Version Management

### .version File Format
```
X.Y.Z.EPOCH64
```

Where:
- **X**: Major version (breaking changes)
- **Y**: Minor version (new features)
- **Z**: Patch version (bug fixes)
- **EPOCH64**: Unix timestamp in milliseconds (build metadata)

### Updating Versions
The project includes version management scripts:
```bash
./scripts/version/update-version.sh          # Update build timestamp
./scripts/version/update-version.sh patch    # Increment patch
./scripts/version/update-version.sh minor    # Increment minor
./scripts/version/update-version.sh major    # Increment major
```

## Security Scanning

### Bandit Integration
- **Language**: Python
- **Configuration**: Medium severity level (`-ll`)
- **Report Format**: JSON (uploaded as workflow artifact)
- **Scan Targets**:
  - `services/` directory
  - `shared/` directory

### Coverage Requirements
- Minimum coverage: 70% (configurable)
- Coverage reports uploaded to Codecov
- Reports available in pull requests

## Build Artifacts

### Generated Artifacts
- **bandit-report.json**: Security scan results
- **coverage.xml**: Code coverage data

### Docker Images
- **Tag Format**: `skauswatch:VERSION` and `skauswatch:latest`
- **Platforms**: Linux AMD64 and ARM64
- **Registry**: GHCR (GitHub Container Registry)

## Workflow Compliance Checklist

- [x] `.version` file monitoring on all workflows
- [x] Epoch64 timestamp support
- [x] Version detection and validation
- [x] Conditional metadata tags (alpha, beta, release)
- [x] Security scanning (Bandit for Python)
- [x] Workflow file self-triggers (changes to workflow files)
- [x] Comprehensive error handling
- [x] Artifact preservation and reporting

## Troubleshooting

### Build Failures

**Bandit Security Issues**:
- Review the bandit report in workflow artifacts
- Check `/api/bandit-report.json` for specific issues
- Fix issues in code or add exceptions with caution

**Lint Failures**:
- Run `black` locally: `black services/ shared/`
- Run `isort` locally: `isort services/ shared/`
- Check `flake8` output: `flake8 services/ shared/`

**Test Failures**:
- Run tests locally: `pytest tests/ -v`
- Check coverage reports
- Ensure all dependencies installed: `pip install -r requirements.txt`

### Release Issues

**Version Detection Failed**:
- Verify `.version` file exists and is readable
- Check file format: should contain semantic version
- Ensure no extra whitespace in file

**Release Already Exists**:
- Check GitHub releases page
- Delete existing release if needed (with caution)
- Or increment version in `.version` file

## Best Practices

1. **Keep Workflows Updated**: Regularly review and update action versions
2. **Monitor Security**: Address Bandit findings promptly
3. **Test Locally First**: Run linting and tests before pushing
4. **Version Discipline**: Update `.version` file for releases only
5. **Review Artifacts**: Check security and coverage reports for each build

## Performance Optimization

- **Caching**: Workflows use GitHub Actions cache for dependencies
- **Parallel Jobs**: Independent jobs run simultaneously
- **Conditional Execution**: Security jobs skip on non-code changes
- **Container Reuse**: Multi-stage Docker builds reduce build time

## Related Documentation

- [Standards and Conventions](STANDARDS.md)
- [Project README](../README.md)
- [Security Guidelines](../SECURITY.md) (if exists)
