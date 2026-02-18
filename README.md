[![CI](https://github.com/PenguinCloud/skauswatch/actions/workflows/ci.yml/badge.svg)](https://github.com/PenguinCloud/skauswatch/actions/workflows/ci.yml)
[![Docker Build](https://github.com/PenguinCloud/skauswatch/actions/workflows/docker-build.yml/badge.svg)](https://github.com/PenguinCloud/skauswatch/actions/workflows/docker-build.yml)
[![codecov](https://codecov.io/gh/PenguinCloud/skauswatch/branch/main/graph/badge.svg)](https://codecov.io/gh/PenguinCloud/skauswatch)
[![version](https://img.shields.io/badge/version-v1.0.0-blue.svg)](https://semver.org)
[![License](https://img.shields.io/badge/License-Limited%20AGPL3-blue.svg)](LICENSE.md)

```
  _____ _                    _       _       _       _       _
 / ____| |                  | |     | |     | |     | |     | |
| (___ | | ____ _ _   _ ___| |  __ _| |_ ___| |__   (_)_ __ | |__
 \___ \| |/ / _` | | | / __| | / _` | __/ __| '_ \   | | '_ \| '_ \
 ____) |   < (_| | |_| \__ \ |(_| | ||(__| | | | |  | | | | | | | |
|_____/|_|\_\__,_|\__,_|___/_|\__,_|\__\___|_| |_|  |_|_| |_|_| |_|

```

# SkausWatch

**S3 malware and threat intelligence scanning platform** by Penguin Tech Inc.

## What It Does

- **Scans S3 buckets** for malware using ClamAV and YARA rules
- **Enriches findings** with VirusTotal and AlienVault OTX threat intelligence
- **Manages PKI certificates** and SSH CA for infrastructure security
- **Provides audit logging** and compliance reporting

## Architecture

Four-service Python architecture:
- **Manager Service** (Quart + gRPC) - Orchestration and API gateway
- **PKI Server** - Certificate authority and management
- **SSH CA** - SSH certificate signing and key management
- **AAA Monitor** - Authentication, authorization, and audit logging

Supported backends: PostgreSQL, Redis, MinIO, ClamAV, Worker-S3, Prometheus, Grafana

## Quick Start

```bash
git clone https://github.com/PenguinCloud/skauswatch.git
cd skauswatch
make setup                    # Install dependencies
make dev                      # Start development environment
make smoke-test              # Verify installation
```

## Documentation

- **Getting Started**: [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)
- **Testing Guide**: [docs/TESTING.md](docs/TESTING.md)
- **Pre-Commit Checklist**: [docs/PRE_COMMIT.md](docs/PRE_COMMIT.md)
- **Architecture & Standards**: [docs/APP_STANDARDS.md](docs/APP_STANDARDS.md)
- **Development Standards**: [docs/STANDARDS.md](docs/STANDARDS.md)

## Maintainers

- **Primary**: info@penguintech.group
- **Company**: [www.penguintech.io](https://www.penguintech.io)

## License

Limited AGPL3 with preamble for fair use - see [LICENSE.md](LICENSE.md)
