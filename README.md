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
- **Vulnerability scanning** via Nuclei, ZAP, and OpenVAS (Worker-Scanner)
- **Endpoint monitoring** via Go-based EDR agent deployed as a K8s DaemonSet
- **Secrets management** via IceBox sub-module (licensed add-on)
- **AI code review** via Darwin sub-module (GitHub/GitLab webhooks)
- **PKI and SSH CA** managed by IceBox (shims maintain v1.x API compatibility)
- **Audit logging** and compliance reporting via AAA Monitor

## Architecture

Eight-service Python/Go/Node.js ecosystem:
- **Manager Service** (Quart + gRPC) - Orchestration and API gateway
- **PKI Server** - Shim proxy to IceBox PKI (v1.x compatibility layer)
- **SSH CA** - Shim proxy to IceBox SSH CA (v1.x compatibility layer)
- **AAA Monitor** - Audit logging, log collection, and AI threat analysis
- **Worker-S3** - Distributed ClamAV + YARA + threat intelligence scan workers
- **Worker-Scanner** - Multi-engine vulnerability scanner (Nuclei, ZAP, OpenVAS)
- **EDR Agent** - Go-based endpoint detection & response (K8s DaemonSet)
- **WebUI** - React/TypeScript frontend dashboard

Supported backends: PostgreSQL, Redis, MinIO, ClamAV, Prometheus, Grafana

## Sub-Modules

### IceBox (Licensed — Secrets Vault)

IceBox is a licensed add-on secrets management platform providing:
- AES-256-GCM envelope encryption (DEK per secret, MEK rotation)
- Just-in-time (JIT) access with HMAC tokens
- One-time secrets (view-once with atomic reveal)
- Cloud vault sync (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, OCI, K8s)

**When IceBox is installed**, PKI Server and SSH CA forward all certificate operations to
IceBox's PKI and SSH CA backends. Without IceBox, these services run standalone.

- Location: `.worktrees/icebox/icebox/` (branch: `icebox-module`)
- Namespace: `icebox` (separate from core `skauswatch` namespace)
- Quick start: `cd .worktrees/icebox/icebox && docker compose up -d`

### Darwin (AI Code Review)

Darwin provides AI-powered code review on pull requests using Claude, OpenAI, or Ollama.

- Location: `darwin/` (project root)
- Worker: `services/worker-darwin/`
- Integrations: GitHub and GitLab webhooks

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
