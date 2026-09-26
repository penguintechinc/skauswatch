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
- **Vulnerability scanning** via Nuclei, ZAP, and OpenVAS (Scanner)
- **Endpoint monitoring** via Go-based ENDPOINT agent deployed as a K8s DaemonSet
- **Secrets management** via Vault sub-module (licensed add-on)
- **AI code review** via CodeScan sub-module (GitHub/GitLab webhooks)
- **PKI and SSH CA** managed by Vault (shims maintain v1.x API compatibility)
- **Audit logging** and compliance reporting via Monitor

## Architecture

Eight-service Python/Go/Node.js ecosystem:
- **Manager Service** (Quart + gRPC) - Orchestration and API gateway
- **PKI Server** - Shim proxy to Vault PKI (v1.x compatibility layer)
- **SSH CA** - Shim proxy to Vault SSH CA (v1.x compatibility layer)
- **Monitor** - Audit logging, log collection, and AI threat analysis
- **S3scan** - Distributed ClamAV + YARA + threat intelligence scan workers
- **Scanner** - Multi-engine vulnerability scanner (Nuclei, ZAP, OpenVAS)
- **ENDPOINT Agent** - Go-based endpoint detection & response (K8s DaemonSet)
- **WebUI** - React/TypeScript frontend dashboard

Supported backends: PostgreSQL, Redis, MinIO, ClamAV, Prometheus, Grafana

## Sub-Modules

### Vault (Licensed — Secrets Vault)

Vault is a licensed add-on secrets management platform providing:
- AES-256-GCM envelope encryption (DEK per secret, MEK rotation)
- Just-in-time (JIT) access with HMAC tokens
- One-time secrets (view-once with atomic reveal)
- Cloud vault sync (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, OCI, K8s)

**When Vault is installed**, PKI Server and SSH CA forward all certificate operations to
Vault's PKI and SSH CA backends. Without Vault, these services run standalone.

- Location: `.worktrees/vault/vault/` (branch: `vault-module`)
- Namespace: `vault` (separate from core `skauswatch` namespace)
- Quick start: `cd .worktrees/vault/vault && docker compose up -d`

### CodeScan (AI Code Review)

CodeScan provides AI-powered code review on pull requests using Claude, OpenAI, or Ollama.

- Location: `codescan/` (project root)
- Worker: `services/worker-codescan/`
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
