# SkausWatch Core Platform Overview

**Audience:** Developers | DevOps | Admins

SkausWatch is an S3 malware and threat-intelligence scanning platform. It scans S3 buckets for malware using ClamAV and YARA rules, enriching findings with threat intelligence from VirusTotal and AlienVault OTX. The platform includes 8 core services with optional licensed sub-modules (IceBox for secrets management, Darwin for AI code review).

## Quick Reference: Core Services

| Service | Port | Language | Framework | Purpose |
|---------|------|----------|-----------|---------|
| **Manager** | 5000 | Python 3.13 | Quart + gRPC | Orchestration, S3 credential mgmt, scan scheduling |
| **PKI Server** | 5001 | Python 3.13 | Quart | Shim proxy → IceBox PKI (v1.x compat) |
| **SSH CA** | 5002 | Python 3.13 | Quart | Shim proxy → IceBox SSH CA (v1.x compat) |
| **AAA Monitor** | 5003 | Python 3.13 | FastAPI | Audit logging, K8s log collection, threat analysis |
| **Worker-S3** | — | Python 3.13 | Celery | ClamAV + YARA + threat intelligence scanning |
| **Worker-Scanner** | — | Python 3.13 | Celery | Nuclei, ZAP, OpenVAS vulnerability scanning |
| **EDR Agent** | — | Go 1.24 | — | Endpoint detection & response (K8s DaemonSet) |
| **WebUI** | 3000 | Node.js 18 + React | Vite + Express | Frontend dashboard with role-based access |

## Documentation Index

| Document | Purpose | Audience |
|----------|---------|----------|
| **[OVERVIEW.md](./OVERVIEW.md)** (this file) | Platform summary, architecture at a glance | Everyone |
| **[USAGE.md](./USAGE.md)** | How to use SkausWatch: workflows, common tasks | Developers |
| **[API.md](./API.md)** | REST/gRPC API reference for all services | Developers |
| **[ARCHITECTURE.md](./ARCHITECTURE.md)** | System design, data flows, service interactions | Architects, Developers |
| **[CONFIGURATION.md](./CONFIGURATION.md)** | Environment variables, per-service config | DevOps, Developers |
| **[TESTING.md](./TESTING.md)** | Running tests, smoke tests, debugging | QA, Developers |
| **[TROUBLESHOOTING.md](./TROUBLESHOOTING.md)** | Common issues and fixes | DevOps, Developers |
| **[RELEASE_NOTES.md](./RELEASE_NOTES.md)** | Version history, deprecations, known issues | Everyone |

## System Architecture

```mermaid
graph TB
    subgraph clients["Clients"]
        webui["🖥️ WebUI<br/>React + Vite<br/>Port 3000"]
        ext_api["📱 External API<br/>REST Clients<br/>gRPC Clients"]
    end

    subgraph core_services["Core Services"]
        manager["📋 Manager<br/>Port 5000<br/>Quart + gRPC"]
        pki["🔐 PKI Server<br/>Port 5001<br/>Shim Proxy"]
        ssh_ca["🔑 SSH CA<br/>Port 5002<br/>Shim Proxy"]
        aaa["📊 AAA Monitor<br/>Port 5003<br/>FastAPI"]
    end

    subgraph workers["Background Workers"]
        worker_s3["🔍 Worker-S3<br/>ClamAV + YARA<br/>+ TI Enrichment"]
        worker_scan["🛡️ Worker-Scanner<br/>Nuclei, ZAP<br/>OpenVAS"]
        edr["🚨 EDR Agent<br/>Go 1.24<br/>DaemonSet"]
    end

    subgraph infrastructure["Infrastructure"]
        postgres[("🗄️ PostgreSQL 16<br/>Shared Database")]
        redis["⚡ Redis 7<br/>Job Queues")]
        minio["📦 MinIO<br/>S3 Storage"]
        clamav["🦠 ClamAV<br/>Antivirus Defs"]
    end

    subgraph optional["Optional Sub-Modules"]
        icebox["🔒 IceBox<br/>Secrets Vault<br/>Port 5100"]
        darwin["🤖 Darwin<br/>AI Code Review"]
    end

    webui -->|REST/Socket| manager
    ext_api -->|REST/gRPC| manager
    manager -->|gRPC| worker_s3
    manager -->|gRPC| worker_scan
    manager -->|REST| pki
    manager -->|REST| ssh_ca
    manager -->|REST| aaa

    worker_s3 --> clamav
    worker_s3 --> minio
    worker_scan -->|Scans| ext_api

    pki -.->|Proxy| icebox
    ssh_ca -.->|Proxy| icebox
    darwin -->|PR Analysis| ext_api

    manager --> postgres
    pki --> postgres
    ssh_ca --> postgres
    aaa --> postgres
    worker_s3 --> postgres
    worker_scan --> postgres

    manager --> redis
    worker_s3 --> redis
    worker_scan --> redis
    aaa --> redis
    icebox --> postgres

    edr -->|K8s API| kubernetes["Kubernetes<br/>Cluster"]
    edr --> postgres

    classDef service fill:#4f46e5
    classDef infrastructure fill:#7c3aed
    classDef optional fill:#ec4899
    classDef client fill:#06b6d4

    class manager,pki,ssh_ca,aaa,worker_s3,worker_scan service
    class postgres,redis,minio,clamav infrastructure
    class icebox,darwin optional
    class webui,ext_api client
```

## Getting Started

### Prerequisites
- Docker & Docker Compose
- Python 3.13
- Go 1.24 (for EDR Agent build)
- Node.js 18+ (for WebUI)
- PostgreSQL 16 (local dev or Docker)
- Redis 7 (local dev or Docker)

### Start Local Development (5 minutes)
```bash
# Clone and setup
git clone https://github.com/penguintechinc/skauswatch.git
cd skauswatch
make setup

# Start all services
make dev

# Seed mock data
make seed-mock-data

# Access WebUI
open http://localhost:3000
```

Access services:
- **Manager**: http://localhost:5000
- **PKI Server**: http://localhost:5001
- **SSH CA**: http://localhost:5002
- **AAA Monitor**: http://localhost:5003
- **WebUI**: http://localhost:3000

## Core Concepts

### 🔐 Shim Proxies (v1.x Compatibility)

PKI Server and SSH CA services in v1.x are thin Quart shim proxies that forward all requests to the optional IceBox sub-module when installed. They return 501/503 responses with `Deprecation:` headers when IceBox is unavailable, directing clients to migrate.

**Why shims exist:** SkausWatch v1.x maintains backward compatibility with direct PKI/SSH CA clients while migrating them toward the centralized IceBox module.

**Removal timeline:** Shims are removed completely in v2.0. v1.x clients should migrate to IceBox endpoints before v2.0 release.

### 📦 Sub-Module Architecture

**IceBox** (Secrets Vault, licensed):
- Envelope-encrypted secret storage (AES-256-GCM)
- JIT access controls with HMAC tokens
- One-time secrets with view-once enforcement
- Cloud vault sync (AWS/Azure/GCP/OCI/K8s)
- Full PKI and SSH CA backend

**Darwin** (AI Code Review, licensed):
- AI-powered PR code review (Claude, OpenAI, Ollama)
- Automated issue triage and ASM analysis
- GitHub and GitLab webhook integration

Both are optional and license-gated.

### 🎯 Role-Based Access Control (RBAC)

Three tiers:
- **Admin**: Full system access, user management
- **Maintainer**: Read/write access, no user management
- **Viewer**: Read-only access

Enforced via OIDC scopes on JWT tokens.

### 🔄 Job Processing

Jobs published to **Redis Streams** (prefix: `skauswatch`):
- Manager publishes scan jobs
- Worker-S3 and Worker-Scanner consume jobs
- Results written to PostgreSQL
- Status updates via gRPC to Manager

## Environment Overview

| Environment | Domain | Cluster | Registry | Method |
|-------------|--------|---------|----------|--------|
| **Alpha** | `skauswatch.localhost.local` | MicroK8s | `localhost:32000` | Kustomize |
| **Beta** | `skauswatch.penguintech.cloud` | dal2 | `registry-dal2.penguintech.cloud` | Helm |
| **Prod** | `skauswatch.app` | Custom | Private ECR/GCR | Helm |

## Security Highlights

- ✅ S3 credentials encrypted at rest (`S3_CRED_ENCRYPTION_KEY`)
- ✅ Inter-service mTLS via IceBox PKI (when IceBox installed)
- ✅ SSH access via signed certificates (IceBox SSH CA or direct)
- ✅ Scan workspace cleaned after each job
- ✅ Worker resources limited (2GB memory, 2 CPU cores)
- ✅ EDR Agent runs as read-only DaemonSet with minimal RBAC
- ✅ All API endpoints require JWT Bearer tokens + OIDC scopes

## Next Steps

1. **Developers**: Read [USAGE.md](./USAGE.md) to start local development
2. **DevOps**: Read [CONFIGURATION.md](./CONFIGURATION.md) for deployment setup
3. **Architects**: Read [ARCHITECTURE.md](./ARCHITECTURE.md) for design deep-dive
4. **QA/Testers**: Read [TESTING.md](./TESTING.md) for testing workflows

---

**Last Updated:** 2026-03-10
**Maintained by:** Penguin Tech Inc
**License:** Limited AGPL-3.0
