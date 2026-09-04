# SkausWatch - Application Standards

## Application Overview

SkausWatch is an S3 malware and threat-intelligence scanning platform. It scans S3 buckets for malware using ClamAV and YARA rules, enriching findings with threat intelligence from VirusTotal and AlienVault OTX. The platform also includes licensed sub-modules for secrets management (Vault) and AI-powered code review (CodeScan).

## Architecture

Eight-service Python/Go ecosystem with two licensed sub-modules:

### Core Services

| Service | Port | Language | Purpose |
|---------|------|----------|---------|
| **Manager** (`services/manager-new/`) | 5000 | Python 3.13 + Quart + gRPC | Configuration, orchestration, S3 credential management |
| **PKI Server** (`services/pki/`) | 5001 | Python 3.13 + Quart | **Shim proxy** -> Vault PKI (v1.x compat); removed at v2.0 |
| **SSH CA** (`services/sshca/`) | 5002 | Python 3.13 + Quart | **Shim proxy** -> Vault SSH CA (v1.x compat); removed at v2.0 |
| **Monitor** (`services/monitor/`) | 5003 | Python 3.13 + FastAPI | Audit logging, K8s/LXC/auditd log collection, AI threat analysis |
| **S3scan** (`services/s3scan/`) | — | Python 3.13 | Distributed scan workers (ClamAV + YARA + TI enrichment) |
| **Scanner** (`services/scanner/`) | — | Python 3.13 | Multi-engine vulnerability scanner (Nuclei, ZAP, OpenVAS) |
| **ENDPOINT Agent** (`services/endpoint-agent/`) | — | Go 1.24 | Endpoint detection & response agent (K8s DaemonSet) |
| **WebUI** (`services/webui/`) | 3000 | Node.js + React | Frontend dashboard (Vite build, Express server) |

> **Note on PKI Server and SSH CA**: As of v1.x, both services are thin Quart shim proxies. They forward all requests to the Vault sub-module's PKI and SSH CA backends, attaching `Deprecation:` and `Link:` headers per RFC 8594. Direct clients should migrate to Vault endpoints before v2.0.

### Supporting Infrastructure

- **PostgreSQL 16**: Primary data store
- **Redis 7**: Cache and Streams for job queuing (prefix: `skauswatch`)
- **MinIO**: S3-compatible storage for ad-hoc uploads
- **ClamAV**: Antivirus scanning engine (freshclam for definition updates)
- **Prometheus + Grafana**: Monitoring and metrics

---

## Sub-Modules

### Vault (Licensed Add-On — Secrets Vault)

Vault is a licensed secrets management sub-module with envelope encryption, JIT access, one-time secrets, and cloud vault sync.

- **Location**: `.worktrees/vault/vault/` (branch `vault-module`)
- **Namespace**: `vault` (separate from core SkausWatch namespace)
- **License requirement**: Requires `vault` feature in PenguinTech license key
- **Production URL**: https://vault.skauswatch.app (when deployed)

**Vault Services (5)**:

| Service | Port | Purpose |
|---------|------|---------|
| `flask-backend` | 5100 | Quart REST API — secrets CRUD, JIT access, one-time secrets, cloud sync |
| `pki` | 5101 | PKI/X.509 backend (SkausWatch PKI shim proxies here) |
| `sshca` | 5102 | SSH CA backend (SkausWatch SSH CA shim proxies here) |
| `sync-worker` | — | Redis Streams consumer for cloud vault sync (AWS/Azure/GCP/OCI/K8s) |
| `webui` | 3100 | React/TS vault UI |

**Key encryption concepts**:
- **DEK** (Data Encryption Key): Per-secret AES-256-GCM key
- **MEK** (Master Encryption Key): Env-var key that wraps all DEKs (versioned for rotation)
- **JIT tokens**: HMAC tokens format `jit:{grant_id}:{grantee_id}:{expires_epoch}` for time-limited access
- **One-time secrets**: SHA-256(URL token) stored; value decrypted and returned only once

### CodeScan (AI Code Review)

CodeScan is an AI-powered code review and issue planning sub-module.

- **Location**: `codescan/` (project root)
- **Worker process**: `services/worker-codescan/`
- **Multi-AI support**: Claude, OpenAI, Ollama
- **Integrations**: GitHub and GitLab webhooks
- **Purpose**: Automated code review on PRs, issue triage, security finding analysis

---

## Tech Stack Decisions

- **Python 3.13** for all Python services
- **Go 1.24** for ENDPOINT Agent (DaemonSet, endpoint monitoring requirements)
- **Node.js 18 + React** for WebUI
- **Quart** (async Flask) for Manager and shim proxies
- **FastAPI** for Monitor (async log ingestion)
- **PyDAL** for database abstraction (runtime queries only)
- **SQLAlchemy + Alembic** for schema definition and migrations
- **Flask-Security-Too** for RBAC authentication
- **Redis Streams** for job distribution (not Celery/RQ)
- **gRPC** for Manager <-> Worker communication

---

## Data Flow

### Core Scan Flow
1. User configures S3 bucket credentials via Manager API
2. Manager encrypts credentials using `S3_CRED_ENCRYPTION_KEY` and stores in PostgreSQL
3. Scan jobs published to Redis Stream (`skauswatch:scan-jobs`)
4. S3scan consumers pick up jobs, download objects from S3
5. Objects scanned: ClamAV (antivirus) -> YARA (pattern matching) -> TI enrichment (VirusTotal/OTX)
6. Results written to PostgreSQL, status update via gRPC to Manager
7. Monitor records audit trail of all scan activities

### Certificate & SSH Flow (with Vault)
- PKI Server shim receives cert request -> proxies to Vault `flask-backend` port 5101
- SSH CA shim receives SSH cert request -> proxies to Vault `flask-backend` port 5102
- Vault manages the full X.509/SSH lifecycle with audit logging

### Vulnerability Scanning Flow
- Scanner runs Nuclei, ZAP, and OpenVAS against configured targets
- Results aggregated and written to PostgreSQL
- Monitor performs AI threat analysis on findings

### AI Code Review Flow (CodeScan)
- GitHub/GitLab webhook triggers CodeScan on PR open/update
- Worker-CodeScan processes PR diff through configured AI provider (Claude/OpenAI/Ollama)
- Review comments posted back to PR

---

## Security Requirements

- S3 credentials encrypted at rest using `S3_CRED_ENCRYPTION_KEY`
- Vault secrets: AES-256-GCM envelope encryption (DEK per secret, MEK from env)
- All inter-service mTLS via Vault PKI (when Vault installed) or direct PKI Server
- SSH access via signed certificates (Vault SSH CA or direct SSH CA)
- Scan workspace (`/tmp/s3-scan-workspace`) cleaned after each job
- No scan artifacts persisted beyond result records
- Worker memory limited to 2GB, CPU limited to 2 cores
- ENDPOINT Agent: read-only DaemonSet with minimal K8s RBAC

---

## Environment Variables (Key)

### Core Services
- `S3_CRED_ENCRYPTION_KEY`: AES key for S3 credential encryption
- `VIRUSTOTAL_API_KEY`: VirusTotal API key for threat intelligence enrichment
- `OTX_API_KEY`: AlienVault OTX API key
- `REDIS_KEY_PREFIX`: Set to `skauswatch` for job queue namespace
- `GRPC_ENABLED` / `GRPC_PORT`: gRPC configuration for Manager service
- `YARA_ENABLED` / `YARA_RULES_PATH`: YARA scanning toggle and rules location

### Vault Integration (when Vault installed)
- `VAULT_PKI_URL`: Vault PKI endpoint (PKI Server shim proxies here)
- `VAULT_SSHCA_URL`: Vault SSH CA endpoint (SSH CA shim proxies here)
- `VAULT_MEK`: Master Encryption Key for Vault envelope encryption
- `VAULT_DB_*`: Separate database credentials for Vault namespace

### CodeScan
- `CODESCAN_AI_PROVIDER`: `claude` | `openai` | `ollama`
- `CODESCAN_GITHUB_WEBHOOK_SECRET`: GitHub webhook HMAC secret
- `CODESCAN_GITLAB_WEBHOOK_SECRET`: GitLab webhook HMAC secret

---

## Deployment

- **Beta**: https://skauswatch.penguintech.cloud
- **Alpha/Local**: https://skauswatch.localhost.local
- **Production**: https://skauswatch.app (TBD)
- **Vault namespace**: `vault` (separate from `skauswatch` namespace)
