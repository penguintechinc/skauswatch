# SkausWatch Architecture (Local Overrides)

> Project-specific architecture context for SkausWatch. General standards remain in template files.

## About This App

SkausWatch is an S3 malware and threat-intelligence scanning platform. Core functionality:
- Scans objects in S3 buckets using ClamAV antivirus engine and YARA pattern-matching rules
- Enriches scan results with threat intelligence from VirusTotal and AlienVault OTX APIs
- Multi-engine vulnerability scanning via Nuclei, ZAP, and OpenVAS (Worker-Scanner)
- Endpoint detection and response via Go-based EDR agent (K8s DaemonSet)
- PKI/X.509 certificate management and SSH CA via IceBox sub-module (shims in v1.x)
- AI-powered code review via Darwin sub-module
- Comprehensive audit logging and threat analysis via AAA Monitor

## Architecture

**Eight-service ecosystem** with Python, Go, and Node.js services:

### Core Services

| Service | Path | Lang | Port | Role |
|---------|------|------|------|------|
| Manager | `services/manager-new/` | Python 3.13 + Quart | 5000 | Orchestration, S3 cred mgmt, API gateway |
| PKI Server | `services/pki-server-new/` | Python 3.13 + Quart | 5001 | **Shim proxy** -> IceBox PKI (v1.x compat) |
| SSH CA | `services/ssh-ca/` | Python 3.13 + Quart | 5002 | **Shim proxy** -> IceBox SSH CA (v1.x compat) |
| AAA Monitor | `services/aaa-monitor/` | Python 3.13 + FastAPI | 5003 | Audit logs, AI threat analysis |
| Worker-S3 | `services/worker-s3/` | Python 3.13 | — | ClamAV + YARA + TI enrichment |
| Worker-Scanner | `services/worker-scanner/` | Python 3.13 | — | Nuclei, ZAP, OpenVAS vulnerability scanner |
| EDR Agent | `services/edr-agent/` | Go 1.24 | — | Endpoint monitoring (K8s DaemonSet) |
| WebUI | `services/webui/` | Node.js + React | 3000 | Frontend dashboard |

**PKI Server shim**: `services/pki-server-new/main.py` forwards all requests to `$ICEBOX_PKI_URL`, adds `Deprecation:` + `Link:` headers. No business logic. Removed at v2.0.

**SSH CA shim**: `services/ssh-ca/async_ssh_processor.py` forwards all requests to `$ICEBOX_SSH_CA_URL`, same deprecation header pattern. Removed at v2.0.

**Job Queue**: Redis Streams (key prefix: `skauswatch`) for async scan job distribution

**Secrets Management**: S3 credentials encrypted at rest using `S3_CRED_ENCRYPTION_KEY` env var

**Shared Resources**: ClamAV virus definitions mounted as Docker volume (`clamav_db`)

## Sub-Module: IceBox

- **Location**: `.worktrees/icebox/icebox/` (worktree from branch `icebox-module`)
- **Namespace**: `icebox` (separate K8s namespace from core `skauswatch`)
- **License gate**: `icebox` feature flag in PenguinTech license

### IceBox Services

| Service | Port | Purpose |
|---------|------|---------|
| `flask-backend` | 5100 | Quart REST API — secrets, JIT, one-time, cloud sync |
| `pki-server` | 5101 | X.509 CA backend (PKI shim proxies here) |
| `ssh-ca` | 5102 | SSH CA backend (SSH CA shim proxies here) |
| `sync-worker` | — | Redis Streams consumer for cloud vault sync |
| `webui` | 3100 | React/TS vault UI |

### IceBox Env Vars (required in core services when IceBox installed)
- `ICEBOX_PKI_URL` — PKI shim proxy destination
- `ICEBOX_SSH_CA_URL` — SSH CA shim proxy destination
- `ICEBOX_MEK` — Master Encryption Key for envelope encryption

### IceBox K8s
- Kustomize overlays: `icebox/k8s/kustomize/overlays/{alpha,beta,prod}/`
- Helm charts: `icebox/k8s/helm/{flask-backend,sync-worker,pki-server,ssh-ca,webui}/`
- Deploy separately: `kubectl apply --context local-alpha -k icebox/k8s/kustomize/overlays/alpha`

## Sub-Module: Darwin

- **Location**: `darwin/` (project root)
- **Worker**: `services/worker-darwin/`
- **Purpose**: AI-powered code review on GitHub/GitLab PRs, issue triage, security analysis
- **AI providers**: Claude, OpenAI, Ollama (configurable)

## Key Files & Locations

- `services/manager-new/` — Manager service (Quart API, gRPC server, job orchestration)
- `services/worker-s3/` — S3 scan workers (ClamAV, YARA, TI enrichment logic)
- `services/worker-scanner/` — Multi-engine vulnerability scanner
- `services/edr-agent/` — Go-based EDR DaemonSet agent
- `services/webui/` — React/TS frontend dashboard
- `services/pki-server-new/` — PKI shim proxy (v1.x, proxies to IceBox)
- `services/ssh-ca/` — SSH CA shim proxy (v1.x, proxies to IceBox)
- `services/aaa-monitor/` — Audit and threat analysis service
- `services/worker-darwin/` — Darwin AI worker
- `darwin/` — Darwin sub-module root
- `.worktrees/icebox/icebox/` — IceBox sub-module root
- `config/yara_rules/` — YARA detection rule files
- `k8s/` — Core Kubernetes manifests and Kustomize overlays

## Domain Terms

- **TI**: Threat Intelligence (data from VirusTotal, AlienVault OTX APIs)
- **YARA**: Pattern-matching rules engine for malware signatures
- **ClamAV**: Open-source antivirus engine with signature-based detection
- **PKI**: Public Key Infrastructure (X.509 digital certificates)
- **SSH CA**: SSH Certificate Authority for cryptographic certificate-based SSH access
- **AAA**: Authentication, Authorization, Accounting (security audit trail)
- **S3**: Object storage API (AWS S3 compatible; MinIO for local development)
- **gRPC**: Remote Procedure Call framework for inter-service communication
- **EDR**: Endpoint Detection & Response (monitors host-level events)
- **DEK**: Data Encryption Key — per-secret AES-256-GCM key (IceBox)
- **MEK**: Master Encryption Key — wraps all DEKs, env-var sourced, versioned for rotation (IceBox)
- **Envelope encryption**: Encrypt plaintext with DEK; encrypt DEK with MEK; store both ciphertext and wrapped DEK
- **JIT token**: Just-in-time access token; format `jit:{grant_id}:{grantee_id}:{expires_epoch}`; SHA-256 stored in DB
- **One-time secret**: Secret viewable exactly once; SHA-256(URL token) stored; `viewed_at` set atomically before decrypt

## Integration Patterns

- **Manager to Worker-S3**: Manager publishes scan jobs to Redis Streams; Worker-S3 consumes and processes
- **Manager to Worker-Scanner**: Manager triggers vulnerability scans; Worker-Scanner runs Nuclei/ZAP/OpenVAS
- **Worker-S3 to S3**: Downloads objects from customer S3 buckets (credentials decrypted on demand)
- **Worker-S3 to TI**: Queries VirusTotal and AlienVault OTX APIs for enrichment
- **Worker-S3 to ClamAV**: Shared Docker volume (`clamav_db`) for updated virus definitions
- **PKI shim -> IceBox**: `pki-server-new` proxies all cert ops to `$ICEBOX_PKI_URL` (5101)
- **SSH CA shim -> IceBox**: `ssh-ca` proxies all cert ops to `$ICEBOX_SSH_CA_URL` (5102)
- **Darwin workflow**: GitHub/GitLab webhook -> worker-darwin -> AI review -> PR comments
- **License Server**: All services validate features at https://license.penguintech.io
- **Audit Trail**: All actions logged to PostgreSQL via AAA Monitor
