# SkausWatch Architecture (Local Overrides)

> Project-specific architecture context for SkausWatch. General standards remain in template files.

## About This App

SkausWatch is an S3 malware and threat-intelligence scanning platform. Core functionality:
- Scans objects in S3 buckets using ClamAV antivirus engine and YARA pattern-matching rules
- Enriches scan results with threat intelligence from VirusTotal and AlienVault OTX APIs
- Provides PKI/X.509 certificate management for internal service communication
- Operates an SSH Certificate Authority for infrastructure access
- Maintains comprehensive audit logging and threat analysis via AAA Monitor

## Architecture

**Four-service Python-only ecosystem** (no Go backend, no Node.js WebUI):
- All services: Python 3.13, PyDAL for database abstraction, Flask-Security-Too for auth
- Manager Service (services/manager-new/): Quart async API + gRPC server for orchestration
- Worker Service (services/worker-s3/): Consumes scan jobs from Redis Streams, executes ClamAV/YARA
- PKI Server (services/pki-server-new/): X.509 certificate lifecycle
- SSH CA (services/ssh-ca/): SSH certificate signing and management
- AAA Monitor (services/aaa-monitor/): Audit logging and threat analysis

**Job Queue**: Redis Streams (key prefix: `skauswatch`) for async scan job distribution

**Secrets Management**: S3 credentials encrypted at rest using `S3_CRED_ENCRYPTION_KEY` env var

**Shared Resources**: ClamAV virus definitions mounted as Docker volume (`clamav_db`)

## Key Files & Locations

- `services/manager-new/` — Manager service (Quart API, gRPC server, job orchestration)
- `services/worker-s3/` — S3 scan workers (ClamAV, YARA, TI enrichment logic)
- `services/pki-server-new/` — PKI/certificate server
- `services/ssh-ca/` — SSH Certificate Authority service
- `services/aaa-monitor/` — Audit and threat analysis service
- `config/yara_rules/` — YARA detection rule files
- `k8s/` — Kubernetes manifests and Kustomize overlays
- `tests/smoke/s3_scan/` — S3 scan smoke tests and configs

## Domain Terms

- **TI**: Threat Intelligence (data from VirusTotal, AlienVault OTX APIs)
- **YARA**: Pattern-matching rules engine for malware signatures
- **ClamAV**: Open-source antivirus engine with signature-based detection
- **PKI**: Public Key Infrastructure (X.509 digital certificates)
- **SSH CA**: SSH Certificate Authority for cryptographic certificate-based SSH access
- **AAA**: Authentication, Authorization, Accounting (security audit trail)
- **S3**: Object storage API (AWS S3 compatible; MinIO for local development)
- **gRPC**: Remote Procedure Call framework for inter-service communication

## Integration Patterns

- **Manager to Worker**: Manager publishes scan jobs to Redis Streams; Worker-S3 consumes and processes
- **Worker to S3**: Worker downloads objects from customer S3 buckets (credentials decrypted on demand)
- **Worker to TI**: Worker queries VirusTotal and AlienVault OTX APIs for enrichment
- **Worker to ClamAV**: Shared Docker volume (`clamav_db`) for updated virus definitions
- **Service-to-Service TLS**: PKI Server manages internal X.509 certs for secure communication
- **SSH CA Integration**: SSH CA signs certificates for operator/service SSH access
- **License Server**: All services validate features at https://license.penguintech.io
- **Audit Trail**: All actions logged to PostgreSQL via AAA Monitor
