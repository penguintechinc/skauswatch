# SkausWatch - Application Standards

## Application Overview

SkausWatch is an S3 malware and threat-intelligence scanning platform. It scans S3 buckets for malware using ClamAV and YARA rules, enriching findings with threat intelligence from VirusTotal and AlienVault OTX.

## Architecture

Four-service Python architecture:
- **Manager** (Quart + gRPC, port 5000): Configuration and management plane, scan orchestration, S3 credential management
- **PKI Server** (Flask, port 5001): X.509 certificate lifecycle management
- **SSH CA** (Flask, port 5002): SSH certificate authority for infrastructure access
- **AAA Monitor** (Flask, port 5003): Audit logging, threat analysis, compliance reporting

Supporting infrastructure:
- **PostgreSQL 16**: Primary data store
- **Redis 7**: Cache and Streams for job queuing (prefix: `skauswatch`)
- **MinIO**: S3-compatible storage for ad-hoc uploads
- **ClamAV**: Antivirus scanning engine (freshclam for definition updates)
- **Worker-S3**: Distributed scan workers (ClamAV + YARA + threat intelligence enrichment)
- **Prometheus + Grafana**: Monitoring and metrics

## Tech Stack Decisions

- **Python 3.13** for all services (no Go, no Node.js)
- **Quart** (async Flask) for Manager due to gRPC and async S3 operations
- **Flask** for other services (simpler request/response patterns)
- **PyDAL** for database abstraction
- **Flask-Security-Too** for RBAC authentication
- **Redis Streams** for job distribution (not Celery/RQ)
- **gRPC** for Manager ↔ Worker communication

## Data Flow

1. User configures S3 bucket credentials via Manager API
2. Manager encrypts credentials using `S3_CRED_ENCRYPTION_KEY` and stores in PostgreSQL
3. Scan jobs published to Redis Stream (`skauswatch:scan-jobs`)
4. Worker-S3 consumers pick up jobs, download objects from S3
5. Objects scanned: ClamAV (antivirus) → YARA (pattern matching) → threat intelligence enrichment (VirusTotal/OTX)
6. Results written to PostgreSQL, status update via gRPC to Manager
7. AAA Monitor records audit trail of all scan activities

## Security Requirements

- S3 credentials encrypted at rest
- All inter-service communication over mTLS (managed by PKI Server)
- SSH access via signed certificates (managed by SSH CA)
- Scan workspace (`/tmp/s3-scan-workspace`) cleaned after each job
- No scan artifacts persisted beyond result records
- Worker memory limited to 2GB, CPU limited to 2 cores

## Environment Variables (Key)

- `S3_CRED_ENCRYPTION_KEY`: AES key for S3 credential encryption
- `VIRUSTOTAL_API_KEY`: VirusTotal API key for threat intelligence enrichment
- `OTX_API_KEY`: AlienVault OTX API key
- `REDIS_KEY_PREFIX`: Set to `skauswatch` for job queue namespace
- `GRPC_ENABLED` / `GRPC_PORT`: gRPC configuration for Manager service
- `YARA_ENABLED` / `YARA_RULES_PATH`: YARA scanning toggle and rules location

## Deployment

- **Beta**: https://skauswatch.penguintech.cloud
- **Alpha/Local**: https://skauswatch.localhost.local
- **Production**: TBD
