# Vault — Enterprise Secrets Vault Sub-Module

**Audience:** Developers | DevOps | Admins

## Overview

Vault is a **licensed add-on** for SkausWatch that provides enterprise-grade secrets management with envelope encryption, just-in-time (JIT) access control, one-time secret sharing, and cloud vault synchronization. It consolidates cryptographic material management (secrets, X.509 certificates, SSH keys) into a single isolated namespace with OIDC-based RBAC.

**License requirement:** Requires `vault` feature in PenguinTech license key.

**Domain:** `vault.skauswatch.app` (production) | `vault.skauswatch.penguintech.cloud` (beta) | `vault.skauswatch.localhost.local` (alpha)

---

## Quick Reference: Vault Services

| Service | Port | Language | Framework | Purpose |
|---------|------|----------|-----------|---------|
| **flask-backend** | 5100 | Python 3.13 | Quart | Secrets CRUD, JIT access, one-time secrets, cloud sync API |
| **pki** | 5101 | Python 3.13 | Quart | X.509 certificate management (from core PKI shim) |
| **sshca** | 5102 | Python 3.13 | Quart | SSH certificate authority (from core SSH CA shim) |
| **sync-worker** | — | Python 3.13 | Celery/asyncio | Cloud vault sync (AWS/Azure/GCP/OCI/K8s) |
| **webui** | 3100 | Node.js 18+ | React/Vite | Vault vault management UI |

---

## Key Capabilities

🔐 **Envelope Encryption**
- AES-256-GCM per-secret Data Encryption Keys (DEK)
- Master Encryption Key (MEK) from environment — versioned for rotation
- Automatic re-encryption on key rotation

🔑 **Just-in-Time (JIT) Access**
- Time-limited tokens for emergency access
- Approval workflows with configurable duration
- Automatic token expiration and revocation

🔓 **One-Time Secrets**
- Shareable URLs with automatic viewing restrictions
- Atomic check-before-decrypt pattern
- 410 Gone on second access attempt

☁️ **Cloud Vault Synchronization**
- Bidirectional sync with AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, Oracle OCI, K8s Secrets
- Event-driven via Redis Streams
- Per-provider credentials and access policies

📋 **Complete Audit Trail**
- All operations logged with user, timestamp, action
- RBAC-enforced read access to audit logs
- Compliance-ready format for regulatory requirements

---

## Documentation Index

| File | Purpose | Audience |
|------|---------|----------|
| **OVERVIEW.md** (this file) | High-level introduction, service mapping, key features | Everyone |
| **[USAGE.md](./USAGE.md)** | Deploying Vault, enabling in SkausWatch, common workflows | DevOps, Developers |
| **[API.md](./API.md)** | Complete REST API reference, all endpoints, auth scopes | Developers, Integrators |
| **[ARCHITECTURE.md](./ARCHITECTURE.md)** | System design, encryption model, JIT flow, database schema | Architects, Developers |
| **[CONFIGURATION.md](./CONFIGURATION.md)** | Environment variables, cloud provider setup, secrets management | DevOps |
| **[TESTING.md](./TESTING.md)** | Unit tests, smoke tests, integration testing, test commands | Developers, QA |
| **[TROUBLESHOOTING.md](./TROUBLESHOOTING.md)** | Common issues, debugging, error messages, FAQs | DevOps, Developers |
| **[RELEASE_NOTES.md](./RELEASE_NOTES.md)** | Version history, features per release, migration guides | Everyone |

---

## Relationship to SkausWatch Core

Vault is **integrated with the core SkausWatch platform** while remaining an optional licensed module:

### Shim Proxies
- **PKI Server** (SkausWatch core, port 5001) → proxies to Vault PKI (port 5101)
- **SSH CA** (SkausWatch core, port 5002) → proxies to Vault SSH CA (port 5102)
- Both shims include `Deprecation:` and `Link:` headers (RFC 8594)
- Shims to be removed in v2.0.0

### Environment Variables (Core)
```bash
VAULT_PKI_URL=http://vault-pki:5101    # PKI endpoint
VAULT_SSHCA_URL=http://vault-sshca:5102     # SSH CA endpoint
```

### Namespace Isolation
- **Core namespace:** `skauswatch`
- **Vault namespace:** `vault`
- Independent K8s deployments, databases, Redis keys

---

## License Validation

Vault validates licensing on **every API request**:

**Auto-Bypass Domains** (no license check):
- `*.nest.localhost.local` (local development)
- `*.nest.penguintech.cloud` (PenguinTech internal)
- `*.nestdata.app` (PenguinTech internal apps)

**Licensed Domains** (require valid license key):
- Production domains and custom customer domains

**Validation Flow:**
1. Check if domain is bypass domain → allow
2. Fetch license from database (cached 6 hours)
3. If license valid and `vault` feature enabled → allow
4. Else → 402 Payment Required

---

## Encryption Model (High-Level)

```
Secret Value
    ↓
[AES-256-GCM encrypt with DEK]
    ↓
Ciphertext + Encrypted DEK (EDEK)
    ↓
[Wrap EDEK with MEK]
    ↓
Store: (ciphertext, EDEK, DEK_version)
    ↓
[On retrieve, unwrap EDEK with MEK, decrypt ciphertext]
    ↓
Plain Secret Value
```

**DEK Rotation:** All secrets keep their DEK, but EDEK is re-wrapped with new MEK version.

---

## JIT Access Flow (High-Level)

```
User
  ↓
POST /api/v1/jit/requests
  ↓
[Create pending grant with requested_duration]
  ↓
Owner/Admin
  ↓
PATCH /api/v1/jit/requests/{id}/approve
  ↓
[Create HMAC-signed token: jit:{grant_id}:{grantee_id}:{expires_epoch}]
  ↓
User receives token
  ↓
GET /api/v1/secrets/{secret_id}/value?token={jit_token}
  ↓
[Validate token HMAC and expiry, return decrypted secret]
```

**Token Format:** `jit:grant-uuid:user-uuid:epoch_seconds`

**Storage:** SHA-256(token) stored in DB, raw token never persisted.

---

## Quick Start

### For Operators (Deploy Vault)
1. Read [USAGE.md](./USAGE.md) for deployment prerequisites
2. Read [CONFIGURATION.md](./CONFIGURATION.md) for environment variables
3. Deploy via Helm or Kustomize to `vault` namespace
4. Validate with smoke tests in [TESTING.md](./TESTING.md)

### For Developers (Integrate Vault)
1. Read [API.md](./API.md) for endpoint signatures and auth scopes
2. Read [ARCHITECTURE.md](./ARCHITECTURE.md) for encryption and JIT details
3. Start local dev stack: `docker compose -f icebox/docker-compose.yml up`
4. Run tests and linting from [TESTING.md](./TESTING.md) and [USAGE.md](./USAGE.md)

### For DevOps (Troubleshoot)
1. Read [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) for common issues
2. Check [CONFIGURATION.md](./CONFIGURATION.md) for env var setup
3. Use health endpoints and logs from [TESTING.md](./TESTING.md)

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Envelope encryption** | Allows key rotation without re-encrypting all secrets; separates data from metadata |
| **JIT tokens with HMAC** | Prevents database queries during secret retrieval; short-lived and scope-limited |
| **One-time atomic check** | Guarantees secret not exposed to multiple requesters; `viewed_at` set before return |
| **Cloud sync via Redis Streams** | Event-driven; decouples sync from API; supports multiple providers and directions |
| **Per-service DB accounts** | Restricts blast radius if a container is compromised; enforces least-privilege access |
| **OIDC scopes only** | Portable, auditable, federation-ready; no ad-hoc role strings |
| **Separate namespace** | Isolates cryptographic material from core SkausWatch; independent scaling and backup |

---

## Support & Links

- **Status page:** https://status.penguintech.io
- **Support email:** support@penguintech.io
- **License server:** https://license.penguintech.io
- **Related docs:** See [../core/](../core/) for SkausWatch core, [../codescan/](../codescan/) for CodeScan AI

---

**Vault v1.0.0** | Implemented Phases 1–10 | Production-ready | License: Limited AGPL-3.0
