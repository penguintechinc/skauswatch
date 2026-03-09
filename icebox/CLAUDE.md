# IceBox — Claude Code Context

## Sub-Module Overview

IceBox is a Darwin-style independent sub-module of SkausWatch that consolidates all
cryptographic material management into one optional licensed add-on. It absorbs the
existing PKI server and SSH CA services, adds secrets lifecycle management, Just-in-Time
(JIT) access with approval workflows, cloud vault synchronization, and one-time secret sharing.

**Product domain:** `icebox.skauswatch.app` / `skauswatch.penguincloud.io/icebox`

## Services

| Service | Path | Port | Purpose |
|---------|------|------|---------|
| flask-backend | services/flask-backend/ | 8080 | REST API: secrets, JIT, one-time, cloud sync |
| sync-worker | services/sync-worker/ | internal | Cloud sync: AWS/Azure/GCP/Oracle/K8s |
| pki-server | services/pki-server/ | 8081 | X.509 cert lifecycle (absorbed from core) |
| ssh-ca | services/ssh-ca/ | 8082 | SSH cert authority (absorbed from core) |

## Architecture

### Encryption
- Envelope encryption: AES-256-GCM per-secret DEK wrapped by env-var MEK
- Cloud KMS support: AWS KMS, Azure Key Vault, GCP KMS for MEK storage
- Key rotation: re-wrap DEKs only, secret ciphertext unchanged

### RBAC & OIDC
- All permissions via OIDC scopes (never ad-hoc role strings)
- Roles are pre-bundled scope sets expanded at token issuance
- Scopes: `secrets:*`, `jit:*`, `audit:read`, `sync:*`, `pki:*`, `ssh:*`

### Cloud Sync
- Redis Streams (one stream per provider: `icebox:sync:{provider}`)
- 5 providers: AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, Oracle OCI, K8s Secrets
- Direction: icebox_to_cloud | cloud_to_icebox | bidirectional per integration

### Licensing
- No RELEASE_MODE env bypass — license managed entirely in DB
- Auto-bypass for Penguin Tech internal domains
- 402 returned on all routes if unlicensed

## Critical Rules

- `migrate=False` on ALL PyDAL DAL() constructors — Alembic manages schema
- Never share DAL instances across threads — use thread-local or per-request
- Envelope encryption MUST be used for all secret values — no plaintext storage
- One-time secrets: mark `viewed_at` atomically before returning value
- JIT tokens: HMAC-signed, scoped to (secret_id, user_id, TTL)
- All API endpoints declare required scope — enforced by middleware, not inline

## Backward Compatibility

- `services/pki-server-new/` in SkausWatch core is now a shim proxy
- `services/ssh-ca/` in SkausWatch core is now a shim proxy
- Both shims add `Deprecation: true` and `Link:` headers
- Shims removed in v2.0.0; fully functional through all v1.x releases

## Development

```bash
# Start all IceBox services locally
docker compose -f icebox/docker-compose.yml up

# Run flask-backend tests
cd icebox/services/flask-backend && python3 -m pytest tests/

# Run alembic migrations
cd icebox/services/flask-backend && alembic upgrade head
```
