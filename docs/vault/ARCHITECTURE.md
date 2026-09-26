# Vault — System Architecture

**Audience:** Architects | Developers

## System Overview

```
┌──────────────────────────────────────────────────────────────────┐
│ WebUI (React/Vite)                                               │
│ Port 3100 | Vault management dashboard                           │
└────────────────────────┬─────────────────────────────────────────┘
                         │ HTTPS
┌────────────────────────▼─────────────────────────────────────────┐
│ Flask-Backend (Quart) REST API                                   │
│ Port 5100 | Secrets CRUD, JIT, one-time, cloud sync             │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ Crypto: Envelope encryption (AES-256-GCM)                  │ │
│ │ Auth: JWT middleware with scope validation                 │ │
│ │ License: Per-request validation (cached 6h)                │ │
│ └─────────────────────────────────────────────────────────────┘ │
└────┬─────────────────┬─────────────────────┬────────────────────┘
     │                 │                     │
 PostgreSQL       Redis Streams          Cloud KMS
 (DB)             (Job Queue)            (MEK storage)
     │                 │                     │
     │                 ▼                     │
     │         ┌───────────────────┐        │
     │         │ Sync-Worker       │        │
     │         │ (Redis Streams)   │───────►│
     │         │ AWS/Azure/GCP/OCI │        │
     │         │ K8s Secrets       │        │
     │         └───────────────────┘        │
     │                                      │
     ▼                                      ▼
  vault_*                          Cloud Provider
  (11 tables)                        Secrets Management
```

---

## Encryption Architecture

### Envelope Encryption Model

Vault uses **envelope encryption** to decouple key management from data encryption:

```
Plain Secret Value (e.g., "super-secret-api-key")
         ↓
[Generate random DEK (Data Encryption Key)]
         ↓
[Encrypt secret with DEK using AES-256-GCM]
         ↓
Ciphertext (binary) + Nonce + Auth Tag
         ↓
[Wrap DEK with MEK (Master Encryption Key)]
         ↓
Encrypted DEK (EDEK) + MEK Version
         ↓
[Store in database]
         ↓
┌─────────────────────────────────────────┐
│ Row: secret_id | ciphertext | edek | v │
└─────────────────────────────────────────┘
         ↓
[On retrieve: unwrap EDEK with MEK]
         ↓
[Decrypt ciphertext with DEK]
         ↓
Plain Secret Value (returned to user)
```

### Key Components

| Component | Size | Source | Rotation |
|-----------|------|--------|----------|
| **DEK** | 32 bytes | Random per secret | Never (secret-bound) |
| **MEK** | 32+ bytes | Environment variable | Manual (re-wraps all DEKs) |
| **Nonce** | 12 bytes | Random per encryption | Per-encryption |
| **Auth Tag** | 16 bytes | AES-256-GCM output | Per-encryption |

### Why Envelope Encryption?

- **Key rotation without re-encrypting data:** Change MEK, re-wrap all DEKs (faster than AES-256-GCM on ciphertext)
- **Separation of concerns:** One key for many secrets
- **Compliance-friendly:** Hardware security module (HSM) can hold MEK only
- **Performance:** Pre-generated DEKs speed up encryption

---

## JIT (Just-in-Time) Access Flow

### Complete Workflow

```
1. Requester (User)
   └─ POST /api/v1/jit/requests
      ├─ secret_id: "550e8400-..."
      ├─ reason: "emergency maintenance"
      └─ requested_duration_seconds: 3600

2. API validates:
   ├─ Secret exists
   ├─ User has jit:request scope
   └─ Duration within policy limits

3. Create Grant (pending):
   └─ INSERT vault_jit_grants (
        id, secret_id, grantee_id, status='pending',
        requested_duration_seconds, created_at
      )

4. Return request_id to user

5. Approver (Admin)
   └─ PATCH /api/v1/jit/requests/{request_id}/approve
      └─ approved_duration_seconds: 1800

6. API validates:
   ├─ Admin has jit:approve scope
   ├─ Request still pending
   └─ Approved duration <= requested

7. Generate HMAC Token:
   ├─ Token = "jit:{grant_id}:{grantee_id}:{expires_epoch}"
   ├─ Token_Hash = SHA-256(Token)
   └─ Store Token_Hash in database (not raw token)

8. Update Grant (approved):
   └─ UPDATE vault_jit_grants SET
        status='approved', approved_duration_seconds=1800,
        token_hash=sha256(token), expires_at=now+1800s

9. Return token to approver (shares with requester securely)

10. Requester retrieves secret:
    └─ GET /api/v1/secrets/{secret_id}/value
       └─ Authorization: Bearer {jit_token}

11. API validates token:
    ├─ Recompute SHA-256(jit_token)
    ├─ Lookup token_hash in DB
    ├─ Verify expiry (token_epoch < current_epoch)
    ├─ Check grant status (must be 'approved')
    └─ If valid: decrypt secret and return

12. Secret decrypted and returned

13. Background task (every 5 min):
    ├─ Find expired grants (expires_at < now)
    ├─ Delete associated token_hashes
    └─ Mark grant status='expired'
```

### Token Format

```
jit:{grant_uuid}:{grantee_uuid}:{expires_epoch}
    ├────────────┬────────────┬───────────┬─────────┘
    │            │            │           │
    Grant ID     Grantee ID   Encoded as  Unix epoch
    (who gets)   (user requesting access) (seconds, UTC)
```

**Example:** `jit:660e8400-e29b-41d4-a716-446655440001:user-uuid-123:1737720000`

### Storage

- **Raw token:** NEVER stored — only shared with user over secure channel
- **Token hash:** SHA-256(token) stored in database for validation
- **Validation:** Recompute SHA-256(provided_token), compare with stored hash
- **Expiry:** Epoch stored as integer, compared at retrieval time

---

## One-Time Secret Lifecycle

```
1. User creates one-time secret:
   POST /api/v1/one-time-secrets
   ├─ value: "temporary-api-key"
   └─ ttl_seconds: 3600

2. API generates:
   ├─ Random URL token: "ots:abcd1234efgh5678..."
   ├─ Token hash: SHA-256(url_token)
   ├─ Encrypt value with DEK
   └─ Store: (token_hash, ciphertext, viewed_at=NULL)

3. Return share URL to user:
   https://vault.skauswatch.app/api/v1/one-time-secrets/{url_token}

4. First access (recipient):
   GET /api/v1/one-time-secrets/{url_token}

5. API validates:
   ├─ Hash token
   ├─ Lookup in database
   ├─ Check: viewed_at IS NULL
   └─ Atomically: SET viewed_at = NOW(), return decrypted value

6. Secret returned to recipient

7. Second access (any user with token):
   GET /api/v1/one-time-secrets/{url_token}

8. API:
   ├─ Hash token
   ├─ Lookup in database
   ├─ Check: viewed_at IS NOT NULL
   └─ Return 410 Gone (or generic 404 for security)

9. Background cleanup (hourly):
   DELETE FROM vault_one_time_secrets
   WHERE expires_at < NOW()
```

### Atomicity Guarantee

**Critical:** The check-before-return must be atomic to prevent race conditions:

```sql
-- WRONG (not atomic, race condition possible):
SELECT * FROM one_time_secrets WHERE token_hash = ?;
IF viewed_at IS NULL THEN:
    UPDATE ... SET viewed_at = NOW();
    RETURN decrypted_value;
ELSE:
    RETURN 410;

-- CORRECT (atomic):
UPDATE one_time_secrets
SET viewed_at = NOW()
WHERE token_hash = ? AND viewed_at IS NULL
RETURNING ciphertext, dek, ...;

IF no rows affected: RETURN 410 Gone;
ELSE: decrypt and return value;
```

---

## Cloud Synchronization Architecture

### Redis Streams Model

```
┌──────────────────────────────────────────────┐
│ Flask-Backend (Secret updates)               │
├──────────────────────────────────────────────┤
│ POST /api/v1/secrets                         │
│  ↓ (on create/update)                        │
│ XADD vault:sync:aws_secrets_manager         │
│      {"action": "sync", "secret_id": "..."}  │
└──────────┬───────────────────────────────────┘
           │
           ├─► XADD vault:sync:azure_key_vault
           │
           ├─► XADD vault:sync:gcp_secret_manager
           │
           ├─► XADD vault:sync:oracle_oci
           │
           └─► XADD vault:sync:k8s_secrets
               │
               ↓
           ┌────────────────────────┐
           │ Sync-Worker (consumers)│
           ├────────────────────────┤
           │ XREAD BLOCK 1000       │
           │ STREAMS                │
           │ vault:sync:*          │
           │  ↓ (per provider)      │
           │ POST AWS Secrets Mgr   │
           │ POST Azure KV          │
           │ POST GCP Secret Mgr    │
           │ etc.                   │
           └────────────────────────┘
               │
               ├─► AWS Secrets Manager
               │
               ├─► Azure Key Vault
               │
               ├─► GCP Secret Manager
               │
               ├─► Oracle OCI Vault
               │
               └─► Kubernetes Secrets
```

### Supported Providers

| Provider | Config Keys | Credentials | Features |
|----------|------------|-------------|----------|
| **AWS Secrets Manager** | `region`, `kms_key_id` | IAM role / access key | Auto-rotation, tags |
| **Azure Key Vault** | `vault_name` | Client credentials / MSI | Versioning, RBAC |
| **GCP Secret Manager** | `project_id` | Service account | Replication, labels |
| **Oracle OCI** | `vault_id`, `compartment_id` | User credentials | Auto-rotation, tags |
| **Kubernetes** | `namespace` | In-cluster SA token | Annotations, RBAC |

---

## Database Schema

11 tables, all prefixed `vault_`:

```sql
-- Core secrets table
vault_secrets (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(255),
  name VARCHAR(255),
  secret_type VARCHAR(50),
  ciphertext BLOB,
  dek_version INT,
  encrypted_dek BLOB,
  metadata JSON,
  created_at TIMESTAMP,
  updated_at TIMESTAMP
)

-- JIT grants table
vault_jit_grants (
  id UUID PRIMARY KEY,
  secret_id UUID FOREIGN KEY,
  grantee_id UUID,
  status VARCHAR(20),  -- pending, approved, rejected, expired, revoked
  reason TEXT,
  requested_duration_seconds INT,
  approved_duration_seconds INT,
  token_hash CHAR(64),  -- SHA-256 hex
  expires_at TIMESTAMP,
  created_at TIMESTAMP
)

-- One-time secrets table
vault_one_time_secrets (
  id UUID PRIMARY KEY,
  token_hash CHAR(64),
  ciphertext BLOB,
  dek_version INT,
  encrypted_dek BLOB,
  viewed_at TIMESTAMP,
  expires_at TIMESTAMP,
  created_at TIMESTAMP
)

-- Cloud sync integrations
vault_cloud_integrations (
  id UUID PRIMARY KEY,
  name VARCHAR(255),
  provider VARCHAR(50),
  direction VARCHAR(20),  -- vault_to_cloud, cloud_to_vault, bidirectional
  config JSON,
  enabled BOOLEAN,
  last_sync_at TIMESTAMP,
  created_at TIMESTAMP
)

-- Audit logs
vault_audit_logs (
  id UUID PRIMARY KEY,
  actor_id UUID,
  action VARCHAR(50),
  resource_id UUID,
  details JSON,
  timestamp TIMESTAMP
)

-- MEK versions (for rotation tracking)
vault_mek_versions (
  id UUID PRIMARY KEY,
  version INT,
  key_hash CHAR(64),
  created_at TIMESTAMP,
  retired_at TIMESTAMP
)

-- License cache
vault_license (
  id UUID PRIMARY KEY,
  license_key VARCHAR(255),
  features JSON,
  valid_until TIMESTAMP,
  cached_at TIMESTAMP
)

-- JIT revocation list (for explicit revocations)
vault_jit_revocations (
  id UUID PRIMARY KEY,
  grant_id UUID,
  reason TEXT,
  created_at TIMESTAMP
)

-- Secret versions (audit trail)
vault_secret_versions (
  id UUID PRIMARY KEY,
  secret_id UUID,
  version INT,
  ciphertext BLOB,
  created_at TIMESTAMP
)

-- Cloud sync event log
vault_sync_events (
  id UUID PRIMARY KEY,
  integration_id UUID,
  event_type VARCHAR(50),
  status VARCHAR(20),
  error_message TEXT,
  timestamp TIMESTAMP
)

-- Session/token cache (for revocation lists)
vault_token_blacklist (
  id UUID PRIMARY KEY,
  token_hash CHAR(64),
  blacklisted_at TIMESTAMP
)
```

---

## Security Boundaries

### Per-Service Database Accounts

```
┌──────────────────────────────────────────────┐
│ PostgreSQL (shared database)                 │
├──────────────────────────────────────────────┤
│ User: vault-flask-backend-rw                │
│ Grants: SELECT, INSERT, UPDATE, DELETE       │
│         on ALL vault_* tables               │
│                                              │
│ User: vault-sync-worker-rw                  │
│ Grants: SELECT, INSERT, UPDATE               │
│         on vault_sync_events, audit_logs    │
│                                              │
│ User: vault-webui-ro                        │
│ Grants: SELECT on secrets, audit_logs        │
│         (no write, no value decryption)      │
│                                              │
│ User: vault-migration-admin                 │
│ Grants: ALL PRIVILEGES (Alembic only)        │
└──────────────────────────────────────────────┘
```

### Tenant Isolation

All queries scoped to `tenant_id` from JWT claim:

```python
# Example PyDAL query (tenant-scoped)
db(db.vault_secrets.tenant_id == current_tenant_id).select()

# NOT:
db(db.vault_secrets).select()  # WRONG: leaks cross-tenant data
```

---

## Integration with SkausWatch Core

### Shim Proxy Architecture

```
SkausWatch Core (Port 5000)
├─ PKI Server (5001) — Shim Proxy
│  ├─ Receives cert request
│  ├─ Forward to Vault PKI (5101)
│  ├─ Add Deprecation: true header
│  ├─ Add Link: <vault-pki-url> header
│  └─ Return response
│
└─ SSH CA (5002) — Shim Proxy
   ├─ Receives SSH cert request
   ├─ Forward to Vault SSH CA (5102)
   ├─ Add headers + deprecation
   └─ Return response

Vault (Port 5100)
├─ flask-backend — Full impl
├─ pki (5101) — From shim
├─ sshca (5102) — From shim
└─ sync-worker — Background
```

### Deprecation Timeline

- **v1.0-v1.9:** Shim proxies active, clients warned via headers
- **v2.0+:** Shims removed, clients must call Vault directly

---

**Vault v1.0.0** | Architecture Overview | Limited AGPL-3.0
