# IceBox — REST API Reference

**Audience:** Developers | Integrators

## Base URL

- **Alpha:** `https://icebox.skauswatch.localhost.local/api/v1`
- **Beta:** `https://icebox.skauswatch.penguintech.cloud/api/v1`
- **Production:** `https://icebox.skauswatch.app/api/v1`

## Authentication

All endpoints require JWT Bearer token in `Authorization` header:

```bash
curl -H "Authorization: Bearer <jwt-token>" https://...
```

**JWT Claims Required:**
```json
{
  "sub": "user-id",
  "iss": "https://auth-service",
  "scope": "secrets:read secrets:write",
  "tenant": "tenant-id",
  "exp": 1234567890
}
```

---

## Scopes

| Scope | Purpose |
|-------|---------|
| `secrets:read` | Read secrets (not values) |
| `secrets:write` | Create/update secrets |
| `secrets:delete` | Delete secrets |
| `secrets:value` | Read secret values |
| `jit:request` | Request JIT access |
| `jit:approve` | Approve JIT requests |
| `jit:reject` | Reject JIT requests |
| `jit:revoke` | Revoke JIT grants |
| `sync:read` | Read cloud integrations |
| `sync:write` | Create/update sync configs |
| `sync:delete` | Delete sync configs |
| `audit:read` | Read audit logs |

---

## Secrets Management

### Create Secret

```http
POST /secrets
Content-Type: application/json
Authorization: Bearer <jwt-token>

{
  "name": "prod-api-key",
  "value": "sk-live-abcd1234...",
  "secret_type": "api_key",
  "metadata": {
    "service": "external-api",
    "environment": "production"
  }
}
```

**Required Scope:** `secrets:write`

**Response (201 Created):**
```json
{
  "status": "success",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "prod-api-key",
    "secret_type": "api_key",
    "version": 1,
    "created_at": "2025-01-24T10:00:00Z",
    "updated_at": "2025-01-24T10:00:00Z",
    "metadata": {
      "service": "external-api",
      "environment": "production"
    }
  }
}
```

### List Secrets

```http
GET /secrets?limit=10&offset=0
Authorization: Bearer <jwt-token>
```

**Required Scope:** `secrets:read`

**Response (200 OK):**
```json
{
  "status": "success",
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "prod-api-key",
      "secret_type": "api_key",
      "version": 1,
      "created_at": "2025-01-24T10:00:00Z"
    }
  ],
  "meta": {
    "total": 42,
    "limit": 10,
    "offset": 0
  }
}
```

### Get Secret

```http
GET /secrets/{secret_id}
Authorization: Bearer <jwt-token>
```

**Required Scope:** `secrets:read`

**Response (200 OK):**
```json
{
  "status": "success",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "prod-api-key",
    "secret_type": "api_key",
    "version": 1,
    "created_at": "2025-01-24T10:00:00Z"
  }
}
```

### Get Secret Value

```http
GET /secrets/{secret_id}/value
Authorization: Bearer <jit-token-or-jwt>
```

**Required Scope:** `secrets:value` (JWT) or valid JIT token

**Response (200 OK):**
```json
{
  "status": "success",
  "data": {
    "value": "sk-live-abcd1234...",
    "decrypted_at": "2025-01-24T10:05:00Z"
  }
}
```

**Error (410 Gone if one-time secret already viewed):**
```json
{
  "status": "error",
  "error": "secret_already_viewed",
  "message": "One-time secret has already been retrieved"
}
```

### Update Secret

```http
PATCH /secrets/{secret_id}
Content-Type: application/json
Authorization: Bearer <jwt-token>

{
  "name": "prod-api-key-v2",
  "value": "sk-live-new-key-12345...",
  "metadata": {
    "rotated_at": "2025-01-24T10:05:00Z"
  }
}
```

**Required Scope:** `secrets:write`

**Response (200 OK):** Updated secret object

### Delete Secret

```http
DELETE /secrets/{secret_id}
Authorization: Bearer <jwt-token>
```

**Required Scope:** `secrets:delete`

**Response (204 No Content)**

---

## JIT (Just-in-Time) Access

### Request JIT Access

```http
POST /jit/requests
Content-Type: application/json
Authorization: Bearer <jwt-token>

{
  "secret_id": "550e8400-e29b-41d4-a716-446655440000",
  "reason": "emergency maintenance",
  "requested_duration_seconds": 3600
}
```

**Required Scope:** `jit:request`

**Response (201 Created):**
```json
{
  "status": "success",
  "data": {
    "id": "660e8400-e29b-41d4-a716-446655440001",
    "secret_id": "550e8400-e29b-41d4-a716-446655440000",
    "grantee_id": "user-uuid",
    "status": "pending",
    "reason": "emergency maintenance",
    "requested_duration_seconds": 3600,
    "approved_duration_seconds": null,
    "created_at": "2025-01-24T10:00:00Z"
  }
}
```

### List JIT Requests

```http
GET /jit/requests?status=pending
Authorization: Bearer <jwt-token>
```

**Required Scope:** `jit:request` or `jit:approve`

**Response (200 OK):**
```json
{
  "status": "success",
  "data": [
    {
      "id": "660e8400-e29b-41d4-a716-446655440001",
      "secret_id": "550e8400-e29b-41d4-a716-446655440000",
      "grantee_id": "user-uuid",
      "status": "pending",
      "created_at": "2025-01-24T10:00:00Z"
    }
  ]
}
```

### Approve JIT Request

```http
PATCH /jit/requests/{request_id}/approve
Content-Type: application/json
Authorization: Bearer <jwt-token>

{
  "approved_duration_seconds": 1800
}
```

**Required Scope:** `jit:approve`

**Response (200 OK):**
```json
{
  "status": "success",
  "data": {
    "id": "660e8400-e29b-41d4-a716-446655440001",
    "status": "approved",
    "jit_token": "jit:660e8400-e29b-41d4-a716-446655440001:user-uuid:1737720000",
    "expires_at": "2025-01-24T10:30:00Z"
  }
}
```

### Reject JIT Request

```http
PATCH /jit/requests/{request_id}/reject
Content-Type: application/json
Authorization: Bearer <jwt-token>

{
  "reason": "policy violation"
}
```

**Required Scope:** `jit:approve`

**Response (200 OK):** Updated request with status `rejected`

---

## One-Time Secrets

### Create One-Time Secret

```http
POST /one-time-secrets
Content-Type: application/json
Authorization: Bearer <jwt-token>

{
  "value": "temporary-shared-secret",
  "ttl_seconds": 3600
}
```

**Required Scope:** `secrets:write`

**Response (201 Created):**
```json
{
  "status": "success",
  "data": {
    "id": "770e8400-e29b-41d4-a716-446655440002",
    "url_token": "ots:abcd1234efgh5678ijkl9012mnop3456",
    "expires_at": "2025-01-24T11:00:00Z",
    "share_url": "https://icebox.skauswatch.app/api/v1/one-time-secrets/ots:abcd1234efgh5678ijkl9012mnop3456"
  }
}
```

### Retrieve One-Time Secret

```http
GET /one-time-secrets/{url_token}
```

**No authentication required** (token provides access)

**Response (200 OK):**
```json
{
  "status": "success",
  "data": {
    "value": "temporary-shared-secret"
  }
}
```

**Error on second retrieval (410 Gone):**
```json
{
  "status": "error",
  "error": "secret_already_viewed",
  "http_status": 410
}
```

---

## Cloud Synchronization

### Create Cloud Integration

```http
POST /sync
Content-Type: application/json
Authorization: Bearer <jwt-token>

{
  "name": "aws-prod",
  "provider": "aws_secrets_manager",
  "direction": "bidirectional",
  "config": {
    "region": "us-east-1",
    "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/abc"
  }
}
```

**Required Scope:** `sync:write`

**Response (201 Created):** Cloud integration object

### List Cloud Integrations

```http
GET /sync
Authorization: Bearer <jwt-token>
```

**Required Scope:** `sync:read`

**Response (200 OK):** Array of cloud integrations

### Delete Cloud Integration

```http
DELETE /sync/{integration_id}
Authorization: Bearer <jwt-token>
```

**Required Scope:** `sync:delete`

**Response (204 No Content)**

---

## Audit Logs

### Get Audit Logs

```http
GET /audit?limit=50&offset=0&action=secret_created
Authorization: Bearer <jwt-token>
```

**Required Scope:** `audit:read`

**Response (200 OK):**
```json
{
  "status": "success",
  "data": [
    {
      "id": "audit-123",
      "actor_id": "user-uuid",
      "action": "secret_created",
      "resource_id": "550e8400-e29b-41d4-a716-446655440000",
      "details": {
        "name": "prod-api-key"
      },
      "timestamp": "2025-01-24T10:00:00Z"
    }
  ],
  "meta": {
    "total": 1042,
    "limit": 50,
    "offset": 0
  }
}
```

---

## Admin Endpoints

### Set License Key

```http
POST /admin/license
Content-Type: application/json
Authorization: Bearer <admin-jwt-token>

{
  "license_key": "PENG-XXXX-XXXX-XXXX-XXXX-XXXX"
}
```

**Required Scope:** `admin:write`

**Response (200 OK):**
```json
{
  "status": "success",
  "message": "License key updated successfully"
}
```

### Rotate Master Encryption Key

```http
POST /admin/rotate-mek
Content-Type: application/json
Authorization: Bearer <admin-jwt-token>

{
  "new_mek": "<base64-encoded-new-key>"
}
```

**Required Scope:** `admin:write`

**Response (202 Accepted):**
```json
{
  "status": "success",
  "message": "MEK rotation started (background job)",
  "job_id": "job-abc123"
}
```

---

## Health & Status

### Health Check

```http
GET /healthz
```

**Response (200 OK):**
```json
{
  "status": "healthy",
  "timestamp": "2025-01-24T10:00:00Z"
}
```

### API Status

```http
GET /api/v1/status
```

**Response (200 OK):**
```json
{
  "status": "ready",
  "version": "1.0.0.1737720000",
  "build_epoch": 1737720000,
  "license": {
    "valid": true,
    "feature": "icebox"
  }
}
```

---

## Error Codes

| Code | HTTP | Meaning |
|------|------|---------|
| `unauthorized` | 401 | Missing or invalid JWT token |
| `forbidden` | 403 | Valid token but insufficient scope |
| `not_found` | 404 | Resource not found |
| `invalid_request` | 400 | Malformed request body |
| `secret_already_viewed` | 410 | One-time secret already retrieved |
| `license_required` | 402 | Feature requires valid license |
| `internal_error` | 500 | Server error |

---

**IceBox API v1** | Limited AGPL-3.0
