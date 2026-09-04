# SkausWatch API Reference

**Audience:** Developers

Complete API reference for all SkausWatch services including REST endpoints, gRPC services, authentication, and error codes.

## 🔐 Authentication

All API requests require **JWT Bearer tokens** with OIDC scopes.

**Header format:**
```
Authorization: Bearer <JWT_TOKEN>
```

**Token claims (OIDC standard):**
```json
{
  "sub": "user-id",
  "iss": "https://auth-service",
  "aud": ["skauswatch"],
  "iat": 1234567890,
  "exp": 1234567890,
  "scope": "scans:read scans:write certificates:read",
  "tenant": "default",
  "role": "admin"
}
```

**Scope format:** `resource:action`
- `scans:read` — View scans
- `scans:write` — Create/modify scans
- `certificates:read` — View certificates
- `certificates:write` — Issue/revoke certificates
- `audit:read` — View audit logs
- `admin` — Admin-only operations

## 📋 Manager Service (Port 5000)

### REST API

**Base:** `http://localhost:5000/api/v1`

#### Scans

```bash
# Create scan job
POST /scans
{
  "bucket_name": "my-bucket",
  "aws_access_key": "AKIA...",
  "aws_secret_key": "...",
  "profile": "clamav-yara-ti",
  "recursive": true
}
Response: { "scan_id": "uuid", "status": "pending" }

# List scans
GET /scans
Query: ?status=completed&limit=10&offset=0
Response: { "scans": [...], "total": 42 }

# Get scan details
GET /scans/{scan_id}
Response: {
  "scan_id": "uuid",
  "bucket_name": "my-bucket",
  "status": "completed",
  "findings": [
    {
      "file_path": "s3://bucket/virus.exe",
      "malware_detected": true,
      "threat_level": "critical",
      "signatures": ["Win.Trojan.GenericKD"],
      "ti_verdict": "malicious"
    }
  ],
  "started_at": "2026-03-10T10:00:00Z",
  "completed_at": "2026-03-10T10:15:00Z"
}

# Cancel scan
DELETE /scans/{scan_id}
Response: { "scan_id": "uuid", "status": "cancelled" }
```

#### S3 Buckets

```bash
# Add bucket
POST /buckets
{
  "name": "my-bucket",
  "aws_region": "us-east-1"
}
Response: { "bucket_id": "uuid", "name": "my-bucket" }

# List buckets
GET /buckets
Response: { "buckets": [...] }

# Remove bucket
DELETE /buckets/{bucket_id}
Response: { "bucket_id": "uuid", "status": "deleted" }
```

#### Scanning Profiles

```bash
# List available profiles
GET /profiles
Response: {
  "profiles": [
    {
      "name": "clamav-yara-ti",
      "description": "ClamAV + YARA + threat intelligence",
      "engines": ["clamav", "yara", "threat-intel"],
      "timeout_seconds": 300
    }
  ]
}
```

#### Health Check

```bash
GET /health
Response: {
  "status": "healthy",
  "services": {
    "database": "healthy",
    "redis": "healthy",
    "grpc": "healthy"
  }
}
```

### gRPC Service

**Port:** 5000 (shared with REST)

**Protocol Buffer:**
```protobuf
service Manager {
  rpc CreateScan(ScanRequest) returns (ScanResponse);
  rpc GetScan(GetScanRequest) returns (ScanResponse);
  rpc UpdateScanStatus(UpdateStatusRequest) returns (StatusResponse);
}

message ScanRequest {
  string bucket_name = 1;
  string profile = 2;
  bool recursive = 3;
}

message ScanResponse {
  string scan_id = 1;
  string status = 2;
  repeated Finding findings = 3;
}

message Finding {
  string file_path = 1;
  bool malware_detected = 2;
  string threat_level = 3;
  repeated string signatures = 4;
}
```

## 🔐 PKI Server (Port 5001)

**Note:** In v1.x, this is a shim proxy to Vault PKI. Requests forward to `$VAULT_PKI_URL`.

### REST API

**Base:** `http://localhost:5001/api/v1`

#### Certificates

```bash
# Generate certificate
POST /certificates
{
  "subject": "cn=server.example.com,o=MyOrg,c=US",
  "days_valid": 365,
  "key_type": "rsa-4096"
}
Response: {
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----\n...",
  "serial_number": "0x123...",
  "not_before": "2026-03-10T00:00:00Z",
  "not_after": "2027-03-10T00:00:00Z"
}

# List certificates
GET /certificates
Response: { "certificates": [...] }

# Get certificate details
GET /certificates/{serial_number}
Response: { "certificate": {...}, "status": "active" }

# Revoke certificate
POST /certificates/revoke
{
  "serial_number": "0x123...",
  "reason": "cessation_of_operation"
}
Response: { "serial_number": "0x123...", "status": "revoked" }

# Check OCSP status
GET /ocsp?serial={serial_number}
Response: {
  "certificate_status": "good",
  "this_update": "2026-03-10T10:00:00Z",
  "next_update": "2026-03-11T10:00:00Z"
}
```

#### Health

```bash
GET /health
Response: { "status": "healthy", "backend": "vault" }  # or "unavailable"
```

**Deprecation headers (v1.x):**
```
Deprecation: true
Link: <https://vault.example.com/api/v1/certificates>; rel="successor-version"
```

## 🔑 SSH CA (Port 5002)

**Note:** In v1.x, this is a shim proxy to Vault SSH CA. Requests forward to `$VAULT_SSHCA_URL`.

### REST API

**Base:** `http://localhost:5002/api/v1`

#### SSH Certificates

```bash
# Issue SSH certificate
POST /ssh-certs
{
  "public_key": "ssh-rsa AAAA... user@host",
  "principals": ["user", "admin"],
  "cert_type": "user",
  "validity_seconds": 3600,
  "critical_options": {
    "force-command": "/bin/bash"
  }
}
Response: {
  "certificate": "ssh-cert-v01@openssh.com ...",
  "key_id": "user@host-2026-03-10",
  "serial": 1234567890,
  "valid_after": 1234567890,
  "valid_before": 1234567890,
  "principals": ["user", "admin"]
}

# Validate SSH certificate
POST /ssh-certs/validate
{
  "certificate": "ssh-cert-v01@openssh.com ..."
}
Response: {
  "valid": true,
  "key_id": "user@host-2026-03-10",
  "principals": ["user", "admin"],
  "valid_after": 1234567890,
  "valid_before": 1234567890
}

# List issued certificates
GET /ssh-certs
Response: { "certificates": [...] }
```

## 📊 Monitor (Port 5003)

### REST API

**Base:** `http://localhost:5003/api/v1`

#### Audit Logs

```bash
# Create audit log entry
POST /audit-logs
{
  "user_id": "uuid",
  "action": "scan_created",
  "resource_type": "scan",
  "resource_id": "uuid",
  "status": "success",
  "details": {
    "bucket": "my-bucket",
    "profile": "clamav-yara-ti"
  }
}
Response: { "log_id": "uuid", "timestamp": "2026-03-10T10:00:00Z" }

# Query audit logs
GET /audit-logs
Query: ?user_id=uuid&action=scan_created&limit=50&offset=0
Response: {
  "logs": [
    {
      "log_id": "uuid",
      "user_id": "uuid",
      "action": "scan_created",
      "resource_type": "scan",
      "status": "success",
      "timestamp": "2026-03-10T10:00:00Z",
      "details": {...}
    }
  ],
  "total": 156
}

# Analyze threat trend (AI)
GET /threats/trend
Query: ?timeframe=7d&limit=10
Response: {
  "top_threats": [
    {
      "signature": "Win.Trojan.GenericKD",
      "occurrences": 12,
      "severity": "critical",
      "first_seen": "2026-03-04T00:00:00Z"
    }
  ]
}
```

## 📦 Worker Services (Background)

Workers communicate via **gRPC** with Manager. No direct API; jobs published to Redis Streams.

### Job Queue Format

**Redis Stream:** `skauswatch:scan-jobs`

**Job entry:**
```json
{
  "scan_id": "uuid",
  "bucket_name": "my-bucket",
  "profile": "clamav-yara-ti",
  "aws_credentials": {
    "access_key": "encrypted",
    "secret_key": "encrypted"
  },
  "created_at": 1234567890
}
```

### ENDPOINT Agent

ENDPOINT Agent runs as Kubernetes DaemonSet. Reports via:
- Kubernetes API (logs, events)
- gRPC to Manager (host info, process events, threat signals)

## 🌐 WebUI (Port 3000)

WebUI is a React frontend that consumes Manager API.

**Socket.IO events:**
- `scan:progress` — Real-time scan progress
- `finding:detected` — Real-time finding alert
- `certificate:revoked` — Certificate revocation notification

## 📊 Response Format

**Success (2xx):**
```json
{
  "status": "success",
  "data": {...},
  "meta": {
    "version": 1,
    "timestamp": "2026-03-10T10:00:00Z"
  }
}
```

**Error (4xx, 5xx):**
```json
{
  "status": "error",
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Missing required field: bucket_name",
    "details": {
      "field": "bucket_name"
    }
  },
  "meta": {
    "version": 1,
    "timestamp": "2026-03-10T10:00:00Z",
    "request_id": "req-uuid"
  }
}
```

## 🔴 Common Error Codes

| Code | HTTP | Meaning |
|------|------|---------|
| `INVALID_REQUEST` | 400 | Missing/invalid parameters |
| `UNAUTHORIZED` | 401 | Missing/expired JWT token |
| `FORBIDDEN` | 403 | Insufficient scopes for operation |
| `NOT_FOUND` | 404 | Resource doesn't exist |
| `CONFLICT` | 409 | Resource already exists or state conflict |
| `RATE_LIMITED` | 429 | Too many requests |
| `SERVICE_ERROR` | 500 | Internal server error |
| `SERVICE_UNAVAILABLE` | 503 | Service temporarily unavailable |

## 🔗 Vault API (Sub-Module)

When Vault is installed, additional endpoints are available (port 5100):
- `POST /api/v1/secrets` — Create secret
- `GET /api/v1/secrets` — List secrets
- `GET /api/v1/secrets/{id}` — Retrieve secret
- `POST /api/v1/jit-access` — Request JIT access
- `POST /api/v1/one-time-secrets` — Create view-once secret

See `docs/vault/API.md` for full reference.

---

**Last Updated:** 2026-03-10
**Maintained by:** Penguin Tech Inc
