# CodeScan - API Reference

**Audience:** Developers | DevOps | Admins

---

## 🔌 Webhook Endpoints

CodeScan exposes two webhook receivers: one for GitHub, one for GitLab. Both use HMAC-SHA256 signature verification.

---

## 🐙 GitHub Webhook

**Endpoint**: `POST /api/v1/webhooks/github`

**Signature Header**: `X-Hub-Signature-256: sha256={hex_digest}`

**Supported Events**:
- `pull_request` (actions: `opened`, `synchronize`, `reopened`)
- `issues` (actions: `opened`, `edited`)

### Request Format

```bash
curl -X POST https://your-codescan/api/v1/webhooks/github \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: pull_request" \
  -H "X-Hub-Signature-256: sha256=abc123..." \
  -d '{...webhook payload...}'
```

### Pull Request Payload Example

```json
{
  "action": "opened",
  "number": 42,
  "pull_request": {
    "id": 1234567,
    "number": 42,
    "title": "Add database migration",
    "body": "This PR adds...",
    "state": "open",
    "created_at": "2025-03-10T10:00:00Z",
    "updated_at": "2025-03-10T10:00:00Z",
    "head": {
      "sha": "abc123abc123abc123abc123abc123abc123abc1",
      "ref": "feature/migration",
      "repo": {
        "full_name": "myorg/myrepo"
      }
    },
    "base": {
      "sha": "def456def456def456def456def456def456def4",
      "ref": "main",
      "repo": {
        "full_name": "myorg/myrepo"
      }
    },
    "user": {
      "login": "octocat",
      "id": 1,
      "avatar_url": "https://avatars.githubusercontent.com/u/1?v=4",
      "type": "User"
    },
    "html_url": "https://github.com/myorg/myrepo/pull/42"
  },
  "repository": {
    "id": 1234567,
    "full_name": "myorg/myrepo",
    "private": false,
    "html_url": "https://github.com/myorg/myrepo"
  },
  "sender": {
    "login": "octocat",
    "id": 1,
    "type": "User"
  }
}
```

### Response

**Success (200)**:
```json
{
  "status": "queued",
  "review_id": "550e8400-e29b-41d4-a716-446655440000",
  "message": "Review queued for processing"
}
```

**Errors**:

| Code | Reason |
|------|--------|
| 400 | Invalid JSON or missing required fields |
| 401 | Invalid webhook signature |
| 400 | Repository not configured in CodeScan |
| 200 | Repository disabled (silently ignored) |

---

## 🦊 GitLab Webhook

**Endpoint**: `POST /api/v1/webhooks/gitlab`

**Signature Header**: `X-Gitlab-Token: {secret}`

**Supported Events**:
- `merge_request` (action: `open`, `update`)
- `issues` (action: `open`, `update`)

### Request Format

```bash
curl -X POST https://your-codescan/api/v1/webhooks/gitlab \
  -H "Content-Type: application/json" \
  -H "X-Gitlab-Token: your-webhook-secret" \
  -d '{...webhook payload...}'
```

### Merge Request Payload Example

```json
{
  "object_kind": "merge_request",
  "event_type": "merge_request",
  "user": {
    "id": 12,
    "name": "Administrator",
    "username": "root",
    "avatar_url": "https://gravatar.com/avatar/xxx"
  },
  "project": {
    "id": 3,
    "name": "Hello World",
    "path_with_namespace": "myorg/myrepo"
  },
  "object_attributes": {
    "id": 142,
    "iid": 1,
    "title": "Test merge request",
    "description": "This is a test MR",
    "state": "opened",
    "created_at": "2025-03-10T10:00:00Z",
    "updated_at": "2025-03-10T10:00:00Z",
    "target_branch": "main",
    "source_branch": "feature-branch",
    "url": "https://gitlab.example.com/myorg/myrepo/-/merge_requests/1",
    "source": {
      "id": 3,
      "name": "Hello World",
      "path_with_namespace": "myorg/myrepo"
    }
  }
}
```

### Response

Same format as GitHub (200 OK or error code).

---

## 🔍 Review Status Endpoints

These endpoints query review history and status.

### Get Review

**Endpoint**: `GET /api/v1/reviews/{review_id}`

**Auth**: JWT bearer token required

**Response (200)**:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "platform": "github",
  "repo_full_name": "myorg/myrepo",
  "pr_number": 42,
  "pr_title": "Add database migration",
  "pr_url": "https://github.com/myorg/myrepo/pull/42",
  "status": "completed",
  "review_result": {
    "security": {
      "findings": [
        {
          "severity": "major",
          "title": "SQL Injection Risk",
          "description": "User input not escaped in query"
        }
      ]
    },
    "best_practices": {
      "findings": [
        {
          "severity": "minor",
          "title": "Missing type hints",
          "description": "Function parameters lack type annotations"
        }
      ]
    },
    "framework": {"findings": []},
    "iac": {"findings": []}
  },
  "triggered_by": "550e8400-e29b-41d4-a716-446655440001",
  "created_at": "2025-03-10T10:00:00Z",
  "completed_at": "2025-03-10T10:02:30Z",
  "tenant_id": "550e8400-e29b-41d4-a716-446655440002"
}
```

### List Reviews

**Endpoint**: `GET /api/v1/reviews`

**Auth**: JWT bearer token required

**Query Parameters**:
- `repo_full_name` (optional): Filter by repository
- `status` (optional): `pending`, `processing`, `completed`, `failed`
- `limit` (optional): Max results (default 50)
- `offset` (optional): Pagination offset

**Response (200)**:
```json
{
  "reviews": [...],
  "total": 150,
  "limit": 50,
  "offset": 0
}
```

---

## 📋 Repository Configuration

### List Repositories

**Endpoint**: `GET /api/v1/repositories`

**Auth**: JWT bearer token required

**Response (200)**:
```json
{
  "repositories": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "platform": "github",
      "full_name": "myorg/myrepo",
      "enabled": true,
      "ai_provider": "claude",
      "categories_enabled": {
        "security": true,
        "best_practices": true,
        "framework": true,
        "iac": false
      },
      "created_at": "2025-03-01T00:00:00Z"
    }
  ]
}
```

### Create Repository Configuration

**Endpoint**: `POST /api/v1/repositories`

**Auth**: JWT bearer token + admin role

**Request Body**:
```json
{
  "platform": "github",
  "full_name": "myorg/newrepo",
  "enabled": true,
  "webhook_secret": "your-webhook-secret-from-github",
  "ai_provider": "claude",
  "categories_enabled": {
    "security": true,
    "best_practices": true,
    "framework": true,
    "iac": false
  }
}
```

**Response (201)**:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "platform": "github",
  "full_name": "myorg/newrepo",
  "enabled": true,
  "ai_provider": "claude",
  "categories_enabled": {...}
}
```

### Update Repository

**Endpoint**: `PATCH /api/v1/repositories/{repo_id}`

**Auth**: JWT bearer token + admin role

**Request Body** (any subset):
```json
{
  "enabled": false,
  "categories_enabled": {
    "security": true,
    "best_practices": false,
    "framework": true,
    "iac": true
  }
}
```

**Response (200)**: Updated repository object

---

## 🎯 Error Responses

All error responses follow this format:

```json
{
  "error": "Error code",
  "message": "Human-readable description",
  "details": {}
}
```

### Common HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Created |
| 400 | Bad request (invalid JSON, missing fields) |
| 401 | Unauthorized (missing/invalid JWT, webhook secret) |
| 403 | Forbidden (insufficient permissions) |
| 404 | Not found (review, repo not found) |
| 429 | Rate limited (too many requests) |
| 500 | Internal server error |

### Example Error

```json
{
  "error": "INVALID_SIGNATURE",
  "message": "Webhook signature verification failed",
  "details": {
    "expected_signature": "sha256=abc123...",
    "received_signature": "sha256=def456..."
  }
}
```

---

## 🔑 Authentication

### JWT Token Format

All API requests (except webhooks) require a JWT bearer token:

```bash
curl -H "Authorization: Bearer eyJhbGc..." \
     https://your-codescan/api/v1/reviews
```

**Token Claims**:
```json
{
  "sub": "user-id",
  "iat": 1234567890,
  "exp": 1234571490,
  "tenant_id": "tenant-uuid",
  "roles": ["admin", "maintainer"],
  "scopes": ["reviews:read", "reviews:write"]
}
```

### Webhook Secret Validation

**GitHub**: HMAC-SHA256 with `sha256=` prefix in header

```python
# Verification
expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
assert hmac.compare_digest(signature[7:], expected)  # Remove 'sha256=' prefix
```

**GitLab**: HMAC-SHA256 token directly in header

```python
# Verification
expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
assert hmac.compare_digest(token, expected)
```

---

## 📊 Metrics Endpoint

**Endpoint**: `GET /metrics`

**Auth**: No authentication required (or internal network only)

**Format**: Prometheus plain text

**Example Output**:
```
codescan_reviews_total{platform="github"} 1234
codescan_reviews_duration_seconds_sum{platform="github"} 3456.7
codescan_reviews_duration_seconds_count{platform="github"} 123
codescan_ai_tokens_used{provider="claude"} 456789
codescan_cost_uusd 12345
```

---

## 🏥 Health Check

**Endpoint**: `GET /healthz`

**Auth**: No authentication

**Response (200)**:
```json
{
  "status": "healthy",
  "database": "connected",
  "redis": "connected",
  "ai_provider": "connected"
}
```

---

## ⚙️ Configuration Endpoints

### Get Current Configuration

**Endpoint**: `GET /api/v1/config`

**Auth**: JWT bearer token

**Response (200)**:
```json
{
  "ai_provider": "claude",
  "categories_enabled": {
    "security": true,
    "best_practices": true,
    "framework": true,
    "iac": true
  },
  "max_reviews_per_day": 100,
  "max_monthly_cost_uusd": 10000,
  "version": "1.0.0"
}
```

---

**Last Updated**: 2025-03-10
**Version**: 1.0.0
