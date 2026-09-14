# CodeScan - Testing Guide

**Audience:** Developers | DevOps | Admins

---

## 🧪 Testing Strategy

CodeScan testing covers three levels:

1. **Unit Tests** — Individual functions, mocked dependencies
2. **Integration Tests** — Component interactions (DB, webhooks, AI)
3. **Smoke Tests** — Build, runtime, endpoint health

---

## 🏃 Running Tests

### Run All Tests

```bash
cd codescan
make test                    # Run all test suites
make test-unit              # Unit tests only
make test-integration       # Integration tests only
make test-smoke             # Smoke tests (build, run, API endpoints)
```

### Run Specific Test

```bash
# Run tests for webhook handler
pytest services/flask-backend/tests/test_webhooks.py -v

# Run test for GitHub signature verification
pytest services/flask-backend/tests/test_webhooks.py::test_verify_github_signature -v

# Run with coverage
pytest services/flask-backend/tests/ --cov=services/flask-backend/app
```

---

## 📝 Unit Tests

### Webhook Signature Verification

Test HMAC-SHA256 validation for GitHub and GitLab webhooks.

**File**: `services/flask-backend/tests/test_webhooks.py`

```python
import hashlib
import hmac
import json
from app.api.v1.webhooks import verify_github_signature, verify_gitlab_signature

def test_verify_github_signature_valid():
    """Test GitHub signature verification with valid signature."""
    secret = "test-secret-12345"
    payload = json.dumps({"action": "opened", "pull_request": {}}).encode()

    # Calculate valid signature
    signature = "sha256=" + hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()

    # Should verify successfully
    assert verify_github_signature(payload, signature, secret) == True

def test_verify_github_signature_invalid():
    """Test GitHub signature verification with invalid signature."""
    secret = "test-secret-12345"
    payload = json.dumps({"action": "opened"}).encode()
    invalid_signature = "sha256=invalid123"

    # Should reject invalid signature
    assert verify_github_signature(payload, invalid_signature, secret) == False

def test_verify_gitlab_signature_valid():
    """Test GitLab signature verification."""
    secret = "gitlab-secret"
    payload = json.dumps({"object_kind": "merge_request"}).encode()

    # Calculate valid signature
    signature = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    # Should verify successfully
    assert verify_gitlab_signature(payload, signature, secret) == True
```

### AI Provider Mocking

Mock AI providers to avoid real API calls during testing.

**File**: `services/flask-backend/tests/conftest.py`

```python
import pytest
from unittest.mock import Mock, patch

@pytest.fixture
def mock_claude_provider():
    """Mock Claude AI provider."""
    with patch('app.providers.claude.ClaudeProvider') as mock:
        provider = Mock()
        provider.analyze_diff.return_value = {
            "security": {
                "findings": [
                    {
                        "severity": "minor",
                        "title": "Missing type hints",
                        "description": "Function parameters lack type annotations"
                    }
                ]
            }
        }
        mock.return_value = provider
        yield provider

def test_review_with_mocked_ai(mock_claude_provider):
    """Test review creation with mocked AI provider."""
    from app.models import create_review

    # Mock AI to return predefined feedback
    result = create_review(
        platform="github",
        repo_full_name="test/repo",
        pr_number=1,
        pr_title="Test PR",
        pr_url="https://github.com/test/repo/pull/1"
    )

    assert result["status"] == "completed"
```

### Database Tests

Test database operations with test database.

**File**: `services/flask-backend/tests/test_models.py`

```python
import pytest
from app.models import create_review, get_review

@pytest.fixture
def test_db():
    """Create test database."""
    from app.db import get_db
    db = get_db("sqlite:///:memory:")
    yield db
    db.close()

def test_create_review(test_db):
    """Test creating a review in database."""
    review = create_review(
        db=test_db,
        platform="github",
        repo_full_name="test/repo",
        pr_number=42,
        pr_title="Add feature",
        pr_url="https://github.com/test/repo/pull/42"
    )

    assert review["id"] is not None
    assert review["status"] == "pending"
    assert review["repo_full_name"] == "test/repo"

def test_get_review(test_db):
    """Test retrieving a review."""
    # Create review
    created = create_review(
        db=test_db,
        platform="github",
        repo_full_name="test/repo",
        pr_number=42,
        pr_title="Add feature",
        pr_url="https://github.com/test/repo/pull/42"
    )

    # Retrieve review
    retrieved = get_review(test_db, created["id"])

    assert retrieved["id"] == created["id"]
    assert retrieved["pr_number"] == 42
```

---

## 🔌 Integration Tests

### Webhook Integration Test

Test full webhook flow: receive → queue → process.

**File**: `services/flask-backend/tests/test_integration_webhooks.py`

```python
import json
from unittest.mock import patch
from app import create_app

@pytest.fixture
def app():
    """Create Flask app for testing."""
    app = create_app()
    with app.app_context():
        yield app

@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()

def test_github_webhook_integration(client, mock_claude_provider):
    """Test full GitHub webhook flow."""
    webhook_secret = "test-secret"

    # Create webhook payload
    payload = {
        "action": "opened",
        "pull_request": {
            "number": 42,
            "title": "Add feature",
            "body": "This PR adds...",
            "head": {"sha": "abc123", "ref": "feature"},
            "base": {"sha": "def456", "ref": "main"},
            "user": {"login": "testuser"},
            "html_url": "https://github.com/test/repo/pull/42"
        },
        "repository": {
            "full_name": "test/repo",
            "html_url": "https://github.com/test/repo"
        },
        "sender": {"login": "testuser"}
    }

    payload_json = json.dumps(payload)
    payload_bytes = payload_json.encode()

    # Calculate signature
    import hashlib, hmac
    signature = "sha256=" + hmac.new(
        webhook_secret.encode(), payload_bytes, hashlib.sha256
    ).hexdigest()

    # Post webhook
    response = client.post(
        "/api/v1/webhooks/github",
        data=payload_json,
        content_type="application/json",
        headers={"X-Hub-Signature-256": signature, "X-GitHub-Event": "pull_request"}
    )

    # Should succeed
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["status"] == "queued"
    assert "review_id" in data
```

### Repository Configuration Test

```python
def test_repository_creation(client):
    """Test creating repository configuration."""
    response = client.post(
        "/api/v1/repositories",
        json={
            "platform": "github",
            "full_name": "test/repo",
            "enabled": True,
            "webhook_secret": "secret-12345",
            "ai_provider": "claude",
            "categories_enabled": {
                "security": True,
                "best_practices": True,
                "framework": False,
                "iac": False
            }
        },
        headers={"Authorization": "Bearer test-token"}
    )

    assert response.status_code == 201
    data = json.loads(response.data)
    assert data["full_name"] == "test/repo"
    assert data["enabled"] == True
```

---

## 🔬 Mock Webhook Payloads

### GitHub Pull Request Webhook

Save as `tests/fixtures/github_pr_webhook.json`:

```json
{
  "action": "opened",
  "number": 42,
  "pull_request": {
    "id": 1234567,
    "number": 42,
    "title": "Add database migration",
    "body": "This PR adds a migration for user profiles table.",
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

### GitHub Issue Webhook

```json
{
  "action": "opened",
  "issue": {
    "number": 123,
    "title": "Implement user authentication",
    "body": "Add JWT-based authentication to the API.",
    "state": "open",
    "created_at": "2025-03-10T10:00:00Z",
    "user": {
      "login": "octocat"
    },
    "html_url": "https://github.com/myorg/myrepo/issues/123"
  },
  "repository": {
    "full_name": "myorg/myrepo"
  },
  "sender": {
    "login": "octocat"
  }
}
```

### GitLab Merge Request Webhook

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
    "url": "https://gitlab.example.com/myorg/myrepo/-/merge_requests/1"
  }
}
```

---

## 🚀 Smoke Tests

Smoke tests verify CodeScan can start, respond to health checks, and process basic operations.

### Run Smoke Tests

```bash
make smoke-test             # All smoke tests
make smoke-test-build       # Docker build only
make smoke-test-startup     # Service startup
make smoke-test-api         # API endpoints
```

### Build Test

Verify Docker image builds without errors:

```bash
docker build -t codescan-test:latest ./services/worker-codescan
docker build -t codescan-webui-test:latest ./services/webui
```

### Startup Test

Verify services start successfully:

```bash
# Run with Docker Compose
docker-compose up -d postgres redis codescan-backend codescan-worker

# Check logs
docker-compose logs codescan-backend | head -50

# Verify running
docker-compose ps | grep codescan
```

### API Endpoint Test

Verify key endpoints respond:

```bash
# Health check
curl -s http://localhost:5000/healthz | jq .

# Metrics endpoint
curl -s http://localhost:5000/metrics | head -20

# Config endpoint (requires token - may fail with 401)
curl -s -H "Authorization: Bearer test" \
  http://localhost:5000/api/v1/config | jq .
```

---

## 🧬 AI Provider Testing

### Test with Mock Provider

```python
def test_review_with_mock_ai():
    """Test review processing with mocked AI."""
    with patch('app.providers.claude.ClaudeProvider') as mock_provider:
        # Configure mock
        mock_instance = Mock()
        mock_instance.analyze_diff.return_value = {
            "security": {"findings": []},
            "best_practices": {
                "findings": [{"severity": "minor", "title": "Test"}]
            },
            "framework": {"findings": []},
            "iac": {"findings": []}
        }
        mock_provider.return_value = mock_instance

        # Run review
        from app.tasks.review_worker import process_review
        result = process_review(pr_diff="...")

        # Verify
        assert result["status"] == "completed"
```

### Test Ollama Connectivity

```bash
# Verify Ollama is running
curl -s http://localhost:11434/api/tags

# Test model available
curl -s http://localhost:11434/api/tags | jq '.models[] | .name'

# Pull model if missing
curl -X POST http://localhost:11434/api/pull -d '{"name": "granite-code:20b"}'
```

---

## 📊 Coverage Requirements

Minimum test coverage expectations:

- **Core functions**: >90% coverage
- **API endpoints**: >85% coverage
- **Webhook handlers**: >95% coverage (security critical)
- **Integration points**: >80% coverage

Run coverage report:

```bash
pytest services/flask-backend/tests/ \
  --cov=services/flask-backend/app \
  --cov-report=html \
  --cov-report=term

# View HTML report
open htmlcov/index.html
```

---

## ✅ Pre-Commit Test Checklist

Before committing, run:

```bash
# 1. Unit tests
make test-unit

# 2. Integration tests
make test-integration

# 3. Linting
make lint

# 4. Security scan
make security-scan

# 5. Smoke tests (build, startup, API)
make smoke-test
```

---

**Last Updated**: 2025-03-10
**Version**: 1.0.0
