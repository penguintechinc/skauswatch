[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/penguintechinc/darwin)
[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0+-blue.svg)](https://flask.palletsprojects.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-blue.svg)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker-Multi--arch-blue.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-Limited%20AGPL3-blue.svg)](LICENSE.md)

<div align="center">
  <img src="./darwin-logo.png" alt="Darwin Logo" width="200" height="200">
</div>

# 🧬 Darwin - Intelligent Code Review & Issue Planning

**Enterprise-Grade AI Code Review with GitHub/GitLab Integration**

Darwin is an intelligent code review and issue planning system that leverages Claude AI to automatically analyze pull requests, generate comprehensive implementation plans, and maintain code quality. Built with enterprise multi-tenancy, role-based access control, and seamless platform integration for GitHub and GitLab.
## ✨ Core Features

### 🤖 AI-Powered Code Review
- **Automated PR Analysis**: Claude AI analyzes pull requests across multiple categories (security, best practices, framework patterns, infrastructure)
- **Intelligent Feedback**: Context-aware suggestions with severity levels (critical, major, minor, suggestion)
- **Multi-Platform Support**: Native GitHub and GitLab webhook integration with platform identity mapping
- **Configurable Reviews**: Per-repository settings for review triggers, AI models, and analysis categories

### 📋 Issue Planning Automation
- **Auto-Generated Plans**: Claude automatically generates implementation plans for new GitHub/GitLab issues
- **Step-by-Step Guidance**: Detailed breakdowns with task dependencies and effort estimates
- **Cost & Rate Controls**: Configurable daily limits and monthly cost caps to manage AI spending
- **Platform Comments**: Automatically posts plans back to issues with status updates

### 👥 Enterprise Multi-Tenancy
- **Tenant Isolation**: Complete data isolation across organizations
- **Team Management**: Flexible team structures with repository-level memberships
- **RBAC System**: Admin, Maintainer, and Viewer roles with custom role support
- **Audit Logging**: Comprehensive activity tracking for compliance

### 🔗 External Account Mapping
- **Platform Identities**: Link GitHub/GitLab users to Darwin accounts for accurate attribution
- **User Resolution**: Webhooks automatically resolve code reviewers to Darwin users
- **Review Attribution**: Track who triggered reviews across platforms

### 🏢 Enterprise Features
- **License Integration**: PenguinTech License Server with feature gating
- **Multi-AI Support**: Claude, OpenAI, and Ollama provider support
- **Scalable Architecture**: Flask backend + React WebUI + PostgreSQL
- **Production Ready**: Kubernetes deployment with Helm charts included

## 🚀 Quick Start

### Local Development
```bash
# Clone repository
git clone https://github.com/penguintechinc/darwin.git
cd darwin

# Setup and run
make setup                    # Install dependencies
make dev                      # Start Docker Compose stack
```

Services available after startup:
- **API**: http://localhost:5000
- **WebUI**: http://localhost:3000
- **Database**: PostgreSQL on localhost:5432
- **Adminer**: http://localhost:8080 (DB management)

### Default Credentials
- **Email**: admin@localhost.local
- **Password**: admin123

### Test the System
```bash
make test-alpha              # Run smoke tests (build, runtime, mock data, API, page load)
```

## 🏗️ Architecture

### Three-Container Design
- **Flask Backend** (`services/flask-backend`): Python 3.13, PyDAL ORM, SQLAlchemy migrations
- **WebUI** (`services/webui`): React + TypeScript, role-based UI
- **Database**: PostgreSQL 15+ with Alembic version control

### API Design
- RESTful endpoints at `/api/v1/*`
- JWT authentication with role-based access control
- Multi-tenancy support via `tenant_id` in requests
- Comprehensive error handling with structured responses

### Key Files
- `services/flask-backend/app/db_schema.py` - SQLAlchemy schema definitions
- `services/flask-backend/app/models.py` - PyDAL runtime models + helpers
- `services/flask-backend/app/api/v1/` - API endpoints (reviews, webhooks, identities, etc.)
- `services/webui/src/client/` - React components and API client

## 🔌 Webhook Integration

### GitHub Integration
1. Create webhook at `https://github.com/{owner}/{repo}/settings/hooks`
2. Payload URL: `https://your-darwin-instance/api/v1/webhooks/github`
3. Content type: `application/json`
4. Events: Pull requests, Issues
5. Set webhook secret in repository config

### GitLab Integration
1. Create webhook at `https://gitlab.com/{group}/{project}/-/hooks`
2. Payload URL: `https://your-darwin-instance/api/v1/webhooks/gitlab`
3. Events: Push, Issues, Merge requests
4. Secret token: Set in repository config

### Platform Identity Mapping
Link external users to Darwin accounts:
```bash
POST /api/v1/platform-identities
{
  "platform": "github",
  "platform_username": "octocat",
  "platform_user_id": "1",
  "platform_avatar_url": "https://..."
}
```

## ☸️ Kubernetes Deployment

### Quick Start
```bash
# Deploy to development (Kustomize)
make k8s-deploy-dev

# Or deploy using Helm
make helm-install-dev

# Check status
make k8s-status-dev

# Verify deployment
./scripts/k8s-verify.sh
```

See [docs/KUBERNETES.md](docs/KUBERNETES.md) for comprehensive deployment guide.

## 📖 Documentation

- **Development Setup**: [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)
- **Testing Guide**: [docs/TESTING.md](docs/TESTING.md)
- **Pre-Commit Checklist**: [docs/PRE_COMMIT.md](docs/PRE_COMMIT.md)
- **Kubernetes Deployment**: [docs/KUBERNETES.md](docs/KUBERNETES.md)
- **Architecture & Standards**: [docs/STANDARDS.md](docs/STANDARDS.md)
- **API Tests**: [tests/alpha/05-api-test.sh](tests/alpha/05-api-test.sh)

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Maintainers
- **Company**: [www.penguintech.io](https://www.penguintech.io)
- **Support Email**: support@penguintech.io
- **Sales Email**: sales@penguintech.io

## 🧪 Testing

Darwin includes comprehensive test suites:

### Alpha Tests (Build & Runtime)
```bash
make test-alpha              # All 5 tests (01-05)
make test-alpha-01          # Build test only
make test-alpha-03          # Mock data integrity
make test-alpha-05          # API endpoint verification
```

### Test Coverage
- **Smoke Tests**: Docker build, service startup, page load
- **API Tests**: Review creation, webhook simulation, identity management
- **Mock Data**: 3 users × 3 reviews each with proper schema compliance
- **Integration Tests**: Webhook→review flow with user resolution

## 📊 Monitoring & Observability

- **Health Checks**: `/healthz` and `/readyz` endpoints
- **Prometheus Metrics**: `/metrics` endpoint for Grafana integration
- **Structured Logging**: Timestamped debug and error logs
- **Database Migrations**: Alembic version control with automatic upgrades

## 💡 Key Implementation Details

### Review-User Association
Reviews now track who triggered them via the `triggered_by` foreign key. Webhook handlers resolve external platform users (GitHub/GitLab) to Darwin users using the `platform_identities` table.

### Multi-Tenancy
- Reviews inherit `tenant_id` and `team_id` from repository configuration
- List operations scope results to authenticated user's tenant
- Repository-level access control via `repository_members` table

### Schema Synchronization
Darwin uses a dual-ORM pattern:
- **SQLAlchemy** (`db_schema.py`): Schema creation and Alembic migrations
- **PyDAL** (`models.py`): Runtime queries and business logic
Both must stay synchronized or columns become invisible to application code.

## 📄 License

This project is licensed under the Limited AGPL3 with preamble for fair use - see [LICENSE.md](LICENSE.md) for details.

**License Highlights:**
- **Personal & Internal Use**: Free under AGPL-3.0
- **Commercial Use**: Requires commercial license
- **SaaS Deployment**: Requires commercial license if providing as a service

### Contributor Employer Exception

Companies employing official contributors receive GPL-2.0 access to community features with perpetual rights to contributed versions. See [LICENSE.md](LICENSE.md) for full terms.
