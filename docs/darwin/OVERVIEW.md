# Darwin - AI-Powered Code Review Module

**Audience:** Developers | DevOps | Admins

---

## 📋 What is Darwin?

Darwin is a licensed AI-powered code review and issue planning sub-module for SkausWatch. It automatically analyzes pull requests and issues on GitHub and GitLab, providing intelligent feedback via configured AI providers (Claude, OpenAI, or self-hosted Ollama). Darwin helps teams maintain code quality, security, and consistency at scale.

**Key Capabilities:**
- 🤖 Automated PR code review (security, best practices, framework patterns, IaC)
- 📋 Auto-generated issue implementation plans
- 🔗 Multi-platform integration (GitHub + GitLab webhooks)
- 💰 Cost controls (daily/monthly limits)
- 👥 Multi-tenancy with RBAC (Admin, Maintainer, Viewer)
- 📊 Audit logging and analytics

---

## 🏗️ Darwin Services & Quick Reference

| Service | Port | Language | Framework | Purpose |
|---------|------|----------|-----------|---------|
| **Flask Backend** (`services/worker-darwin/`) | 5000 | Python 3.13 | Flask/Quart | REST API, webhook handlers, review orchestration |
| **Celery Worker** (`services/worker-darwin-celery/`) | — | Python 3.13 | Celery | Async review processing, plan generation |
| **WebUI** (`services/webui/`) | 3000 | Node.js 18 | React + TS | Dashboard, review management, settings |
| **PostgreSQL** (shared) | 5432 | — | — | Reviews, issues, users, audit logs |
| **Redis** (shared) | 6379 | — | — | Job queue, caching, Celery broker |

---

## 🎯 Review Categories

Darwin analyzes code across four configurable categories:

| Category | Focus | Examples |
|----------|-------|----------|
| **Security** | Vulnerability detection | SQL injection, XSS, hardcoded secrets, OWASP Top 10 |
| **Best Practices** | Code quality & patterns | DRY, SOLID principles, design patterns, naming |
| **Framework** | Framework-specific rules | Django/Flask patterns, React hooks, Go idioms |
| **IaC** | Infrastructure as Code | Terraform, CloudFormation, Kubernetes, security policies |

---

## 🤖 AI Provider Options

Darwin supports multiple AI backends for flexibility:

| Provider | Model Options | Setup | Cost | Best For |
|----------|---------------|-------|------|----------|
| **Claude** | Sonnet 4.5, Opus, Haiku | API key | $3-15/1M input tokens | Production, large context |
| **OpenAI** | GPT-4o, o1-preview, Mini | API key | $0.15-15/1M input tokens | Cost-conscious, fast |
| **Ollama** | Granite, Codestral, Llama | Self-hosted | Hardware only | Private, on-premise, offline |

---

## 🔗 Integration Points

Darwin integrates with:
- **GitHub** — Webhooks on PR open/update, issue open, comment posting
- **GitLab** — Webhooks on merge request open/update, issue open
- **SkausWatch Core** — Shared PostgreSQL database and Redis
- **License Server** — Feature gating (`darwin` feature required)

---

## 📂 Documentation Index

Complete Darwin documentation is organized by topic. Start with your role:

### 👨‍💻 For Developers

| File | Purpose |
|------|---------|
| [**USAGE.md**](./USAGE.md) | Getting started, prerequisites, webhook configuration, starting Darwin |
| [**ARCHITECTURE.md**](./ARCHITECTURE.md) | System design, workflow, integration patterns, data flow diagrams |
| [**API.md**](./API.md) | Webhook endpoints, request/response formats, authentication, error codes |

### 🛠️ For Operations & DevOps

| File | Purpose |
|------|---------|
| [**CONFIGURATION.md**](./CONFIGURATION.md) | Environment variables, provider setup, per-variable reference table |
| [**TESTING.md**](./TESTING.md) | Mock webhook payloads, test patterns, AI provider mocking, test execution |
| [**TROUBLESHOOTING.md**](./TROUBLESHOOTING.md) | Common issues, error diagnosis, rate limits, connectivity problems |

### 📚 For Project Managers & Release

| File | Purpose |
|------|---------|
| [**RELEASE_NOTES.md**](./RELEASE_NOTES.md) | Version history, breaking changes, known limitations |

---

## ⚡ Quick Start

### 1. Deploy Darwin

```bash
# Using Kustomize (alpha/local)
kubectl apply --context local-alpha -k k8s/kustomize/overlays/alpha

# Or using Helm (beta/production)
helm upgrade --install darwin ./k8s/helm/darwin \
  --kube-context dal2-beta --namespace skauswatch \
  --values ./k8s/helm/darwin/values-beta.yaml
```

### 2. Configure AI Provider

Set environment variables (see [CONFIGURATION.md](./CONFIGURATION.md)):

```bash
# Example: Claude
DARWIN_AI_PROVIDER=claude
ANTHROPIC_API_KEY=sk-ant-xxx

# Or: OpenAI
DARWIN_AI_PROVIDER=openai
OPENAI_API_KEY=sk-xxx
```

### 3. Add Webhook to GitHub Repo

1. Go to **Settings > Webhooks > Add webhook**
2. **Payload URL**: `https://your-darwin-instance/api/v1/webhooks/github`
3. **Content type**: `application/json`
4. **Events**: Pull Requests, Issues
5. **Secret**: Set `DARWIN_GITHUB_WEBHOOK_SECRET` in Darwin config

### 4. Test Review

Open a PR in your repository. Darwin will automatically analyze it and post comments.

---

## 🔐 License & Availability

**License Requirement**: Darwin requires the `darwin` feature in your PenguinTech license key.

**Feature Availability:**
- ✅ Included in: Enterprise+ license tiers
- ❌ Not included in: Community/Open Source licenses
- 🔄 Trial: 30-day trial available (contact sales@penguintech.io)

---

## 📞 Support & Resources

- **Documentation**: See links above
- **Support Email**: support@penguintech.io
- **Sales**: sales@penguintech.io
- **Community**: GitHub Discussions (penguintechinc/skauswatch)
- **Status**: https://status.penguintech.io

---

## 📊 Key Metrics

Darwin tracks the following metrics:

- **Reviews per day**: Number of code reviews completed
- **Average review time**: Time from webhook trigger to comment posting
- **AI provider usage**: Token consumption by provider
- **Cost tracking**: Monthly AI spending vs configured limits
- **Plan generation success rate**: % of issues with successful plan generation

---

**Last Updated**: 2025-03-10
**Version**: 1.0.0
