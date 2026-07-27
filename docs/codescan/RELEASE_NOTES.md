# CodeScan - Release Notes

**Audience:** DevOps | Product | Engineering

---

## 📋 Version History

---

## v1.0.0 — Initial Release (2025-03-10)

**Status**: ✅ Production Ready

Initial release of CodeScan as a licensed sub-module for SkausWatch.

### 🎉 New Features

- 🤖 **AI-Powered Code Review**
  - Multi-provider support: Claude, OpenAI, Ollama
  - Four review categories: Security, Best Practices, Framework, IaC
  - Configurable per-repository settings
  - Severity-based findings (critical, major, minor, suggestion)

- 📋 **Issue Planning Automation**
  - Auto-generate implementation plans from issues
  - Daily and monthly cost controls
  - Step-by-step task breakdown with effort estimates

- 🔗 **Platform Integration**
  - GitHub webhook support (PR, Issue events)
  - GitLab webhook support (MR, Issue events)
  - Webhook secret validation (HMAC-SHA256)
  - HTTPS required for webhooks

- 👥 **Multi-Tenancy & RBAC**
  - Full tenant isolation
  - Role-based access control (Admin, Maintainer, Viewer)
  - Team-scoped repositories
  - Audit logging of all review activity

- 📊 **Analytics & Monitoring**
  - Review processing metrics (Prometheus)
  - Cost tracking per tenant/team
  - Health check endpoints
  - Structured JSON logging

- ⚙️ **Enterprise Features**
  - PenguinTech License Server integration
  - Feature gating (`codescan` license feature)
  - Configurable cost limits
  - Multi-language support (Python, Go, JavaScript, etc.)

### 🏗️ Architecture

- **Flask Backend** (Python 3.13 + Quart)
- **Celery Workers** (async review processing)
- **WebUI** (React + TypeScript)
- **PostgreSQL** (shared with SkausWatch)
- **Redis** (job queue, caching)

### 📝 API Endpoints

- `POST /api/v1/webhooks/github` — GitHub webhook receiver
- `POST /api/v1/webhooks/gitlab` — GitLab webhook receiver
- `GET /api/v1/reviews` — List reviews
- `GET /api/v1/reviews/{id}` — Get review details
- `GET /api/v1/repositories` — List configured repositories
- `POST /api/v1/repositories` — Create repository config
- `GET /healthz` — Health check
- `GET /metrics` — Prometheus metrics

### ✨ Default Configuration

```
AI Provider:           claude
Security Reviews:      enabled
Best Practices:        enabled
Framework Reviews:     enabled
IaC Reviews:           enabled
Max Reviews/Day:       1000
Max Monthly Cost:      $1000
Webhook Secret Req:    yes (HMAC-SHA256)
```

### 📚 Documentation

- [OVERVIEW.md](./OVERVIEW.md) — Quick reference & architecture
- [USAGE.md](./USAGE.md) — Getting started & deployment
- [ARCHITECTURE.md](./ARCHITECTURE.md) — System design details
- [API.md](./API.md) — Endpoint reference
- [CONFIGURATION.md](./CONFIGURATION.md) — Environment variables
- [TESTING.md](./TESTING.md) — Test strategy & examples
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) — Common issues & solutions

### 🔐 Security

- HMAC-SHA256 webhook validation
- JWT bearer token authentication
- Per-service database accounts
- Audit logging of all operations
- No secrets in logs
- TLS 1.2+ enforced

### 🛠️ Known Limitations

1. **Large Diffs**
   - Diffs > 500KB are truncated for analysis
   - Increase `REVIEW_MAX_DIFF_SIZE_KB` with caution (impacts latency/cost)

2. **Rate Limits**
   - Claude: 1000 req/min (standard), 40K req/day
   - OpenAI: Depends on plan (typically 3,500 req/min)
   - Ollama: Local only, no external rate limits

3. **Language Support**
   - All languages supported via text analysis
   - Language-specific linters not integrated (future)

4. **Webhook Events**
   - PR open/update, Issue open/update only
   - Push events not analyzed

5. **Comment Formatting**
   - Basic markdown formatting
   - Syntax highlighting may be limited

### 🔄 Migration from Beta

No migration needed. v1.0.0 is the first release.

### 📦 Dependencies

**Python 3.13+**
- Flask 3.0+
- SQLAlchemy + Alembic
- PyDAL
- Celery + Redis
- anthropic, openai (API clients)
- pytest (testing)

**Node.js 18+**
- React 18
- TypeScript
- Tailwind CSS
- @tanstack/react-query

### 🙏 Acknowledgments

CodeScan was built by the Penguin Tech Inc engineering team.

Special thanks to:
- Anthropic for Claude API
- OpenAI for GPT models
- Ollama project for local LLM support

---

## 🚀 Roadmap

### Q2 2025 (Planned)

- **v1.1.0**
  - Language-specific linters integration
  - Custom review prompts per repository
  - Review templates/presets
  - Comment summarization (reduce verbosity)
  - Batch review processing

- **v1.2.0**
  - Slack/Discord integration for review notifications
  - JIRA/Linear integration for auto-issue creation
  - Performance profiling (identify slow reviews)
  - Advanced metrics dashboard
  - Custom webhooks

### Q3 2025 (Future)

- **v2.0.0** (Breaking Changes)
  - Remove deprecated v1.x API endpoints
  - New ML-based confidence scoring
  - Real-time review streaming
  - Multi-model ensemble reviews
  - GraphQL API option

---

## 🐛 Bug Fixes

### v1.0.0 (2025-03-10)

**Fixed in Initial Release:**
- Initial release, no bug fixes

---

## ⚠️ Breaking Changes

### v1.0.0

- None (initial release)

---

## 📈 Performance Benchmarks (v1.0.0)

### Review Processing Times

| Model | Avg Time | Tokens | Cost |
|-------|----------|--------|------|
| Claude Sonnet 4.5 | 15-25s | ~2.5K in, 500 out | $0.01 |
| GPT-4o | 10-20s | ~2.5K in, 500 out | $0.01 |
| Claude Haiku 4 | 5-15s | ~2.5K in, 500 out | $0.003 |
| Ollama granite:20b | 30-60s | N/A | $0 |

### Throughput

- **Single Worker**: 4-6 reviews/minute
- **3 Workers**: 12-18 reviews/minute
- **Queue Depth**: <1s latency with <100 pending

### Scalability

- Horizontal: Both Flask backend and Celery workers scale independently
- Vertical: Tested up to 20 concurrent reviews

---

## 📞 Support & Feedback

- **Report Bugs**: GitHub Issues (penguintechinc/skauswatch)
- **Feature Requests**: GitHub Discussions
- **Commercial Support**: support@penguintech.io
- **Sales Inquiries**: sales@penguintech.io

---

## 📄 License

CodeScan is a licensed feature under SkausWatch.

**License Types:**
- ✅ Community Edition: Not available
- ✅ Enterprise Edition: Included (requires `codescan` feature)
- ✅ Trial: 30 days available upon request

---

## 🔗 Related Documentation

- [SkausWatch README](../../README.md)
- [SkausWatch APP_STANDARDS.md](../APP_STANDARDS.md)
- [License Server Integration](../licensing/license-server-integration.md)

---

**Last Updated**: 2025-03-10
**Maintained by**: Penguin Tech Inc Engineering
**Contact**: support@penguintech.io
