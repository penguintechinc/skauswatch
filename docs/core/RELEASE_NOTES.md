# SkausWatch Release Notes

**Audience:** Everyone

Version history, deprecations, known issues, and migration guides.

## v1.0.0 (2026-03-10) — Initial Release

**Initial release of SkausWatch core platform with eight services, Vault and CodeScan sub-modules, Helm and Kustomize deployment.**

### ✨ Features

#### Core Services
- **Manager** (Port 5000): Orchestration, S3 credential mgmt, scan scheduling
- **PKI Server** (Port 5001): Shim proxy to Vault PKI (v1.x compat)
- **SSH CA** (Port 5002): Shim proxy to Vault SSH CA (v1.x compat)
- **Monitor** (Port 5003): Audit logging, K8s log collection, threat analysis
- **S3scan**: ClamAV + YARA + threat intelligence scanning
- **Scanner**: Nuclei, ZAP, OpenVAS vulnerability scanning
- **ENDPOINT Agent**: Endpoint detection & response (K8s DaemonSet)
- **WebUI** (Port 3000): React frontend with role-based access (Admin, Maintainer, Viewer)

#### Infrastructure
- PostgreSQL 16 shared database with per-service accounts
- Redis 7 for job queues and caching (Streams-based job distribution)
- MinIO for S3-compatible object storage
- ClamAV + YARA for malware detection
- Prometheus + Grafana for monitoring

#### Sub-Modules (Licensed)
- **Vault**: Secrets vault with envelope encryption (AES-256-GCM), JIT access, one-time secrets, cloud sync
- **CodeScan**: AI-powered code review and ASM surface analysis

#### Deployment
- Kubernetes Helm charts (5 charts: Manager, PKI, SSH CA, Monitor, WebUI)
- Kustomize overlays for alpha/beta/prod environments
- Multi-architecture support (amd64/arm64)
- Docker Compose for local development

### 🔐 Security

- S3 credentials encrypted at rest (AES-256-GCM)
- JWT Bearer token authentication on all API endpoints
- OIDC scopes for fine-grained RBAC
- mTLS support via Vault PKI (when Vault installed)
- SSH certificate-based authentication via Vault SSH CA
- Scan workspace cleaned after each job
- Worker resource limits (2GB memory, 2 CPU cores)
- ENDPOINT Agent as read-only DaemonSet with minimal K8s RBAC

### 🛠️ Technical Stack

- **Python 3.13** (Manager, PKI Server, SSH CA, Monitor, Workers)
- **Go 1.24** (ENDPOINT Agent)
- **Node.js 18 + React** (WebUI)
- **Quart** (async Flask alternative for Manager, PKI/SSH CA shims)
- **FastAPI** (async for Monitor)
- **PyDAL + SQLAlchemy** (database abstraction)
- **Redis Streams** (job queue distribution)
- **gRPC** (internal service communication)
- **Kubernetes + Helm + Kustomize** (orchestration)

### 📦 Deployment Environments

| Environment | Domain | Method | Notes |
|-------------|--------|--------|-------|
| **Alpha** | `skauswatch.localhost.local` | Kustomize + MicroK8s | Local development |
| **Beta** | `skauswatch.penguintech.cloud` | Helm + dal2 cluster | Staging environment |
| **Production** | `skauswatch.app` | Helm + custom cluster | Live production |

### 📝 Documentation

- `docs/core/OVERVIEW.md` — Platform summary
- `docs/core/USAGE.md` — Common workflows
- `docs/core/API.md` — REST/gRPC API reference
- `docs/core/ARCHITECTURE.md` — System design
- `docs/core/CONFIGURATION.md` — Environment variables
- `docs/core/TESTING.md` — Testing guide
- `docs/core/TROUBLESHOOTING.md` — Common issues
- `docs/DEVELOPMENT.md` — Local setup
- `docs/TESTING.md` — Testing procedures
- `docs/PRE_COMMIT.md` — Pre-commit checklist

---

## 📋 Deprecations & Migration

### PKI Server & SSH CA Shim Proxies (v1.x → v2.0)

**Status (v1.x):** Both services are thin Quart shim proxies that forward requests to Vault PKI and SSH CA backends when `$VAULT_PKI_URL` and `$VAULT_SSHCA_URL` are configured.

**Deprecation:** Shims will be removed in v2.0. Clients should migrate to Vault endpoints before v2.0 release.

**Migration Guide:**
```
Old (v1.x):
  POST http://manager:5000/api/v1/certificates
  └─ Proxies through PKI Server shim (Port 5001)
  └─ Forwards to Vault PKI (Port 5101)

New (v2.0):
  POST http://vault:5100/api/v1/pki/certificates
  └─ Use Vault PKI directly
```

**Timeline:**
- v1.x: Shims available, deprecation headers attached
- v1.5: Shims may be removed (check release notes)
- v2.0: Shims definitely removed

---

## ⚠️ Known Issues

### Issue #1: WebUI npm package installation fails on first attempt

**Symptom:** `npm install @penguintechinc/react-libs` fails with "404 Not Found"

**Cause:** GitHub token not set for npm.pkg.github.com registry

**Workaround:**
```bash
# Ensure GITHUB_TOKEN is set with read:packages scope
export GITHUB_TOKEN=ghp_xxxx...
cd services/webui && npm install
```

**Status:** Fixed in v1.1 (auto-detection of GITHUB_TOKEN)

### Issue #2: S3scan memory leak after 500+ scans

**Symptom:** Memory grows from 512MB to 2GB+ over 24 hours

**Cause:** Python garbage collection not releasing large scan buffers

**Workaround:** Restart s3scan daily via cron job or K8s restart policy

**Status:** Under investigation, fix targeted for v1.1

### Issue #3: ClamAV definitions become stale without manual update

**Symptom:** ClamAV signatures > 7 days old, new malware not detected

**Cause:** `freshclam` not running automatically in Docker container

**Workaround:** Manual `docker-compose exec s3scan freshclam`

**Status:** Fixed in v1.1 (added cron job in Dockerfile)

### Issue #4: ENDPOINT Agent DaemonSet logs not aggregated to Monitor

**Symptom:** Host-level events not appearing in Monitor audit logs

**Cause:** ENDPOINT Agent K8s API queries incomplete, missing event filters

**Workaround:** Manually configure K8s API reader RBAC for ENDPOINT Agent namespace

**Status:** Fixed in v1.1 (improved K8s RBAC template)

---

## 🔧 Upgrade Instructions

### v1.0.0 → v1.1.0 (When Released)

```bash
# 1. Backup database
docker-compose exec postgres pg_dump -U postgres skauswatch_dev > backup.sql

# 2. Pull latest code
git pull origin main

# 3. Update dependencies
make setup

# 4. Run migrations (automatic on startup)
docker-compose down
docker-compose up -d

# 5. Verify all services healthy
curl http://localhost:5000/api/health
curl http://localhost:3000/health

# 6. If any issues, restore from backup
# docker-compose exec -T postgres psql -U postgres skauswatch_dev < backup.sql
```

---

## 📊 Release Timeline

| Version | Release Date | Status | EOL |
|---------|--------------|--------|-----|
| v1.0.0 | 2026-03-10 | Current | TBD |
| v1.1.0 | 2026-05-01 (planned) | In development | TBD |
| v2.0.0 | 2026-09-01 (planned) | Planned | TBD |

---

## 🎯 Roadmap

### v1.1.0 (May 2026)
- Fix memory leak in S3scan
- Auto-update ClamAV definitions via cron
- Improve ENDPOINT Agent K8s integration
- Add Prometheus metrics for all services
- Grafana dashboard templates

### v1.2.0 (July 2026)
- Add support for YARA rule management UI
- Custom scanning profiles via WebUI
- Integration with AWS GuardDuty and Azure Defender
- Performance optimizations for large-scale scanning

### v2.0.0 (September 2026)
- Remove PKI Server and SSH CA shims (clients use Vault directly)
- Horizontal scaling for PostgreSQL (read replicas)
- Service mesh integration (Istio for mTLS)
- Multi-tenant support (organizational isolation)
- Advanced AI threat analysis (CodeScan integration tighter)

---

## 🤝 Contributing

SkausWatch development follows Penguin Tech standards:

- **Branch strategy:** Feature branches off `v{Major}.{Minor}.x` release branches
- **PRs:** Require code review + passing all tests before merge
- **Commits:** Include descriptive messages and reference GitHub issues
- **Tests:** Unit + integration coverage required (>80% target)
- **Documentation:** Update docs/ for all user-facing changes

See [DEVELOPMENT.md](../DEVELOPMENT.md) for detailed contribution guidelines.

---

## 📞 Support

**Issues & Bug Reports:**
- GitHub Issues: https://github.com/penguintechinc/skauswatch/issues
- Email: support@penguintech.io

**Security Issues:**
- Email: security@penguintech.io (do NOT file public issue)

**Feature Requests:**
- GitHub Discussions: https://github.com/penguintechinc/skauswatch/discussions

---

## 📄 License

SkausWatch is licensed under **Limited AGPL-3.0** with commercial use restrictions and Contributor Employer Exception.

See `LICENSE.md` in the repository root for full license text.

---

**Last Updated:** 2026-03-10
**Maintained by:** Penguin Tech Inc
**Website:** https://www.penguintech.io
