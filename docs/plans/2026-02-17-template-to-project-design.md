# SkausWatch: Template-to-Project Customization Design

**Date**: 2026-02-17
**Status**: Approved

## Context

SkausWatch is an S3 malware/threat-intelligence scanning platform with ClamAV, YARA rules, VirusTotal/OTX enrichment, gRPC workers, MinIO for ad-hoc uploads, and a four-service Python/Flask architecture (Manager, PKI Server, SSH CA, AAA Monitor). The repo was scaffolded from the PenguinTech project-template but most boilerplate was never replaced.

## Four-Service Architecture (Source of Truth)

| Service | Purpose | Port | Language |
|---------|---------|------|----------|
| Manager | Config/management plane, S3 scan orchestration, gRPC | 5000 | Python 3.13 + Quart |
| PKI Server | X.509 certificate management | 5001 | Python 3.13 + Flask |
| SSH CA | SSH certificate authority | 5002 | Python 3.13 + Flask |
| AAA Monitor | Audit logging, threat analysis | 5003 | Python 3.13 + Flask |

Supporting services: PostgreSQL, Redis, MinIO, ClamAV (freshclam), Worker-S3, Prometheus, Grafana.

## Work Groups

### Group 1 — Project Identity (parallel)

1. **README.md** — SkausWatch branding, ASCII art, correct GitHub badges, S3 malware scanning description
2. **Makefile** — PROJECT_NAME=skauswatch, four-service targets, remove Go/Node template paths
3. **.version** — Create `v1.0.0`
4. **.claude/app.md** — Fill with SkausWatch domain context
5. **docs/APP_STANDARDS.md** — Architecture, services, tech decisions

### Group 2 — Docker Compose (after Group 1 design is clear)

6. **docker-compose.yml** — Remove template services (go-backend, template flask-backend, template webui, nginx), rename `project-template-*` → `skauswatch-*`, keep/refine real services
7. **docker-compose.dev.yml** — Rewrite for four-service dev setup

### Group 3 — K8s Overhaul (parallel)

8. **k8s/helm/** — Restructure charts: manager, pki-server, ssh-ca, aaa-monitor, worker-s3 (borrow from flask-backend template chart as base)
9. **k8s/manifests/** — Update to match real services
10. **k8s/kustomize/** — Update overlays

## Principles

- Use template files as base — copy/adapt, don't start from scratch
- Four-service architecture is the source of truth
- Keep Python-only stack (no Go backend, no Node webui in this phase)
- Parallel execution with task agents where possible
