# SkausWatch Release Notes

## v1.0.0 (2026-02-19)

**Initial SkausWatch Release**

### Summary
First official release of SkausWatch, a comprehensive S3 malware and threat-intelligence scanning platform. Project converted from PenguinTech template with complete platform identity, multi-environment deployment support, and automated CI/CD infrastructure.

### Key Changes
- **Four-Service Python Architecture**: Manager (Quart, 5000), PKI Server (Flask, 5001), SSH CA (Flask, 5002), Monitor (Flask, 5003)
- **Docker Compose**: Full local development stack with S3scan, ClamAV, Redis, PostgreSQL, MinIO
- **Kubernetes Deployment**: Helm charts, raw manifests, Kustomize overlays for alpha/beta/prod environments
- **Malware Scanning**: ClamAV and YARA rule integration for file threat detection
- **S3 Orchestration**: Worker pool for asynchronous bucket scanning with distributed task processing
- **gRPC Workers**: High-performance worker communication for scalability
- **Research/OSINT Module**: Integrated threat intelligence gathering and correlation
- **AI Alert Review**: Machine learning-powered alert triage and severity assessment
- **CI Pipeline**: Automated linting, security scanning, multi-architecture builds (AMD64, ARM64)

---

**Maintained by**: Penguin Tech Inc
**License**: Limited AGPL-3.0
**Support**: support@penguintech.io
