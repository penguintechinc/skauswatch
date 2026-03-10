# SkausWatch Configuration Reference

**Audience:** DevOps | Developers

Complete environment variable reference for all SkausWatch services and infrastructure components.

## 📋 Configuration Files

```
Project Root
├── .env                    # Default development config
├── .env.local             # Local machine overrides (gitignored)
├── .env.example           # Template for new developers
└── .env.production        # Production secrets (never commit)
```

## 🌍 Shared Infrastructure Variables

These apply to all services:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DB_TYPE` | Yes | `postgresql` | Database type: `postgresql`, `mysql`, `sqlite` |
| `DB_HOST` | Yes | `localhost` | Database hostname |
| `DB_PORT` | Yes | `5432` | Database port |
| `DB_NAME` | Yes | `skauswatch_dev` | Database name |
| `DB_USER` | Yes | `postgres` | Database username |
| `DB_PASS` | Yes | `postgres` | Database password (encrypt in prod) |
| `DB_POOL_SIZE` | No | `10` | Connection pool size per service |
| `DB_MAX_RETRIES` | No | `5` | DB connection retry attempts |
| `REDIS_URL` | Yes | `redis://localhost:6379/0` | Redis connection string |
| `REDIS_KEY_PREFIX` | Yes | `skauswatch` | Redis key namespace prefix |
| `RELEASE_MODE` | No | `false` | Enable license enforcement |
| `LICENSE_KEY` | No | `dev` | PenguinTech license key |
| `LICENSE_SERVER_URL` | No | `https://license.penguintech.io` | License server endpoint |

## 📋 Manager Service (Port 5000)

Configuration for `services/manager-new/`

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MANAGER_PORT` | No | `5000` | HTTP server port |
| `MANAGER_HOST` | No | `0.0.0.0` | Bind address |
| `MANAGER_DEBUG` | No | `false` | Enable debug logging |
| `MANAGER_SECRET_KEY` | Yes | — | Flask session secret key (generate with `secrets.token_hex(32)`) |
| `GRPC_ENABLED` | No | `true` | Enable gRPC worker communication |
| `GRPC_PORT` | No | `50051` | gRPC server port |
| `S3_CRED_ENCRYPTION_KEY` | Yes | — | AES-256 key for encrypting S3 credentials (32-byte hex) |
| `VIRUSTOTAL_API_KEY` | No | — | VirusTotal API key for threat intelligence |
| `OTX_API_KEY` | No | — | AlienVault OTX API key |
| `PROMETHEUS_ENABLED` | No | `true` | Enable Prometheus metrics endpoint |
| `PROMETHEUS_PORT` | No | `9090` | Prometheus metrics port |
| `SCAN_TIMEOUT_SECONDS` | No | `300` | S3 scan timeout (5 minutes) |
| `SCAN_WORKSPACE` | No | `/tmp/s3-scan-workspace` | Temp directory for scan artifacts |
| `MAX_CONCURRENT_SCANS` | No | `10` | Max parallel scans |
| `WORKER_GRPC_TIMEOUT` | No | `30` | Worker gRPC timeout (seconds) |
| `LOG_LEVEL` | No | `INFO` | Log level: DEBUG, INFO, WARNING, ERROR |

## 🔐 PKI Server (Port 5001)

Configuration for `services/pki-server-new/`

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PKI_PORT` | No | `5001` | HTTP server port |
| `PKI_HOST` | No | `0.0.0.0` | Bind address |
| `PKI_DEBUG` | No | `false` | Enable debug logging |
| `ICEBOX_PKI_URL` | No | — | IceBox PKI backend URL (shim proxy target) |
| `PKI_CERT_VALIDITY_DAYS` | No | `365` | Default certificate validity period |
| `PKI_KEY_SIZE` | No | `4096` | Default RSA key size |
| `PKI_COUNTRY` | No | `US` | Default cert subject country |
| `PKI_ORGANIZATION` | No | `SkausWatch` | Default cert subject organization |
| `LOG_LEVEL` | No | `INFO` | Log level |

## 🔑 SSH CA (Port 5002)

Configuration for `services/ssh-ca/`

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SSH_CA_PORT` | No | `5002` | HTTP server port |
| `SSH_CA_HOST` | No | `0.0.0.0` | Bind address |
| `SSH_CA_DEBUG` | No | `false` | Enable debug logging |
| `ICEBOX_SSH_CA_URL` | No | — | IceBox SSH CA backend URL (shim proxy target) |
| `SSH_CERT_VALIDITY_SECONDS` | No | `3600` | Default SSH cert validity (1 hour) |
| `LOG_LEVEL` | No | `INFO` | Log level |

## 📊 AAA Monitor (Port 5003)

Configuration for `services/aaa-monitor/`

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AAA_PORT` | No | `5003` | HTTP server port |
| `AAA_HOST` | No | `0.0.0.0` | Bind address |
| `AAA_DEBUG` | No | `false` | Enable debug logging |
| `K8S_LOG_COLLECTOR_ENABLED` | No | `true` | Collect K8s cluster logs |
| `K8S_NAMESPACE` | No | `skauswatch` | K8s namespace to monitor |
| `AUDITD_ENABLED` | No | `false` | Collect Linux auditd logs |
| `THREAT_AI_ANALYSIS_ENABLED` | No | `false` | Enable AI threat analysis (requires AI provider) |
| `THREAT_AI_PROVIDER` | No | — | AI provider: `claude`, `openai`, `ollama` |
| `LOG_RETENTION_DAYS` | No | `90` | Audit log retention period |
| `LOG_LEVEL` | No | `INFO` | Log level |

## 🔍 Worker-S3

Configuration for `services/worker-s3/`

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `WORKER_CONSUMER_GROUP` | No | `worker-s3-group` | Redis consumer group name |
| `WORKER_BATCH_SIZE` | No | `5` | Jobs to consume per batch |
| `WORKER_POLL_TIMEOUT_MS` | No | `1000` | Redis XREADGROUP timeout |
| `CLAMAV_HOST` | No | `localhost` | ClamAV server hostname |
| `CLAMAV_PORT` | No | `3310` | ClamAV CLAMD port |
| `CLAMAV_TIMEOUT` | No | `60` | ClamAV scan timeout (seconds) |
| `YARA_ENABLED` | No | `true` | Enable YARA scanning |
| `YARA_RULES_PATH` | No | `/etc/yara/rules` | YARA rules directory |
| `YARA_TIMEOUT` | No | `30` | YARA scan timeout (seconds) |
| `TI_ENRICHMENT_ENABLED` | No | `true` | Enrich findings with threat intel |
| `VIRUSTOTAL_API_KEY` | No | — | VirusTotal API key |
| `OTX_API_KEY` | No | — | AlienVault OTX API key |
| `S3_WORKSPACE_SIZE_GB` | No | `50` | Max temp storage for S3 objects (GB) |
| `LOG_LEVEL` | No | `INFO` | Log level |

## 🛡️ Worker-Scanner

Configuration for `services/worker-scanner/`

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `WORKER_CONSUMER_GROUP` | No | `worker-scanner-group` | Redis consumer group name |
| `WORKER_BATCH_SIZE` | No | `2` | Jobs per batch (lower than S3 due to heaviness) |
| `NUCLEI_ENABLED` | No | `true` | Enable Nuclei scanner |
| `NUCLEI_TIMEOUT` | No | `120` | Nuclei scan timeout (seconds) |
| `NUCLEI_TEMPLATES_DIR` | No | `/opt/nuclei/templates` | Nuclei templates location |
| `ZAP_ENABLED` | No | `false` | Enable OWASP ZAP scanner |
| `ZAP_TIMEOUT` | No | `300` | ZAP scan timeout (seconds) |
| `ZAP_API_KEY` | No | — | ZAP API key |
| `OPENVAS_ENABLED` | No | `false` | Enable OpenVAS scanner |
| `OPENVAS_HOST` | No | — | OpenVAS server hostname |
| `OPENVAS_USERNAME` | No | — | OpenVAS username |
| `OPENVAS_PASSWORD` | No | — | OpenVAS password |
| `OPENVAS_TIMEOUT` | No | `600` | OpenVAS scan timeout (seconds) |
| `LOG_LEVEL` | No | `INFO` | Log level |

## 🌐 WebUI (Port 3000)

Configuration for `services/webui/`

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | `3000` | HTTP server port |
| `VITE_API_URL` | No | `http://localhost:5000` | Manager API base URL |
| `VITE_ENVIRONMENT` | No | `development` | Environment: development, staging, production |
| `NODE_ENV` | No | `development` | Node.js environment |
| `GITHUB_TOKEN` | Yes | — | GitHub personal access token (for npm.pkg.github.com) |

## 🔒 IceBox Sub-Module (Licensed)

Configuration for `.worktrees/icebox/icebox/` (if installed)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ICEBOX_PORT` | No | `5100` | IceBox Flask backend port |
| `ICEBOX_MEK` | Yes | — | Master Encryption Key (32-byte hex) |
| `ICEBOX_DB_HOST` | Yes | — | IceBox database host |
| `ICEBOX_DB_PORT` | Yes | `5432` | IceBox database port |
| `ICEBOX_DB_NAME` | Yes | `icebox_dev` | IceBox database name |
| `ICEBOX_DB_USER` | Yes | — | IceBox database user |
| `ICEBOX_DB_PASS` | Yes | — | IceBox database password |
| `ICEBOX_REDIS_URL` | No | `redis://localhost:6379/1` | IceBox Redis (separate DB recommended) |

## 🤖 Darwin Sub-Module (Licensed)

Configuration for `darwin/` and `services/worker-darwin/`

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DARWIN_ENABLED` | No | `false` | Enable Darwin integration |
| `DARWIN_AI_PROVIDER` | No | `claude` | AI provider: `claude`, `openai`, `ollama` |
| `DARWIN_CLAUDE_API_KEY` | No | — | Anthropic Claude API key |
| `DARWIN_OPENAI_API_KEY` | No | — | OpenAI API key |
| `DARWIN_OLLAMA_ENDPOINT` | No | `http://ollama:11434` | Ollama server endpoint |
| `DARWIN_GITHUB_WEBHOOK_SECRET` | No | — | GitHub webhook HMAC secret |
| `DARWIN_GITLAB_WEBHOOK_SECRET` | No | — | GitLab webhook HMAC secret |
| `DARWIN_REPOS` | No | — | Comma-separated repos to scan (e.g., `org/repo1,org/repo2`) |

## 📝 Example Configurations

### Development (Local)

```bash
# .env (development)
DB_TYPE=postgresql
DB_HOST=localhost
DB_PORT=5432
DB_NAME=skauswatch_dev
DB_USER=postgres
DB_PASS=postgres

REDIS_URL=redis://localhost:6379/0
REDIS_KEY_PREFIX=skauswatch

MANAGER_PORT=5000
MANAGER_DEBUG=true
MANAGER_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
S3_CRED_ENCRYPTION_KEY=$(python3 -c 'import os; print(os.urandom(32).hex())')

RELEASE_MODE=false
LICENSE_KEY=dev

VIRUSTOTAL_API_KEY=
OTX_API_KEY=

# IceBox (optional)
ICEBOX_PKI_URL=http://localhost:5101
ICEBOX_SSH_CA_URL=http://localhost:5102
```

### Beta (Staging)

```bash
# .env.beta
DB_TYPE=postgresql
DB_HOST=rds-instance.amazonaws.com
DB_PORT=5432
DB_NAME=skauswatch_beta
DB_USER=skauswatch_user
DB_PASS=${RDS_PASSWORD}  # From secrets manager

REDIS_URL=redis://elasticache-instance.amazonaws.com:6379/0
REDIS_KEY_PREFIX=skauswatch-beta

MANAGER_PORT=5000
MANAGER_DEBUG=false
MANAGER_SECRET_KEY=${SECRET_KEY}  # From secrets manager
S3_CRED_ENCRYPTION_KEY=${S3_CRED_KEY}  # From secrets manager

RELEASE_MODE=true
LICENSE_KEY=${LICENSE_KEY}  # From secrets manager

VIRUSTOTAL_API_KEY=${VT_KEY}
OTX_API_KEY=${OTX_KEY}

ICEBOX_PKI_URL=http://icebox-pki:5101
ICEBOX_SSH_CA_URL=http://icebox-ssh-ca:5102
```

### Production

```bash
# .env.production (encrypted, stored in secrets manager)
DB_TYPE=postgresql
DB_HOST=prod-rds.amazonaws.com
DB_PORT=5432
DB_NAME=skauswatch_prod
DB_USER=skauswatch_prod_user
DB_PASS=${PROD_DB_PASSWORD}

REDIS_URL=redis+tls://prod-elasticache.amazonaws.com:6379/0
REDIS_KEY_PREFIX=skauswatch-prod

MANAGER_PORT=5000
MANAGER_DEBUG=false
MANAGER_SECRET_KEY=${PROD_SECRET_KEY}
S3_CRED_ENCRYPTION_KEY=${PROD_S3_KEY}

RELEASE_MODE=true
LICENSE_KEY=${PROD_LICENSE_KEY}

VIRUSTOTAL_API_KEY=${PROD_VT_KEY}
OTX_API_KEY=${PROD_OTX_KEY}

ICEBOX_MEK=${ICEBOX_MEK_PROD}
ICEBOX_DB_HOST=icebox-rds.amazonaws.com
ICEBOX_DB_NAME=icebox_prod
ICEBOX_DB_USER=${ICEBOX_USER}
ICEBOX_DB_PASS=${ICEBOX_PASS}

DARWIN_ENABLED=true
DARWIN_AI_PROVIDER=claude
DARWIN_CLAUDE_API_KEY=${PROD_CLAUDE_KEY}
```

## 🔑 Generating Secrets

**Flask secret key:**
```bash
python3 -c 'import secrets; print(secrets.token_hex(32))'
```

**AES-256 key:**
```bash
python3 -c 'import os; print(os.urandom(32).hex())'
```

**License key:** Contact Penguin Tech at sales@penguintech.io

## 🚀 Kubernetes Secrets

Store sensitive configuration in K8s Secrets:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: skauswatch-config
  namespace: skauswatch
type: Opaque
stringData:
  DB_PASS: "encrypted-password"
  MANAGER_SECRET_KEY: "secret-key"
  S3_CRED_ENCRYPTION_KEY: "encryption-key"
  LICENSE_KEY: "PENG-XXXX-XXXX-XXXX-XXXX-ABCD"
  VIRUSTOTAL_API_KEY: "api-key"
  OTX_API_KEY: "api-key"
```

Reference in deployment:
```yaml
spec:
  containers:
  - name: manager
    envFrom:
    - secretRef:
        name: skauswatch-config
    env:
    - name: LOG_LEVEL
      value: "INFO"
```

---

**Last Updated:** 2026-03-10
**Maintained by:** Penguin Tech Inc
