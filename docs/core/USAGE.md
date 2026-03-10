# SkausWatch Usage Guide

**Audience:** Developers | DevOps

Quick reference for common SkausWatch workflows, tasks, and operational patterns.

## 🚀 Quick Start (5 Minutes)

```bash
# 1. Clone repository
git clone https://github.com/penguintechinc/skauswatch.git
cd skauswatch

# 2. Setup (installs dependencies, initializes DB)
make setup

# 3. Start all services
make dev

# 4. Populate mock data
make seed-mock-data

# 5. Access WebUI
open http://localhost:3000
# Login: admin@localhost.local / admin123
```

## 📋 Common Workflows

### Scanning an S3 Bucket

**Via WebUI:**
1. Navigate to **Manager** → **S3 Buckets**
2. Click **Add Bucket**
3. Enter AWS credentials (encrypted at rest)
4. Select scanning profile: `ClamAV + YARA + TI`
5. Click **Scan Now**
6. View results in **Dashboard**

**Via API:**
```bash
curl -X POST http://localhost:5000/api/v1/scans \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "bucket_name": "my-bucket",
    "aws_access_key": "AKIA...",
    "aws_secret_key": "...",
    "profile": "clamav-yara-ti"
  }'
```

### Running a Vulnerability Scan

**Via WebUI:**
1. Navigate to **Scanner** → **Targets**
2. Add target: `https://example.com` or IP
3. Select scanner profile:
   - `Nuclei` (fast, vulnerabilities)
   - `ZAP` (medium, web app)
   - `OpenVAS` (slow, comprehensive)
4. Click **Scan**
5. Results appear in **Dashboard** → **Vulnerabilities**

**Via API:**
```bash
curl -X POST http://localhost:5000/api/v1/vuln-scans \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{
    "target": "https://example.com",
    "engine": "nuclei"
  }'
```

### Viewing Audit Logs

**Via WebUI:**
1. Navigate to **Admin** → **Audit Logs**
2. Filter by date, user, action type
3. View details: click log entry for full context

**Via API:**
```bash
curl http://localhost:5003/api/v1/audit-logs \
  -H "Authorization: Bearer $JWT_TOKEN" | jq
```

### Managing Certificates (PKI Server)

**Generate Certificate:**
```bash
curl -X POST http://localhost:5001/api/v1/certificates \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{
    "subject": "cn=server.example.com,o=MyOrg",
    "days_valid": 365,
    "key_type": "rsa-4096"
  }' | jq .certificate_pem
```

**List Certificates:**
```bash
curl http://localhost:5001/api/v1/certificates \
  -H "Authorization: Bearer $JWT_TOKEN" | jq
```

**Revoke Certificate:**
```bash
curl -X POST http://localhost:5001/api/v1/certificates/revoke \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{"serial_number": "0x123..."}'
```

### Managing SSH Certificates (SSH CA)

**Generate SSH Certificate:**
```bash
curl -X POST http://localhost:5002/api/v1/ssh-certs \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{
    "public_key": "ssh-rsa AAAA...",
    "principals": ["user@host"],
    "cert_type": "user",
    "validity": 3600
  }' | jq .certificate
```

**Validate SSH Certificate:**
```bash
curl -X POST http://localhost:5002/api/v1/ssh-certs/validate \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{"certificate": "..."}' | jq
```

## 🛠️ Development Tasks

### Add a New S3 Scanning Profile

1. Edit `services/manager-new/config.py`:
```python
SCANNING_PROFILES = {
    "clamav-yara-ti": {
        "engines": ["clamav", "yara", "threat-intel"],
        "timeout": 300,
    },
    "my-custom-profile": {  # Add new profile
        "engines": ["clamav"],
        "timeout": 180,
    }
}
```

2. Rebuild and restart Manager:
```bash
docker-compose up -d --build manager
```

3. Test via API:
```bash
curl http://localhost:5000/api/v1/profiles | jq '.[] | select(.name == "my-custom-profile")'
```

### Modify YARA Rules

1. Update rules file: `services/worker-s3/yara_rules/`
2. Restart worker:
```bash
docker-compose restart worker-s3
```

### Test with ClamAV Updates

```bash
# Force ClamAV definition update
docker-compose exec worker-s3 freshclam

# Verify signature count
docker-compose exec worker-s3 clamscan --version
```

### Adding a New Vulnerability Scanner

1. Create scanner module in `services/worker-scanner/scanners/my_scanner.py`
2. Implement `Scanner` interface
3. Add to `worker-scanner/config.py`
4. Test:
```bash
cd services/worker-scanner
pytest tests/unit/test_my_scanner.py -v
```

## 📊 Monitoring & Debugging

### View Service Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f manager

# Last 100 lines, follow new entries
docker-compose logs -f --tail=100 pki-server

# Search logs
docker-compose logs manager | grep "ERROR"
```

### Check Service Health

```bash
# Manager
curl http://localhost:5000/api/health

# PKI Server
curl http://localhost:5001/api/health

# SSH CA
curl http://localhost:5002/api/health

# AAA Monitor
curl http://localhost:5003/api/health
```

### Database Inspection

```bash
# Connect to PostgreSQL
docker-compose exec postgres psql -U postgres -d skauswatch_dev

# List tables
\dt

# View scan results
SELECT id, bucket_name, status, created_at FROM scans LIMIT 5;

# View audit logs
SELECT user_id, action, resource, timestamp FROM audit_logs LIMIT 5;

# Exit
\q
```

### Check Job Queue Status

```bash
# View pending jobs
docker-compose exec redis redis-cli \
  -h redis XLEN skauswatch:scan-jobs

# View job details
docker-compose exec redis redis-cli \
  -h redis XREAD STREAMS skauswatch:scan-jobs 0 | head -20
```

## 🔄 Common Operations

### Restart All Services

```bash
# Stop all
docker-compose down

# Start all (rebuild if code changed)
docker-compose up -d --build

# Verify all healthy
docker-compose ps
```

### Reset Development Database

```bash
# Stop services, remove volumes
docker-compose down -v

# Reinitialize
make db-init
make seed-mock-data

# Restart
make dev
```

### Update Dependencies

**Python service:**
```bash
# Add to requirements.txt
echo "new-package==1.0.0" >> services/manager/requirements.txt

# Rebuild
docker-compose up -d --build manager
```

**WebUI (Node.js):**
```bash
cd services/webui
npm install new-package
docker-compose up -d --build webui
```

### Build Multi-Architecture Images

```bash
# Enable buildx
docker buildx create --name multiarch --driver docker-container
docker buildx use multiarch

# Build for both platforms
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t manager:latest \
  services/manager/

# Or just test (don't push)
docker buildx build \
  --platform linux/arm64 \
  services/manager/  # Uses QEMU emulation
```

## 🚨 Troubleshooting Common Issues

### Services Won't Start

**Check logs:**
```bash
docker-compose logs manager
docker-compose logs postgres
```

**Common causes:**
- Port already in use → change in `.env`
- Database not initialized → run `make db-init`
- Missing .env file → run `cp .env.example .env`

### Database Connection Error

```bash
# Verify PostgreSQL is running
docker-compose ps postgres

# Test connection
docker-compose exec postgres psql -U postgres -c "SELECT 1"

# Check credentials in .env
grep "DB_" .env
```

### Manager can't reach PKI/SSH CA

```bash
# Test connectivity
docker-compose exec manager curl http://pki-server:5001/api/health
docker-compose exec manager curl http://ssh-ca:5002/api/health

# Check if services are running
docker-compose ps pki-server ssh-ca

# View logs for errors
docker-compose logs pki-server ssh-ca
```

### Worker jobs not processing

```bash
# Check Redis connection
docker-compose exec worker-s3 redis-cli -h redis ping

# Check job queue
docker-compose exec redis redis-cli XLEN skauswatch:scan-jobs

# View worker logs
docker-compose logs -f worker-s3
```

## 📖 Reference Documentation

- **Full development setup**: See `../DEVELOPMENT.md`
- **Testing procedures**: See `TESTING.md`
- **API reference**: See `API.md`
- **System architecture**: See `ARCHITECTURE.md`
- **Configuration details**: See `CONFIGURATION.md`

---

**Last Updated:** 2026-03-10
**Maintained by:** Penguin Tech Inc
