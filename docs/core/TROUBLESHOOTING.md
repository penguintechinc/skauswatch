# SkausWatch Troubleshooting Guide

**Audience:** DevOps | Developers

Common issues, root causes, and fixes for SkausWatch deployment and development.

## 🔴 Core Services Won't Start

### Problem: "Connection refused" on port 5000

**Symptoms:**
```
Error: Cannot connect to http://localhost:5000
curl: (7) Failed to connect to localhost port 5000: Connection refused
```

**Root causes:**
1. Port already in use
2. Manager container not running
3. Database not initialized

**Fix:**
```bash
# 1. Check if port is in use
lsof -i :5000

# 2. If process found, kill it
kill -9 <PID>

# 3. Or change port in .env
echo "MANAGER_PORT=5001" >> .env

# 4. Restart services
docker-compose down
docker-compose up -d --build manager

# 5. Verify health
curl http://localhost:5000/api/health
```

### Problem: "Database connection timeout"

**Symptoms:**
```
Error: Unable to connect to PostgreSQL: connection timeout
sqlalchemy.exc.OperationalError: could not connect to server: No address associated with hostname
```

**Root causes:**
1. PostgreSQL not running
2. Wrong database credentials
3. Database not initialized

**Fix:**
```bash
# 1. Check if postgres is running
docker-compose ps postgres

# 2. If not running, start it
docker-compose up -d postgres

# 3. Wait for readiness (listen on 5432)
docker-compose logs postgres | grep "accepting connections"

# 4. Check credentials in .env
grep "DB_" .env

# 5. Initialize database
make db-init

# 6. Test connection
docker-compose exec postgres psql -U postgres -d skauswatch_dev -c "SELECT 1"
```

### Problem: "Redis connection refused"

**Symptoms:**
```
redis.exceptions.ConnectionError: Error 111 connecting to localhost:6379. Connection refused.
```

**Fix:**
```bash
# 1. Check Redis status
docker-compose ps redis

# 2. Start Redis
docker-compose up -d redis

# 3. Test connection
docker-compose exec redis redis-cli PING
# Should return: PONG

# 4. Check Redis logs
docker-compose logs redis
```

## 🔐 PKI Server & SSH CA Issues

### Problem: "503 Service Unavailable" from PKI/SSH CA

**Symptoms:**
```
HTTP 503: Service Unavailable
Deprecation: true
Link: <https://vault.example.com/api/v1/certificates>; rel="successor-version"
```

**Root cause:** Vault not running or `$VAULT_PKI_URL` not configured

**Fix:**
```bash
# 1. Check if VAULT_PKI_URL is set
grep VAULT_PKI .env

# 2. If not set, add it
echo "VAULT_PKI_URL=http://vault:5101" >> .env
echo "VAULT_SSHCA_URL=http://vault:5102" >> .env

# 3. Check if Vault is running
docker-compose ps vault

# 4. If not, start Vault
cd .worktrees/vault/vault
docker-compose up -d

# 5. Test Vault endpoint
curl http://localhost:5101/api/v1/health

# 6. Restart PKI/SSH CA shims
docker-compose restart pki sshca

# 7. Verify shim proxy working
curl http://localhost:5001/api/v1/certificates \
  -H "Authorization: Bearer $JWT_TOKEN"
```

### Problem: "Certificate validation failed"

**Symptoms:**
```
Error: X.509 certificate validation failed: self signed certificate
```

**Fix (development only):**
```bash
# Disable certificate verification for local dev
export PYTHONHTTPSVERIFY=0

# Or in .env
VERIFY_SSL=false

# Restart service
docker-compose restart manager
```

**Fix (production):**
Ensure Vault has valid CA certificates:
```bash
# Check certificate chain in Vault
curl -v http://vault:5101/api/v1/health 2>&1 | grep "certificate"
```

## 🚀 Worker Issues

### Problem: "Worker jobs not being consumed"

**Symptoms:**
```
# Jobs pile up in Redis
docker-compose exec redis redis-cli XLEN skauswatch:scan-jobs
# Returns: 42 (growing)

# But no workers processing
docker-compose logs s3scan | grep "consuming"
# No output
```

**Root causes:**
1. Redis connection failure
2. Worker crashed
3. Consumer group issue

**Fix:**
```bash
# 1. Check Redis connectivity
docker-compose exec s3scan redis-cli -h redis PING
# Should return: PONG

# 2. View worker logs
docker-compose logs -f s3scan

# 3. Check consumer group status
docker-compose exec redis redis-cli \
  XINFO GROUPS skauswatch:scan-jobs

# 4. If group exists but no consumers, reset it
docker-compose exec redis redis-cli \
  XGROUP DESTROY skauswatch:scan-jobs s3scan-group

# 5. Restart worker
docker-compose restart s3scan

# 6. Monitor job consumption
watch -n 1 'docker-compose exec redis redis-cli XLEN skauswatch:scan-jobs'
```

### Problem: "Worker memory usage growing unbounded"

**Symptoms:**
```
docker stats s3scan
# MEMORY: 1.5G → 2.0G (growing)

# Log shows
OutOfMemory: Cannot allocate memory
```

**Fix:**
```bash
# 1. Check worker logs for large operations
docker-compose logs s3scan | tail -100

# 2. Reduce batch size
echo "WORKER_BATCH_SIZE=1" >> .env
docker-compose restart s3scan

# 3. Reduce S3 workspace size
echo "S3_WORKSPACE_SIZE_GB=10" >> .env
docker-compose restart s3scan

# 4. Monitor memory
docker stats s3scan --no-stream

# 5. If still failing, check for stuck jobs
docker-compose exec redis redis-cli XLEN skauswatch:scan-jobs
```

### Problem: "ClamAV not updating signatures"

**Symptoms:**
```
docker-compose logs s3scan | grep "ClamAV"
# ClamAV definitions outdated (last update: 7 days ago)

# Scan results missing expected malware
```

**Fix:**
```bash
# 1. Manually update ClamAV definitions
docker-compose exec s3scan freshclam

# 2. Verify update success
docker-compose exec s3scan clamscan --version
# Last db update: ...

# 3. Check ClamAV daemon status
docker-compose exec s3scan clamdscan --ping
# Should return: OK

# 4. If not working, restart ClamAV
docker-compose restart s3scan

# 5. For persistent updates, add cron job (in Dockerfile)
# /etc/cron.d/clamav: 0 */3 * * * /usr/bin/freshclam
```

## 📊 Database Issues

### Problem: "Migration conflict" or "Database schema mismatch"

**Symptoms:**
```
Error: Alembic migration conflict
Current revision: abc123
Latest revision: def456
```

**Fix:**
```bash
# 1. Check migration history
docker-compose exec manager alembic current

# 2. View pending migrations
docker-compose exec manager alembic heads

# 3. Run missing migrations
docker-compose exec manager alembic upgrade head

# 4. If conflict, reset (development only)
docker-compose down -v
make db-init
```

### Problem: "PyDAL migrate=True causing schema drift"

**Symptoms:**
```
Error: Table 'users' already exists (but Alembic doesn't know about it)
RuntimeError: Duplicate table definition in PyDAL migration
```

**Fix:**
```bash
# 1. Check PyDAL config
grep "migrate=" services/manager/models.py
# Must be: migrate=False

# 2. Fix if needed
# In models.py: db = DAL(..., migrate=False)

# 3. Run Alembic migrations explicitly
docker-compose exec manager alembic upgrade head

# 4. Verify schema matches
docker-compose exec postgres psql -U postgres -d skauswatch_dev -c "\dt"
```

### Problem: "Database deadlock on concurrent scans"

**Symptoms:**
```
Error: Deadlock detected
sqlalchemy.exc.DatabaseError: (psycopg2.extensions.TransactionRollbackError) deadlock detected
```

**Fix:**
```bash
# 1. Reduce max concurrent scans
echo "MAX_CONCURRENT_SCANS=2" >> .env
docker-compose restart manager

# 2. Increase connection pool
echo "DB_POOL_SIZE=20" >> .env
docker-compose restart manager

# 3. Monitor active connections
docker-compose exec postgres psql -U postgres -c \
  "SELECT count(*) FROM pg_stat_activity WHERE state = 'active'"

# 4. Kill long-running transactions if needed (DANGEROUS)
# docker-compose exec postgres psql -U postgres -c \
#   "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE duration > '10 minutes'"
```

## 🌐 WebUI Issues

### Problem: "WebUI can't reach Manager API"

**Symptoms:**
```
Browser console error:
Failed to fetch http://localhost:5000/api/scans
Response code: 0 (CORS or network error)
```

**Root cause:** Manager API not reachable or CORS not configured

**Fix:**
```bash
# 1. Check Manager health
curl http://localhost:5000/api/health

# 2. Check VITE_API_URL in WebUI
grep VITE_API_URL services/webui/.env

# 3. Update if needed
echo "VITE_API_URL=http://localhost:5000" > services/webui/.env

# 4. Rebuild WebUI
docker-compose up -d --build webui

# 5. Check CORS headers
curl -i -H "Origin: http://localhost:3000" \
  http://localhost:5000/api/health
# Should include: Access-Control-Allow-Origin: http://localhost:3000
```

### Problem: "npm install fails for @penguintechinc/react-libs"

**Symptoms:**
```
npm ERR! 404 Not Found - GET https://registry.npmjs.org/@penguintechinc%2Freact-libs
npm ERR! 404 '@penguintechinc/react-libs@*' is not in the npm registry
```

**Fix:**
```bash
# 1. Check GitHub token is set
echo $GITHUB_TOKEN

# 2. If not set, generate at https://github.com/settings/tokens
#    Scope: read:packages

# 3. Create .npmrc in webui directory
cd services/webui
cat > .npmrc << 'EOF'
@penguintechinc:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
EOF

# 4. Test token
npm install

# 5. If still failing, check token permissions
curl -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/user/packages
```

## 🔒 Security Issues

### Problem: "Credentials appear in logs"

**Symptoms:**
```
Log output:
aws_access_key: AKIA...
aws_secret_key: wJal...
```

**Fix:**
```bash
# 1. Find and fix the logging statement
grep -r "aws_secret_key" services/

# 2. Replace with masked version
# Before: logger.debug(f"credentials: {creds}")
# After:  logger.debug(f"credentials: [REDACTED]")

# 3. Use sanitizer utility
from penguintechinc.utils import sanitize_logs
logger = sanitize_logs.get_logger(__name__)
```

### Problem: "S3 credentials decryption fails"

**Symptoms:**
```
Error: Failed to decrypt S3 credentials: authentication tag verification failed
```

**Root cause:** Wrong encryption key or corrupted ciphertext

**Fix:**
```bash
# 1. Verify S3_CRED_ENCRYPTION_KEY is set correctly
grep S3_CRED_ENCRYPTION_KEY .env

# 2. Check key length (must be 32 bytes = 64 hex chars)
echo -n "$S3_CRED_ENCRYPTION_KEY" | wc -c
# Should be: 64

# 3. If key changed, re-encrypt credentials
# (No automated fix; must re-enter S3 credentials in WebUI)

# 4. Restart Manager with correct key
docker-compose restart manager
```

## ⚠️ Performance Issues

### Problem: "Scans taking longer than expected"

**Symptoms:**
```
S3 scan (1GB) taking 5+ minutes instead of typical 30-60s
```

**Root cause:** ClamAV, YARA, or network bottleneck

**Fix:**
```bash
# 1. Profile ClamAV performance
docker-compose exec s3scan \
  time clamdscan /path/to/file

# 2. Check system resources
docker stats s3scan

# 3. If CPU-bound, increase worker resources
# In docker-compose.yml:
# cpus: "2.0"
# mem_limit: 2GB

# 4. Restart worker
docker-compose restart s3scan

# 5. Check network bandwidth
docker-compose exec s3scan iftop
```

### Problem: "High memory usage after many scans"

**Symptoms:**
```
Memory grows from 512MB → 2GB over several hours
```

**Root cause:** Memory leak in worker or Python garbage collection

**Fix:**
```bash
# 1. Check for memory leaks
docker-compose exec s3scan python -m memory_profiler worker.py

# 2. Force garbage collection
echo "import gc; gc.collect()" | docker-compose exec -T s3scan python

# 3. Restart worker periodically
# Add to cron: 0 4 * * * docker-compose restart s3scan

# 4. Monitor memory
docker stats s3scan --no-stream
```

## 🆘 Emergency Procedures

### Complete Reset (Development)

```bash
# Stop everything and remove all data
docker-compose down -v

# Clean Docker resources
docker system prune -a

# Reinitialize
make setup
make dev
make seed-mock-data
```

### Service Recovery

```bash
# If a service becomes unresponsive
docker-compose kill <service-name>
docker-compose restart <service-name>

# Check logs
docker-compose logs <service-name>
```

### Database Recovery

```bash
# Restore from backup
docker-compose exec -T postgres psql -U postgres skauswatch_dev < backup.sql

# Or reset completely
docker-compose down -v
make db-init
```

---

**Last Updated:** 2026-03-10
**Maintained by:** Penguin Tech Inc
