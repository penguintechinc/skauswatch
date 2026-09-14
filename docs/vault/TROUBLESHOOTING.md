# Vault Troubleshooting Guide

## 🔍 Common Issues & Solutions

### Database & Connection Issues

#### Database Connection Timeout
**Symptom:** `psycopg2.OperationalError: could not connect to server` or `pymysql.err.OperationalError`

**Diagnosis:**
```bash
# Check database is running
docker ps | grep postgres
# or
kubectl get pods --context local-alpha -n vault | grep postgres

# Test connectivity
psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "SELECT 1"
# or
mysql -h $DB_HOST -u $DB_USER -p$DB_PASS $DB_NAME -e "SELECT 1"
```

**Solutions:**
1. **Verify environment variables:**
   ```bash
   echo "DB_HOST: $DB_HOST"
   echo "DB_PORT: $DB_PORT"
   echo "DB_USER: $DB_USER"
   # DO NOT echo DB_PASS — logs will leak credentials
   ```

2. **Check database service is ready:**
   - Wait 30–60 seconds after starting (databases need initialization time)
   - For Kubernetes: `kubectl logs -f <postgres-pod>`
   - For Docker Compose: `docker logs vault-postgres`

3. **Verify network connectivity (Docker Compose):**
   ```bash
   docker network ls | grep vault
   docker network inspect <vault-network>
   ```

4. **Reset database (development only):**
   ```bash
   # Drop and recreate (WARNING: data loss)
   psql -h $DB_HOST -U postgres -c "DROP DATABASE IF EXISTS vault_db;"
   psql -h $DB_HOST -U postgres -c "CREATE DATABASE vault_db OWNER vault_app;"

   # Run migrations
   docker exec vault-flask-backend \
     alembic -c icebox/services/flask-backend/alembic.ini upgrade head
   ```

5. **Check per-service account permissions:**
   ```sql
   -- PostgreSQL
   \du vault_app
   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO vault_app;

   -- MySQL
   SHOW GRANTS FOR 'vault_app'@'%';
   ```

---

#### Database Migration Failed
**Symptom:** `sqlalchemy.exc.IntegrityError` during migration or startup

**Diagnosis:**
```bash
# Check migration history
docker exec vault-flask-backend \
  alembic -c icebox/services/flask-backend/alembic.ini current
docker exec vault-flask-backend \
  alembic -c icebox/services/flask-backend/alembic.ini history
```

**Solutions:**
1. **Verify Alembic configuration:**
   - Check `sqlalchemy.url` in `alembic.ini` matches `DB_*` env vars
   - For multi-DB support: `sqlalchemy.url = driver://user:pass@host/db`

2. **Downgrade if migration is corrupt:**
   ```bash
   docker exec vault-flask-backend \
     alembic -c icebox/services/flask-backend/alembic.ini downgrade -1
   ```

3. **Check for existing schema (first-run issue):**
   ```sql
   -- PostgreSQL
   \dt vault_*
   -- If tables exist, stamp the initial migration
   ```

4. **Ensure PyDAL `migrate=False`:**
   - All DAL instances must initialize with `migrate=False`
   - Alembic is the single source of truth for schema changes
   - If PyDAL is set to `migrate=True`, it will silently modify schema and conflict with Alembic

---

### Encryption & Key Management

#### Invalid MEK (Master Encryption Key)
**Symptom:** `cryptography.fernet.InvalidToken` or `ValueError: Incorrect padding` when decrypting

**Diagnosis:**
```bash
echo "MEK length: $(echo -n $VAULT_MEK | base64 -d | wc -c)"
# Should be exactly 32 bytes
```

**Solutions:**
1. **Regenerate MEK (development only):**
   ```bash
   python3 -c "import secrets; print(secrets.token_bytes(32).hex())" | base64
   ```

2. **Verify MEK format:**
   - Must be base64-encoded 32-byte string (256 bits)
   - Decode and check length: `base64 -d <<< "$VAULT_MEK" | wc -c` → 32

3. **Check MEK version matches:**
   ```bash
   echo "VAULT_MEK_VERSION=$VAULT_MEK_VERSION"
   # Must match version in database table vault_mek_rotations
   ```

4. **Clear corrupted cache (if using Redis):**
   ```bash
   redis-cli -h $REDIS_HOST DEL vault:*
   ```

---

#### DEK Rotation Blocked
**Symptom:** Secrets using old DEK cannot be decrypted after rotation

**Diagnosis:**
```bash
# Check MEK rotation history
docker exec vault-flask-backend \
  python3 -c "
from vault.services.flask_backend.models.db import db
from vault.services.flask_backend.models.db import vault_mek_rotations
rows = db(vault_mek_rotations).select()
for r in rows: print(f'{r.version}: {r.created_at} → {r.retired_at}')
"
```

**Solutions:**
1. **Rotate MEK securely:**
   ```bash
   # POST /api/v1/admin/mek/rotate (requires admin scope)
   curl -X POST https://vault.localhost.local/api/v1/admin/mek/rotate \
     -H "Authorization: Bearer $JWT_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"new_mek_base64": "<new-mek>"}'
   ```

2. **Re-encrypt secrets with new MEK:**
   - Old DEKs remain readable with old MEK versions
   - On secret access, detect old MEK version and update in background
   - No manual intervention required if old MEK versions are retained

3. **Verify old MEK versions are still available:**
   - Check `vault_mek_rotations.retired_at` — should be NULL for active versions
   - Active MEK versions allow decryption of older secrets

---

### JIT Access Control Issues

#### JIT Token Invalid or Expired
**Symptom:** `403 Forbidden` with message "JIT token invalid, expired, or already used"

**Diagnosis:**
```bash
# Check token format
# Format: jit:{grant_id}:{grantee_id}:{expires_epoch}
# Example: jit:grant-001:user-123:1234567890

# Check token expiration
python3 -c "import time; print(f'Now: {int(time.time())}')"
# Compare with expires_epoch in token
```

**Solutions:**
1. **Verify token hasn't expired:**
   - Extract `expires_epoch` from token (4th component)
   - Compare: `now < expires_epoch`
   - Extend JIT grant TTL if needed

2. **Check token not already used:**
   ```bash
   # Query database for token usage
   docker exec vault-flask-backend \
     python3 -c "
from vault.services.flask_backend.models.db import db, vault_jit_grants
rows = db(vault_jit_grants).select()
for r in rows: print(f'{r.id}: {r.status} (uses: {r.uses_remaining}/{r.uses_allowed})')
"
   ```

3. **Regenerate new token if needed:**
   ```bash
   # POST /api/v1/jit/request (request new JIT grant)
   curl -X POST https://vault.localhost.local/api/v1/jit/request \
     -H "Authorization: Bearer $USER_JWT" \
     -H "Content-Type: application/json" \
     -d '{"secret_id": "sec-001", "grantee_id": "user-123", "ttl_seconds": 300}'
   ```

4. **Check token HMAC signature:**
   - Token is HMAC-SHA256 signed with internal key
   - Invalid signature → token tampering detected → reject immediately

---

#### JIT Grant Not Found
**Symptom:** `404 Not Found` or "JIT grant does not exist" when attempting to use token

**Diagnosis:**
```bash
# Extract grant_id from token (2nd component)
# Example token: jit:grant-001:user-123:1234567890
# grant_id = grant-001

# Check if grant exists in database
docker exec vault-flask-backend \
  python3 -c "
from vault.services.flask_backend.models.db import db, vault_jit_grants
row = db(vault_jit_grants.id == 'grant-001').select().first()
print(f'Grant found: {row is not None}' if row else 'Not found')
"
```

**Solutions:**
1. **Request new JIT grant:**
   ```bash
   curl -X POST https://vault.localhost.local/api/v1/jit/request \
     -H "Authorization: Bearer $USER_JWT" \
     -H "Content-Type: application/json" \
     -d '{"secret_id": "sec-001", "grantee_id": "user-456", "ttl_seconds": 300, "uses_allowed": 3}'
   ```

2. **Approve pending grant (if awaiting approval):**
   ```bash
   curl -X POST https://vault.localhost.local/api/v1/jit/approve \
     -H "Authorization: Bearer $ADMIN_JWT" \
     -H "Content-Type: application/json" \
     -d '{"grant_id": "grant-001"}'
   ```

3. **Check grant status:**
   ```bash
   curl -H "Authorization: Bearer $JWT" \
     https://vault.localhost.local/api/v1/jit/{grant_id}
   ```

---

### One-Time Secret Issues

#### One-Time Secret Already Viewed
**Symptom:** `410 Gone` when attempting to retrieve one-time secret after first view

**Diagnosis:**
```bash
# Check if secret was already viewed
docker exec vault-flask-backend \
  python3 -c "
from vault.services.flask_backend.models.db import db, vault_one_time_secrets
row = db(vault_one_time_secrets.id == 'ots-001').select().first()
if row:
    print(f'Viewed: {row.viewed_at is not None}')
    if row.viewed_at:
        print(f'Viewed at: {row.viewed_at}')
"
```

**Solutions:**
1. **Create new one-time secret:**
   ```bash
   curl -X POST https://vault.localhost.local/api/v1/one-time \
     -H "Authorization: Bearer $JWT" \
     -H "Content-Type: application/json" \
     -d '{"secret_id": "sec-001", "ttl_seconds": 300}'
   ```

2. **Verify token hasn't been shared:**
   - One-time secret tokens should **never** be shared in logs or chat
   - If token is compromised, regenerate immediately

3. **Check token URL encoding:**
   - Token contains special characters
   - Ensure token is properly URL-encoded in request: `?token=jit%3A...`

---

### Authentication & Authorization Issues

#### JWT Token Invalid or Missing
**Symptom:** `401 Unauthorized` with "Missing or invalid JWT token"

**Diagnosis:**
```bash
# Check Authorization header
curl -v https://vault.localhost.local/api/v1/secrets \
  -H "Authorization: Bearer $JWT_TOKEN" 2>&1 | grep "Authorization"

# Decode JWT (inspect claims)
python3 -c "
import json, base64
token = '$JWT_TOKEN'.split('.')[1]
# Add padding if needed
token += '=' * (4 - len(token) % 4)
print(json.dumps(json.loads(base64.b64decode(token)), indent=2))
"
```

**Solutions:**
1. **Verify JWT is not expired:**
   - Check `exp` claim in decoded JWT
   - Must be > current Unix timestamp

2. **Check Authorization header format:**
   - Must be: `Authorization: Bearer <token>` (space between Bearer and token)
   - NOT: `Authorization: JWT <token>` or `Authorization: <token>`

3. **Refresh expired token:**
   ```bash
   # POST /api/v1/auth/refresh
   curl -X POST https://vault.localhost.local/api/v1/auth/refresh \
     -H "Authorization: Bearer $REFRESH_TOKEN" \
     -H "Content-Type: application/json"
   ```

4. **Verify OIDC issuer and audience:**
   - Check `iss` claim matches `OIDC_ISSUER`
   - Check `aud` claim includes service name

---

#### Insufficient Scope
**Symptom:** `403 Forbidden` with "Insufficient scope" error

**Diagnosis:**
```bash
# Decode JWT and check scopes
python3 -c "
import json, base64
token = '$JWT_TOKEN'.split('.')[1]
token += '=' * (4 - len(token) % 4)
claims = json.loads(base64.b64decode(token))
print(f\"Scopes: {claims.get('scope', 'NONE')}\")
"

# Check endpoint requirement
# Example: GET /api/v1/secrets requires 'vault:secrets:read' scope
```

**Solutions:**
1. **Request scopes from auth service:**
   - Contact admin to grant required scopes to user/service account
   - Scopes must be granted at token issuance

2. **Use service account with higher scopes:**
   - Service-to-service calls can use service account JWT with `vault:*` scope

3. **Check role mapping:**
   - admin role → `vault:*:*` (all operations)
   - maintainer role → `vault:secrets:read vault:secrets:write vault:jit:request`
   - viewer role → `vault:secrets:read vault:audit:read`

---

### Redis & Cloud Sync Issues

#### Redis Connection Failed
**Symptom:** `redis.exceptions.ConnectionError` or cloud sync hangs

**Diagnosis:**
```bash
# Check Redis is running
docker ps | grep redis

# Test connectivity
redis-cli -h $REDIS_HOST -p $REDIS_PORT PING
# Should return PONG

# Check authentication if enabled
redis-cli -h $REDIS_HOST -u "redis://:$REDIS_PASS@$REDIS_HOST:$REDIS_PORT" PING
```

**Solutions:**
1. **Verify Redis environment variables:**
   ```bash
   echo "REDIS_HOST=$REDIS_HOST"
   echo "REDIS_PORT=$REDIS_PORT"
   # DO NOT echo REDIS_PASS
   ```

2. **Check Redis ACLs (if using Redis 6+):**
   ```bash
   redis-cli ACL WHOAMI
   redis-cli ACL LIST | grep vault_sync
   ```

3. **Verify consumer group exists:**
   ```bash
   redis-cli XINFO GROUPS vault:cloud-sync
   # If error, sync-worker creates group on startup
   ```

4. **Clear stuck Redis stream (development only):**
   ```bash
   redis-cli DEL vault:cloud-sync
   # WARNING: data loss — use in development only
   ```

---

#### Cloud Sync Events Stalled
**Symptom:** Secrets updated locally but not syncing to cloud providers

**Diagnosis:**
```bash
# Check sync-worker is running
kubectl get pods --context local-alpha -n vault | grep sync-worker
# or
docker ps | grep sync-worker

# Check Redis stream has events
redis-cli XLEN vault:cloud-sync
# If > 0, events are queued

# Check consumer lag
redis-cli XINFO GROUPS vault:cloud-sync
```

**Solutions:**
1. **Verify cloud provider credentials:**
   ```bash
   # Check secret mounted in sync-worker pod
   kubectl get secret vault-cloud-creds --context local-alpha -n vault -o yaml
   ```

2. **Restart sync-worker:**
   ```bash
   kubectl rollout restart deployment/sync-worker --context local-alpha -n vault
   ```

3. **Check sync-worker logs:**
   ```bash
   kubectl logs -f deployment/sync-worker --context local-alpha -n vault
   # Look for: "Failed to sync to AWS" or provider-specific errors
   ```

4. **Manually trigger sync for specific provider:**
   ```bash
   curl -X POST https://vault.localhost.local/api/v1/admin/sync \
     -H "Authorization: Bearer $ADMIN_JWT" \
     -H "Content-Type: application/json" \
     -d '{"provider": "aws", "force": true}'
   ```

---

### License & Feature Gating Issues

#### License Validation Failed
**Symptom:** `403 License validation failed` when accessing features

**Diagnosis:**
```bash
# Check license key is set
echo "LICENSE_KEY=$LICENSE_KEY" | grep -v empty

# Check license server is reachable
curl -I $LICENSE_SERVER_URL/api/v2/validate

# Check RELEASE_MODE
echo "RELEASE_MODE=$RELEASE_MODE"
# In development, RELEASE_MODE=false bypasses validation
```

**Solutions:**
1. **Verify license key format:**
   - Format: `PENG-XXXX-XXXX-XXXX-XXXX-ABCD`
   - Check with license team if unsure

2. **Check auto-bypass domains:**
   - `*.localhost.local` (development)
   - `*.penguintech.cloud` (beta)
   - `*.nestdata.app` (production)
   - If running on auto-bypass domain, license check should pass

3. **Set RELEASE_MODE to false for development:**
   ```bash
   export RELEASE_MODE=false
   # Redeploy or restart Flask-Backend
   ```

4. **Validate license directly:**
   ```bash
   curl -X POST $LICENSE_SERVER_URL/api/v2/validate \
     -H "Content-Type: application/json" \
     -d "{\"license_key\": \"$LICENSE_KEY\", \"product\": \"vault\"}"
   ```

---

### WebUI Issues

#### Login Page Fails to Load
**Symptom:** Blank page or "Failed to load" on login at `https://vault.localhost.local/`

**Diagnosis:**
```bash
# Check WebUI container is running
docker ps | grep webui
kubectl get pods --context local-alpha -n vault | grep webui

# Check browser console for errors (F12 → Console tab)

# Check WebUI logs
docker logs vault-webui
# or
kubectl logs deployment/webui --context local-alpha -n vault
```

**Solutions:**
1. **Verify WebUI environment variables:**
   ```bash
   # In Dockerfile or k8s/helm/webui/values-alpha.yaml
   env:
     - name: VITE_API_URL
       value: "https://vault.localhost.local"  # or backend IP:port
   ```

2. **Check API connection:**
   ```bash
   # From WebUI container, test API reachability
   curl -I https://vault-flask-backend:5000/api/v1/status
   ```

3. **Clear browser cache and hard reload:**
   ```
   Ctrl+Shift+R (Windows/Linux) or Cmd+Shift+R (macOS)
   ```

4. **Check React version compatibility:**
   - Ensure `@penguintechinc/react-libs` version is compatible
   - Check `package.json` dependencies

---

#### API Calls Return 404 or CORS Error
**Symptom:** `404 Not Found` from WebUI or `Access-Control-Allow-Origin` CORS error

**Diagnosis:**
```bash
# Check API endpoint exists
curl -I https://vault.localhost.local/api/v1/secrets

# Check CORS headers are present
curl -I -H "Origin: https://vault.localhost.local" \
  https://vault.localhost.local/api/v1/secrets | grep "Access-Control"
```

**Solutions:**
1. **Verify API is running:**
   ```bash
   docker ps | grep flask-backend
   kubectl get pods --context local-alpha -n vault | grep flask-backend
   ```

2. **Check CORS_ORIGINS environment variable:**
   ```bash
   # Flask-Backend must allow WebUI origin
   CORS_ORIGINS="https://vault.localhost.local"
   # Or use wildcard for development: "http://localhost:*,https://localhost:*"
   ```

3. **Check API endpoint path:**
   - Endpoints use versioning: `/api/v1/endpoint`
   - NOT `/endpoint` or `/api/endpoint`

4. **Verify certificate if using HTTPS:**
   ```bash
   curl -k https://vault.localhost.local/api/v1/status  # Skip cert validation with -k
   ```

---

## 🆘 Getting Help

### Logs to Collect

**When reporting issues, provide:**

1. **Flask-Backend logs:**
   ```bash
   docker logs vault-flask-backend 2>&1 | tail -100
   # or
   kubectl logs deployment/flask-backend --context local-alpha -n vault --tail=100
   ```

2. **WebUI browser console (F12 → Console tab)**

3. **Environment info:**
   ```bash
   docker --version
   docker-compose --version
   python3 --version
   node --version
   ```

4. **Kubernetes cluster info (if applicable):**
   ```bash
   kubectl version --context local-alpha
   kubectl get nodes --context local-alpha
   ```

5. **Database logs (if using Docker):**
   ```bash
   docker logs vault-postgres 2>&1 | tail -50
   ```

---

### Common Error Messages

| Error | Root Cause | Solution |
|-------|-----------|----------|
| `sqlalchemy.exc.IntegrityError: UNIQUE constraint failed` | Duplicate secret name or key | Use unique names; check existing data |
| `cryptography.fernet.InvalidToken` | Wrong MEK or corrupted data | Verify VAULT_MEK matches storage |
| `psycopg2.OperationalError: FATAL: Ident authentication failed` | Wrong database user or no CREATEUSER role | Grant CREATEUSER role to db_user |
| `redis.exceptions.ResponseError: MOVED` | Redis cluster redirect | Ensure REDIS_HOST is cluster endpoint |
| `jwt.exceptions.DecodeError: Invalid token` | Malformed or unsigned JWT | Regenerate token from auth service |
| `FileNotFoundError: [Errno 2] No such file or directory: 'alembic'` | Alembic not installed | Run `pip install alembic` or check venv |
| `docker: 'compose' is not a command` | Using Docker without Compose plugin | Install: `sudo apt install docker-compose-plugin` |

---

### Support Contacts

- **SkausWatch Team**: support@penguintech.io
- **License Issues**: sales@penguintech.io
- **Status Page**: https://status.penguintech.io
- **Vault GitHub Issues**: https://github.com/penguintechinc/skauswatch/issues

---

**Last Updated:** 2026-03-10
**Vault Version:** 1.0.0
