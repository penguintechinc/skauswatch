# IceBox — Configuration & Setup Guide

**Audience:** DevOps | Infrastructure Engineers

## Environment Variables

### Flask-Backend Configuration

**Database Connection:**
```bash
DB_TYPE=postgresql              # postgresql | mysql | sqlite (default: postgresql)
DB_HOST=localhost               # Database host
DB_PORT=5432                    # Database port
DB_NAME=icebox_db               # Database name
DB_USER=icebox-flask-backend-rw # Per-service database account
DB_PASS=<secure-password>       # Database password
DB_POOL_SIZE=10                 # Connection pool size (default: 10)
DB_POOL_TIMEOUT=30              # Pool timeout in seconds (default: 30)
```

**Redis/Valkey (Cloud Sync & Job Queue):**
```bash
REDIS_HOST=localhost            # Redis host
REDIS_PORT=6379                 # Redis port (default: 6379)
REDIS_USER=icebox-sync-worker   # Per-service Redis user (Redis 6+)
REDIS_PASS=<secure-password>    # Redis password
REDIS_DB=0                      # Database number (default: 0)
REDIS_SSL=false                 # Use SSL/TLS (default: false)
```

**Encryption (Master Encryption Key):**
```bash
ICEBOX_MEK=<base64-32-bytes>    # Master Encryption Key (AES-256, base64 encoded)
ICEBOX_MEK_VERSION=1            # Current MEK version for rotation tracking (default: 1)
```

**Authentication & Authorization:**
```bash
OIDC_ISSUER=https://auth-service  # OIDC issuer URL
OIDC_AUDIENCE=icebox              # Expected JWT audience claim
JWT_ALGORITHM=RS256               # JWT signing algorithm (default: RS256)
JWT_PUBLIC_KEY=/path/to/key.pub   # Public key for JWT verification
JWT_EXPIRATION=3600               # JWT expiration in seconds (default: 1 hour)
```

**License Validation:**
```bash
LICENSE_KEY=PENG-XXXX-XXXX-XXXX-XXXX-ABCD  # PenguinTech license key
LICENSE_SERVER_URL=https://license.penguintech.io  # License server endpoint
RELEASE_MODE=false              # Enable license enforcement (default: false)
FEATURES_REQUIRED=icebox        # Required features (comma-separated)
```

**Flask Application:**
```bash
FLASK_ENV=development           # development | production (default: development)
FLASK_DEBUG=false               # Enable debug mode (default: false)
SECRET_KEY=<secure-random-string>  # Flask session secret
LOG_LEVEL=info                  # debug | info | warning | error (default: info)
CORS_ORIGINS=http://localhost:3100,http://localhost:5000  # CORS allowed origins
```

**Service Configuration:**
```bash
SERVICE_NAME=icebox-flask-backend  # Service identifier
SERVICE_PORT=5100               # API port (default: 5100)
WORKERS=4                       # Gunicorn workers (default: 4)
WORKER_CLASS=uvicorn.workers.UvicornWorker  # Worker class for async
WORKER_TIMEOUT=120              # Worker timeout in seconds (default: 120)
```

### Sync-Worker Configuration

**Redis Streams:**
```bash
REDIS_HOST=localhost            # Redis host
REDIS_PORT=6379                 # Redis port
REDIS_USER=icebox-sync-worker   # Per-service Redis user
REDIS_PASS=<secure-password>    # Redis password
REDIS_STREAMS_BATCH_SIZE=10     # Messages per batch (default: 10)
REDIS_STREAMS_TIMEOUT=1000      # XREAD timeout in ms (default: 1000)
CONSUMER_GROUP=icebox-sync      # Consumer group name
```

**Cloud Provider Credentials (Per Integration):**

See "Cloud Provider Setup" section below for detailed provider configurations.

**Logging:**
```bash
LOG_LEVEL=info                  # debug | info | warning | error
LOG_FORMAT=json                 # json | text (default: json)
```

### WebUI Configuration

**API Endpoint:**
```bash
VITE_API_URL=http://localhost:5100  # Flask backend API URL
VITE_API_TIMEOUT=10000              # Request timeout in ms (default: 10s)
VITE_AUTH_REDIRECT_URI=http://localhost:3100/auth/callback  # OAuth2 redirect
```

**Feature Flags:**
```bash
VITE_ENABLE_JIT=true            # Enable JIT feature
VITE_ENABLE_ONE_TIME=true       # Enable one-time secrets
VITE_ENABLE_CLOUD_SYNC=true     # Enable cloud sync
VITE_ENABLE_AUDIT_LOGS=true     # Enable audit log viewing
```

---

## Cloud Provider Setup

### AWS Secrets Manager Integration

**Configuration in IceBox:**
```json
{
  "provider": "aws_secrets_manager",
  "region": "us-east-1",
  "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
  "secret_name_prefix": "icebox/",
  "secret_rotation_enabled": true,
  "secret_rotation_days": 30,
  "tags": {
    "Environment": "production",
    "ManagedBy": "IceBox"
  }
}
```

**AWS IAM Policy (Sync-Worker):**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:CreateSecret",
        "secretsmanager:GetSecretValue",
        "secretsmanager:UpdateSecret",
        "secretsmanager:DeleteSecret",
        "secretsmanager:TagResource"
      ],
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:icebox/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/*"
    }
  ]
}
```

**Kubernetes Secret (sync-worker pod):**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: icebox-aws-credentials
  namespace: icebox
type: Opaque
stringData:
  aws_access_key_id: <YOUR_ACCESS_KEY>
  aws_secret_access_key: <YOUR_SECRET_KEY>
---
# Reference in sync-worker Deployment:
env:
  - name: AWS_ACCESS_KEY_ID
    valueFrom:
      secretKeyRef:
        name: icebox-aws-credentials
        key: aws_access_key_id
  - name: AWS_SECRET_ACCESS_KEY
    valueFrom:
      secretKeyRef:
        name: icebox-aws-credentials
        key: aws_secret_access_key
```

### Azure Key Vault Integration

**Configuration in IceBox:**
```json
{
  "provider": "azure_key_vault",
  "vault_name": "my-icebox-vault",
  "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "secret_name_prefix": "icebox-",
  "enable_versioning": true,
  "tags": {
    "Environment": "production",
    "ManagedBy": "IceBox"
  }
}
```

**Azure App Registration (Sync-Worker):**
1. Create app in Azure AD
2. Generate client secret
3. Grant permissions: `Microsoft.KeyVault/vaults/secrets/*`

**Kubernetes Secret:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: icebox-azure-credentials
  namespace: icebox
type: Opaque
stringData:
  azure_client_id: <CLIENT_ID>
  azure_client_secret: <CLIENT_SECRET>
  azure_tenant_id: <TENANT_ID>
---
env:
  - name: AZURE_CLIENT_ID
    valueFrom:
      secretKeyRef:
        name: icebox-azure-credentials
        key: azure_client_id
```

### GCP Secret Manager Integration

**Configuration in IceBox:**
```json
{
  "provider": "gcp_secret_manager",
  "project_id": "my-gcp-project",
  "secret_name_prefix": "icebox-",
  "enable_replication": true,
  "replication_policy": "automatic",
  "labels": {
    "environment": "production",
    "managed_by": "icebox"
  }
}
```

**GCP Service Account (Sync-Worker):**
1. Create service account in GCP Console
2. Grant roles: `roles/secretmanager.secretAccessor`, `roles/secretmanager.admin`
3. Create JSON key file
4. Mount as Kubernetes Secret

**Kubernetes Secret:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: icebox-gcp-credentials
  namespace: icebox
type: Opaque
data:
  gcp-key.json: <base64-encoded-service-account-key>
---
volumeMounts:
  - name: gcp-credentials
    mountPath: /var/secrets/google
    readOnly: true
volumes:
  - name: gcp-credentials
    secret:
      secretName: icebox-gcp-credentials
env:
  - name: GOOGLE_APPLICATION_CREDENTIALS
    value: /var/secrets/google/gcp-key.json
```

### Oracle OCI Vault Integration

**Configuration in IceBox:**
```json
{
  "provider": "oracle_oci",
  "vault_id": "ocid1.vault.oc1.phx.xxxxxxxxxxxxx",
  "compartment_id": "ocid1.compartment.oc1.xxxxxxxxxxxxx",
  "region": "us-phoenix-1",
  "secret_name_prefix": "icebox-",
  "encryption_key_id": "ocid1.key.oc1.phx.xxxxxxxxxxxxx",
  "freeform_tags": {
    "environment": "production",
    "managed_by": "icebox"
  }
}
```

**OCI User Credentials (Sync-Worker):**
```bash
OCI_USER_OCID=ocid1.user.oc1.xxxxxxxxxxxxx
OCI_FINGERPRINT=xx:xx:xx:xx:xx:xx:xx:xx
OCI_PRIVATE_KEY=/path/to/oci_api_key.pem
OCI_TENANCY_OCID=ocid1.tenancy.oc1.xxxxxxxxxxxxx
OCI_REGION=us-phoenix-1
```

### Kubernetes Secrets Integration

**Configuration in IceBox:**
```json
{
  "provider": "kubernetes",
  "namespace": "default",
  "secret_name_prefix": "icebox-",
  "labels": {
    "app": "icebox",
    "managed_by": "icebox"
  },
  "annotations": {
    "icebox.skauswatch.app/synced": "true"
  }
}
```

**RBAC Requirements (Sync-Worker ServiceAccount):**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: icebox-sync-worker
  namespace: icebox
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: icebox-sync-worker
  namespace: icebox
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: icebox-sync-worker
subjects:
  - kind: ServiceAccount
    name: icebox-sync-worker
    namespace: icebox
```

---

## Database Setup

### PostgreSQL (Primary)

```bash
# Create database
createdb icebox_db

# Create service accounts
psql -c "CREATE USER \"icebox-flask-backend-rw\" WITH PASSWORD '<password>';"
psql -c "CREATE USER \"icebox-sync-worker-rw\" WITH PASSWORD '<password>';"
psql -c "CREATE USER \"icebox-webui-ro\" WITH PASSWORD '<password>';"
psql -c "CREATE USER \"icebox-migration-admin\" WITH SUPERUSER PASSWORD '<password>';"

# Run migrations
cd services/flask-backend
alembic upgrade head

# Grant permissions
psql icebox_db << EOF
GRANT USAGE ON SCHEMA public TO "icebox-flask-backend-rw";
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "icebox-flask-backend-rw";
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO "icebox-flask-backend-rw";

GRANT USAGE ON SCHEMA public TO "icebox-sync-worker-rw";
GRANT SELECT, INSERT, UPDATE ON icebox_sync_events TO "icebox-sync-worker-rw";
GRANT SELECT, INSERT ON icebox_audit_logs TO "icebox-sync-worker-rw";

GRANT USAGE ON SCHEMA public TO "icebox-webui-ro";
GRANT SELECT ON icebox_secrets TO "icebox-webui-ro";
GRANT SELECT ON icebox_audit_logs TO "icebox-webui-ro";
EOF
```

### MySQL / MariaDB

```bash
# Create database
mysql -u root -e "CREATE DATABASE icebox_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"

# Create service accounts
mysql -u root << EOF
CREATE USER 'icebox-flask-backend-rw'@'%' IDENTIFIED BY '<password>';
CREATE USER 'icebox-sync-worker-rw'@'%' IDENTIFIED BY '<password>';
CREATE USER 'icebox-webui-ro'@'%' IDENTIFIED BY '<password>';
CREATE USER 'icebox-migration-admin'@'%' IDENTIFIED BY '<password>';
EOF

# Run migrations
cd services/flask-backend
alembic upgrade head

# Grant permissions
mysql -u root << EOF
GRANT ALL PRIVILEGES ON icebox_db.* TO 'icebox-flask-backend-rw'@'%';
GRANT SELECT, INSERT, UPDATE ON icebox_db.icebox_sync_events TO 'icebox-sync-worker-rw'@'%';
GRANT SELECT, INSERT ON icebox_db.icebox_audit_logs TO 'icebox-sync-worker-rw'@'%';
GRANT SELECT ON icebox_db.icebox_secrets TO 'icebox-webui-ro'@'%';
GRANT SELECT ON icebox_db.icebox_audit_logs TO 'icebox-webui-ro'@'%';
GRANT ALL PRIVILEGES ON icebox_db.* TO 'icebox-migration-admin'@'%';
FLUSH PRIVILEGES;
EOF
```

---

## Redis/Valkey Setup

```bash
# Create Redis users (Redis 6+ / Valkey)
redis-cli << EOF
ACL SETUSER icebox-flask-backend-rw on >/path/password ~icebox-flask-backend:* +@all
ACL SETUSER icebox-sync-worker on >/path/password ~icebox-sync:* +@all
ACL SETUSER icebox-webui-ro on >/path/password ~icebox:* +@read
SAVE
EOF

# Or in Valkey config (valkey.conf):
user icebox-flask-backend-rw on >password ~icebox-flask-backend:* +@all
user icebox-sync-worker on >password ~icebox-sync:* +@all
user icebox-webui-ro on >password ~icebox:* +@read

# Create consumer group for sync-worker
redis-cli << EOF
XGROUP CREATE icebox:sync:aws_secrets_manager icebox-sync MKSTREAM
XGROUP CREATE icebox:sync:azure_key_vault icebox-sync MKSTREAM
XGROUP CREATE icebox:sync:gcp_secret_manager icebox-sync MKSTREAM
XGROUP CREATE icebox:sync:oracle_oci icebox-sync MKSTREAM
XGROUP CREATE icebox:sync:k8s_secrets icebox-sync MKSTREAM
EOF
```

---

## Kubernetes Secrets & ConfigMaps

**License Configuration:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: icebox-license
  namespace: icebox
type: Opaque
stringData:
  license_key: PENG-XXXX-XXXX-XXXX-XXXX-ABCD

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: icebox-config
  namespace: icebox
data:
  license_server_url: https://license.penguintech.io
  release_mode: "true"  # Enable license enforcement
```

**Encryption Key:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: icebox-encryption
  namespace: icebox
type: Opaque
stringData:
  mek: <base64-32-byte-key>
  mek_version: "1"
```

**Database Credentials:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: icebox-db-credentials
  namespace: icebox
type: Opaque
stringData:
  db_host: postgresql.default.svc.cluster.local
  db_port: "5432"
  db_name: icebox_db
  db_user: icebox-flask-backend-rw
  db_pass: <secure-password>
```

---

## Environment Overlays

| Variable | Alpha | Beta | Prod |
|----------|-------|------|------|
| `LOG_LEVEL` | `debug` | `info` | `warn` |
| `DB_POOL_SIZE` | 2 | 5 | 20 |
| `RELEASE_MODE` | `false` | `true` | `true` |
| `WORKERS` | 2 | 4 | 8 |
| `REPLICA_COUNT` | 1 | 1 | 3 |
| `CPU_REQUEST` | 100m | 250m | 500m |
| `MEMORY_REQUEST` | 128Mi | 256Mi | 512Mi |

---

## Helm Values Override Pattern

```bash
# Deploy with environment-specific values
helm upgrade --install icebox-flask-backend ./k8s/helm/flask-backend \
  --kube-context dal2-beta \
  --namespace icebox \
  --values ./k8s/helm/flask-backend/values.yaml \
  --values ./k8s/helm/flask-backend/values-beta.yaml \
  --set image.tag=beta-$(date +%s)
```

---

**IceBox v1.0.0** | Configuration Guide | Limited AGPL-3.0
