# Vault — Configuration & Setup Guide

**Audience:** DevOps | Infrastructure Engineers

## Environment Variables

### Flask-Backend Configuration

**Database Connection:**
```bash
DB_TYPE=postgresql              # postgresql | mysql | sqlite (default: postgresql)
DB_HOST=localhost               # Database host
DB_PORT=5432                    # Database port
DB_NAME=vault_db               # Database name
DB_USER=vault-flask-backend-rw # Per-service database account
DB_PASS=<secure-password>       # Database password
DB_POOL_SIZE=10                 # Connection pool size (default: 10)
DB_POOL_TIMEOUT=30              # Pool timeout in seconds (default: 30)
```

**Redis/Valkey (Cloud Sync & Job Queue):**
```bash
REDIS_HOST=localhost            # Redis host
REDIS_PORT=6379                 # Redis port (default: 6379)
REDIS_USER=vault-sync-worker   # Per-service Redis user (Redis 6+)
REDIS_PASS=<secure-password>    # Redis password
REDIS_DB=0                      # Database number (default: 0)
REDIS_SSL=false                 # Use SSL/TLS (default: false)
```

**Encryption (Master Encryption Key):**
```bash
VAULT_MEK=<base64-32-bytes>    # Master Encryption Key (AES-256, base64 encoded)
VAULT_MEK_VERSION=1            # Current MEK version for rotation tracking (default: 1)
```

**Authentication & Authorization:**
```bash
OIDC_ISSUER=https://auth-service  # OIDC issuer URL
OIDC_AUDIENCE=vault              # Expected JWT audience claim
JWT_ALGORITHM=RS256               # JWT signing algorithm (default: RS256)
JWT_PUBLIC_KEY=/path/to/key.pub   # Public key for JWT verification
JWT_EXPIRATION=3600               # JWT expiration in seconds (default: 1 hour)
```

**License Validation:**
```bash
LICENSE_KEY=PENG-XXXX-XXXX-XXXX-XXXX-ABCD  # PenguinTech license key
LICENSE_SERVER_URL=https://license.penguintech.io  # License server endpoint
RELEASE_MODE=false              # Enable license enforcement (default: false)
FEATURES_REQUIRED=vault        # Required features (comma-separated)
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
SERVICE_NAME=vault-flask-backend  # Service identifier
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
REDIS_USER=vault-sync-worker   # Per-service Redis user
REDIS_PASS=<secure-password>    # Redis password
REDIS_STREAMS_BATCH_SIZE=10     # Messages per batch (default: 10)
REDIS_STREAMS_TIMEOUT=1000      # XREAD timeout in ms (default: 1000)
CONSUMER_GROUP=vault-sync      # Consumer group name
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

**Configuration in Vault:**
```json
{
  "provider": "aws_secrets_manager",
  "region": "us-east-1",
  "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
  "secret_name_prefix": "vault/",
  "secret_rotation_enabled": true,
  "secret_rotation_days": 30,
  "tags": {
    "Environment": "production",
    "ManagedBy": "Vault"
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
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:vault/*"
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
  name: vault-aws-credentials
  namespace: vault
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
        name: vault-aws-credentials
        key: aws_access_key_id
  - name: AWS_SECRET_ACCESS_KEY
    valueFrom:
      secretKeyRef:
        name: vault-aws-credentials
        key: aws_secret_access_key
```

### Azure Key Vault Integration

**Configuration in Vault:**
```json
{
  "provider": "azure_key_vault",
  "vault_name": "my-vault-vault",
  "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "secret_name_prefix": "vault-",
  "enable_versioning": true,
  "tags": {
    "Environment": "production",
    "ManagedBy": "Vault"
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
  name: vault-azure-credentials
  namespace: vault
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
        name: vault-azure-credentials
        key: azure_client_id
```

### GCP Secret Manager Integration

**Configuration in Vault:**
```json
{
  "provider": "gcp_secret_manager",
  "project_id": "my-gcp-project",
  "secret_name_prefix": "vault-",
  "enable_replication": true,
  "replication_policy": "automatic",
  "labels": {
    "environment": "production",
    "managed_by": "vault"
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
  name: vault-gcp-credentials
  namespace: vault
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
      secretName: vault-gcp-credentials
env:
  - name: GOOGLE_APPLICATION_CREDENTIALS
    value: /var/secrets/google/gcp-key.json
```

### Oracle OCI Vault Integration

**Configuration in Vault:**
```json
{
  "provider": "oracle_oci",
  "vault_id": "ocid1.vault.oc1.phx.xxxxxxxxxxxxx",
  "compartment_id": "ocid1.compartment.oc1.xxxxxxxxxxxxx",
  "region": "us-phoenix-1",
  "secret_name_prefix": "vault-",
  "encryption_key_id": "ocid1.key.oc1.phx.xxxxxxxxxxxxx",
  "freeform_tags": {
    "environment": "production",
    "managed_by": "vault"
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

**Configuration in Vault:**
```json
{
  "provider": "kubernetes",
  "namespace": "default",
  "secret_name_prefix": "vault-",
  "labels": {
    "app": "vault",
    "managed_by": "vault"
  },
  "annotations": {
    "vault.skauswatch.app/synced": "true"
  }
}
```

**RBAC Requirements (Sync-Worker ServiceAccount):**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: vault-sync-worker
  namespace: vault
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: vault-sync-worker
  namespace: vault
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: vault-sync-worker
subjects:
  - kind: ServiceAccount
    name: vault-sync-worker
    namespace: vault
```

---

## Database Setup

### PostgreSQL (Primary)

```bash
# Create database
createdb vault_db

# Create service accounts
psql -c "CREATE USER \"vault-flask-backend-rw\" WITH PASSWORD '<password>';"
psql -c "CREATE USER \"vault-sync-worker-rw\" WITH PASSWORD '<password>';"
psql -c "CREATE USER \"vault-webui-ro\" WITH PASSWORD '<password>';"
psql -c "CREATE USER \"vault-migration-admin\" WITH SUPERUSER PASSWORD '<password>';"

# Run migrations
cd services/flask-backend
alembic upgrade head

# Grant permissions
psql vault_db << EOF
GRANT USAGE ON SCHEMA public TO "vault-flask-backend-rw";
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "vault-flask-backend-rw";
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO "vault-flask-backend-rw";

GRANT USAGE ON SCHEMA public TO "vault-sync-worker-rw";
GRANT SELECT, INSERT, UPDATE ON vault_sync_events TO "vault-sync-worker-rw";
GRANT SELECT, INSERT ON vault_audit_logs TO "vault-sync-worker-rw";

GRANT USAGE ON SCHEMA public TO "vault-webui-ro";
GRANT SELECT ON vault_secrets TO "vault-webui-ro";
GRANT SELECT ON vault_audit_logs TO "vault-webui-ro";
EOF
```

### MySQL / MariaDB

```bash
# Create database
mysql -u root -e "CREATE DATABASE vault_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"

# Create service accounts
mysql -u root << EOF
CREATE USER 'vault-flask-backend-rw'@'%' IDENTIFIED BY '<password>';
CREATE USER 'vault-sync-worker-rw'@'%' IDENTIFIED BY '<password>';
CREATE USER 'vault-webui-ro'@'%' IDENTIFIED BY '<password>';
CREATE USER 'vault-migration-admin'@'%' IDENTIFIED BY '<password>';
EOF

# Run migrations
cd services/flask-backend
alembic upgrade head

# Grant permissions
mysql -u root << EOF
GRANT ALL PRIVILEGES ON vault_db.* TO 'vault-flask-backend-rw'@'%';
GRANT SELECT, INSERT, UPDATE ON vault_db.vault_sync_events TO 'vault-sync-worker-rw'@'%';
GRANT SELECT, INSERT ON vault_db.vault_audit_logs TO 'vault-sync-worker-rw'@'%';
GRANT SELECT ON vault_db.vault_secrets TO 'vault-webui-ro'@'%';
GRANT SELECT ON vault_db.vault_audit_logs TO 'vault-webui-ro'@'%';
GRANT ALL PRIVILEGES ON vault_db.* TO 'vault-migration-admin'@'%';
FLUSH PRIVILEGES;
EOF
```

---

## Redis/Valkey Setup

```bash
# Create Redis users (Redis 6+ / Valkey)
redis-cli << EOF
ACL SETUSER vault-flask-backend-rw on >/path/password ~vault-flask-backend:* +@all
ACL SETUSER vault-sync-worker on >/path/password ~vault-sync:* +@all
ACL SETUSER vault-webui-ro on >/path/password ~vault:* +@read
SAVE
EOF

# Or in Valkey config (valkey.conf):
user vault-flask-backend-rw on >password ~vault-flask-backend:* +@all
user vault-sync-worker on >password ~vault-sync:* +@all
user vault-webui-ro on >password ~vault:* +@read

# Create consumer group for sync-worker
redis-cli << EOF
XGROUP CREATE vault:sync:aws_secrets_manager vault-sync MKSTREAM
XGROUP CREATE vault:sync:azure_key_vault vault-sync MKSTREAM
XGROUP CREATE vault:sync:gcp_secret_manager vault-sync MKSTREAM
XGROUP CREATE vault:sync:oracle_oci vault-sync MKSTREAM
XGROUP CREATE vault:sync:k8s_secrets vault-sync MKSTREAM
EOF
```

---

## Kubernetes Secrets & ConfigMaps

**License Configuration:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: vault-license
  namespace: vault
type: Opaque
stringData:
  license_key: PENG-XXXX-XXXX-XXXX-XXXX-ABCD

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: vault-config
  namespace: vault
data:
  license_server_url: https://license.penguintech.io
  release_mode: "true"  # Enable license enforcement
```

**Encryption Key:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: vault-encryption
  namespace: vault
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
  name: vault-db-credentials
  namespace: vault
type: Opaque
stringData:
  db_host: postgresql.default.svc.cluster.local
  db_port: "5432"
  db_name: vault_db
  db_user: vault-flask-backend-rw
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
helm upgrade --install vault-flask-backend ./k8s/helm/flask-backend \
  --kube-context dal2-beta \
  --namespace vault \
  --values ./k8s/helm/flask-backend/values.yaml \
  --values ./k8s/helm/flask-backend/values-beta.yaml \
  --set image.tag=beta-$(date +%s)
```

---

**Vault v1.0.0** | Configuration Guide | Limited AGPL-3.0
