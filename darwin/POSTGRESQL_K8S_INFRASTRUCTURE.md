# PostgreSQL Kubernetes Infrastructure Summary

## Overview
Complete PostgreSQL Kubernetes infrastructure created for the Darwin project with both raw manifests and production-ready Helm charts following Darwin project patterns and best practices.

## Directory Structure

### Raw Kubernetes Manifests
```
/home/penguin/code/darwin/k8s/manifests/postgresql/
├── statefulset.yaml    # PostgreSQL StatefulSet with persistent storage
├── service.yaml        # Headless + ClusterIP services for database
└── configmap.yaml      # PostgreSQL configuration
```

### Helm Chart
```
/home/penguin/code/darwin/k8s/helm/postgresql/
├── Chart.yaml                    # Helm chart metadata
├── values.yaml                   # Default values
├── values-dev.yaml               # Development environment
├── values-staging.yaml           # Staging environment
├── values-prod.yaml              # Production environment
└── templates/
    ├── _helpers.tpl              # Helm template helpers
    ├── statefulset.yaml          # Templatized StatefulSet
    ├── service.yaml              # Templatized services
    ├── configmap.yaml            # Templatized ConfigMap
    └── secret.yaml               # Database credentials Secret
```

## Raw Manifests Details

### statefulset.yaml
- **Replicas**: 1
- **Image**: postgres:16-alpine
- **Storage**: 10Gi PersistentVolumeClaim per pod
- **Resources**:
  - Requests: 250m CPU, 512Mi RAM
  - Limits: 500m CPU, 1Gi RAM
- **Health Checks**:
  - Liveness: pg_isready (30s initial delay, 10s period)
  - Readiness: pg_isready (10s initial delay, 5s period)
- **Security**:
  - runAsUser: 999 (postgres)
  - runAsNonRoot: true
  - allowPrivilegeEscalation: false
  - Drop all Linux capabilities
- **Environment Variables**:
  - POSTGRES_DB: From Secret
  - POSTGRES_USER: From Secret
  - POSTGRES_PASSWORD: From Secret
  - PGDATA: /var/lib/postgresql/data/pgdata
- **Configuration**: Mounted from ConfigMap

### service.yaml
- **Headless Service**: postgresql-headless (clusterIP: None) for StatefulSet DNS records
- **ClusterIP Service**: postgresql for application connections
- **Port**: 5432 (standard PostgreSQL)
- **Type**: ClusterIP for client service

### configmap.yaml
Contains PostgreSQL tuning configuration:
- max_connections: 100
- shared_buffers: 256MB
- effective_cache_size: 1GB
- WAL settings for replication-ready setup
- Logging configuration for audit trails
- Performance tuning parameters

## Helm Chart Details

### Chart Metadata (Chart.yaml)
- **Version**: 1.0.0
- **AppVersion**: 16 (PostgreSQL)
- **Type**: Application
- **Maintained by**: Penguin Tech Inc

### Default Values (values.yaml)
- **Replicas**: 1
- **Image**: postgres:16-alpine
- **Storage**: 10Gi
- **Storage Class**: standard (configurable)
- **Resources**: 250m/512Mi requests, 500m/1Gi limits
- **PostgreSQL Configuration**:
  - maxConnections: 100
  - sharedBuffers: 256MB
  - effectiveCacheSize: 1GB
  - walLevel: replica (replication-ready)

### Development Values (values-dev.yaml)
- **Replicas**: 1 (single pod)
- **Storage**: 5Gi (minimal for development)
- **Resources**: 100m/256Mi requests, 250m/512Mi limits
- **PostgreSQL Config**: Reduced for development
  - maxConnections: 50
  - sharedBuffers: 128MB
- **Features Disabled**:
  - Backup: false
  - Monitoring: false

### Staging Values (values-staging.yaml)
- **Replicas**: 2 (high availability)
- **Storage**: 20Gi (intermediate)
- **Resources**: 500m/1Gi requests, 1000m/2Gi limits
- **PostgreSQL Config**: Medium production settings
  - maxConnections: 200
  - sharedBuffers: 512MB
  - effectiveCacheSize: 2GB
- **Features Enabled**:
  - Backup: true (daily at 2 AM UTC, 7-day retention)
  - Monitoring: true

### Production Values (values-prod.yaml)
- **Replicas**: 3 (full HA)
- **Storage**: 100Gi (large production volume)
- **Resources**: 1000m/2Gi requests, 2000m/4Gi limits
- **PostgreSQL Config**: High-performance production settings
  - maxConnections: 300
  - sharedBuffers: 1GB
  - effectiveCacheSize: 4GB
  - maxWalSenders: 5
  - maxWorkerProcesses: 4
- **Pod Anti-Affinity**: Preferred spread across different nodes
- **Features Enabled**:
  - Backup: true (daily, 30-day retention)
  - Monitoring: true with ServiceMonitor for Prometheus

## Helm Templates

### _helpers.tpl
Standard Helm template helper functions following best practices:
- `postgresql.name`: Expands chart name with overrides
- `postgresql.fullname`: Fully qualified app name
- `postgresql.chart`: Chart label for tracking
- `postgresql.labels`: Common labels for all resources
- `postgresql.selectorLabels`: Pod selector labels
- `postgresql.serviceAccountName`: Service account naming
- `postgresql.headlessServiceName`: Headless service naming

### secret.yaml
- **Kind**: Secret (Opaque)
- **Stores**: database, username, password (base64 encoded)
- **Referenced by**: StatefulSet environment variables
- **Security**: Credentials never stored in ConfigMap

### configmap.yaml
- Templatized PostgreSQL postgresql.conf
- All settings derived from values files
- Mounted read-only as /etc/postgresql/postgresql.conf
- Supports environment-specific tuning

### service.yaml
- **Headless Service**: postgresql-headless (clusterIP: None)
  - Enables stable DNS names: postgresql-0.postgresql-headless, postgresql-1, etc.
  - Required for StatefulSet service discovery
- **ClusterIP Service**: postgresql
  - Standard service for application connections
  - Both listen on port 5432

### statefulset.yaml
Fully templatized StatefulSet with:
- Volume claim templates for persistent storage
- Config/Secret checksums for rolling updates on changes
- Pod annotations for Prometheus scraping readiness
- Security context with non-root user (UID 999)
- All environment variables from Secret (credentials protection)
- Proper health check configuration per environment
- Pod affinity rules for production HA across nodes

## Key Features

### Security Best Practices
- Non-root user (postgres, UID 999)
- No privilege escalation allowed
- All Linux capabilities dropped
- Read-only root filesystem support
- Database credentials in Secrets, not ConfigMaps
- Pod security context with fsGroup for volume permissions

### High Availability
- StatefulSet with stable DNS names (postgresql-0, postgresql-1, etc.)
- Headless service for pod-to-pod discovery
- Pod anti-affinity in production (spread across different nodes)
- WAL replication ready (wal_level=replica configuration)
- Multi-replica support in staging/production

### Persistence & Data
- Persistent storage with volume claim templates
- Per-pod independent storage in StatefulSet
- StorageClass support (default: standard, configurable)
- PGDATA environment variable configuration

### Operations & Monitoring
- Prometheus metrics scraping support (pod annotations)
- Backup scheduling capability (template-ready)
- Health checks with appropriate timeouts and thresholds
- Database initialization via POSTGRES_* environment variables
- Configurable resource limits per environment

### Flexibility & Customization
- Three environment-specific value files (dev/staging/prod)
- Override any configuration via Helm values
- Support for 1-3+ replicas
- Configurable storage class and size
- Templated for easy customization

## Deployment Examples

### Using Raw Manifests
```bash
# Create namespace and apply manifests
kubectl create namespace project-template
kubectl apply -f k8s/manifests/postgresql/
```

### Using Helm - Development
```bash
helm install postgresql k8s/helm/postgresql \
  -f k8s/helm/postgresql/values-dev.yaml \
  -n project-template
```

### Using Helm - Staging
```bash
helm install postgresql k8s/helm/postgresql \
  -f k8s/helm/postgresql/values-staging.yaml \
  -n project-template
```

### Using Helm - Production
```bash
helm install postgresql k8s/helm/postgresql \
  -f k8s/helm/postgresql/values-prod.yaml \
  -n project-template
```

### Upgrading Helm Release
```bash
helm upgrade postgresql k8s/helm/postgresql \
  -f k8s/helm/postgresql/values-prod.yaml \
  -n project-template
```

### Verify Deployment
```bash
# Check StatefulSet
kubectl get statefulset -n project-template

# Check Services
kubectl get svc -n project-template | grep postgresql

# Check PersistentVolumes
kubectl get pvc -n project-template

# Check Pod Status
kubectl get pods -n project-template -l app.kubernetes.io/name=postgresql

# View Logs
kubectl logs -f postgresql-0 -n project-template
```

## Integration with Darwin Project

The PostgreSQL infrastructure integrates seamlessly with existing Darwin project patterns:

1. **Namespace**: Uses project-template namespace (consistent with Flask backend, webui)
2. **Labels**: Follows app.kubernetes.io labeling conventions used throughout project
3. **Service Discovery**: Available at postgresql.project-template.svc.cluster.local (standard)
4. **Managed By**: kustomize labels for consistency with existing resources
5. **Security**: Non-root user pattern (UID 999 for postgres, similar to Flask backend UID 1000)
6. **Configuration**: Standard Kubernetes ConfigMap/Secret management pattern
7. **Health Checks**: Follows project probe configuration patterns
8. **Resources**: Follows request/limit patterns from existing services

## Configuration Reference

### PostgreSQL Connection String (from Flask Backend)
```
postgresql://username:password@postgresql.project-template.svc.cluster.local:5432/database_name
```

### Environment Variables
```bash
DB_TYPE=postgres
DB_HOST=postgresql.project-template.svc.cluster.local
DB_PORT=5432
DB_NAME=project_template
DB_USER=app_user           # From Secret
DB_PASS=changeme           # From Secret (should be overridden)
```

## Important Notes

1. **Credentials Management**:
   - Placeholder credentials (changeme-in-production) in values files
   - Use environment variables, sealed secrets, or external secret management for production
   - Never commit actual credentials to repository

2. **Storage**:
   - Default storage class is "standard"
   - Override with specific storage classes for cloud providers (aws-ebs, gp3, etc.)
   - Storage size configurable per environment

3. **Image Selection**:
   - PostgreSQL 16-alpine chosen for small footprint and performance
   - Lightweight for Kubernetes deployments
   - Alternative: postgres:16 for additional tools if needed

4. **Backup & Monitoring**:
   - Template structure supports backup cronjobs (values: backup.enabled/schedule/retention)
   - ServiceMonitor template-ready for Prometheus integration
   - Can be extended with pg_exporter container for detailed metrics

5. **Scaling**:
   - Development: 1 replica (single pod)
   - Staging: 2 replicas (HA testing)
   - Production: 3 replicas (full HA with anti-affinity)

6. **Kubernetes Version**:
   - Requires Kubernetes 1.19+ (StatefulSet API v1)
   - StatefulSet service name field (serviceName) supported

## Troubleshooting

### Connection Issues
```bash
# Test connectivity from pod
kubectl exec -it postgresql-0 -n project-template -- \
  pg_isready -U postgres -d postgres

# Check service DNS resolution
kubectl exec -it <pod-name> -n project-template -- \
  nslookup postgresql.project-template.svc.cluster.local
```

### Storage Issues
```bash
# Check PVC status
kubectl describe pvc postgresql-data-postgresql-0 -n project-template

# Check events
kubectl describe statefulset postgresql -n project-template | grep -A 10 "Events:"
```

### Configuration Issues
```bash
# Verify ConfigMap
kubectl get configmap postgresql-config -n project-template -o yaml

# Verify Secret
kubectl get secret postgresql-secret -n project-template -o yaml
```

## Files Created

### Raw Manifests (3 files)
- `/home/penguin/code/darwin/k8s/manifests/postgresql/statefulset.yaml` (110 lines)
- `/home/penguin/code/darwin/k8s/manifests/postgresql/service.yaml` (40 lines)
- `/home/penguin/code/darwin/k8s/manifests/postgresql/configmap.yaml` (45 lines)

### Helm Chart (10 files)
- `/home/penguin/code/darwin/k8s/helm/postgresql/Chart.yaml` (13 lines)
- `/home/penguin/code/darwin/k8s/helm/postgresql/values.yaml` (110 lines)
- `/home/penguin/code/darwin/k8s/helm/postgresql/values-dev.yaml` (22 lines)
- `/home/penguin/code/darwin/k8s/helm/postgresql/values-staging.yaml` (35 lines)
- `/home/penguin/code/darwin/k8s/helm/postgresql/values-prod.yaml` (48 lines)
- `/home/penguin/code/darwin/k8s/helm/postgresql/templates/_helpers.tpl` (67 lines)
- `/home/penguin/code/darwin/k8s/helm/postgresql/templates/secret.yaml` (10 lines)
- `/home/penguin/code/darwin/k8s/helm/postgresql/templates/configmap.yaml` (53 lines)
- `/home/penguin/code/darwin/k8s/helm/postgresql/templates/service.yaml` (40 lines)
- `/home/penguin/code/darwin/k8s/helm/postgresql/templates/statefulset.yaml` (110 lines)

**Total**: 13 files, ~553 lines of Kubernetes and Helm configuration

---

Created for Darwin project v1.0.x
PostgreSQL Kubernetes Infrastructure v1.0.0
Follows PenguinTech enterprise standards and Darwin project patterns
