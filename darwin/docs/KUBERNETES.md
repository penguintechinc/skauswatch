# Kubernetes Deployment Guide

Comprehensive guide for deploying the Darwin project to Kubernetes using Helm, Kustomize, and raw manifests.

## Prerequisites

### Required Tools
- **kubectl 1.28+** - Kubernetes command-line tool
  ```bash
  kubectl version --client
  ```

- **Helm 3.12+** (optional, for Helm deployments)
  ```bash
  helm version
  ```

- **Kustomize 5.0+** (optional, typically built into kubectl)
  ```bash
  kubectl kustomize --version
  ```

### Cluster Access
- Active Kubernetes cluster access
- Appropriate namespace and RBAC permissions
- Docker image registry access (if using private images)

### Environment Variables
Set these before deployment:
```bash
export NAMESPACE=darwin-dev        # Kubernetes namespace
export FLASK_PORT=5000             # Flask backend port
export WEBUI_PORT=3000             # WebUI port
export DB_TYPE=postgres            # Database type
export POSTGRES_DB=app_db           # Database name
export POSTGRES_USER=app_user       # Database user
export POSTGRES_PASSWORD=password   # Database password (use secrets in production)
export REDIS_PASSWORD=password      # Redis password
```

## Quick Start

### Option 1: Using Kustomize (Recommended for Development)

```bash
# Deploy to development namespace
kubectl apply -k k8s/kustomize/overlays/dev/

# Verify deployment
./scripts/k8s-verify.sh -n darwin-dev

# Check status
kubectl get pods -n darwin-dev
```

### Option 2: Using Helm (Recommended for Production)

```bash
# Add repository (if using external Helm repos)
helm repo add project-template k8s/helm

# Install all services
helm install darwin-release k8s/helm/flask-backend \
  --namespace darwin-prod \
  --create-namespace \
  --values k8s/helm/values-prod.yaml

helm install darwin-release k8s/helm/webui \
  --namespace darwin-prod \
  --values k8s/helm/values-prod.yaml

# Verify installation
helm list -n darwin-prod
./scripts/k8s-verify.sh -n darwin-prod
```

### Option 3: Using Raw Manifests

```bash
# Apply all manifests
kubectl apply -f k8s/manifests/

# Verify deployment
./scripts/k8s-verify.sh
```

## Architecture

### Service Components

The Darwin deployment consists of three main services:

#### 1. Flask Backend (API Server)
- **Purpose**: REST API, authentication, user management
- **Image**: `ghcr.io/penguintechinc/project-template-flask-backend:latest`
- **Port**: 5000
- **Resources**: 512Mi memory, 500m CPU
- **Scaling**: HPA recommended for >100 concurrent users

#### 2. WebUI (Frontend)
- **Purpose**: React-based user interface
- **Image**: `ghcr.io/penguintechinc/project-template-webui:latest`
- **Port**: 3000
- **Resources**: 256Mi memory, 250m CPU
- **Scaling**: HPA recommended for CDN + multiple replicas

#### 3. Backing Services
- **PostgreSQL**: Primary database (StatefulSet)
- **Redis**: Cache and session store (StatefulSet)

### Namespace Organization

```
darwin-dev/              # Development environment
├── flask-backend-*      # API pods
├── webui-*              # Frontend pods
├── postgres-*           # Database
└── redis-*              # Cache

darwin-staging/          # Staging environment
└── [same structure]

darwin-prod/             # Production environment
└── [same structure with HA]
```

## Configuration Management

### Secrets

Store sensitive configuration in Kubernetes Secrets:

```bash
# Create database secret
kubectl create secret generic database-credentials \
  --from-literal=username=app_user \
  --from-literal=password=secure_password \
  --from-literal=database=app_db \
  -n darwin-dev

# Create Redis secret
kubectl create secret generic redis-credentials \
  --from-literal=password=secure_password \
  -n darwin-dev

# Create license secret
kubectl create secret generic license-credentials \
  --from-literal=license-key=PENG-XXXX-XXXX-XXXX-XXXX-ABCD \
  --from-literal=license-server-url=https://license.penguintech.io \
  -n darwin-dev
```

### ConfigMaps

Store non-sensitive configuration:

```bash
# Create application config
kubectl create configmap app-config \
  --from-literal=RELEASE_MODE=false \
  --from-literal=AI_ENABLED=true \
  --from-literal=PRODUCT_NAME=darwin \
  -n darwin-dev
```

### AI Configuration

For AI features (WaddleAI integration):

```yaml
# In k8s/kustomize/overlays/dev/kustomization.yaml
configMapGenerator:
  - name: ai-config
    literals:
      - AI_ENABLED=true
      - WADDLEAI_URL=http://waddleai-service:8080
      - AI_MODEL=default
      - AI_TIMEOUT=30
```

## Deployment Commands

### Using Make Targets

The Makefile includes convenience targets for Kubernetes operations:

```bash
# Deploy to development
make k8s-deploy-dev              # Deploy using Kustomize
make helm-install-dev            # Deploy using Helm

# Check status
make k8s-status-dev              # Show deployment status
make k8s-logs-dev                # View logs
make k8s-logs-flask-dev          # View Flask backend logs

# Scale deployments
make k8s-scale-dev REPLICAS=3

# Cleanup
make k8s-cleanup-dev             # Remove all resources
make helm-uninstall-dev          # Remove Helm release
```

### Manual kubectl Commands

```bash
# Apply configuration
kubectl apply -k k8s/kustomize/overlays/dev/
kubectl apply -f k8s/manifests/

# Check deployment status
kubectl get deployments -n darwin-dev
kubectl get pods -n darwin-dev -o wide

# View events
kubectl get events -n darwin-dev --sort-by='.lastTimestamp'

# Describe resources
kubectl describe deployment flask-backend -n darwin-dev
kubectl describe pod flask-backend-abc123 -n darwin-dev
```

### Helm Commands

```bash
# Install
helm install darwin k8s/helm/flask-backend \
  --namespace darwin-dev \
  --create-namespace

# Upgrade
helm upgrade darwin k8s/helm/flask-backend \
  --namespace darwin-dev \
  --values custom-values.yaml

# View status
helm status darwin -n darwin-dev
helm get values darwin -n darwin-dev

# Rollback
helm rollback darwin -n darwin-dev

# Uninstall
helm uninstall darwin -n darwin-dev
```

## Monitoring

### Prometheus Integration

Access metrics via Prometheus:

```bash
# Port forward to Prometheus
kubectl port-forward -n darwin-dev svc/prometheus 9090:9090

# Access at http://localhost:9090
```

### Grafana Dashboards

Access dashboards via Grafana:

```bash
# Port forward to Grafana
kubectl port-forward -n darwin-dev svc/grafana 3001:3000

# Default credentials: admin/admin
# Access at http://localhost:3001
```

### Health Checks

Verify service health:

```bash
# Use verification script
./scripts/k8s-verify.sh -n darwin-dev

# Or manually check
kubectl exec -n darwin-dev deployment/flask-backend \
  -- wget -q -O- http://localhost:5000/healthz

kubectl exec -n darwin-dev deployment/webui \
  -- wget -q -O- http://localhost:3000/healthz
```

### Metrics Queries

Common Prometheus queries:

```promql
# Request rate (requests per second)
rate(http_requests_total[1m])

# Error rate
rate(http_requests_total{status=~"5.."}[1m])

# Pod memory usage
container_memory_usage_bytes{pod=~"flask-backend.*"}

# Pod CPU usage
rate(container_cpu_usage_seconds_total{pod=~"flask-backend.*"}[5m])
```

## Scaling

### Horizontal Pod Autoscaling (HPA)

Enable automatic scaling based on metrics:

```bash
# View existing HPAs
kubectl get hpa -n darwin-dev

# Create HPA for Flask backend
kubectl autoscale deployment flask-backend \
  --min=2 --max=10 \
  --cpu-percent=70 \
  -n darwin-dev

# View HPA status
kubectl get hpa -n darwin-dev -w
```

### Manual Scaling

Scale deployments manually:

```bash
# Scale Flask backend to 3 replicas
kubectl scale deployment flask-backend --replicas=3 -n darwin-dev

# Scale WebUI to 2 replicas
kubectl scale deployment webui --replicas=2 -n darwin-dev

# Verify
kubectl get deployments -n darwin-dev
```

### Resource Management

Define resource limits for optimal scaling:

```yaml
# In deployment specification
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Pods Not Starting

```bash
# Check pod status
kubectl describe pod flask-backend-abc123 -n darwin-dev

# Common causes:
# - Image pull failures: Check image availability and registry credentials
# - Insufficient resources: Check node capacity
# - Dependency failures: Check postgres/redis are running

# Check logs
kubectl logs pod/flask-backend-abc123 -n darwin-dev
kubectl logs pod/flask-backend-abc123 -n darwin-dev --previous
```

#### 2. Database Connection Failures

```bash
# Verify PostgreSQL is running
kubectl get pods -n darwin-dev -l app=postgres

# Test connection from Flask pod
kubectl exec -n darwin-dev deployment/flask-backend -- \
  psql -h postgres -U app_user -d app_db -c "SELECT version();"

# Check connection string in ConfigMap/Secret
kubectl get configmap -n darwin-dev
kubectl get secrets -n darwin-dev
```

#### 3. Service Not Accessible

```bash
# Check service exists
kubectl get svc -n darwin-dev

# Port forward for testing
kubectl port-forward -n darwin-dev svc/flask-backend 5000:5000

# Test from local machine
curl http://localhost:5000/healthz
```

#### 4. High Memory/CPU Usage

```bash
# Check resource usage
kubectl top pods -n darwin-dev
kubectl top nodes

# Check for resource limits
kubectl get pods -n darwin-dev -o yaml | grep -A 5 "resources:"

# View HPA status
kubectl get hpa -n darwin-dev
kubectl describe hpa flask-backend -n darwin-dev
```

### Debugging Commands

```bash
# Execute shell in pod
kubectl exec -it pod/flask-backend-abc123 -n darwin-dev -- /bin/bash

# Copy file from pod
kubectl cp darwin-dev/flask-backend-abc123:/app/file.log ./file.log

# Port forward to service
kubectl port-forward -n darwin-dev svc/flask-backend 5000:5000

# Stream logs
kubectl logs -f deployment/flask-backend -n darwin-dev

# Watch resources
kubectl get pods -n darwin-dev -w
```

## Production Considerations

### High Availability (HA)

For production deployments:

```yaml
# Deployment replicas (minimum 3)
replicas: 3

# Pod Disruption Budgets
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: flask-backend-pdb
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: flask-backend
```

### Backup and Restore

#### PostgreSQL Backup

```bash
# Create backup pod
kubectl exec -n darwin-dev postgres-0 -- \
  pg_dump -U app_user app_db > backup.sql

# Restore from backup
kubectl exec -i -n darwin-dev postgres-0 -- \
  psql -U app_user app_db < backup.sql
```

#### Data Persistence

Verify PersistentVolumeClaims are configured:

```bash
# Check PVCs
kubectl get pvc -n darwin-dev

# Check volume status
kubectl get pv

# Describe PVC for details
kubectl describe pvc postgres-data -n darwin-dev
```

### Security Best Practices

1. **Secrets Management**
   - Use sealed-secrets or external-secrets operator
   - Never commit secrets to Git
   - Rotate credentials regularly

2. **RBAC Configuration**
   - Create namespace-specific service accounts
   - Apply principle of least privilege
   - Audit RBAC changes

3. **Network Policies**
   - Restrict inter-pod communication
   - Block unnecessary external access
   - Use network segmentation

4. **Image Security**
   - Scan images with Trivy
   - Use signed/verified images only
   - Keep base images updated

### Certificate Management

For TLS/HTTPS:

```bash
# Create TLS secret
kubectl create secret tls flask-tls \
  --cert=path/to/cert.pem \
  --key=path/to/key.pem \
  -n darwin-dev

# Reference in Ingress
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: flask-ingress
spec:
  tls:
    - hosts:
        - api.example.com
      secretName: flask-tls
```

## Cleanup

### Remove Deployments

```bash
# Using Kustomize
kubectl delete -k k8s/kustomize/overlays/dev/

# Using Helm
helm uninstall darwin -n darwin-dev

# Delete namespace (removes all resources)
kubectl delete namespace darwin-dev
```

### Clean Up Resources

```bash
# Remove orphaned PVCs
kubectl delete pvc --all -n darwin-dev

# Remove completed pods
kubectl delete pods --field-selector status.phase=Failed -n darwin-dev
kubectl delete pods --field-selector status.phase=Succeeded -n darwin-dev

# Delete entire namespace
kubectl delete namespace darwin-dev
```

## Support & Resources

- **Official Kubernetes Docs**: https://kubernetes.io/docs/
- **Helm Documentation**: https://helm.sh/docs/
- **Kustomize Guide**: https://kustomize.io/
- **Project Issues**: Check GitHub issues for common problems
- **License Server**: https://license.penguintech.io
- **Support Contact**: support@penguintech.io

## Additional References

- See [STANDARDS.md](STANDARDS.md) for architecture details
- See [DEVELOPMENT.md](DEVELOPMENT.md) for local development setup
- See [TESTING.md](TESTING.md) for testing in Kubernetes environments
