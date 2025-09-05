# SkausWatch Deployment Guide

This directory contains comprehensive deployment configurations for SkausWatch across different environments.

## Directory Structure

```
deployment/
├── README.md                    # This file
├── docker-compose.yml           # Root docker-compose file (moved to root)
├── .env.example                 # Environment variables template
├── redis/
│   └── redis.conf              # Redis configuration
├── k8s/                        # Kubernetes manifests
│   ├── namespace.yaml          # Namespace definition
│   ├── configmap.yaml          # Configuration maps
│   ├── secrets.yaml            # Secrets template
│   ├── services.yaml           # Service definitions
│   ├── ingress.yaml            # Ingress configuration
│   ├── manager-deployment.yaml
│   ├── pki-server-deployment.yaml
│   ├── ssh-ca-deployment.yaml
│   ├── aaa-monitor-deployment.yaml
│   ├── postgres-deployment.yaml
│   └── redis-deployment.yaml
└── helm/                       # Helm chart
    └── skauswatch/
        ├── Chart.yaml
        ├── values.yaml
        └── templates/
```

## Deployment Options

### 1. Docker Compose (Development/Testing)

The simplest way to get SkausWatch running for development or testing.

#### Prerequisites

- Docker 24.0+
- Docker Compose 2.20+
- At least 8GB RAM
- At least 20GB disk space

#### Quick Start

1. **Clone and prepare environment**:
   ```bash
   git clone https://github.com/penguintechinc/skauswatch.git
   cd skauswatch
   cp .env.example .env
   ```

2. **Update environment variables**:
   ```bash
   # Edit .env file with your settings
   nano .env
   
   # At minimum, change these for security:
   POSTGRES_PASSWORD=your_secure_postgres_password
   REDIS_PASSWORD=your_secure_redis_password
   JWT_SECRET_KEY=your_jwt_secret_key_minimum_256_bits
   ```

3. **Start services**:
   ```bash
   # Development mode
   docker-compose up -d
   
   # Production mode
   ENVIRONMENT=production docker-compose up -d
   ```

4. **Verify deployment**:
   ```bash
   # Check service status
   docker-compose ps
   
   # View logs
   docker-compose logs -f manager
   ```

5. **Access services**:
   - Manager: http://localhost:8000
   - PKI Server: http://localhost:8001
   - SSH CA: http://localhost:8002
   - AAA Monitor: http://localhost:8003
   - Grafana: http://localhost:3000 (admin/admin)
   - Prometheus: http://localhost:9090

### 2. Kubernetes (Production)

Enterprise-grade deployment with high availability, auto-scaling, and monitoring.

#### Prerequisites

- Kubernetes 1.28+
- kubectl configured
- Helm 3.12+
- cert-manager (for TLS certificates)
- NGINX Ingress Controller
- Persistent storage (recommended: SSD)

#### Manual Kubernetes Deployment

1. **Create namespace and secrets**:
   ```bash
   # Create namespace
   kubectl apply -f deployment/k8s/namespace.yaml
   
   # Copy and customize secrets
   cp deployment/k8s/secrets.yaml secrets-custom.yaml
   # Edit secrets-custom.yaml with real secrets
   kubectl apply -f secrets-custom.yaml
   ```

2. **Deploy configuration**:
   ```bash
   kubectl apply -f deployment/k8s/configmap.yaml
   ```

3. **Deploy infrastructure**:
   ```bash
   # PostgreSQL
   kubectl apply -f deployment/k8s/postgres-deployment.yaml
   
   # Redis
   kubectl apply -f deployment/k8s/redis-deployment.yaml
   
   # Wait for infrastructure to be ready
   kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=database -n skauswatch --timeout=300s
   kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=cache -n skauswatch --timeout=300s
   ```

4. **Deploy SkausWatch services**:
   ```bash
   kubectl apply -f deployment/k8s/manager-deployment.yaml
   kubectl apply -f deployment/k8s/pki-server-deployment.yaml
   kubectl apply -f deployment/k8s/ssh-ca-deployment.yaml
   kubectl apply -f deployment/k8s/aaa-monitor-deployment.yaml
   ```

5. **Deploy services and ingress**:
   ```bash
   kubectl apply -f deployment/k8s/services.yaml
   
   # Edit ingress.yaml with your domain names
   kubectl apply -f deployment/k8s/ingress.yaml
   ```

#### Helm Deployment (Recommended)

1. **Add dependencies** (optional, for external components):
   ```bash
   helm repo add bitnami https://charts.bitnami.com/bitnami
   helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
   helm repo add grafana https://grafana.github.io/helm-charts
   helm repo update
   ```

2. **Customize values**:
   ```bash
   cp deployment/helm/skauswatch/values.yaml values-production.yaml
   # Edit values-production.yaml with your settings
   ```

3. **Install SkausWatch**:
   ```bash
   helm install skauswatch deployment/helm/skauswatch \
     --namespace skauswatch \
     --create-namespace \
     --values values-production.yaml
   ```

4. **Verify deployment**:
   ```bash
   # Check status
   helm status skauswatch -n skauswatch
   
   # View pods
   kubectl get pods -n skauswatch
   
   # Check services
   kubectl get svc -n skauswatch
   ```

## Configuration

### Environment Variables

Key environment variables that must be configured:

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `ENVIRONMENT` | Deployment environment | `development` | Yes |
| `POSTGRES_PASSWORD` | PostgreSQL password | - | Yes |
| `REDIS_PASSWORD` | Redis password | - | Yes |
| `JWT_SECRET_KEY` | JWT signing key | - | Yes |
| `LOG_LEVEL` | Logging level | `INFO` | No |
| `CORS_ORIGINS` | Allowed CORS origins | - | Production |

### Security Considerations

#### Development
- Uses default passwords (change immediately)
- Services exposed on host network
- Debug logging enabled
- No TLS encryption

#### Production
- **Strong passwords required**
- **TLS encryption mandatory**
- **Network policies enforced**
- **Resource limits configured**
- **Security scanning recommended**
- **Regular updates required**

### Storage Requirements

| Component | Storage Type | Size (Dev) | Size (Prod) |
|-----------|--------------|------------|-------------|
| PostgreSQL | Persistent | 1GB | 20GB+ |
| Redis | Persistent | 100MB | 5GB |
| PKI Certs | Persistent | 100MB | 2GB |
| SSH Keys | Persistent | 50MB | 1GB |
| Audit Logs | Persistent | 500MB | 10GB+ |
| Application Data | Persistent | 100MB | 2GB |

### Monitoring

SkausWatch includes comprehensive monitoring:

- **Prometheus**: Metrics collection
- **Grafana**: Dashboards and visualization
- **Health checks**: Built-in health endpoints
- **Logging**: Structured JSON logging
- **Alerts**: Configurable alerting rules

Access points:
- Grafana: `https://monitoring.yourdomain.com`
- Prometheus: `https://prometheus.yourdomain.com` (admin only)

## Troubleshooting

### Common Issues

1. **Services not starting**:
   ```bash
   # Check logs
   docker-compose logs service-name
   # or
   kubectl logs -f deployment/service-name -n skauswatch
   ```

2. **Database connection issues**:
   ```bash
   # Test database connectivity
   docker-compose exec postgres psql -U skauswatch -d skauswatch -c "SELECT 1;"
   ```

3. **Permission issues**:
   ```bash
   # Check file permissions
   ls -la certs/ keys/ logs/
   
   # Fix permissions if needed
   sudo chown -R 65534:65534 certs/ keys/ logs/
   ```

4. **Certificate issues**:
   ```bash
   # Check certificate validity
   openssl x509 -in certs/ca.crt -text -noout
   ```

### Health Checks

All services provide health check endpoints:

- Manager: `GET /health`
- PKI Server: `GET /health`
- SSH CA: `GET /health`
- AAA Monitor: `GET /health`

### Scaling

#### Docker Compose
```bash
# Scale specific service
docker-compose up -d --scale manager=3
```

#### Kubernetes
```bash
# Scale deployment
kubectl scale deployment manager --replicas=5 -n skauswatch

# Enable autoscaling
kubectl autoscale deployment manager --cpu-percent=70 --min=2 --max=10 -n skauswatch
```

## Security Hardening

### Network Security
- Configure firewall rules
- Use VPN for admin access
- Enable network policies
- Regular security scans

### Application Security
- Change all default passwords
- Use strong JWT secrets
- Enable TLS encryption
- Regular security updates
- Audit logging enabled

### Infrastructure Security
- Use dedicated service accounts
- Implement RBAC
- Enable Pod Security Standards
- Regular vulnerability scanning

## Backup and Recovery

### Database Backup
```bash
# PostgreSQL backup
docker-compose exec postgres pg_dump -U skauswatch skauswatch > backup.sql

# Kubernetes backup
kubectl exec -n skauswatch deployment/postgres -- pg_dump -U skauswatch skauswatch > backup.sql
```

### Certificate Backup
```bash
# Backup certificates and keys
tar -czf certificates-backup.tar.gz certs/ keys/
```

### Restore Procedures
1. Stop services
2. Restore database from backup
3. Restore certificates and keys
4. Start services
5. Verify functionality

## Support

For support and documentation:

- **Documentation**: https://docs.skauswatch.io
- **Issues**: https://github.com/penguintechinc/skauswatch/issues
- **Support**: support@skauswatch.io

## License

SkausWatch is commercial software. See LICENSE file for details.