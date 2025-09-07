# SkausWatch Docker Compose Setup

This comprehensive Docker Compose setup provides a complete development and testing environment for the SkausWatch certificate authority management platform.

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Architecture Overview](#architecture-overview)
- [Services](#services)
- [Environment Configuration](#environment-configuration)
- [Development Workflow](#development-workflow)
- [Production Deployment](#production-deployment)
- [Monitoring & Observability](#monitoring--observability)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

## 🚀 Quick Start

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- 8GB RAM (minimum)
- 20GB disk space
- Linux/macOS/Windows with WSL2

### Initial Setup

1. **Clone and Navigate**
   ```bash
   git clone <repository-url>
   cd skauswatch
   ```

2. **Run Setup Script**
   ```bash
   ./scripts/dev-setup.sh
   ```

3. **Start Development Environment**
   ```bash
   ./scripts/dev-start.sh
   ```

4. **Access the Application**
   - Web Portal: http://localhost:3000
   - API Gateway: http://localhost:8080
   - Grafana: http://localhost:3001 (admin/admin)

## 🏗️ Architecture Overview

The Docker Compose setup includes three configurations:

### 1. Development Environment (`docker-compose.yml` + `docker-compose.override.yml`)
- Hot reload enabled
- Debug ports exposed
- Development tools included
- Relaxed security settings

### 2. Production-like Testing (`docker-compose.prod.yml`)
- Production-grade security
- Secrets management
- Resource limits
- Load balancer (HAProxy)
- Log aggregation

### 3. Base Configuration (`docker-compose.yml`)
- Core services definition
- Shared volume and network configuration
- Health checks

## 🔧 Services

### Core Application Services

| Service | Port | Description |
|---------|------|-------------|
| **web-portal** | 3000 | React/Next.js frontend |
| **manager** | 8080 | Main API gateway service |
| **pki-server** | 8081 | Certificate authority operations |
| **ssh-ca** | 8082 | SSH certificate authority |
| **aaa-monitor** | 8083 | Authentication, authorization, audit |

### Infrastructure Services

| Service | Port | Description |
|---------|------|-------------|
| **postgres** | 5432 | PostgreSQL database |
| **redis** | 6379 | Cache and session store |
| **rabbitmq** | 5672/15672 | Message queue (+ management UI) |
| **minio** | 9000/9001 | Object storage (+ console) |
| **elasticsearch** | 9200/9300 | Search and log storage |

### Monitoring & Observability

| Service | Port | Description |
|---------|------|-------------|
| **prometheus** | 9090 | Metrics collection |
| **grafana** | 3001 | Dashboards and visualization |
| **filebeat** | - | Log collection and shipping |

### Development Tools (Dev Only)

| Service | Port | Description |
|---------|------|-------------|
| **adminer** | 8084 | Database administration |
| **redis-commander** | 8085 | Redis management |
| **mailhog** | 8025/1025 | Email testing (UI/SMTP) |

### Load Balancer (Production)

| Service | Port | Description |
|---------|------|-------------|
| **haproxy** | 80/443/8404 | Load balancer + SSL termination |

## ⚙️ Environment Configuration

### Environment Files

- **`.env.example`** - Complete configuration template
- **`.env.local.example`** - Development-specific settings
- **`.env.test.example`** - Testing environment settings

### Key Configuration Areas

1. **Database Settings**
   ```env
   POSTGRES_DB=skauswatch
   POSTGRES_USER=skauswatch
   POSTGRES_PASSWORD=changeme_strong_password
   ```

2. **Security Configuration**
   ```env
   JWT_SECRET=changeme_jwt_secret_at_least_32_characters
   ENCRYPTION_KEY=changeme_encryption_key_exactly_32_chars
   ```

3. **Service URLs**
   ```env
   MANAGER_URL=http://localhost:8080
   PKI_SERVER_URL=http://localhost:8081
   ```

## 💻 Development Workflow

### Starting Services

```bash
# Full setup (first time)
./scripts/dev-setup.sh

# Start all services
./scripts/dev-start.sh

# Start specific services
docker-compose up postgres redis rabbitmq

# Start in background
docker-compose up -d
```

### Stopping Services

```bash
# Graceful stop
./scripts/dev-stop.sh

# Force stop
./scripts/dev-stop.sh --force

# Stop specific service
docker-compose stop manager
```

### Development Commands

```bash
# View logs
docker-compose logs -f manager
docker-compose logs -f

# Restart service
docker-compose restart pki-server

# Execute commands in containers
docker-compose exec manager bash
docker-compose exec postgres psql -U skauswatch

# Check service status
docker-compose ps
```

### Hot Reload & Debugging

- **Frontend**: Automatic reload on code changes
- **Backend**: Delve debugger available on ports 40000-40003
- **Configuration**: Live reload for supported services

## 🚀 Production Deployment

### Production Environment

```bash
# Use production configuration
docker-compose -f docker-compose.prod.yml up -d

# With custom environment
docker-compose -f docker-compose.prod.yml --env-file .env.prod up -d
```

### Production Features

- **Secrets Management**: File-based secrets for sensitive data
- **Resource Limits**: CPU and memory constraints
- **Security Hardening**: Non-root users, read-only filesystems
- **Load Balancing**: HAProxy with SSL termination
- **Log Aggregation**: Centralized logging with Filebeat
- **Health Checks**: Comprehensive service monitoring

### Secrets Setup (Production)

```bash
# Create secrets directory
mkdir -p secrets/prod

# Generate secure passwords
echo "$(openssl rand -base64 32)" > secrets/prod/postgres_password.txt
echo "$(openssl rand -base64 32)" > secrets/prod/jwt_secret.txt

# Set proper permissions
chmod 600 secrets/prod/*
```

## 📊 Monitoring & Observability

### Prometheus Metrics

- Application performance metrics
- Infrastructure health metrics
- Business logic metrics
- Custom alerting rules

### Grafana Dashboards

- **Overview Dashboard**: System health and key metrics
- **Application Dashboard**: Service-specific metrics
- **Infrastructure Dashboard**: Database, cache, queue metrics
- **Security Dashboard**: Authentication and audit metrics

### Log Management

- **Centralized Logging**: All services log to Elasticsearch
- **Log Aggregation**: Filebeat collects and ships logs
- **Log Analysis**: Kibana-compatible log exploration

### Alerting

- Prometheus alerting rules for critical scenarios
- Service health monitoring
- Performance degradation detection
- Security event alerting

## 🔒 Security Considerations

### Development Security

- **Insecure defaults**: Development uses weak passwords
- **Debug ports exposed**: Debuggers accessible locally
- **Relaxed validation**: Faster development iteration

### Production Security

- **Secrets management**: File-based secrets, no hardcoded values
- **Network segmentation**: Separate frontend/backend networks
- **SSL/TLS encryption**: HTTPS everywhere with proper certificates
- **Resource limits**: Prevent resource exhaustion attacks
- **Security headers**: HSTS, CSP, XSS protection

### Certificate Management

- **CA Security**: Hardware Security Module (HSM) support
- **Key Storage**: Encrypted key storage in MinIO
- **Certificate Lifecycle**: Automated renewal and expiration monitoring
- **Audit Logging**: Complete audit trail for all operations

## 🔍 Troubleshooting

### Common Issues

1. **Services Won't Start**
   ```bash
   # Check Docker daemon
   docker info
   
   # Check logs
   docker-compose logs <service-name>
   
   # Verify port availability
   netstat -tulpn | grep <port>
   ```

2. **Database Connection Issues**
   ```bash
   # Test database connectivity
   docker-compose exec postgres pg_isready -U skauswatch
   
   # Connect to database
   docker-compose exec postgres psql -U skauswatch -d skauswatch
   ```

3. **Memory Issues**
   ```bash
   # Check resource usage
   docker stats
   
   # Restart services
   ./scripts/dev-stop.sh && ./scripts/dev-start.sh
   ```

4. **Permission Issues**
   ```bash
   # Fix file permissions
   sudo chown -R $USER:$USER data/ logs/ config/
   
   # Reset environment
   ./scripts/dev-reset.sh
   ```

### Log Analysis

```bash
# Application logs
docker-compose logs -f manager pki-server ssh-ca aaa-monitor

# Infrastructure logs
docker-compose logs -f postgres redis rabbitmq elasticsearch

# Real-time monitoring
docker-compose logs -f --tail=100
```

### Health Checks

```bash
# Check all service health
for service in manager pki-server ssh-ca aaa-monitor; do
  echo "Checking $service..."
  curl -f http://localhost:$(docker-compose port $service | cut -d: -f2)/health || echo "Failed"
done

# Database health
docker-compose exec postgres pg_isready -U skauswatch

# Cache health
docker-compose exec redis redis-cli ping
```

### Resource Monitoring

```bash
# Container resource usage
docker stats --no-stream

# Disk usage
docker system df

# Clean up resources
docker system prune -f
docker volume prune -f
```

## 📚 Additional Resources

### Scripts Reference

- **`dev-setup.sh`**: Initialize development environment
- **`dev-start.sh`**: Start all development services
- **`dev-stop.sh`**: Stop services with options
- **`dev-reset.sh`**: Complete environment reset

### Configuration Directories

- **`config/`**: Service configuration files
- **`data/`**: Persistent data storage
- **`logs/`**: Application and service logs
- **`secrets/`**: Production secrets (not in git)

### Useful Commands

```bash
# Complete reset
./scripts/dev-reset.sh

# Production deployment
docker-compose -f docker-compose.prod.yml up -d

# Backup data
docker run --rm -v skauswatch_postgres_data:/data -v $(pwd):/backup alpine tar czf /backup/backup.tar.gz -C /data .

# Restore data
docker run --rm -v skauswatch_postgres_data:/data -v $(pwd):/backup alpine tar xzf /backup/backup.tar.gz -C /data
```

## 🤝 Contributing

When making changes to the Docker setup:

1. Test in development environment first
2. Update relevant documentation
3. Verify production configuration compatibility
4. Test complete setup/teardown cycle
5. Update environment variable examples

## 📝 License

This Docker Compose setup is part of the SkausWatch project and follows the same license terms.

---

For more detailed information, refer to the individual service documentation and configuration files in the `config/` directory.