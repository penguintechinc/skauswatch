# SkausWatch

🔒 **Commercial License** | 🌐 [skauswatch.io](https://skauswatch.io) | 📚 [Documentation](https://docs.skauswatch.io) | 💻 [GitHub](https://github.com/penguintechinc/skauswatch)

![Python Version](https://img.shields.io/badge/python-3.13-blue.svg)
![License](https://img.shields.io/badge/license-Commercial-orange.svg)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen.svg)

**SkausWatch** is a comprehensive security monitoring and alerting system designed for enterprise environments. It provides real-time monitoring, certificate management, SSH certificate authority services, and authentication/authorization/accounting (AAA) monitoring capabilities.

## 💰 Pricing

- **$7.50/month** per compute node (cloud VM or hardware)
- Volume discounts available starting at 100 nodes
- Enterprise support included
- Contact [sales@penguintech.io](mailto:sales@penguintech.io) for custom pricing

## Features

### Core Services

- **Manager Service**: Central orchestration and management service
- **PKI Server**: Public Key Infrastructure management and certificate lifecycle
- **SSH CA**: SSH Certificate Authority for secure server access
- **AAA Monitor**: Authentication, Authorization, and Accounting monitoring

### Key Capabilities

- 🔐 **Certificate Management**: Automated certificate lifecycle management
- 🔑 **SSH CA Services**: Secure SSH certificate provisioning
- 📊 **Real-time Monitoring**: Comprehensive system and security monitoring  
- 🚨 **Alerting System**: Intelligent alerting with multiple notification channels
- 📈 **Metrics & Dashboards**: Prometheus metrics with Grafana visualization
- 🔒 **Security Auditing**: Comprehensive audit logging and compliance reporting
- 🔄 **API-First Design**: RESTful APIs for all services
- 🐳 **Container Ready**: Full Docker and Kubernetes support

## Architecture

SkausWatch follows a microservices architecture with the following components:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Manager        │    │  PKI Server     │    │  SSH CA         │
│  Service        │    │  Service        │    │  Service        │
│  (Port 8000)    │    │  (Port 8001)    │    │  (Port 8002)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
         ┌─────────────────┐    │    ┌─────────────────┐
         │  AAA Monitor    │    │    │  Shared         │
         │  Service        │────┼────│  Components     │
         │  (Port 8003)    │    │    │                 │
         └─────────────────┘    │    └─────────────────┘
                                │
    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
    │  PostgreSQL  │    │    Redis     │    │ Prometheus + │
    │   Database   │    │    Cache     │    │   Grafana    │
    └──────────────┘    └──────────────┘    └──────────────┘
```

## Quick Start

### Prerequisites

- Python 3.13+
- Docker and Docker Compose
- PostgreSQL 16+
- Redis 7+

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/SkausWatch.git
   cd SkausWatch
   ```

2. **Set up development environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e ".[dev]"
   ```

3. **Install pre-commit hooks**
   ```bash
   pre-commit install
   ```

4. **Start development services**
   ```bash
   docker-compose up -d
   ```

5. **Run database migrations**
   ```bash
   alembic upgrade head
   ```

6. **Start the services**
   ```bash
   # Terminal 1 - Manager Service
   python -m services.manager

   # Terminal 2 - PKI Server
   python -m services.pki_server

   # Terminal 3 - SSH CA
   python -m services.ssh_ca

   # Terminal 4 - AAA Monitor
   python -m services.aaa_monitor
   ```

### Using Docker (Recommended)

```bash
docker-compose up -d
```

This will start all services with their dependencies. Access the services at:

- Manager Service: http://localhost:8000
- PKI Server: http://localhost:8001
- SSH CA: http://localhost:8002
- AAA Monitor: http://localhost:8003
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (admin/admin)

## Project Structure

```
SkausWatch/
├── services/
│   ├── manager/           # Central management service
│   ├── pki-server/        # PKI and certificate management
│   ├── ssh-ca/           # SSH Certificate Authority
│   └── aaa-monitor/      # AAA monitoring service
├── shared/
│   ├── models/           # Shared data models
│   ├── utils/            # Common utilities
│   └── security/         # Security utilities
├── deployment/           # Deployment configurations
├── docs/                 # Project documentation
├── website/              # Project website
├── tests/                # Test suites
├── pyproject.toml        # Project configuration
├── docker-compose.yml    # Development environment
└── requirements-dev.txt  # Development dependencies
```

## Configuration

Configuration is handled through environment variables and YAML files. Key settings:

- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `ENVIRONMENT`: deployment environment (development/staging/production)
- `LOG_LEVEL`: logging level (DEBUG/INFO/WARNING/ERROR)

## Testing

Run the test suite:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=skauswatch --cov-report=html

# Run specific test categories
pytest -m unit          # Unit tests only
pytest -m integration   # Integration tests only
```

## API Documentation

API documentation is available at:

- Manager Service: http://localhost:8000/docs
- PKI Server: http://localhost:8001/docs
- SSH CA: http://localhost:8002/docs
- AAA Monitor: http://localhost:8003/docs

## Monitoring

SkausWatch includes comprehensive monitoring:

- **Metrics**: Prometheus metrics for all services
- **Dashboards**: Pre-built Grafana dashboards
- **Health Checks**: Service health endpoints
- **Logging**: Structured logging with correlation IDs

Access monitoring at:
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000

## Security

SkausWatch takes security seriously:

- All communications use TLS encryption
- Certificate-based authentication
- Comprehensive audit logging
- Regular security scanning
- RBAC (Role-Based Access Control)

See [SECURITY.md](SECURITY.md) for our security policy.

## Contributing

We welcome contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

SkausWatch is proprietary software under commercial license.
- **Pricing**: $7.50/month per compute node
- **Volume Discounts**: Available for 100+ nodes
- **Enterprise Support**: Included with license

For licensing inquiries: [sales@penguintech.io](mailto:sales@penguintech.io)

## 🔗 Links & Support

- **Website**: [skauswatch.io](https://skauswatch.io)
- **Documentation**: [docs.skauswatch.io](https://docs.skauswatch.io)
- **GitHub**: [github.com/penguintechinc/skauswatch](https://github.com/penguintechinc/skauswatch)
- **Support**: [support@skauswatch.io](mailto:support@skauswatch.io)
- **Sales**: [sales@penguintech.io](mailto:sales@penguintech.io)

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and changes.
