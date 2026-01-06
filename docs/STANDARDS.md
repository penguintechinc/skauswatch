# Development Standards

This document consolidates all development standards, patterns, and requirements for SkausWatch.

## Table of Contents

1. [Language Selection Criteria](#language-selection-criteria)
2. [Flask-Security-Too Integration](#flask-security-too-integration)
3. [Database Standards](#database-standards)
4. [Protocol Support](#protocol-support)
5. [API Versioning](#api-versioning)
6. [Performance Best Practices](#performance-best-practices)
7. [Microservices Architecture](#microservices-architecture)
8. [Docker Standards](#docker-standards)
9. [Testing Requirements](#testing-requirements)
10. [Security Standards](#security-standards)
11. [Documentation Standards](#documentation-standards)
12. [Logging & Monitoring](#logging--monitoring)
13. [WaddleAI Integration](#waddleai-integration)

---

## Language Selection Criteria

**Python 3.13** is the primary language for SkausWatch services.

### Why Python for SkausWatch
- Rapid development and iteration for security features
- Rich ecosystem of libraries for cryptography and security
- Excellent for prototyping and MVPs
- Strong support for data processing and analysis
- Easy maintenance and debugging

**Go can be considered** for:
- High-performance networking components (if requirements exceed 10K req/sec)
- Network-intensive services with low latency requirements
- Services with latency requirements <10ms
- Only when performance profiling shows necessity

---

## Flask-Security-Too Integration

**MANDATORY for ALL Flask applications in SkausWatch**

### Core Features
- User authentication and session management
- Role-based access control (RBAC)
- Password hashing with bcrypt
- Email confirmation and password reset
- Two-factor authentication (2FA)
- Token-based authentication for APIs
- Login tracking and session management

### Default Roles
1. **Admin**: Full access to all services and configurations
2. **Maintainer**: Read/write access to resources, no user management
3. **Viewer**: Read-only access to resources and audit logs

### Integration Pattern

```python
from flask import Flask
from flask_security import Security, auth_required, hash_password
from pydal import DAL, Field
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SECURITY_PASSWORD_SALT'] = os.getenv('SECURITY_PASSWORD_SALT')
app.config['SECURITY_PASSWORD_HASH'] = 'bcrypt'

# PyDAL database
db = DAL(
    f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASS')}@"
    f"{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}",
    pool_size=10,
    migrate=True
)

# Define tables for PyDAL
db.define_table('users',
    Field('email', 'string', unique=True),
    Field('password', 'string'),
    Field('active', 'boolean', default=True),
    Field('fs_uniquifier', 'string', unique=True),
)

db.define_table('roles',
    Field('name', 'string', unique=True),
    Field('description', 'string'),
)

# Initialize Flask-Security
from flask_security import PyDALUserDatastore
user_datastore = PyDALUserDatastore(db, db.users, db.roles)
security = Security(app, user_datastore)

@app.route('/api/protected')
@auth_required()
def protected_resource():
    return {'message': 'Access granted'}
```

---

## Database Standards

### Hybrid Approach: SQLAlchemy Init + PyDAL Operations

**MANDATORY for ALL Python applications in SkausWatch**

#### SQLAlchemy - Database Initialization ONLY

Use SQLAlchemy exclusively for initial schema creation:

```python
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String
import os

def init_schema_sqlalchemy(engine):
    """Create database schema using SQLAlchemy"""
    metadata = MetaData()

    Table('users', metadata,
        Column('id', Integer, primary_key=True),
        Column('email', String(255), unique=True),
        Column('password', String(255)),
        Column('active', Integer, default=1),
    )

    metadata.create_all(engine)
```

#### PyDAL - Day-to-Day Operations (Mandatory)

All CRUD operations and migrations use PyDAL:

```python
from pydal import DAL, Field

def get_db_connection():
    """Initialize PyDAL for operations"""
    db_type = os.getenv('DB_TYPE', 'postgres')

    # Build connection string
    if db_type == 'sqlite':
        db_url = f"sqlite:///{os.getenv('DB_PATH', 'app.db')}"
    else:
        db_url = (f"{'postgresql' if db_type == 'postgres' else 'mysql'}://"
                 f"{os.getenv('DB_USER')}:{os.getenv('DB_PASS')}@"
                 f"{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/"
                 f"{os.getenv('DB_NAME')}")

    db = DAL(
        db_url,
        pool_size=int(os.getenv('DB_POOL_SIZE', '10')),
        migrate_enabled=True,
        check_reserved=['all'],
        lazy_tables=True
    )

    return db

# Usage in Flask app
db = get_db_connection()

@app.route('/api/users/<int:user_id>')
def get_user(user_id):
    """Fetch user using PyDAL"""
    user = db(db.users.id == user_id).select().first()
    return {'user': user}
```

### Environment Variables

Applications MUST accept these Docker environment variables:
- `DB_TYPE`: Database type (postgresql, mysql, sqlite)
- `DB_HOST`: Database host/IP address
- `DB_PORT`: Database port
- `DB_NAME`: Database name
- `DB_USER`: Database username
- `DB_PASS`: Database password
- `DB_POOL_SIZE`: Connection pool size (default: 10)
- `DB_MAX_RETRIES`: Maximum connection retry attempts (default: 5)
- `DB_RETRY_DELAY`: Delay between retry attempts in seconds (default: 5)

### Supported Databases

| Database | Status | Notes |
|----------|--------|-------|
| PostgreSQL | Recommended | Default choice, best for production |
| MySQL/MariaDB | Supported | Full compatibility with SQLAlchemy and PyDAL |
| SQLite | Supported | Development and testing only |

### MariaDB Galera Cluster Support

For high-availability deployments using MariaDB Galera:

```python
GALERA_MODE = os.getenv('GALERA_MODE', 'false').lower() == 'true'

if GALERA_MODE and db_type == 'mysql':
    dal_kwargs['driver_args'] = {
        'init_command': (
            'SET wsrep_sync_wait=1; '
            'SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED;'
        )
    }
```

**Requirements**:
- WSREP sync wait: `wsrep_sync_wait=1` for consistency
- Auto-increment: `innodb_autoinc_lock_mode=2`
- Transaction isolation: `READ-COMMITTED` (not SERIALIZABLE)
- Primary keys: ALL tables MUST have explicit primary keys
- Connection handling: Retry logic for `WSREP_NOT_READY` errors

---

## Protocol Support

### Required Protocol Support

**ALL applications MUST support multiple communication protocols:**

1. **REST API**: RESTful HTTP endpoints
   - JSON request/response format
   - Proper HTTP status codes
   - Resource-based URL design

2. **HTTP/1.1**: Standard HTTP protocol
   - Keep-alive connections
   - Chunked transfer encoding
   - Compression (gzip, deflate)

3. **HTTP/2**: Modern HTTP protocol
   - Multiplexing multiple requests
   - Header compression (HPACK)
   - Stream prioritization

4. **HTTP/3 (QUIC)**: Next-generation protocol
   - UDP-based transport with TLS 1.3
   - Zero round-trip time (0-RTT)
   - Built-in encryption

### Configuration via Environment Variables

Applications must accept:
- `HTTP1_ENABLED`: Enable HTTP/1.1 (default: true)
- `HTTP2_ENABLED`: Enable HTTP/2 (default: true)
- `HTTP3_ENABLED`: Enable HTTP/3/QUIC (default: false)
- `HTTP_PORT`: HTTP/REST API port (default: 8080)
- `METRICS_PORT`: Prometheus metrics port (default: 9090)

---

## API Versioning

**ALL REST APIs MUST use versioning in the URL path**

### URL Structure

**Required Format**: `/api/v{major}/endpoint`

**Examples**:
- `/api/v1/users` - User management
- `/api/v1/auth/login` - Authentication
- `/api/v1/certificates` - Certificate management

**Key Rules**:
1. Always include version prefix in URL path
2. Semantic versioning for API versions: `v1`, `v2`, `v3`, etc.
3. Major version only in URL - minor/patch versions are NOT in URL
4. Consistent prefix across all endpoints in a service

### Version Lifecycle

**Version Strategy**:
- **Current Version**: Active development and fully supported
- **Previous Version (N-1)**: Supported with bug fixes and security patches
- **Older Versions (N-2+)**: Deprecated with warnings

**Deprecation Process**:
1. Release new major version
2. Support previous version for at least 12 months
3. Add deprecation headers to older versions
4. Include sunset date
5. Provide migration path documentation

**Example Deprecation Headers**:
```python
@app.route('/api/v1/users')
def get_users_v1():
    """Deprecated - use /api/v2/users instead"""
    from flask import make_response, jsonify
    response = make_response(jsonify(users))
    response.headers['Deprecation'] = 'true'
    response.headers['Sunset'] = 'Sun, 01 Jan 2026 00:00:00 GMT'
    response.headers['Link'] = '</api/v2/users>; rel="successor-version"'
    return response
```

---

## Performance Best Practices

### Python Performance Requirements

#### Concurrency Patterns

1. **asyncio** - For I/O-bound operations:
   - Database queries and connections
   - HTTP/REST API calls
   - File I/O operations
   - Network communication

2. **threading.Thread** - For blocking operations:
   - Legacy libraries without async support
   - Blocking I/O
   - Moderate parallelism (10-100 threads)

3. **multiprocessing** - For CPU-bound operations:
   - Data processing and transformations
   - Cryptographic operations
   - Heavy computational tasks

#### Dataclasses with Slots - MANDATORY

```python
from dataclasses import dataclass

@dataclass(slots=True, frozen=True)
class Certificate:
    """Certificate model with memory efficiency"""
    id: int
    subject: str
    issuer: str
    expires_at: str
    serial_number: str
```

**Benefits**:
- 30-50% less memory per instance
- Faster attribute access
- Better type safety

#### Type Hints - MANDATORY

```python
from typing import Optional, List, Dict

def fetch_certificate(cert_id: int) -> Optional[Dict[str, str]]:
    """Fetch certificate by ID."""
    pass

def list_users(role: str) -> List[Dict[str, str]]:
    """List users by role."""
    pass
```

---

## Microservices Architecture

### Four-Service Architecture

SkausWatch uses four independent containerized services:

| Service | Purpose | Technology |
|---------|---------|-----------|
| **Manager** | Management plane and configuration | Flask + PyDAL |
| **PKI Server** | Certificate management | Flask + PyDAL |
| **SSH CA** | SSH certificate authority | Flask + PyDAL |
| **AAA Monitor** | Audit and threat analysis | Flask + PyDAL |

### Service Communication

- **Synchronous**: REST API for request/response
- **Data Consistency**: Shared database layer
- **Independent Deployment**: Each service deployable independently
- **Scaling**: Scale individual services based on demand

### Design Principles

1. **Single Responsibility**: Each service has one clear purpose
2. **API-First Design**: Well-defined inter-service APIs
3. **Data Isolation**: Services own their data models
4. **Fault Isolation**: Failures don't cascade to other services
5. **Independent Scaling**: Scale services independently

---

## Docker Standards

### Build Standards

**All builds MUST be executed within Docker containers**:

```bash
# Python builds
docker run --rm -v $(pwd):/app -w /app python:3.13-slim \
    pip install -r requirements.txt
```

### Multi-Stage Builds

```dockerfile
FROM python:3.13-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

FROM debian:stable-slim

WORKDIR /app
COPY --from=builder /root/.local /root/.local
COPY . .

ENV PATH=/root/.local/bin:$PATH

CMD ["python", "app.py"]
```

### Docker Compose Standards

**ALWAYS create docker-compose.dev.yml for local development**

```yaml
version: '3.8'

networks:
  app-network:
    driver: bridge

services:
  manager:
    build: ./services/manager
    networks:
      - app-network
    ports:
      - "5000:5000"
    environment:
      - DATABASE_URL=postgresql://user:pass@postgres:5432/skauswatch
    depends_on:
      - postgres

  postgres:
    image: postgres:16-alpine
    networks:
      - app-network
    environment:
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
      - POSTGRES_DB=skauswatch
    volumes:
      - postgres-data:/var/lib/postgresql/data

volumes:
  postgres-data:
```

---

## Testing Requirements

### Unit Testing

**Framework**: pytest with async support

**Coverage**: Minimum 70% code coverage

**Requirements**:
- Network isolated (no external calls)
- Mock all external dependencies
- Fast execution (milliseconds)
- Independent and repeatable

```bash
pytest tests/ -v --cov=services --cov=shared --cov-report=html
```

### Integration Testing

- Database interactions
- External service calls (mocked)
- Multi-component workflows
- Authentication and authorization

### Test Organization

```
tests/
├── unit/
│   ├── test_auth.py
│   ├── test_certificates.py
│   └── test_audit.py
├── integration/
│   ├── test_database.py
│   └── test_api.py
├── api/
│   ├── manager/
│   ├── pki-server/
│   ├── ssh-ca/
│   └── aaa-monitor/
└── conftest.py
```

---

## Security Standards

### Input Validation

**MANDATORY for ALL endpoints**:

```python
from py_libs.validation import chain, IsNotEmpty, IsEmail, IsLength

email_validator = chain(IsNotEmpty(), IsLength(3, 255), IsEmail())
result = email_validator(user_input)
if not result.is_valid:
    return {"error": result.error}, 400
```

### Authentication & Authorization

- Multi-factor authentication support
- Role-based access control (Admin, Maintainer, Viewer)
- API key management with rotation
- JWT token validation with proper expiration
- Session management with secure cookies

### TLS/Encryption

- **TLS 1.2 minimum**, prefer TLS 1.3
- HTTPS for all endpoints
- HTTP/3 (QUIC) for high-performance
- JWT and MFA as standard

### Secret Management

**Rules**:
- Never commit credentials, tokens, or keys
- Use environment variables for sensitive data
- Use `.env` files (added to `.gitignore`)
- Use GitHub Secrets for CI/CD

### Dependency Security

**MANDATORY**:
- Regular `pip-audit` checks
- Address high/critical vulnerabilities immediately
- Keep dependencies updated
- Monitor via Dependabot

---

## Documentation Standards

### Code Comments

**Rule**: Comments explain WHY, not WHAT

**Good**:
```python
# Use exponential backoff for rate-limited API calls
retry_delay = base_delay * (2 ** attempt)
```

**Bad**:
```python
# Multiply base_delay by 2^attempt
retry_delay = base_delay * (2 ** attempt)
```

### Module Documentation

**Requirement**: Each module must have a docstring

```python
"""Certificate management module.

This module handles X.509 certificate lifecycle including issuance,
validation, revocation, and expiration tracking.

Classes:
    CertificateManager: Main certificate handler
    Certificate: Certificate model

Functions:
    issue_certificate: Create new certificate
    validate_certificate: Verify certificate validity
"""
```

### Function Documentation

**Standard**: Docstring for all public functions

```python
def issue_certificate(
    subject: str,
    validity_days: int = 365
) -> Dict[str, str]:
    """Issue new X.509 certificate.

    Creates a new certificate with the provided subject and
    validity period.

    Args:
        subject: Certificate subject (CN=...)
        validity_days: Certificate validity period in days

    Returns:
        Dictionary with certificate data and PEM encoding

    Raises:
        ValueError: If subject is invalid format
        PermissionError: If user lacks issuance permission
    """
    pass
```

---

## Logging & Monitoring

### Logging Standards

- **Console logging**: Always implement console output
- **Structured logging**: Use correlation IDs for tracing
- **Logging levels**:
  - `-v`: Warnings and criticals
  - `-vv`: Info level (default)
  - `-vvv`: Debug logging

### Health Endpoints

**MANDATORY for all applications**:

```python
@app.route('/healthz')
def health():
    """Health check endpoint"""
    return {'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}
```

### Prometheus Metrics

```python
from prometheus_client import Counter, Histogram, generate_latest

REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint']
)
REQUEST_DURATION = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration'
)

@app.route('/metrics')
def metrics():
    return generate_latest(), {'Content-Type': 'text/plain'}
```

---

## WaddleAI Integration

**Optional** - integrate only when AI features are required.

### When to Use WaddleAI

- Natural language processing (NLP)
- Machine learning model inference
- AI-powered threat detection
- Intelligent data analysis
- Anomaly detection in audit logs

### Integration Pattern

```python
import os
import httpx
from typing import Dict, Any

class WaddleAIClient:
    """Client for WaddleAI service"""

    def __init__(self):
        self.base_url = os.getenv('WADDLEAI_URL', 'http://localhost:8000')
        self.client = httpx.AsyncClient(base_url=self.base_url)

    async def analyze_threat(self, log_data: Dict[str, Any]) -> Dict:
        """Analyze audit log for threats"""
        response = await self.client.post(
            "/api/v1/analyze",
            json={"data": log_data}
        )
        return response.json()

# Flask integration
from shared.licensing import requires_feature

@app.route('/api/analyze-threat', methods=['POST'])
@auth_required()
@requires_feature('ai_analysis')
async def analyze_threat():
    """AI-powered threat analysis"""
    ai_client = WaddleAIClient()
    result = await ai_client.analyze_threat(request.get_json())
    return jsonify(result)
```

### License-Gating

**AI features MUST be license-gated as enterprise-only**:

```python
# License configuration
AI_FEATURES = {
    'ai_threat_analysis': 'professional',
    'ai_anomaly_detection': 'professional',
    'ai_custom_models': 'enterprise',
}

# Feature checking
from shared.licensing import license_client

if license_client.has_feature('ai_threat_analysis'):
    # AI features available
    pass
```

---

## CI/CD Standards

### Workflow Monitoring

All builds monitor `.version` file for automatic versioning.

### Build Naming

| Scenario | Tag Format |
|----------|-----------|
| Regular build (main) | `skauswatch:beta-<epoch64>` |
| Regular build (other) | `skauswatch:alpha-<epoch64>` |
| Version release (main) | `skauswatch:vX.X.X-beta` |
| Version release (other) | `skauswatch:vX.X.X-alpha` |
| Release tag | `skauswatch:vX.X.X` + `latest` |

### Security Scanning

**MANDATORY**:
- Bandit for Python security analysis
- CodeQL for code analysis
- Trivy for container scanning

---

## Quality Checklist

Before marking any task complete, verify:

- ✅ All error cases handled properly
- ✅ Unit tests cover all code paths
- ✅ Integration tests verify interactions
- ✅ Security requirements fully implemented
- ✅ Performance acceptable
- ✅ Documentation complete and accurate
- ✅ Code review standards met
- ✅ No hardcoded secrets or credentials
- ✅ Logging and monitoring in place
- ✅ Build passes in containerized environment
- ✅ No security vulnerabilities in dependencies
- ✅ Edge cases and boundary conditions tested

---

## Related Documents

- [Project Overview](../CLAUDE.md)
- [Workflows Documentation](WORKFLOWS.md)
- [README](../README.md)
