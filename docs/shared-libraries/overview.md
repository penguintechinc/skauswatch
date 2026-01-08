# Shared Libraries

Reusable, enterprise-grade libraries for secure application development across Python, Go, and Node.js/TypeScript ecosystems. These libraries implement consistent patterns for validation, security, cryptography, and more.

## Overview

The shared libraries provide:

- **Validation**: PyDAL-style input validators with chainable API
- **Security**: Rate limiting, CSRF protection, secure headers, sanitization
- **Crypto**: Token generation, password hashing, encryption
- **HTTP**: Request correlation, resilient HTTP client with retries
- **gRPC**: Server/client setup with security interceptors

## Available Libraries

### [Python Library](./py-libs.md)

```bash
pip install -e "py_libs[all]"
```

Full-featured Python library with Flask integration, gRPC support, and Redis connectivity.

**Key Features:**
- PyDAL-style validators with type hints
- Flask security middleware
- Argon2id password hashing
- AES-256-GCM encryption
- gRPC server with interceptors

### [Go Library](./go-libs.md)

```bash
go get github.com/penguintechinc/project-template/shared/go_libs
```

High-performance Go library for microservices with Gin framework integration.

**Key Features:**
- Chainable validators with functional options
- Gin middleware for security
- bcrypt password hashing
- XChaCha20-Poly1305 encryption
- gRPC server setup

### [Node.js/TypeScript Library](./node-libs.md)

```bash
npm install @penguin/node_libs
```

Modern TypeScript library for Express.js applications with full type safety.

**Key Features:**
- Type-safe validators with chainable API
- Express middleware integration
- Argon2 password hashing
- ChaCha20-Poly1305 encryption
- gRPC client/server support

## Quick Start

### Python

```python
from py_libs.validation import chain, IsNotEmpty, IsLength, IsEmail

# Validate email with multiple validators
validators = chain(IsNotEmpty(), IsLength(3, 255), IsEmail())
result = validators("user@example.com")

if result.is_valid:
    email = result.unwrap()
else:
    print(f"Validation error: {result.error}")
```

### Go

```go
package main

import (
    "fmt"
    "github.com/penguintechinc/project-template/shared/go_libs/validation"
)

func main() {
    // Chain multiple validators
    validator := validation.Chain(
        validation.NotEmpty(),
        validation.Length(3, 255),
        validation.Email(),
    )

    result := validator.Validate("user@example.com")
    if !result.IsValid {
        fmt.Println("Error:", result.Error)
        return
    }

    email := result.Value.(string)
    fmt.Println("Valid email:", email)
}
```

### Node.js/TypeScript

```typescript
import { chain, notEmpty, length, email } from '@penguin/node_libs/validation';

const validator = chain(
  notEmpty(),
  length(3, 255),
  email()
);

const result = validator("user@example.com");
if (!result.isValid) {
  console.error("Validation error:", result.error);
} else {
  console.log("Valid email:", result.value);
}
```

## Directory Structure

```
shared/
├── py_libs/              # Python library
│   ├── py_libs/
│   │   ├── validation/   # Input validators
│   │   ├── security/     # Security utilities
│   │   ├── crypto/       # Cryptography
│   │   ├── http/         # HTTP client
│   │   └── grpc/         # gRPC support
│   └── pyproject.toml
├── go_libs/              # Go library
│   ├── validation/       # Input validators
│   ├── crypto/           # Cryptography
│   ├── security/         # Security utilities
│   ├── http/             # HTTP client
│   ├── grpc/             # gRPC support
│   └── go.mod
├── node_libs/            # Node.js/TypeScript library
│   ├── src/
│   │   ├── validation/   # Input validators
│   │   ├── security/     # Security utilities
│   │   ├── crypto/       # Cryptography
│   │   ├── http/         # HTTP client
│   │   └── grpc/         # gRPC support
│   ├── package.json
│   └── tsconfig.json
├── auth/                 # Shared authentication
├── config/               # Configuration utilities
├── database/             # Database utilities
├── licensing/            # License validation
├── monitoring/           # Monitoring helpers
└── types/                # Shared type definitions
```

## Common Features Across All Libraries

### Validation

All three libraries implement PyDAL-style validators with chainable APIs:

- String: empty, length, pattern matching, alphanumeric, slug, set membership
- Numeric: integer, float, range validation
- Network: email, URL, IP address, hostname
- DateTime: date, time, datetime, date range
- Password: configurable strength validation

### Security

Cross-library security utilities:

- Rate limiting (in-memory and Redis-backed)
- CSRF protection
- Secure HTTP headers
- Input sanitization
- Audit logging

### Cryptography

Standard cryptographic operations:

- **Password Hashing**: Argon2id (Python/Node.js), bcrypt (Go)
- **Encryption**: AES-256-GCM (Python), XChaCha20-Poly1305 (Go), ChaCha20-Poly1305 (Node.js)
- **Token Generation**: Secure random tokens
- **JWT**: JWT creation and validation

### gRPC

Production-ready gRPC support:

- Server setup with interceptors
- Security interceptors for auth/validation
- Error handling and logging
- Metadata propagation

## Development

### Python Development

```bash
cd py_libs
python -m venv venv
source venv/bin/activate
pip install -e ".[dev,all]"
./scripts/lint.sh
python -m pytest tests/
```

### Go Development

```bash
cd go_libs
go mod download
./scripts/lint.sh
go test ./...
```

### Node.js Development

```bash
cd node_libs
npm install
./scripts/lint.sh
npm test
```

## Installation in Projects

### Using Python Library

```bash
# In Flask backend
pip install -e "../shared/py_libs[flask,redis]"
```

### Using Go Library

```bash
# In go-backend
go get -u github.com/penguintechinc/project-template/shared/go_libs
```

### Using Node.js Library

```bash
# In webui or Node.js service
npm install file:../shared/node_libs
```

## API Documentation

- **Python**: [py_libs README](./py-libs.md)
- **Go**: [go_libs README](./go-libs.md)
- **Node.js**: [node_libs README](./node-libs.md)

## Testing

Each library includes comprehensive tests:

- Unit tests for all validators and utilities
- Integration tests for middleware and frameworks
- Type checking (mypy for Python, strict TypeScript)
- Security scanning (bandit for Python, golangci-lint for Go)

Run tests from each library directory:

```bash
# Python
python -m pytest tests/

# Go
go test ./...

# Node.js
npm test
```

## Security

All libraries are designed with security-first principles:

- Input validation to prevent injection attacks
- Password hashing with modern algorithms
- Secure randomization for tokens
- Protected against common vulnerabilities
- Regular security audits via scanning tools
- No hardcoded secrets or credentials

## License

Licensed under GNU Affero General Public License v3 (AGPL-3.0)

See LICENSE files in individual library directories for details.

---

For library-specific documentation, setup instructions, and API references, see the README files in each library directory.
