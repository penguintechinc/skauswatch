# Shared Libraries

This directory contains **SkausWatch-specific** shared utilities that are unique to this project.

## 🔄 Migration to Penguin-Libs (Completed)

Common libraries have been migrated to centralized published packages:
- **Python**: `penguin-libs`, `penguin-licensing`, `penguintechinc-utils` (PyPI)
- **React**: `@penguintechinc/react-libs` (GitHub Packages/npm)

## 📦 Remaining Modules (Application-Specific)

### Python Libraries (`py_libs/`)
Currently empty after migration - all common Python utilities moved to penguin-libs

### Performance Utilities (`performance/`)
**Kept in shared/** - No equivalent in penguin-libs

Application-specific performance utilities:
- `async_utils.py` - Async/await helpers
- `cache_manager.py` - Caching strategies
- `connection_pool.py` - Database connection pooling
- `rate_limiter.py` - API rate limiting
- `thread_pool.py` - Thread pool management
- `message_queue.py` - Message queue utilities
- `monitoring.py` - Performance monitoring

### Database Utilities (`database/`)
**Kept in shared/** - Application-specific

PostgreSQL and Redis connection utilities tailored to SkausWatch architecture.

### Go Libraries (`go_libs/`)
**Kept in shared/** - go-common package incomplete

Waiting for penguin-libs/go-common to expand with validation, crypto, http, grpc modules.
Will migrate when go-common is feature-complete.

Modules:
- `validation/` - Input validation
- `crypto/` - Cryptographic utilities
- `http/` - HTTP client/server helpers
- `grpc/` - gRPC utilities
- `security/` - Security utilities

### Go Licensing (`licensing/client.go`, `licensing/middleware.go`)
**Kept in shared/** - Not yet in go-common

Go license client for PenguinTech License Server integration.
Will migrate when added to penguin-libs/go-common.

### Node.js Libraries (`node_libs/`)
**Kept in shared/** - No penguin-libs package exists

TypeScript/Node.js utilities with validation, crypto, http, grpc, security modules.
Consider creating `penguin-libs/packages/node-libs` in future.

## 📚 Published Package Documentation

- **Python**: [penguin-libs](https://github.com/penguintechinc/penguin-libs/tree/main/packages/python)
- **React**: [@penguintechinc/react-libs](https://github.com/penguintechinc/penguin-libs/tree/main/packages/react-libs)
- **Licensing**: [penguin-licensing](https://github.com/penguintechinc/penguin-libs/tree/main/packages/python-licensing)

## 🎯 Usage Guidelines

1. **Use published packages first** - Check penguin-libs before adding to shared/
2. **Application-specific only** - Only keep utilities unique to SkausWatch
3. **Document rationale** - Explain why utilities remain in shared/
4. **Consider extraction** - If utilities are useful across projects, move to penguin-libs

## 🔮 Future Migrations

### Planned
- `go_libs/` → `penguin-libs/go-common` (when expanded)
- `licensing/client.go` → `penguin-libs/go-common` (when added)

### Under Consideration
- `performance/` → `penguin-libs/python-performance` (if reusable)
- `node_libs/` → `penguin-libs/node-libs` (create new package)

---

See [docs/shared-libraries/overview.md](../docs/shared-libraries/overview.md) for complete documentation.
