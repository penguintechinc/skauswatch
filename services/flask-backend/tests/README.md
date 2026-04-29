# Flask Backend Test Suite

Comprehensive pytest test suite for the Quart backend service with OIDC auth and penguin-dal.

## Test Files

### `conftest.py` (185 lines)
Pytest fixtures providing:
- `app` — Quart test app with TestingConfig, SQLite :memory: DB, OIDCProvider
- `client` — Quart test client
- User fixtures: `admin_user`, `maintainer_user`, `viewer_user`
- Token fixtures: `admin_token`, `maintainer_token`, `viewer_token`
- Header fixtures: `admin_headers`, `maintainer_headers`, `viewer_headers`

### `test_auth.py` (324 lines)
Authentication endpoint tests covering:
- POST /api/v1/auth/register — creates user, validates password, prevents duplicates
- POST /api/v1/auth/login — valid/invalid credentials, deactivated users
- POST /api/v1/auth/refresh — token refresh with valid/invalid tokens
- POST /api/v1/auth/logout — revokes tokens
- GET /api/v1/auth/me — returns current user info
- Password hashing and verification functions

### `test_users.py` (415 lines)
User management endpoint tests covering:
- GET /api/v1/users — list users (admin only), pagination, role-based access
- GET /api/v1/users/<id> — fetch single user, 404 handling
- POST /api/v1/users — create user (admin only), validation, duplicates
- PUT /api/v1/users/<id> — update user, role changes, email conflicts
- DELETE /api/v1/users/<id> — delete user, prevent self-deletion
- GET /api/v1/users/roles — list valid roles

### `test_models.py` (318 lines)
penguin-dal database model tests covering:
- `get_user_by_email` — returns None or user dict
- `get_user_by_id` — fetches user by ID
- `create_user` — creates user with defaults
- `update_user` — updates single/multiple fields, ignores invalid fields
- `delete_user` — deletes user, returns bool
- `list_users` — paginated list, offset handling

### `test_middleware.py` (314 lines)
Authentication and authorization middleware tests covering:
- `LocalTokenValidator.verify_token` — validates RS256 tokens
- Token rejection — invalid, expired, wrong audience
- `@auth_required` decorator — accepts/rejects tokens
- `@role_required` decorator — enforces scopes
- `@admin_required` decorator — admin-only access
- Context population — user and claims in `g`
- Deactivated and nonexistent users

## Configuration

### `pytest.ini` (20 lines)
- `asyncio_mode = auto` — auto-detect async tests
- Coverage threshold: 90% (lines, branches, functions, statements)
- HTML coverage report in `htmlcov/`

## Running Tests

```bash
# All tests with coverage
pytest tests/ --cov=app --cov-fail-under=90

# Specific test file
pytest tests/test_auth.py -v

# Specific test function
pytest tests/test_auth.py::test_login_valid_credentials_returns_tokens -v

# With coverage report
pytest tests/ --cov=app --cov-report=html

# Async tests only
pytest tests/ -m asyncio
```

## Test Coverage

**Total: ~1,577 lines of test code**

- `conftest.py`: 185 lines
- `test_auth.py`: 324 lines
- `test_users.py`: 415 lines
- `test_models.py`: 318 lines
- `test_middleware.py`: 314 lines
- `pytest.ini`: 20 lines

**Test Cases: 90+ scenarios** covering:
- ✓ Happy path scenarios (valid inputs, successful operations)
- ✓ Error cases (400, 401, 403, 404, 409 status codes)
- ✓ Validation (email format, password length, role validity)
- ✓ Authorization (role-based access control, scope checks)
- ✓ Authentication (token validation, expiration, audience)
- ✓ Database operations (CRUD, pagination, uniqueness)
- ✓ Edge cases (deactivated users, self-deletion, empty updates)

## Setup

1. Install test dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Verify setup:
   ```bash
   pytest tests/ --collect-only
   ```

3. Run tests:
   ```bash
   pytest tests/ -v
   ```

## Fixtures Available

All test functions can use these fixtures:

- `app: Quart` — Test Quart application
- `client: AsyncTestClient` — HTTP test client
- `admin_user: dict` — Created admin user
- `maintainer_user: dict` — Created maintainer user
- `viewer_user: dict` — Created viewer user
- `admin_token: str` — JWT token for admin
- `maintainer_token: str` — JWT token for maintainer
- `viewer_token: str` — JWT token for viewer
- `admin_headers: dict` — Authorization headers with admin token
- `maintainer_headers: dict` — Authorization headers with maintainer token
- `viewer_headers: dict` — Authorization headers with viewer token
- `admin_user_data: dict` — Admin user credentials
- `maintainer_user_data: dict` — Maintainer user credentials
- `viewer_user_data: dict` — Viewer user credentials

## Notes

- Uses async/await syntax throughout (`pytest-asyncio`)
- All HTTP tests use `async with app.test_client()`
- Database operations use SQLite in-memory (no external DB needed)
- Tokens issued by real OIDCProvider, validated by LocalTokenValidator
- Type hints on all test functions
- No manual session management — fixtures handle app context
