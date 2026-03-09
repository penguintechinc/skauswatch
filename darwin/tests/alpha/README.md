# Alpha Test Suite

**Purpose**: Validate local Docker Compose builds and deployments before K8s deployment.

## What Alpha Tests Cover

### 1. Build Verification
- All containers build successfully
- No build errors or warnings
- Multi-architecture support (amd64/arm64)

### 2. Container Runtime
- All services start successfully
- Health checks pass
- Container logs show no errors
- Services can communicate with each other

### 3. Mock Data Integration
- Mock data scripts populate database
- 3-4 items per feature/entity
- Data relationships are valid
- No data integrity errors

### 4. Page Load Tests
- All pages load successfully
- No 404 or 500 errors
- Pages render correctly
- No JavaScript console errors

### 5. Tab Load Tests
- All tabs/sections load successfully
- Tab switching works correctly
- No content loading errors

### 6. API Tests
- Health endpoints respond
- Authentication endpoints work
- CRUD operations succeed
- Error handling is correct
- Response formats are valid

## Running Alpha Tests

```bash
# Run all alpha tests
./tests/alpha/run-all.sh

# Run individual test suites
./tests/alpha/01-build-test.sh
./tests/alpha/02-runtime-test.sh
./tests/alpha/03-mock-data-test.sh
./tests/alpha/04-page-load-test.sh
./tests/alpha/05-api-test.sh

# Clean up after tests
./tests/alpha/cleanup.sh
```

## Test Output

- Results logged to `/tmp/alpha-tests-<timestamp>/`
- Screenshots saved for visual verification
- JSON reports for CI/CD integration
- Exit code 0 = success, non-zero = failure

## Prerequisites

- Docker and Docker Compose installed
- Port 5000 (Flask) and 3000 (WebUI) available
- At least 4GB RAM available
- Node.js 18+ for page load tests
