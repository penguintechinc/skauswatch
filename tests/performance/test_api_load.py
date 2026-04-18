"""API load/performance tests.

Tests response time percentiles for critical endpoints.
Uses concurrent requests via the Quart test client.
Marked as @performance and @slow — not run in pre-commit.
"""

import asyncio
import os
import statistics
import sys
import time
from unittest.mock import AsyncMock, patch

import pytest

MANAGER_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "services", "manager-new"
)
sys.path.insert(0, MANAGER_DIR)


@pytest.fixture
def app():
    """Create app for performance testing."""
    os.environ.update(
        {
            "DB_TYPE": "sqlite",
            "DB_NAME": ":memory:",
            "JWT_SECRET_KEY": "test-jwt-secret",
            "SECRET_KEY": "test-secret-key",
            "GRPC_ENABLED": "false",
            "AI_ENABLED": "false",
            "REDIS_URL": "redis://localhost:6379/15",
            "LOG_LEVEL": "WARNING",
        }
    )

    mock_stream = AsyncMock(
        connect=AsyncMock(),
        close=AsyncMock(),
        create_consumer_group=AsyncMock(),
        _client=AsyncMock(ping=AsyncMock(return_value=True)),
    )

    with (
        patch("main.RedisStreamManager", return_value=mock_stream),
        patch("main.create_stream_consumer", new_callable=AsyncMock),
        patch("main.AuditLogPublisher", return_value=AsyncMock()),
    ):
        from config import AuthConfig, DatabaseConfig, ManagerConfig, RedisConfig
        from main import create_app

        config = ManagerConfig(
            environment="testing",
            database=DatabaseConfig(type="sqlite", name=":memory:"),
            redis=RedisConfig(url="redis://localhost:6379/15", streams_enabled=False),
            auth=AuthConfig(jwt_secret="test-jwt-secret"),
        )
        test_app = create_app(config)
        test_app.config["TESTING"] = True
        yield test_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
async def auth_token(client, app):
    """Create user and get token."""
    import bcrypt

    from models.db import get_db

    config = app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)
    pw_hash = bcrypt.hashpw(b"PerfTest123!", bcrypt.gensalt()).decode("utf-8")
    db.users.insert(
        email="perf@test.com",
        password_hash=pw_hash,
        full_name="Perf User",
        role="admin",
        is_active=True,
        failed_login_attempts=0,
    )
    db.commit()

    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "perf@test.com", "password": "PerfTest123!"},
    )
    data = await resp.get_json()
    return data["access_token"]


@pytest.mark.performance
@pytest.mark.slow
class TestAPIResponseTimes:
    """API endpoint response time benchmarks."""

    async def test_login_p95_under_500ms(self, client, app):
        """Login endpoint p95 < 500ms (test client, not network)."""
        import bcrypt

        from models.db import get_db

        config = app.config["MANAGER_CONFIG"]
        db = get_db(config.database.uri)
        pw_hash = bcrypt.hashpw(b"BenchPass123!", bcrypt.gensalt()).decode("utf-8")
        db.users.insert(
            email="bench@test.com",
            password_hash=pw_hash,
            full_name="Bench User",
            role="viewer",
            is_active=True,
            failed_login_attempts=0,
        )
        db.commit()

        times = []
        for _ in range(20):
            start = time.monotonic()
            await client.post(
                "/api/v1/auth/login",
                json={"email": "bench@test.com", "password": "BenchPass123!"},
            )
            elapsed_ms = (time.monotonic() - start) * 1000
            times.append(elapsed_ms)

        p95 = sorted(times)[int(len(times) * 0.95)]
        assert p95 < 500, f"Login p95 = {p95:.1f}ms (expected < 500ms)"

    async def test_alerts_list_p95_under_200ms(self, client, auth_token):
        """Alerts list endpoint p95 < 200ms."""
        headers = {"Authorization": f"Bearer {auth_token}"}

        times = []
        for _ in range(20):
            start = time.monotonic()
            await client.get("/api/v1/alerts", headers=headers)
            elapsed_ms = (time.monotonic() - start) * 1000
            times.append(elapsed_ms)

        p95 = sorted(times)[int(len(times) * 0.95)]
        assert p95 < 200, f"Alerts list p95 = {p95:.1f}ms (expected < 200ms)"

    async def test_healthz_p95_under_100ms(self, client):
        """Health check p95 < 100ms."""
        times = []
        for _ in range(20):
            start = time.monotonic()
            await client.get("/healthz")
            elapsed_ms = (time.monotonic() - start) * 1000
            times.append(elapsed_ms)

        p95 = sorted(times)[int(len(times) * 0.95)]
        assert p95 < 100, f"Healthz p95 = {p95:.1f}ms (expected < 100ms)"
