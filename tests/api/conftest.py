"""Shared fixtures for API-level tests against the manager service."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Make manager service importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../services/manager"))

# These tests require manager service dependencies (quart, quart_cors, etc.)
# Skip the entire module if they aren't installed
pytest.importorskip("quart", reason="quart not installed (manager service deps required)")
pytest.importorskip("quart_cors", reason="quart_cors not installed (manager service deps required)")


@pytest.fixture
def manager_app():
    """Create a manager Quart app instance wired with test configuration."""
    # Patch external deps before importing the app
    mock_db = MagicMock()
    mock_db.define_tables = MagicMock()
    mock_db.commit = MagicMock()
    mock_db.users = MagicMock()
    mock_db.users.count = MagicMock(return_value=0)

    with patch("models.db.init_database_schema"), patch("models.db.get_db", return_value=mock_db):
        from main import create_app

        from config import AuthConfig, ManagerConfig, SIEMConfig

        test_cfg = ManagerConfig(
            environment="test",
            auth=AuthConfig(
                secret_key="test-secret",
                jwt_secret="test-jwt-secret",
            ),
            siem=SIEMConfig(
                enabled=True,
                opensearch_url="http://localhost:9200",
                logs_url="http://localhost:5010",
                retention_days=90,
            ),
        )
        app = create_app(test_cfg)
        app.config["TESTING"] = True
        return app


@pytest.fixture
def manager_test_client(manager_app):
    """Quart test client for the manager service."""
    return manager_app.test_client()


@pytest.fixture
def admin_token(manager_app):
    """Generate a valid admin JWT for use in test requests."""
    from datetime import datetime, timedelta

    import jwt as pyjwt

    cfg = manager_app.config["MANAGER_CONFIG"]
    payload = {
        "sub": "1",
        "role": "admin",
        "type": "access",
        "exp": datetime.utcnow() + timedelta(hours=1),
        "iat": datetime.utcnow(),
    }
    return pyjwt.encode(payload, cfg.auth.jwt_secret, algorithm=cfg.auth.jwt_algorithm)
