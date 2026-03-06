"""Pytest configuration and shared fixtures for unit tests."""

import os
import sys
from pathlib import Path

import pytest

# Add the Flask backend app to the Python path
flask_backend_path = Path(__file__).parent.parent.parent / "services" / "flask-backend"
sys.path.insert(0, str(flask_backend_path))


@pytest.fixture(scope="session")
def test_config():
    """Test configuration fixture."""
    return {
        "TESTING": True,
        "DATABASE_URL": "sqlite:///:memory:",
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "JWT_SECRET": "test-secret-key",
        "AI_PROVIDER": "claude",
        "ANTHROPIC_API_KEY": "test-api-key",
    }


@pytest.fixture(autouse=True)
def reset_imports():
    """Reset module imports before each test to avoid side effects."""
    yield
    # Clean up after test
    pass


@pytest.fixture
def mock_flask_app(test_config):
    """Create a mock Flask app for testing."""
    from flask import Flask

    app = Flask(__name__)
    app.config.update(test_config)

    with app.app_context():
        yield app


@pytest.fixture
def mock_app_context(mock_flask_app):
    """Provide Flask application context."""
    with mock_flask_app.app_context():
        yield mock_flask_app


# Async support for pytest
@pytest.fixture
def event_loop():
    """Create an event loop for async tests."""
    import asyncio

    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# Markers for test categorization
def pytest_configure(config):
    """Register pytest markers."""
    config.addinivalue_line(
        "markers", "asyncio: mark test as async (deselect with '-m \"not asyncio\"')"
    )
    config.addinivalue_line(
        "markers", "unit: mark test as unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
