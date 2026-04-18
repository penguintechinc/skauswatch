"""
Unit tests for /api/v1/modules endpoint.

Tests module flag retrieval from environment variables.
Tests enable/disable per module and default values.
"""

import os
from unittest.mock import patch

import pytest


@pytest.fixture
def clear_env():
    """Fixture to clear and restore environment."""
    original_env = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(original_env)


class TestModulesEndpoint:
    """Test GET /api/v1/modules endpoint."""

    def test_modules_all_false_by_default(self, clear_env):
        """All modules disabled by default when env vars not set."""
        with patch.dict(os.environ, {}, clear=True):
            from api.v1.modules import _bool_env

            result = {
                "checkpoint": _bool_env("CHECKPOINT_ENABLED", "false"),
                "elder_push": _bool_env("ELDER_PUSH_ENABLED", "false"),
                "icebox": _bool_env("ICEBOX_ENABLED", "false"),
                "darwin": _bool_env("DARWIN_ENABLED", "true"),
                "asm": _bool_env("ASM_ENABLED", "true"),
                "siem": _bool_env("SIEM_ENABLED", "true"),
                "s3_scan": _bool_env("S3_SCAN_ENABLED", "true"),
            }

            assert result["checkpoint"] is False
            assert result["elder_push"] is False
            assert result["icebox"] is False
            # darwin, asm, siem, s3_scan default to true
            assert result["darwin"] is True
            assert result["asm"] is True
            assert result["siem"] is True
            assert result["s3_scan"] is True

    def test_modules_checkpoint_enabled(self, clear_env):
        """CHECKPOINT_ENABLED=true enables checkpoint module."""
        with patch.dict(os.environ, {"CHECKPOINT_ENABLED": "true"}, clear=True):
            from api.v1.modules import _bool_env

            result = _bool_env("CHECKPOINT_ENABLED", "false")
            assert result is True

    def test_modules_checkpoint_enabled_case_insensitive(self, clear_env):
        """CHECKPOINT_ENABLED=TRUE (uppercase) also enables."""
        with patch.dict(os.environ, {"CHECKPOINT_ENABLED": "TRUE"}, clear=True):
            from api.v1.modules import _bool_env

            result = _bool_env("CHECKPOINT_ENABLED", "false")
            assert result is True

    def test_modules_checkpoint_enabled_mixed_case(self, clear_env):
        """CHECKPOINT_ENABLED=True (mixed case) also enables."""
        with patch.dict(os.environ, {"CHECKPOINT_ENABLED": "True"}, clear=True):
            from api.v1.modules import _bool_env

            result = _bool_env("CHECKPOINT_ENABLED", "false")
            assert result is True

    def test_modules_icebox_enabled(self, clear_env):
        """ICEBOX_ENABLED=true enables icebox module."""
        with patch.dict(os.environ, {"ICEBOX_ENABLED": "true"}, clear=True):
            from api.v1.modules import _bool_env

            result = _bool_env("ICEBOX_ENABLED", "false")
            assert result is True

    def test_modules_multiple_enabled(self, clear_env):
        """Multiple modules can be enabled independently."""
        with patch.dict(
            os.environ, {"ICEBOX_ENABLED": "true", "DARWIN_ENABLED": "false"}, clear=True
        ):
            from api.v1.modules import _bool_env

            icebox = _bool_env("ICEBOX_ENABLED", "false")
            darwin = _bool_env("DARWIN_ENABLED", "true")
            checkpoint = _bool_env("CHECKPOINT_ENABLED", "false")

            assert icebox is True
            assert darwin is False
            assert checkpoint is False

    def test_modules_false_value(self, clear_env):
        """Env var set to 'false' disables module."""
        with patch.dict(os.environ, {"CHECKPOINT_ENABLED": "false"}, clear=True):
            from api.v1.modules import _bool_env

            result = _bool_env("CHECKPOINT_ENABLED", "true")
            assert result is False

    def test_modules_false_value_case_insensitive(self, clear_env):
        """Env var set to 'FALSE' disables module."""
        with patch.dict(os.environ, {"CHECKPOINT_ENABLED": "FALSE"}, clear=True):
            from api.v1.modules import _bool_env

            result = _bool_env("CHECKPOINT_ENABLED", "true")
            assert result is False

    def test_modules_invalid_value_uses_default(self, clear_env):
        """Invalid env value falls back to default."""
        with patch.dict(os.environ, {"CHECKPOINT_ENABLED": "maybe"}, clear=True):
            from api.v1.modules import _bool_env

            result = _bool_env("CHECKPOINT_ENABLED", "false")
            assert result is False

    def test_modules_whitespace_handling(self, clear_env):
        """Leading/trailing whitespace is stripped."""
        with patch.dict(os.environ, {"CHECKPOINT_ENABLED": "  true  "}, clear=True):
            from api.v1.modules import _bool_env

            result = _bool_env("CHECKPOINT_ENABLED", "false")
            assert result is True

    def test_modules_empty_string_uses_default(self, clear_env):
        """Empty env var uses default."""
        with patch.dict(os.environ, {"CHECKPOINT_ENABLED": ""}, clear=True):
            from api.v1.modules import _bool_env

            result = _bool_env("CHECKPOINT_ENABLED", "false")
            assert result is False

    def test_modules_not_set_uses_default(self, clear_env):
        """Unset env var uses provided default."""
        with patch.dict(os.environ, {}, clear=True):
            from api.v1.modules import _bool_env

            result_false = _bool_env("UNKNOWN_MODULE", "false")
            result_true = _bool_env("UNKNOWN_MODULE", "true")

            assert result_false is False
            assert result_true is True
