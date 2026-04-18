"""pytest tests for audit/logger.py — 90%+ coverage of AuditLogger."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from audit.logger import AuditLogger, _sanitise


class TestSanitise:
    """Test the _sanitise function for removing sensitive keys."""

    def test_sanitise_removes_password(self) -> None:
        """Test password field is redacted."""
        details = {"password": "secret123", "username": "alice"}
        result = _sanitise(details)

        assert result["password"] == "[REDACTED]"
        assert result["username"] == "alice"

    def test_sanitise_removes_token(self) -> None:
        """Test token field is redacted."""
        details = {"token": "abc123xyz", "event": "login"}
        result = _sanitise(details)

        assert result["token"] == "[REDACTED]"
        assert result["event"] == "login"

    def test_sanitise_removes_secret(self) -> None:
        """Test secret field is redacted."""
        details = {"secret": "mysecret", "id": "123"}
        result = _sanitise(details)

        assert result["secret"] == "[REDACTED]"

    def test_sanitise_removes_private_key(self) -> None:
        """Test private_key field is redacted."""
        details = {"private_key": "-----BEGIN PRIVATE KEY-----"}
        result = _sanitise(details)

        assert result["private_key"] == "[REDACTED]"

    def test_sanitise_removes_client_secret(self) -> None:
        """Test client_secret field is redacted."""
        details = {"client_secret": "secret"}
        result = _sanitise(details)

        assert result["client_secret"] == "[REDACTED]"

    def test_sanitise_removes_code_verifier(self) -> None:
        """Test code_verifier field is redacted."""
        details = {"code_verifier": "verifier123"}
        result = _sanitise(details)

        assert result["code_verifier"] == "[REDACTED]"

    def test_sanitise_removes_assertion(self) -> None:
        """Test assertion field is redacted."""
        details = {"assertion": "saml_assertion_xyz"}
        result = _sanitise(details)

        assert result["assertion"] == "[REDACTED]"

    def test_sanitise_removes_refresh_token(self) -> None:
        """Test refresh_token field is redacted."""
        details = {"refresh_token": "refresh123"}
        result = _sanitise(details)

        assert result["refresh_token"] == "[REDACTED]"

    def test_sanitise_removes_access_token(self) -> None:
        """Test access_token field is redacted."""
        details = {"access_token": "access123"}
        result = _sanitise(details)

        assert result["access_token"] == "[REDACTED]"

    def test_sanitise_removes_id_token(self) -> None:
        """Test id_token field is redacted."""
        details = {"id_token": "id123"}
        result = _sanitise(details)

        assert result["id_token"] == "[REDACTED]"

    def test_sanitise_removes_jwt(self) -> None:
        """Test jwt field is redacted."""
        details = {"jwt": "eyJ..."}
        result = _sanitise(details)

        assert result["jwt"] == "[REDACTED]"

    def test_sanitise_removes_api_key(self) -> None:
        """Test api_key field is redacted."""
        details = {"api_key": "key123"}
        result = _sanitise(details)

        assert result["api_key"] == "[REDACTED]"

    def test_sanitise_removes_credential(self) -> None:
        """Test credential field is redacted."""
        details = {"credential": "cred123"}
        result = _sanitise(details)

        assert result["credential"] == "[REDACTED]"

    def test_sanitise_case_insensitive(self) -> None:
        """Test key matching is case-insensitive."""
        details = {"PASSWORD": "secret", "Token": "token123", "CLIENT_SECRET": "secret"}
        result = _sanitise(details)

        assert result["PASSWORD"] == "[REDACTED]"
        assert result["Token"] == "[REDACTED]"
        assert result["CLIENT_SECRET"] == "[REDACTED]"

    def test_sanitise_nested_dict(self) -> None:
        """Test nested dicts are recursively sanitised."""
        details = {
            "user": {"username": "alice", "password": "secret"},
            "request": {"method": "POST"},
        }
        result = _sanitise(details)

        assert result["user"]["username"] == "alice"
        assert result["user"]["password"] == "[REDACTED]"
        assert result["request"]["method"] == "POST"

    def test_sanitise_deeply_nested(self) -> None:
        """Test deeply nested structures are sanitised."""
        details = {"a": {"b": {"c": {"token": "value", "name": "test"}}}}
        result = _sanitise(details)

        assert result["a"]["b"]["c"]["token"] == "[REDACTED]"
        assert result["a"]["b"]["c"]["name"] == "test"

    def test_sanitise_non_dict_values(self) -> None:
        """Test non-dict values are left untouched."""
        details = {
            "password": "secret",
            "count": 123,
            "active": True,
            "tags": ["tag1", "tag2"],
        }
        result = _sanitise(details)

        assert result["password"] == "[REDACTED]"
        assert result["count"] == 123
        assert result["active"] is True
        assert result["tags"] == ["tag1", "tag2"]

    def test_sanitise_empty_dict(self) -> None:
        """Test empty dict returns empty dict."""
        result = _sanitise({})
        assert result == {}

    def test_sanitise_no_sensitive_keys(self) -> None:
        """Test dict with no sensitive keys is returned as-is."""
        details = {"username": "alice", "email": "alice@example.com", "created_at": "2025-01-01"}
        result = _sanitise(details)

        assert result == details


@pytest.mark.asyncio
class TestAuditLogger:
    """Test the AuditLogger class."""

    async def test_log_inserts_to_database(self, mock_db: MagicMock) -> None:
        """Test log() inserts audit event to database."""
        logger = AuditLogger(mock_db)

        await logger.log(
            event_type="oauth2.token_issued",
            actor_uuid="user-123",
            actor_ip="10.0.0.1",
        )

        mock_db.checkpoint_audit_log.insert.assert_called_once()
        call_kwargs = mock_db.checkpoint_audit_log.insert.call_args[1]

        assert call_kwargs["event_type"] == "oauth2.token_issued"
        assert call_kwargs["actor_uuid"] == "user-123"
        assert call_kwargs["actor_ip"] == "10.0.0.1"
        assert "created_at" in call_kwargs
        assert mock_db.commit.called

    async def test_log_sanitises_details(self, mock_db: MagicMock) -> None:
        """Test log() sanitises sensitive data in details."""
        logger = AuditLogger(mock_db)

        details = {
            "grant_type": "password",
            "password": "secret123",
            "client_id": "my-app",
        }
        await logger.log(
            event_type="oauth2.auth_attempt",
            details=details,
        )

        call_kwargs = mock_db.checkpoint_audit_log.insert.call_args[1]
        stored_details = json.loads(call_kwargs["details_json"])

        assert stored_details["grant_type"] == "password"
        assert stored_details["password"] == "[REDACTED]"
        assert stored_details["client_id"] == "my-app"

    async def test_log_defaults_to_none_details(self, mock_db: MagicMock) -> None:
        """Test log() handles None details."""
        logger = AuditLogger(mock_db)

        await logger.log(
            event_type="user.login",
            actor_uuid="user-123",
            details=None,
        )

        call_kwargs = mock_db.checkpoint_audit_log.insert.call_args[1]
        stored_details = json.loads(call_kwargs["details_json"])

        assert stored_details == {}

    async def test_log_all_fields(self, mock_db: MagicMock) -> None:
        """Test log() with all optional fields provided."""
        logger = AuditLogger(mock_db)

        await logger.log(
            event_type="resource.created",
            actor_uuid="user-123",
            actor_ip="10.0.0.1",
            target_uuid="resource-456",
            target_type="document",
            client_id="my-app",
            scopes="documents:write",
            details={"action": "create"},
        )

        call_kwargs = mock_db.checkpoint_audit_log.insert.call_args[1]

        assert call_kwargs["event_type"] == "resource.created"
        assert call_kwargs["actor_uuid"] == "user-123"
        assert call_kwargs["actor_ip"] == "10.0.0.1"
        assert call_kwargs["target_uuid"] == "resource-456"
        assert call_kwargs["target_type"] == "document"
        assert call_kwargs["client_id"] == "my-app"
        assert call_kwargs["scopes"] == "documents:write"

    async def test_log_handles_db_insert_failure(self, mock_db: MagicMock) -> None:
        """Test log() continues even if DB insert fails."""
        mock_db.checkpoint_audit_log.insert.side_effect = Exception("DB connection lost")
        logger = AuditLogger(mock_db)

        with patch("audit.logger.logger") as mock_logger:
            await logger.log(
                event_type="oauth2.token_issued",
                actor_uuid="user-123",
            )

            mock_logger.error.assert_called_once()
            call_args = mock_logger.error.call_args[0]
            assert "audit_log.db_write_failed" in call_args[0]
            assert "oauth2.token_issued" in call_args

    async def test_log_watcher_disabled(self, mock_db: MagicMock) -> None:
        """Test log() does not fire HTTP request when watcher is disabled."""
        logger = AuditLogger(mock_db, watcher_enabled=False)

        with patch("audit.logger.aiohttp.ClientSession") as mock_session:
            await logger.log(
                event_type="user.login",
                actor_uuid="user-123",
            )

            # Allow any pending tasks to complete
            await asyncio.sleep(0.1)

            # Session should not be created
            mock_session.assert_not_called()

    async def test_log_watcher_enabled_fires_task(self, mock_db: MagicMock) -> None:
        """Test log() creates async task when watcher is enabled."""
        logger = AuditLogger(
            mock_db, watcher_enabled=True, watcher_url="https://watcher.example.com"
        )

        with patch(
            "audit.logger.asyncio.create_task"
        ) as mock_create_task, patch("audit.logger.logger"):
            await logger.log(
                event_type="oauth2.token_issued",
                actor_uuid="user-123",
            )

            # create_task should be called to dispatch watcher forward
            mock_create_task.assert_called_once()

    async def test_log_creates_utc_timestamp(self, mock_db: MagicMock) -> None:
        """Test log() uses UTC timestamp."""
        logger = AuditLogger(mock_db)

        before = datetime.now(tz=timezone.utc).replace(tzinfo=None)
        await logger.log(event_type="test.event")
        after = datetime.now(tz=timezone.utc).replace(tzinfo=None)

        call_kwargs = mock_db.checkpoint_audit_log.insert.call_args[1]
        stored_time = call_kwargs["created_at"]

        assert before <= stored_time <= after


@pytest.mark.asyncio
class TestAuditLoggerWatcherForwarding:
    """Test AuditLogger._forward_to_watcher method."""

    async def test_forward_to_watcher_success(self, mock_db: MagicMock) -> None:
        """Test _forward_to_watcher POSTs event to watcher endpoint."""
        logger = AuditLogger(
            mock_db, watcher_enabled=True, watcher_url="https://watcher.example.com"
        )

        event_time = datetime.now(tz=timezone.utc).replace(tzinfo=None)
        details = {"action": "token_issued"}

        with patch("audit.logger.aiohttp.ClientSession") as mock_session_class:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_session = AsyncMock()
            mock_session.post = AsyncMock()
            mock_session.post.return_value.__aenter__.return_value = mock_response
            mock_session_class.return_value.__aenter__.return_value = mock_session

            await logger._forward_to_watcher(
                "oauth2.token_issued",
                event_time,
                details,
                "user-123",
                "10.0.0.1",
            )

            # Verify POST was called
            mock_session.post.assert_called_once()
            call_args = mock_session.post.call_args

            assert call_args[0][0] == "https://watcher.example.com/api/v1/events"
            payload = call_args[1]["json"]
            assert payload["service"] == "checkpoint-core"
            assert payload["event_type"] == "oauth2.token_issued"
            assert payload["actor_uuid"] == "user-123"
            assert payload["actor_ip"] == "10.0.0.1"
            assert payload["details"] == details

    async def test_forward_to_watcher_url_construction(self, mock_db: MagicMock) -> None:
        """Test _forward_to_watcher constructs URL correctly."""
        logger = AuditLogger(
            mock_db, watcher_enabled=True, watcher_url="https://watcher.example.com/api"
        )

        with patch("audit.logger.aiohttp.ClientSession") as mock_session_class:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_session = AsyncMock()
            mock_session.post = AsyncMock()
            mock_session.post.return_value.__aenter__.return_value = mock_response
            mock_session_class.return_value.__aenter__.return_value = mock_session

            await logger._forward_to_watcher(
                "test.event", datetime.now(tz=timezone.utc).replace(tzinfo=None), {}, None, None
            )

            call_args = mock_session.post.call_args
            assert call_args[0][0] == "https://watcher.example.com/api/api/v1/events"

    async def test_forward_to_watcher_url_strips_trailing_slash(self, mock_db: MagicMock) -> None:
        """Test _forward_to_watcher strips trailing slash from base URL."""
        logger = AuditLogger(
            mock_db, watcher_enabled=True, watcher_url="https://watcher.example.com/"
        )

        with patch("audit.logger.aiohttp.ClientSession") as mock_session_class:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_session = AsyncMock()
            mock_session.post = AsyncMock()
            mock_session.post.return_value.__aenter__.return_value = mock_response
            mock_session_class.return_value.__aenter__.return_value = mock_session

            await logger._forward_to_watcher(
                "test.event", datetime.now(tz=timezone.utc).replace(tzinfo=None), {}, None, None
            )

            call_args = mock_session.post.call_args
            assert call_args[0][0] == "https://watcher.example.com/api/v1/events"

    async def test_forward_to_watcher_http_error(self, mock_db: MagicMock) -> None:
        """Test _forward_to_watcher logs warning on HTTP error."""
        logger = AuditLogger(
            mock_db, watcher_enabled=True, watcher_url="https://watcher.example.com"
        )

        with patch("audit.logger.aiohttp.ClientSession") as mock_session_class, patch(
            "audit.logger.logger"
        ) as mock_logger:
            # aiohttp uses sync context managers around async post, so mock accordingly:
            # session.post(url, ...) returns an async context manager (not a coroutine)
            mock_response = MagicMock()
            mock_response.status = 500

            mock_post_cm = MagicMock()
            mock_post_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.post = MagicMock(return_value=mock_post_cm)

            mock_session_cm = MagicMock()
            mock_session_cm.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session_cm.__aexit__ = AsyncMock(return_value=None)
            mock_session_class.return_value = mock_session_cm

            await logger._forward_to_watcher(
                "test.event", datetime.now(tz=timezone.utc).replace(tzinfo=None), {}, None, None
            )

            mock_logger.warning.assert_called_once()
            call_args = mock_logger.warning.call_args[0]
            assert "audit_log.watcher_error" in call_args[0]
            assert call_args[2] == 500

    async def test_forward_to_watcher_connection_error(self, mock_db: MagicMock) -> None:
        """Test _forward_to_watcher logs warning on connection error."""
        logger = AuditLogger(
            mock_db, watcher_enabled=True, watcher_url="https://watcher.example.com"
        )

        with patch("audit.logger.aiohttp.ClientSession") as mock_session_class, patch(
            "audit.logger.logger"
        ) as mock_logger:
            mock_session_class.return_value.__aenter__.side_effect = Exception("Connection failed")

            await logger._forward_to_watcher(
                "test.event", datetime.now(tz=timezone.utc).replace(tzinfo=None), {}, None, None
            )

            mock_logger.warning.assert_called_once()
            call_args = mock_logger.warning.call_args[0]
            assert "audit_log.watcher_unreachable" in call_args[0]

    async def test_forward_to_watcher_timeout(self, mock_db: MagicMock) -> None:
        """Test _forward_to_watcher timeout handling."""
        logger = AuditLogger(
            mock_db, watcher_enabled=True, watcher_url="https://watcher.example.com"
        )

        with patch("audit.logger.aiohttp.ClientSession") as mock_session_class, patch(
            "audit.logger.logger"
        ) as mock_logger:
            mock_session_class.return_value.__aenter__.side_effect = asyncio.TimeoutError(
                "Request timed out"
            )

            await logger._forward_to_watcher(
                "test.event", datetime.now(tz=timezone.utc).replace(tzinfo=None), {}, None, None
            )

            mock_logger.warning.assert_called_once()
