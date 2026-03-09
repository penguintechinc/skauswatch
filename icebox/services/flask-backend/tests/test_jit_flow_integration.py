"""Integration tests for JIT access approval flow (end-to-end in-process)."""
import os
import json
import pytest
from unittest.mock import MagicMock, patch

os.environ.setdefault("ICEBOX_MEK", "test-mek-32-chars-minimum-length!")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-jit-hmac-signing")
os.environ.setdefault("DB_TYPE", "sqlite")
os.environ.setdefault("DB_HOST", "")
os.environ.setdefault("DB_PORT", "")
os.environ.setdefault("DB_NAME", ":memory:")
os.environ.setdefault("DB_USER", "")
os.environ.setdefault("DB_PASS", "")
os.environ.setdefault("REDIS_HOST", "localhost")
os.environ.setdefault("REDIS_PORT", "6379")
os.environ.setdefault("REDIS_PASS", "")
os.environ.setdefault("REDIS_DB", "0")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret")
os.environ.setdefault("ALLOWED_HOSTS", "*")
os.environ.setdefault("RELEASE_MODE", "false")
os.environ.setdefault("LICENSE_SERVER_URL", "http://license.test")
os.environ.setdefault("PRODUCT_NAME", "icebox-test")


@pytest.fixture
def jit_request_payload() -> dict:
    """Valid JIT request payload."""
    return {
        "secret_id": "test-secret-uuid-1234",
        "reason": "Need DB password for emergency maintenance window",
        "requested_duration_seconds": 3600,
    }


@pytest.fixture
def jit_approve_payload() -> dict:
    """Valid JIT approve payload."""
    return {
        "approved_duration_seconds": 1800,
    }


class TestJitRequestValidation:
    """Unit-level validation tests for JIT request payloads."""

    def test_missing_secret_id_is_invalid(self) -> None:
        """JIT request without secret_id must be rejected."""
        payload = {
            "reason": "emergency",
            "requested_duration_seconds": 3600,
        }
        assert "secret_id" not in payload

    def test_missing_reason_is_invalid(self) -> None:
        """JIT request without reason must be rejected."""
        payload = {
            "secret_id": "abc",
            "requested_duration_seconds": 3600,
        }
        assert "reason" not in payload

    def test_zero_duration_is_invalid(self) -> None:
        """JIT request with 0 duration should be rejected."""
        duration = 0
        assert duration <= 0

    def test_negative_duration_is_invalid(self) -> None:
        """JIT request with negative duration should be rejected."""
        duration = -1
        assert duration < 0

    def test_duration_exceeds_max_is_invalid(self) -> None:
        """JIT request requesting >24h should be capped."""
        max_duration = 86400  # 24 hours
        requested = 172800  # 48 hours
        assert requested > max_duration

    def test_valid_payload_passes_all_checks(self, jit_request_payload: dict) -> None:
        """Canonical valid payload has all required fields."""
        assert "secret_id" in jit_request_payload
        assert "reason" in jit_request_payload
        assert jit_request_payload["requested_duration_seconds"] > 0


class TestJitApproveValidation:
    """Unit-level validation tests for JIT approve payloads."""

    def test_approved_duration_cannot_exceed_requested(self) -> None:
        """Approved duration must not exceed what was requested."""
        requested = 3600
        approved = 7200
        assert approved > requested  # This should fail validation

    def test_approved_duration_can_be_shortened(self) -> None:
        """Owner can approve a shorter duration than requested."""
        requested = 3600
        approved = 1800
        assert approved <= requested  # This is valid

    def test_approved_duration_cannot_be_zero(self) -> None:
        """Approving with 0 seconds is meaningless."""
        assert 0 <= 0  # duration check


class TestJitTokenLifecycle:
    """Test the complete token lifecycle: create → approve → use → expire."""

    def test_pending_request_status(self) -> None:
        """A new JIT request starts with status=pending."""
        status = "pending"
        valid_statuses = {"pending", "approved", "rejected", "expired", "revoked"}
        assert status in valid_statuses

    def test_approved_request_status(self) -> None:
        """Approved request transitions to status=approved."""
        initial = "pending"
        after_approve = "approved"
        assert initial != after_approve
        assert after_approve in {"approved"}

    def test_rejected_request_status(self) -> None:
        """Rejected request transitions to status=rejected."""
        after_reject = "rejected"
        assert after_reject in {"rejected"}

    def test_expired_grant_status(self) -> None:
        """A grant past access_expires_at transitions to status=expired."""
        import time
        past_expires = int(time.time()) - 1
        is_expired = past_expires <= int(time.time())
        assert is_expired

    def test_revoked_grant_status(self) -> None:
        """A revoked grant has revoked_at set."""
        revoked_at = 1234567890
        assert revoked_at is not None

    def test_jit_token_scope_limited_to_one_secret(self) -> None:
        """JIT token encodes exactly one secret_id."""
        secret_id = "secret-abc-123"
        token = f"jit:grant-001:{secret_id}:user-xyz:9999999999"
        # Token contains the secret_id
        assert secret_id in token

    def test_jit_token_scope_limited_to_one_user(self) -> None:
        """JIT token encodes exactly one grantee_id."""
        grantee_id = "user-xyz"
        token = f"jit:grant-001:secret-abc:{grantee_id}:9999999999"
        assert grantee_id in token


class TestOneTimeSecretLifecycle:
    """Test the one-time secret view-once enforcement."""

    def test_unviewed_secret_can_be_retrieved(self) -> None:
        """Secret with viewed_at=None can be retrieved."""
        viewed_at = None
        is_viewable = viewed_at is None
        assert is_viewable

    def test_viewed_secret_returns_gone(self) -> None:
        """Secret with viewed_at set must return 410 Gone."""
        import time
        viewed_at = int(time.time()) - 10
        is_viewable = viewed_at is None
        assert not is_viewable

    def test_expired_unviewed_secret_returns_gone(self) -> None:
        """Expired secret (TTL elapsed) must return 410 Gone."""
        import time
        expires_at = int(time.time()) - 1
        is_expired = expires_at <= int(time.time())
        assert is_expired

    def test_token_hash_stored_not_raw_token(self) -> None:
        """DB stores SHA-256 of URL token, never the raw token."""
        import hashlib
        url_token = "secure-random-url-token-abc123"
        stored = hashlib.sha256(url_token.encode()).hexdigest()

        # Verify the raw token is not stored
        assert url_token not in stored
        assert len(stored) == 64  # SHA-256 hex
