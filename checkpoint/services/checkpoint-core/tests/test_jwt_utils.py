"""
Tests for oidc/jwt_utils.py — JWT signing, verification, token issuance.

Covers:
  - issue_access_token() — JWT with correct claims, JTI, stored in DB
  - issue_id_token() — OIDC token with nonce, standard claims
  - issue_refresh_token() — opaque token, different on each call
  - verify_token() — valid/expired/revoked/unknown key validation
  - get_active_signing_key() — returns active key or None
  - get_jwks() — returns JWK array with active + grace-period keys
  - generate_signing_keypair() — RSA-2048 and EC P-256 generation
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jose import jwt

from oidc import jwt_utils


def _make_rows_mock(*rows: Any) -> MagicMock:
    """Create a mock PyDAL Rows object supporting iteration AND .first()."""
    m = MagicMock()
    m.__iter__ = MagicMock(side_effect=lambda: iter(rows))
    m.first.return_value = rows[0] if rows else None
    return m


@pytest.fixture
def test_rsa_keypair() -> tuple[str, str]:
    """Generate a test RSA-2048 key pair."""
    public_pem, private_pem = jwt_utils.generate_signing_keypair("RS256")
    return public_pem, private_pem


@pytest.fixture
def test_ec_keypair() -> tuple[str, str]:
    """Generate a test EC P-256 key pair."""
    public_pem, private_pem = jwt_utils.generate_signing_keypair("ES256")
    return public_pem, private_pem


@pytest.fixture
def mek_b64() -> str:
    """Create a valid AES-256 MEK (base64-encoded)."""
    key = secrets.token_bytes(32)
    return base64.b64encode(key).decode()


@pytest.fixture
def mock_db(test_rsa_keypair: tuple[str, str], mek_b64: str) -> MagicMock:
    """Create a mock DB with signing key and token tables."""
    db = MagicMock()
    public_pem, private_pem = test_rsa_keypair

    # Encrypt private key
    encrypted_key = jwt_utils.encrypt_private_key(private_pem.encode(), mek_b64)

    # Mock signing key row
    key_row = MagicMock()
    key_row.id = "key-1"
    key_row.kid = "test-kid-1"
    key_row.algorithm = "RS256"
    key_row.public_key = public_pem
    key_row.private_key_encrypted = encrypted_key
    key_row.created_at = datetime.now(tz=timezone.utc)
    key_row.is_active = True
    key_row.grace_period_until = datetime.now(tz=timezone.utc) - timedelta(hours=1)

    # Mock db(expr).select(...) — the PyDAL call pattern
    # db(expr) → db.return_value; .select() → db.return_value.select.return_value
    # db() accepts any expression (filter) and returns a query set
    rows_mock = _make_rows_mock(key_row)
    db_set = MagicMock()
    db_set.select.return_value = rows_mock
    # Use side_effect to allow db(expr) to work for any expression
    db.side_effect = lambda *args, **kwargs: db_set

    # Mock db.checkpoint_signing_keys and db.checkpoint_tokens as attributes
    # These are used in filter expressions like db.checkpoint_signing_keys.is_active
    mock_signing_keys_table = MagicMock()
    mock_signing_keys_table.is_active = MagicMock()
    mock_signing_keys_table.grace_period_until = MagicMock()
    mock_signing_keys_table.created_at = MagicMock()
    db.checkpoint_signing_keys = mock_signing_keys_table

    # Mock token table insert and checkpoint_tokens table
    mock_tokens_table = MagicMock()
    mock_tokens_table.insert = MagicMock()
    mock_tokens_table.jti = MagicMock()
    mock_tokens_table.revoked_at = MagicMock()
    db.checkpoint_tokens = mock_tokens_table
    db.commit = MagicMock()

    return db


class TestEncryptDecrypt:
    """Test AES-256-GCM encryption/decryption helpers."""

    def test_encrypt_private_key_roundtrip(self, test_rsa_keypair: tuple[str, str], mek_b64: str) -> None:
        """Encrypt and decrypt a private key — should match original."""
        _, private_pem = test_rsa_keypair
        original_bytes = private_pem.encode()

        encrypted = jwt_utils.encrypt_private_key(original_bytes, mek_b64)
        decrypted = jwt_utils.decrypt_private_key(encrypted, mek_b64)

        assert decrypted == original_bytes

    def test_encrypt_generates_unique_nonce(self, test_rsa_keypair: tuple[str, str], mek_b64: str) -> None:
        """Each encryption generates a different nonce."""
        _, private_pem = test_rsa_keypair
        data = private_pem.encode()

        encrypted1 = jwt_utils.encrypt_private_key(data, mek_b64)
        encrypted2 = jwt_utils.encrypt_private_key(data, mek_b64)

        # Different nonces -> different ciphertexts
        assert encrypted1 != encrypted2
        # But both should decrypt to original
        assert jwt_utils.decrypt_private_key(encrypted1, mek_b64) == data
        assert jwt_utils.decrypt_private_key(encrypted2, mek_b64) == data

    def test_decrypt_wrong_mek_fails(self, test_rsa_keypair: tuple[str, str], mek_b64: str) -> None:
        """Decrypt with wrong MEK fails."""
        _, private_pem = test_rsa_keypair
        encrypted = jwt_utils.encrypt_private_key(private_pem.encode(), mek_b64)

        # Generate different MEK
        wrong_mek = base64.b64encode(secrets.token_bytes(32)).decode()

        with pytest.raises(Exception):
            jwt_utils.decrypt_private_key(encrypted, wrong_mek)


class TestGetActiveSigningKey:
    """Test get_active_signing_key() lookup."""

    def test_returns_active_key(self, mock_db: MagicMock, test_rsa_keypair: tuple[str, str], mek_b64: str) -> None:
        """Returns active signing key with expected fields."""
        result = jwt_utils.get_active_signing_key(mock_db)

        assert result is not None
        assert result["kid"] == "test-kid-1"
        assert result["algorithm"] == "RS256"
        assert result["public_key"] == test_rsa_keypair[0]
        assert "private_key_encrypted" in result

    def test_returns_none_when_no_active_key(self, mock_db: MagicMock) -> None:
        """Returns None when no active key exists."""
        # Override the query set to return no rows
        empty_rows_mock = _make_rows_mock()  # Empty rows
        mock_db.side_effect = lambda *args, **kwargs: MagicMock(select=MagicMock(return_value=empty_rows_mock))

        result = jwt_utils.get_active_signing_key(mock_db)
        assert result is None


class TestGetJwks:
    """Test get_jwks() JWKS document generation."""

    def test_returns_jwks_with_active_keys(self, test_rsa_keypair: tuple[str, str]) -> None:
        """get_jwks() returns JWKS with active keys."""
        public_pem = test_rsa_keypair[0]
        key_row = MagicMock()
        key_row.kid = "test-kid-1"
        key_row.algorithm = "RS256"
        key_row.public_key = public_pem
        key_row.is_active = True
        key_row.grace_period_until = datetime.now(tz=timezone.utc) - timedelta(hours=1)

        # Create a fresh mock db for this test
        test_db = MagicMock()
        # Field mocks: grace_period_until needs to support comparison operators
        # Use a real datetime that supports comparison
        test_db.checkpoint_signing_keys.grace_period_until = MagicMock(__gt__=lambda self, other: True)
        test_db.checkpoint_signing_keys.is_active = MagicMock(__eq__=lambda self, other: True)
        test_db.checkpoint_tokens = MagicMock()
        test_db.side_effect = lambda *args, **kwargs: MagicMock(select=MagicMock(return_value=_make_rows_mock(key_row)))

        result = jwt_utils.get_jwks(test_db)

        assert "keys" in result
        assert len(result["keys"]) >= 1
        assert result["keys"][0]["kid"] == "test-kid-1"
        assert result["keys"][0]["kty"] == "RSA"
        assert result["keys"][0]["alg"] == "RS256"
        assert "n" in result["keys"][0]
        assert "e" in result["keys"][0]

    def test_jwks_includes_grace_period_keys(self, test_rsa_keypair: tuple[str, str]) -> None:
        """JWKS includes keys in grace period."""
        public_pem = test_rsa_keypair[0]
        key_row = MagicMock()
        key_row.kid = "grace-key"
        key_row.algorithm = "RS256"
        key_row.public_key = public_pem
        key_row.is_active = False
        key_row.grace_period_until = datetime.now(tz=timezone.utc) + timedelta(hours=1)

        # Create a fresh mock db for this test
        test_db = MagicMock()
        test_db.checkpoint_signing_keys.grace_period_until = MagicMock(__gt__=lambda self, other: True)
        test_db.checkpoint_signing_keys.is_active = MagicMock(__eq__=lambda self, other: False)
        test_db.checkpoint_tokens = MagicMock()
        test_db.side_effect = lambda *args, **kwargs: MagicMock(select=MagicMock(return_value=_make_rows_mock(key_row)))

        result = jwt_utils.get_jwks(test_db)

        assert len(result["keys"]) >= 1
        assert any(k["kid"] == "grace-key" for k in result["keys"])


class TestIssueAccessToken:
    """Test issue_access_token() JWT issuance."""

    def test_returns_jwt_and_jti(self, mock_db: MagicMock, mek_b64: str) -> None:
        """issue_access_token() returns JWT and JTI."""
        token, jti = jwt_utils.issue_access_token(
            mock_db,
            mek_b64,
            issuer="https://checkpoint.example.com",
            user_uuid="user-123",
            client_id="app-1",
            scopes="read write",
        )

        assert isinstance(token, str)
        assert isinstance(jti, str)
        assert len(jti) > 0

    def test_token_has_required_claims(self, mock_db: MagicMock, mek_b64: str, test_rsa_keypair: tuple[str, str]) -> None:
        """Issued token contains required OIDC claims."""
        public_pem = test_rsa_keypair[0]
        token, jti = jwt_utils.issue_access_token(
            mock_db,
            mek_b64,
            issuer="https://checkpoint.example.com",
            user_uuid="user-123",
            client_id="app-1",
            scopes="read write",
            ttl=3600,
        )

        claims = jwt.decode(
            token,
            public_pem,
            algorithms=["RS256"],
            options={"verify_exp": False, "verify_aud": False},
        )

        assert claims["iss"] == "https://checkpoint.example.com"
        assert claims["sub"] == "user-123"
        assert claims["aud"] == "app-1"
        assert claims["scope"] == "read write"
        assert claims["jti"] == jti
        assert claims["client_id"] == "app-1"
        assert "iat" in claims
        assert "exp" in claims

    def test_token_includes_extra_claims(self, mock_db: MagicMock, mek_b64: str, test_rsa_keypair: tuple[str, str]) -> None:
        """Extra claims are included in token."""
        public_pem = test_rsa_keypair[0]
        extra_claims = {"custom_claim": "custom_value", "another": 42}

        token, _ = jwt_utils.issue_access_token(
            mock_db,
            mek_b64,
            issuer="https://checkpoint.example.com",
            user_uuid="user-123",
            client_id="app-1",
            scopes="read",
            extra_claims=extra_claims,
        )

        claims = jwt.decode(
            token,
            public_pem,
            algorithms=["RS256"],
            options={"verify_exp": False, "verify_aud": False},
        )

        assert claims["custom_claim"] == "custom_value"
        assert claims["another"] == 42

    def test_stores_token_in_db(self, mock_db: MagicMock, mek_b64: str) -> None:
        """Token is stored in checkpoint_tokens table."""
        token, jti = jwt_utils.issue_access_token(
            mock_db,
            mek_b64,
            issuer="https://checkpoint.example.com",
            user_uuid="user-123",
            client_id="app-1",
            scopes="read",
        )

        mock_db.checkpoint_tokens.insert.assert_called_once()
        call_kwargs = mock_db.checkpoint_tokens.insert.call_args[1]

        assert call_kwargs["jti"] == jti
        assert call_kwargs["user_uuid"] == "user-123"
        assert call_kwargs["client_id"] == "app-1"
        assert call_kwargs["scopes"] == "read"
        assert call_kwargs["token_type"] == "access"
        assert call_kwargs["token_hash"] == hashlib.sha256(token.encode()).hexdigest()

    def test_raises_when_no_active_key(self, mock_db: MagicMock, mek_b64: str) -> None:
        """Raises RuntimeError when no active signing key."""
        # Override query to return no rows
        mock_db.side_effect = lambda *args, **kwargs: MagicMock(select=MagicMock(return_value=_make_rows_mock()))

        with pytest.raises(RuntimeError, match="No active signing key"):
            jwt_utils.issue_access_token(
                mock_db,
                mek_b64,
                issuer="https://checkpoint.example.com",
                user_uuid="user-123",
                client_id="app-1",
                scopes="read",
            )


class TestIssueIdToken:
    """Test issue_id_token() OIDC id_token issuance."""

    def test_returns_id_token(self, mock_db: MagicMock, mek_b64: str) -> None:
        """issue_id_token() returns a JWT id_token."""
        user_record = {
            "uuid": "user-123",
            "email": "alice@example.com",
            "display_name": "Alice Smith",
        }

        token = jwt_utils.issue_id_token(
            mock_db,
            mek_b64,
            issuer="https://checkpoint.example.com",
            user_uuid="user-123",
            client_id="app-1",
            nonce="nonce-abc",
            user_record=user_record,
        )

        assert isinstance(token, str)

    def test_id_token_has_oidc_claims(self, mock_db: MagicMock, mek_b64: str, test_rsa_keypair: tuple[str, str]) -> None:
        """id_token includes OIDC standard claims."""
        public_pem = test_rsa_keypair[0]
        user_record = {
            "uuid": "user-123",
            "email": "alice@example.com",
            "display_name": "Alice Smith",
            "username": "alice",
        }

        token = jwt_utils.issue_id_token(
            mock_db,
            mek_b64,
            issuer="https://checkpoint.example.com",
            user_uuid="user-123",
            client_id="app-1",
            nonce="nonce-abc",
            user_record=user_record,
        )

        claims = jwt.decode(
            token,
            public_pem,
            algorithms=["RS256"],
            options={"verify_exp": False, "verify_aud": False},
        )

        assert claims["sub"] == "user-123"
        assert claims["iss"] == "https://checkpoint.example.com"
        assert claims["aud"] == "app-1"
        assert claims["email"] == "alice@example.com"
        assert claims["name"] == "Alice Smith"
        assert claims["preferred_username"] == "alice"
        assert claims["nonce"] == "nonce-abc"

    def test_id_token_without_nonce(self, mock_db: MagicMock, mek_b64: str, test_rsa_keypair: tuple[str, str]) -> None:
        """id_token without nonce omits nonce claim."""
        public_pem = test_rsa_keypair[0]
        user_record = {"uuid": "user-123", "email": "alice@example.com"}

        token = jwt_utils.issue_id_token(
            mock_db,
            mek_b64,
            issuer="https://checkpoint.example.com",
            user_uuid="user-123",
            client_id="app-1",
            nonce=None,
            user_record=user_record,
        )

        claims = jwt.decode(
            token,
            public_pem,
            algorithms=["RS256"],
            options={"verify_exp": False, "verify_aud": False},
        )

        assert "nonce" not in claims


class TestIssueRefreshToken:
    """Test issue_refresh_token() opaque refresh token issuance."""

    def test_returns_opaque_token(self, mock_db: MagicMock) -> None:
        """issue_refresh_token() returns an opaque string."""
        token = jwt_utils.issue_refresh_token(
            mock_db,
            user_uuid="user-123",
            client_id="app-1",
            scopes="read",
        )

        assert isinstance(token, str)
        assert len(token) > 0
        # Not a JWT
        assert token.count(".") != 2

    def test_generates_unique_tokens(self, mock_db: MagicMock) -> None:
        """Each refresh token is unique."""
        token1 = jwt_utils.issue_refresh_token(
            mock_db,
            user_uuid="user-123",
            client_id="app-1",
            scopes="read",
        )
        token2 = jwt_utils.issue_refresh_token(
            mock_db,
            user_uuid="user-123",
            client_id="app-1",
            scopes="read",
        )

        assert token1 != token2

    def test_stores_hash_in_db(self, mock_db: MagicMock) -> None:
        """Refresh token hash stored in DB, not plaintext."""
        token = jwt_utils.issue_refresh_token(
            mock_db,
            user_uuid="user-123",
            client_id="app-1",
            scopes="read",
        )

        mock_db.checkpoint_tokens.insert.assert_called_once()
        call_kwargs = mock_db.checkpoint_tokens.insert.call_args[1]

        assert call_kwargs["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
        assert call_kwargs["token_type"] == "refresh"


class TestVerifyToken:
    """Test verify_token() token verification."""

    def test_verifies_valid_token(self, mock_db: MagicMock, mek_b64: str, test_rsa_keypair: tuple[str, str]) -> None:
        """Valid token verifies successfully."""
        public_pem, private_pem = test_rsa_keypair

        # Create a properly configured signing key row for token issuance
        key_row = MagicMock()
        key_row.id = "key-1"
        key_row.kid = "test-kid-1"
        key_row.algorithm = "RS256"
        key_row.public_key = public_pem
        key_row.private_key_encrypted = jwt_utils.encrypt_private_key(private_pem.encode(), mek_b64)
        key_row.created_at = datetime.now(tz=timezone.utc)
        key_row.is_active = True
        key_row.grace_period_until = datetime.now(tz=timezone.utc) - timedelta(hours=1)

        rows_with_key = _make_rows_mock(key_row)
        rows_no_revocation = _make_rows_mock()  # Empty for revocation check

        call_count = [0]

        def side_effect_fn(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 3:
                return MagicMock(select=MagicMock(return_value=rows_no_revocation))
            return MagicMock(select=MagicMock(return_value=rows_with_key))

        mock_db.side_effect = side_effect_fn

        # Issue token
        token, jti = jwt_utils.issue_access_token(
            mock_db,
            mek_b64,
            issuer="https://checkpoint.example.com",
            user_uuid="user-123",
            client_id="app-1",
            scopes="read",
        )

        # Create a fresh mock for verify with proper field mocks
        verify_mock_db = MagicMock()
        verify_mock_db.checkpoint_signing_keys.grace_period_until = MagicMock(__gt__=lambda self, other: True)
        verify_mock_db.checkpoint_signing_keys.is_active = MagicMock(__eq__=lambda self, other: True)
        verify_mock_db.checkpoint_tokens = MagicMock()

        verify_call_count = [0]

        def verify_side_effect(*args, **kwargs):
            verify_call_count[0] += 1
            if verify_call_count[0] == 2:
                return MagicMock(select=MagicMock(return_value=rows_no_revocation))
            return MagicMock(select=MagicMock(return_value=rows_with_key))

        verify_mock_db.side_effect = verify_side_effect

        # Verify
        claims = jwt_utils.verify_token(
            verify_mock_db,
            issuer="https://checkpoint.example.com",
            token=token,
        )

        assert claims["sub"] == "user-123"
        assert claims["jti"] == jti

    def test_rejects_revoked_token(self, mock_db: MagicMock, mek_b64: str, test_rsa_keypair: tuple[str, str]) -> None:
        """Revoked token raises JWTError."""
        public_pem, private_pem = test_rsa_keypair

        # Create signing key row
        key_row = MagicMock()
        key_row.id = "key-1"
        key_row.kid = "test-kid-1"
        key_row.algorithm = "RS256"
        key_row.public_key = public_pem
        key_row.private_key_encrypted = jwt_utils.encrypt_private_key(private_pem.encode(), mek_b64)
        key_row.created_at = datetime.now(tz=timezone.utc)
        key_row.is_active = True
        key_row.grace_period_until = datetime.now(tz=timezone.utc) - timedelta(hours=1)

        rows_with_key = _make_rows_mock(key_row)

        # For issue_access_token
        initial_calls = [0]

        def issue_side_effect(*args, **kwargs):
            initial_calls[0] += 1
            return MagicMock(select=MagicMock(return_value=rows_with_key))

        mock_db.side_effect = issue_side_effect

        # Issue token
        token, jti = jwt_utils.issue_access_token(
            mock_db,
            mek_b64,
            issuer="https://checkpoint.example.com",
            user_uuid="user-123",
            client_id="app-1",
            scopes="read",
        )

        # Setup DB for verify: first query gets keys, second query gets revoked_row
        revoked_row = MagicMock()
        revoked_row.revoked_at = datetime.now(tz=timezone.utc)

        verify_calls = [0]

        def verify_side_effect(*args, **kwargs):
            verify_calls[0] += 1
            # First call: fetch keys for verification
            if verify_calls[0] == 1:
                return MagicMock(select=MagicMock(return_value=rows_with_key))
            # Second call: check revocation (returns the revoked row)
            return MagicMock(select=MagicMock(return_value=_make_rows_mock(revoked_row)))

        mock_db.side_effect = verify_side_effect

        with pytest.raises(Exception):
            jwt_utils.verify_token(
                mock_db,
                issuer="https://checkpoint.example.com",
                token=token,
            )

    def test_rejects_tampered_token(self, mock_db: MagicMock, mek_b64: str, test_rsa_keypair: tuple[str, str]) -> None:
        """Tampered token raises JWTError."""
        public_pem, private_pem = test_rsa_keypair

        # Create signing key row
        key_row = MagicMock()
        key_row.id = "key-1"
        key_row.kid = "test-kid-1"
        key_row.algorithm = "RS256"
        key_row.public_key = public_pem
        key_row.private_key_encrypted = jwt_utils.encrypt_private_key(private_pem.encode(), mek_b64)
        key_row.created_at = datetime.now(tz=timezone.utc)
        key_row.is_active = True
        key_row.grace_period_until = datetime.now(tz=timezone.utc) - timedelta(hours=1)

        rows_with_key = _make_rows_mock(key_row)

        # For issue_access_token
        initial_calls = [0]

        def issue_side_effect(*args, **kwargs):
            initial_calls[0] += 1
            return MagicMock(select=MagicMock(return_value=rows_with_key))

        mock_db.side_effect = issue_side_effect

        # Issue a token
        token, _ = jwt_utils.issue_access_token(
            mock_db,
            mek_b64,
            issuer="https://checkpoint.example.com",
            user_uuid="user-123",
            client_id="app-1",
            scopes="read",
        )

        # Tamper with signature
        parts = token.split(".")
        tampered = parts[0] + "." + parts[1] + ".invalid_signature"

        # Setup DB for verification - return the key for verification
        mock_db.side_effect = lambda *args, **kwargs: MagicMock(select=MagicMock(return_value=rows_with_key))

        with pytest.raises(Exception):
            jwt_utils.verify_token(
                mock_db,
                issuer="https://checkpoint.example.com",
                token=tampered,
            )


class TestGenerateSigningKeypair:
    """Test generate_signing_keypair() key generation."""

    def test_generates_rsa_keypair(self) -> None:
        """Generates RSA-2048 public/private key pair."""
        public_pem, private_pem = jwt_utils.generate_signing_keypair("RS256")

        assert isinstance(public_pem, str)
        assert isinstance(private_pem, str)
        assert "BEGIN PUBLIC KEY" in public_pem
        assert "BEGIN RSA PRIVATE KEY" in private_pem or "BEGIN PRIVATE KEY" in private_pem

    def test_generates_ec_keypair(self) -> None:
        """Generates EC P-256 public/private key pair."""
        public_pem, private_pem = jwt_utils.generate_signing_keypair("ES256")

        assert isinstance(public_pem, str)
        assert isinstance(private_pem, str)
        assert "BEGIN PUBLIC KEY" in public_pem
        assert "BEGIN EC PRIVATE KEY" in private_pem or "BEGIN PRIVATE KEY" in private_pem

    def test_generated_rsa_key_can_sign(self) -> None:
        """Generated RSA key can sign and verify JWTs."""
        public_pem, private_pem = jwt_utils.generate_signing_keypair("RS256")

        claims = {"sub": "user-1", "aud": "app-1"}
        token = jwt.encode(claims, private_pem, algorithm="RS256")
        decoded = jwt.decode(token, public_pem, algorithms=["RS256"], audience="app-1")

        assert decoded["sub"] == "user-1"

    def test_generated_ec_key_can_sign(self) -> None:
        """Generated EC key can sign and verify JWTs."""
        public_pem, private_pem = jwt_utils.generate_signing_keypair("ES256")

        claims = {"sub": "user-1", "aud": "app-1"}
        token = jwt.encode(claims, private_pem, algorithm="ES256")
        decoded = jwt.decode(token, public_pem, algorithms=["ES256"], audience="app-1")

        assert decoded["sub"] == "user-1"


class TestPemToJwk:
    """Test _pem_to_jwk() PEM to JWK conversion."""

    def test_converts_rsa_pem_to_jwk(self, test_rsa_keypair: tuple[str, str]) -> None:
        """Converts RSA PEM to JWK."""
        public_pem = test_rsa_keypair[0]
        jwk = jwt_utils._pem_to_jwk(public_pem, "test-kid", "RS256")

        assert jwk is not None
        assert jwk["kty"] == "RSA"
        assert jwk["alg"] == "RS256"
        assert jwk["kid"] == "test-kid"
        assert "n" in jwk
        assert "e" in jwk

    def test_converts_ec_pem_to_jwk(self, test_ec_keypair: tuple[str, str]) -> None:
        """Converts EC PEM to JWK."""
        public_pem = test_ec_keypair[0]
        jwk = jwt_utils._pem_to_jwk(public_pem, "test-kid", "ES256")

        assert jwk is not None
        assert jwk["kty"] == "EC"
        assert jwk["alg"] == "ES256"
        assert jwk["crv"] == "P-256"
        assert "x" in jwk
        assert "y" in jwk

    def test_rejects_invalid_pem(self) -> None:
        """Returns None for invalid PEM."""
        invalid_pem = "not a valid pem"
        jwk = jwt_utils._pem_to_jwk(invalid_pem, "test-kid", "RS256")

        assert jwk is None
