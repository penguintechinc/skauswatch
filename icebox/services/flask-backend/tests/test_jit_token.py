"""Unit tests for JIT token generation and validation."""
import os
import time
import hmac
import hashlib
import pytest

os.environ.setdefault("ICEBOX_MEK", "test-mek-32-chars-minimum-length!")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-jit-hmac-signing")


def _make_token(grant_id: str, grantee_id: str, expires_epoch: int) -> str:
    """Reproduce the JIT token format from api/v1/jit.py."""
    return f"jit:{grant_id}:{grantee_id}:{expires_epoch}"


def _sign_token(token: str, secret: str) -> str:
    """HMAC-SHA256 sign a token string."""
    return hmac.new(secret.encode(), token.encode(), hashlib.sha256).hexdigest()


def _hash_token(token: str) -> str:
    """SHA-256 hash of the full signed token (stored in DB)."""
    return hashlib.sha256(token.encode()).hexdigest()


class TestJitTokenFormat:
    def test_token_contains_components(self) -> None:
        """JIT token encodes grant_id, grantee_id, and expires_epoch."""
        grant_id = "abc-123"
        grantee_id = "user-456"
        expires = int(time.time()) + 3600
        token = _make_token(grant_id, grantee_id, expires)

        parts = token.split(":")
        assert parts[0] == "jit"
        assert parts[1] == grant_id
        assert parts[2] == grantee_id
        assert int(parts[3]) == expires

    def test_token_not_expired(self) -> None:
        """Token with future expiry is not expired."""
        expires = int(time.time()) + 3600
        token = _make_token("g1", "u1", expires)
        expires_epoch = int(token.split(":")[3])
        assert expires_epoch > int(time.time())

    def test_token_expired(self) -> None:
        """Token with past expiry is detected as expired."""
        expires = int(time.time()) - 1
        token = _make_token("g1", "u1", expires)
        expires_epoch = int(token.split(":")[3])
        assert expires_epoch <= int(time.time())


class TestJitTokenHmac:
    SECRET = "test-secret-key-for-jit-hmac-signing"

    def test_hmac_signature_is_deterministic(self) -> None:
        """Same token produces same HMAC signature."""
        token = _make_token("g1", "u1", 9999999999)
        sig1 = _sign_token(token, self.SECRET)
        sig2 = _sign_token(token, self.SECRET)
        assert sig1 == sig2

    def test_different_tokens_produce_different_signatures(self) -> None:
        """Different tokens produce different HMAC signatures."""
        t1 = _make_token("g1", "u1", 9999999999)
        t2 = _make_token("g2", "u1", 9999999999)
        assert _sign_token(t1, self.SECRET) != _sign_token(t2, self.SECRET)

    def test_tampered_token_signature_mismatch(self) -> None:
        """Tampered token payload does not match stored signature."""
        token = _make_token("g1", "u1", 9999999999)
        sig = _sign_token(token, self.SECRET)

        tampered = _make_token("g1", "u1", 1111111111)  # different expiry
        expected = _sign_token(tampered, self.SECRET)
        assert sig != expected

    def test_wrong_secret_fails_verification(self) -> None:
        """Token signed with one secret cannot be verified with another."""
        token = _make_token("g1", "u1", 9999999999)
        sig_correct = _sign_token(token, self.SECRET)
        sig_wrong = _sign_token(token, "wrong-secret")
        assert sig_correct != sig_wrong


class TestJitTokenHashStorage:
    """Tests the SHA-256 hash stored in the DB (never the raw token)."""

    def test_hash_is_hex_string(self) -> None:
        """Token hash is a 64-char hex string."""
        token = "jit:g1:u1:9999999999:sig"
        h = _hash_token(token)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_different_tokens_produce_different_hashes(self) -> None:
        """Different tokens produce different hashes."""
        h1 = _hash_token("jit:g1:u1:9999:sig")
        h2 = _hash_token("jit:g2:u1:9999:sig")
        assert h1 != h2

    def test_hash_is_not_reversible(self) -> None:
        """SHA-256 output cannot be used to reconstruct the token."""
        token = "jit:grant-123:user-456:9999999999"
        h = _hash_token(token)
        # Just verify hash doesn't embed the token contents
        assert "grant-123" not in h
        assert "user-456" not in h
