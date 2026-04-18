"""Tests for crypto envelope encryption/decryption functions."""
from __future__ import annotations

import base64
import json
import os
from unittest.mock import patch

import pytest

from crypto.envelope import (
    _get_mek,
    decrypt_config_json,
    encrypt_config_json,
)


class TestGetMek:
    """Test _get_mek function."""

    def test_get_mek_valid(self) -> None:
        """Test _get_mek returns 32 bytes when env var is set correctly."""
        # CHECKPOINT_SIGNING_MEK is already set in conftest.py
        mek = _get_mek()
        assert isinstance(mek, bytes)
        assert len(mek) == 32

    def test_get_mek_missing_env_var(self) -> None:
        """Test _get_mek raises RuntimeError when env var is not set."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(RuntimeError, match="CHECKPOINT_SIGNING_MEK environment variable not set"):
                _get_mek()

    def test_get_mek_wrong_length(self) -> None:
        """Test _get_mek raises RuntimeError when decoded key is not 32 bytes."""
        # Set a base64-encoded string that decodes to wrong length
        short_key = base64.b64encode(b"short").decode("ascii")
        with patch.dict(os.environ, {"CHECKPOINT_SIGNING_MEK": short_key}):
            with pytest.raises(RuntimeError, match="must be a 32-byte base64-encoded key"):
                _get_mek()


class TestEncryptConfigJson:
    """Test encrypt_config_json function."""

    def test_encrypt_config_json_roundtrip(self) -> None:
        """Test encrypt/decrypt roundtrip with simple config."""
        config = {"username": "testuser", "password": "secret123", "host": "localhost"}
        encrypted = encrypt_config_json(config)

        # Verify it's a valid base64 string
        assert isinstance(encrypted, str)
        payload = base64.b64decode(encrypted)
        assert len(payload) > 13  # version (1) + nonce (12) + ciphertext

        # Decrypt and verify
        decrypted = decrypt_config_json(encrypted)
        assert decrypted == config

    def test_encrypt_config_json_different_ciphertexts(self) -> None:
        """Test that encrypting same config twice produces different ciphertexts."""
        config = {"key": "value", "number": 42}

        encrypted1 = encrypt_config_json(config)
        encrypted2 = encrypt_config_json(config)

        # Both should be valid base64
        assert isinstance(encrypted1, str)
        assert isinstance(encrypted2, str)

        # But they should be different (due to random nonce)
        assert encrypted1 != encrypted2

        # Both should decrypt to the same value
        assert decrypt_config_json(encrypted1) == config
        assert decrypt_config_json(encrypted2) == config

    def test_encrypt_config_json_complex_structure(self) -> None:
        """Test encryption with nested dicts and lists."""
        config = {
            "database": {
                "host": "db.example.com",
                "port": 5432,
                "credentials": {"user": "admin", "pass": "secret"},
            },
            "servers": ["server1", "server2", "server3"],
            "enabled": True,
            "count": 0,
        }
        encrypted = encrypt_config_json(config)
        decrypted = decrypt_config_json(encrypted)
        assert decrypted == config


class TestDecryptConfigJson:
    """Test decrypt_config_json function."""

    def test_decrypt_config_json_valid(self) -> None:
        """Test decryption of valid ciphertext."""
        config = {"api_key": "sk-1234567890abcdef", "endpoint": "https://api.example.com"}
        encrypted = encrypt_config_json(config)
        decrypted = decrypt_config_json(encrypted)
        assert decrypted == config

    def test_decrypt_config_json_tampered_ciphertext(self) -> None:
        """Test that decryption fails with tampered ciphertext."""
        config = {"secret": "value"}
        encrypted = encrypt_config_json(config)

        # Tamper with the encrypted payload
        payload = base64.b64decode(encrypted)
        # Flip some bits in the ciphertext portion (after version + nonce)
        tampered = payload[:15] + bytes([payload[15] ^ 0xFF]) + payload[16:]
        tampered_encrypted = base64.b64encode(tampered).decode("ascii")

        # Decryption should raise an exception
        with pytest.raises(Exception):  # cryptography raises InvalidTag
            decrypt_config_json(tampered_encrypted)

    def test_decrypt_config_json_empty_dict(self) -> None:
        """Test encryption/decryption of empty dict."""
        config = {}
        encrypted = encrypt_config_json(config)
        decrypted = decrypt_config_json(encrypted)
        assert decrypted == config

    def test_decrypt_config_json_unicode_values(self) -> None:
        """Test encryption/decryption with Unicode characters."""
        config = {
            "name": "José",
            "city": "São Paulo",
            "emoji": "🔐",
            "chinese": "加密",
        }
        encrypted = encrypt_config_json(config)
        decrypted = decrypt_config_json(encrypted)
        assert decrypted == config
