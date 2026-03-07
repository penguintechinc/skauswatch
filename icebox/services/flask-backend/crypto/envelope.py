"""
IceBox Envelope Encryption

Application-layer envelope encryption using AES-256-GCM:
  secret_value → encrypted with per-secret DEK (AES-256-GCM)
  DEK          → wrapped (AES-256 key wrap) with Master Encryption Key (MEK)
  MEK          → sourced from env var ICEBOX_MEK (base64) or cloud KMS

Key rotation re-wraps encrypted_dek rows with a new MEK version.
Secret ciphertext is NOT re-encrypted during rotation — only the DEK wrapper.

Usage:
    enc = EnvelopeEncryption.from_env()
    ciphertext, encrypted_dek, version = enc.encrypt("my-secret")
    plaintext = enc.decrypt(ciphertext, encrypted_dek, version)
"""

from __future__ import annotations

import base64
import os
import struct
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(slots=True)
class MekVersion:
    """A versioned Master Encryption Key."""

    version: int
    key_bytes: bytes  # 32 bytes for AES-256


@dataclass(slots=True)
class EnvelopeEncryption:
    """
    Envelope encryption engine for IceBox secrets.

    Holds one or more MEK versions so that decryption can handle
    secrets encrypted under old MEK versions during rotation.
    """

    mek_versions: Dict[int, MekVersion] = field(default_factory=dict)
    current_version: int = 1

    @classmethod
    def from_env(cls) -> "EnvelopeEncryption":
        """
        Create instance from ICEBOX_MEK environment variable.

        ICEBOX_MEK must be a base64-encoded 32-byte key.
        For rotation, set ICEBOX_MEK_V2 = new key, ICEBOX_MEK_V1 = old key,
        and ICEBOX_MEK_CURRENT_VERSION = 2.
        """
        enc = cls()
        current_version = int(os.getenv("ICEBOX_MEK_CURRENT_VERSION", "1"))
        enc.current_version = current_version

        # Load all versioned MEKs (ICEBOX_MEK_V1, ICEBOX_MEK_V2, ...)
        for v in range(1, current_version + 1):
            mek_b64 = os.getenv(f"ICEBOX_MEK_V{v}") or os.getenv("ICEBOX_MEK")
            if not mek_b64:
                raise ValueError(
                    f"ICEBOX_MEK_V{v} (or ICEBOX_MEK) environment variable not set"
                )
            key_bytes = base64.b64decode(mek_b64)
            if len(key_bytes) != 32:
                raise ValueError(
                    f"ICEBOX_MEK_V{v} must be a base64-encoded 32-byte key"
                )
            enc.mek_versions[v] = MekVersion(version=v, key_bytes=key_bytes)

        return enc

    def _get_mek(self, version: int) -> bytes:
        """Return MEK bytes for the given version."""
        mek = self.mek_versions.get(version)
        if mek is None:
            raise ValueError(f"MEK version {version} not loaded")
        return mek.key_bytes

    def _generate_dek(self) -> bytes:
        """Generate a fresh 32-byte Data Encryption Key."""
        return os.urandom(32)

    def _wrap_dek(self, dek: bytes, mek: bytes) -> bytes:
        """
        Wrap (encrypt) a DEK using AES-256-GCM with the MEK.

        Returns nonce (12 bytes) || ciphertext (32 + 16 bytes tag).
        Total: 60 bytes, base64-encoded for storage.
        """
        nonce = os.urandom(12)
        aesgcm = AESGCM(mek)
        wrapped = aesgcm.encrypt(nonce, dek, None)
        return nonce + wrapped

    def _unwrap_dek(self, wrapped_dek_bytes: bytes, mek: bytes) -> bytes:
        """
        Unwrap (decrypt) a DEK using AES-256-GCM with the MEK.

        Expects nonce (12 bytes) || ciphertext from _wrap_dek.
        """
        nonce = wrapped_dek_bytes[:12]
        wrapped = wrapped_dek_bytes[12:]
        aesgcm = AESGCM(mek)
        return aesgcm.decrypt(nonce, wrapped, None)

    def _encrypt_with_dek(self, plaintext: str, dek: bytes) -> bytes:
        """
        Encrypt plaintext using AES-256-GCM with the DEK.

        Returns nonce (12 bytes) || ciphertext.
        """
        nonce = os.urandom(12)
        aesgcm = AESGCM(dek)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return nonce + ciphertext

    def _decrypt_with_dek(self, ciphertext_bytes: bytes, dek: bytes) -> str:
        """
        Decrypt ciphertext using AES-256-GCM with the DEK.

        Expects nonce (12 bytes) || ciphertext from _encrypt_with_dek.
        """
        nonce = ciphertext_bytes[:12]
        ciphertext = ciphertext_bytes[12:]
        aesgcm = AESGCM(dek)
        return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")

    def encrypt(self, plaintext: str) -> Tuple[str, str, int]:
        """
        Encrypt a secret value using envelope encryption.

        Returns:
            (encrypted_value_b64, encrypted_dek_b64, mek_version)
            All bytes fields are base64-encoded for database storage.
        """
        dek = self._generate_dek()
        mek = self._get_mek(self.current_version)

        ciphertext_bytes = self._encrypt_with_dek(plaintext, dek)
        wrapped_dek_bytes = self._wrap_dek(dek, mek)

        return (
            base64.b64encode(ciphertext_bytes).decode("ascii"),
            base64.b64encode(wrapped_dek_bytes).decode("ascii"),
            self.current_version,
        )

    def decrypt(
        self, encrypted_value_b64: str, encrypted_dek_b64: str, dek_version: int
    ) -> str:
        """
        Decrypt a secret value using envelope encryption.

        Args:
            encrypted_value_b64: base64-encoded ciphertext from encrypt()
            encrypted_dek_b64: base64-encoded wrapped DEK from encrypt()
            dek_version: MEK version used to wrap the DEK

        Returns:
            Decrypted plaintext string.
        """
        mek = self._get_mek(dek_version)

        ciphertext_bytes = base64.b64decode(encrypted_value_b64)
        wrapped_dek_bytes = base64.b64decode(encrypted_dek_b64)

        dek = self._unwrap_dek(wrapped_dek_bytes, mek)
        return self._decrypt_with_dek(ciphertext_bytes, dek)

    def rotate_mek(self, new_version: int, rows: list) -> int:
        """
        Re-wrap all DEKs under the new MEK version.

        Args:
            new_version: The new MEK version to rotate to (must be loaded).
            rows: List of dicts with keys: id, encrypted_dek, dek_version.
                  Modified in place: encrypted_dek and dek_version are updated.

        Returns:
            Number of rows re-wrapped.
        """
        if new_version not in self.mek_versions:
            raise ValueError(f"MEK version {new_version} not loaded — cannot rotate")

        new_mek = self._get_mek(new_version)
        updated = 0

        for row in rows:
            old_version = row["dek_version"]
            if old_version == new_version:
                continue  # Already on new version

            old_mek = self._get_mek(old_version)
            wrapped_bytes = base64.b64decode(row["encrypted_dek"])
            dek = self._unwrap_dek(wrapped_bytes, old_mek)
            new_wrapped = self._wrap_dek(dek, new_mek)

            row["encrypted_dek"] = base64.b64encode(new_wrapped).decode("ascii")
            row["dek_version"] = new_version
            updated += 1

        self.current_version = new_version
        return updated


def generate_mek_b64() -> str:
    """Generate a new random MEK and return it as base64. For key setup only."""
    return base64.b64encode(os.urandom(32)).decode("ascii")
