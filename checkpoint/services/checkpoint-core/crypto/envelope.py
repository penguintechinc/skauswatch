"""
checkpoint-core — Envelope encryption for IDP config and signing key storage.

Encrypts sensitive config dicts (upstream IDP credentials, signing key material)
using AES-256-GCM with the CHECKPOINT_SIGNING_MEK environment variable.

Storage format (base64-encoded):
  1 byte  : version (currently 0x01)
  12 bytes: random nonce
  N bytes : AES-256-GCM ciphertext + 16-byte tag
"""
from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_VERSION = b"\x01"


def _get_mek() -> bytes:
    """Return the 32-byte Master Encryption Key from environment."""
    mek_b64 = os.environ.get("CHECKPOINT_SIGNING_MEK", "")
    if not mek_b64:
        raise RuntimeError("CHECKPOINT_SIGNING_MEK environment variable not set")
    key = base64.b64decode(mek_b64)
    if len(key) != 32:
        raise RuntimeError("CHECKPOINT_SIGNING_MEK must be a 32-byte base64-encoded key")
    return key


def encrypt_config_json(config: dict[str, Any]) -> str:
    """Encrypt a config dict and return a base64-encoded ciphertext string."""
    mek = _get_mek()
    nonce = os.urandom(12)
    plaintext = json.dumps(config, separators=(",", ":")).encode("utf-8")
    aesgcm = AESGCM(mek)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    payload = _VERSION + nonce + ciphertext
    return base64.b64encode(payload).decode("ascii")


def decrypt_config_json(config_json_encrypted: str) -> dict[str, Any]:
    """Decrypt a config_json_encrypted string and return the config dict."""
    mek = _get_mek()
    payload = base64.b64decode(config_json_encrypted)
    # version byte (1) + nonce (12) + ciphertext
    nonce = payload[1:13]
    ciphertext = payload[13:]
    aesgcm = AESGCM(mek)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))
