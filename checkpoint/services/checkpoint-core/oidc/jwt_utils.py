"""
checkpoint-core — JWT / JWK utilities.

Handles signing and verification of OIDC/OAuth2 tokens using keys stored
in checkpoint_signing_keys.  Private keys are encrypted at rest with the
signing MEK (AES-256-GCM).
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import struct
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jose import JWTError, jwt
from penguin_dal import DB

logger = logging.getLogger(__name__)


# ── Key encryption helpers (AES-256-GCM) ─────────────────────────────────────


def _get_mek_bytes(mek_b64: str) -> bytes:
    """Decode the base64-encoded MEK to raw bytes."""
    return base64.b64decode(mek_b64)


def encrypt_private_key(pem: bytes, mek_b64: str) -> str:
    """
    Encrypt a PEM private key with AES-256-GCM using the signing MEK.

    Returns a base64url-encoded ciphertext string:
      <nonce_b64>.<ciphertext_b64>
    """
    mek = _get_mek_bytes(mek_b64)
    nonce = os.urandom(12)
    aesgcm = AESGCM(mek)
    ciphertext = aesgcm.encrypt(nonce, pem, None)
    nonce_b64 = base64.b64encode(nonce).decode()
    ct_b64 = base64.b64encode(ciphertext).decode()
    return f"{nonce_b64}.{ct_b64}"


def decrypt_private_key(encrypted: str, mek_b64: str) -> bytes:
    """Decrypt an AES-256-GCM encrypted private key blob and return raw PEM bytes."""
    mek = _get_mek_bytes(mek_b64)
    nonce_b64, ct_b64 = encrypted.split(".", 1)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ct_b64)
    aesgcm = AESGCM(mek)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ── Active signing key lookup ─────────────────────────────────────────────────


def get_active_signing_key(db: DB) -> dict[str, Any] | None:
    """
    Return the active signing key row from checkpoint_signing_keys.

    Returns None if no active key exists (service needs key rotation).
    """
    row = db(
        (db.checkpoint_signing_keys.is_active == True)  # noqa: E712
    ).select(orderby=~db.checkpoint_signing_keys.created_at).first()

    if row is None:
        logger.error("signing_key.no_active_key")
        return None

    return {
        "id": row.id,
        "kid": row.kid,
        "algorithm": row.algorithm,
        "public_key": row.public_key,
        "private_key_encrypted": row.private_key_encrypted,
    }


def get_jwks(db: DB) -> dict[str, list[dict[str, Any]]]:
    """
    Build a JWKS document from all active and grace-period signing keys.

    Only public key material is included — never private keys.
    """
    now = datetime.now(tz=timezone.utc).replace(tzinfo=None)
    rows = db(
        (db.checkpoint_signing_keys.is_active == True)  # noqa: E712
        | (db.checkpoint_signing_keys.grace_period_until > now)
    ).select()

    keys = []
    for row in rows:
        jwk = _pem_to_jwk(row.public_key, row.kid, row.algorithm)
        if jwk:
            keys.append(jwk)

    return {"keys": keys}


def _pem_to_jwk(public_pem: str, kid: str, algorithm: str) -> dict[str, Any] | None:
    """Convert a PEM public key to a JWK dict (RSA or EC)."""
    try:
        pub_key = serialization.load_pem_public_key(
            public_pem.encode(), backend=default_backend()
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("jwk.pem_parse_error kid=%s error=%r", kid, exc)
        return None

    if algorithm.startswith("RS"):
        pub_numbers = pub_key.public_key().public_numbers() if hasattr(pub_key, "public_key") else pub_key.public_numbers()  # type: ignore[attr-defined]
        n = pub_numbers.n
        e = pub_numbers.e
        n_b64 = base64.urlsafe_b64encode(
            n.to_bytes((n.bit_length() + 7) // 8, "big")
        ).decode().rstrip("=")
        e_b64 = base64.urlsafe_b64encode(
            e.to_bytes((e.bit_length() + 7) // 8, "big")
        ).decode().rstrip("=")
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": algorithm,
            "kid": kid,
            "n": n_b64,
            "e": e_b64,
        }
    elif algorithm.startswith("ES"):
        pub_numbers = pub_key.public_key().public_numbers() if hasattr(pub_key, "public_key") else pub_key.public_numbers()  # type: ignore[attr-defined]
        x = pub_numbers.x
        y = pub_numbers.y
        x_b64 = base64.urlsafe_b64encode(
            x.to_bytes(32, "big")
        ).decode().rstrip("=")
        y_b64 = base64.urlsafe_b64encode(
            y.to_bytes(32, "big")
        ).decode().rstrip("=")
        return {
            "kty": "EC",
            "use": "sig",
            "alg": algorithm,
            "kid": kid,
            "crv": "P-256",
            "x": x_b64,
            "y": y_b64,
        }
    else:
        logger.warning("jwk.unsupported_algorithm kid=%s alg=%s", kid, algorithm)
        return None


# ── Token issuance ────────────────────────────────────────────────────────────


def issue_access_token(
    db: DB,
    mek_b64: str,
    issuer: str,
    user_uuid: str | None,
    client_id: str,
    scopes: str,
    ttl: int = 3600,
    extra_claims: dict[str, Any] | None = None,
) -> tuple[str, str]:
    """
    Issue a signed JWT access token.

    Returns (raw_jwt, jti).
    Stores the token record in checkpoint_tokens.
    Raises RuntimeError if no active signing key is available.
    """
    key_row = get_active_signing_key(db)
    if key_row is None:
        raise RuntimeError("No active signing key — cannot issue tokens")

    private_pem = decrypt_private_key(key_row["private_key_encrypted"], mek_b64)

    now = datetime.now(tz=timezone.utc)
    jti = secrets.token_urlsafe(32)
    claims: dict[str, Any] = {
        "iss": issuer,
        "aud": client_id,
        "sub": user_uuid or client_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl)).timestamp()),
        "jti": jti,
        "scope": scopes,
        "client_id": client_id,
    }
    if user_uuid:
        claims["sub"] = user_uuid
    if extra_claims:
        claims.update(extra_claims)

    token = jwt.encode(
        claims,
        private_pem.decode(),
        algorithm=key_row["algorithm"],
        headers={"kid": key_row["kid"]},
    )

    # Persist token record
    db.checkpoint_tokens.insert(
        jti=jti,
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        user_uuid=user_uuid,
        client_id=client_id,
        scopes=scopes,
        token_type="access",
        expires_at=now.replace(tzinfo=None) + timedelta(seconds=ttl),
        issued_at=now.replace(tzinfo=None),
    )
    db.commit()

    return token, jti


def issue_id_token(
    db: DB,
    mek_b64: str,
    issuer: str,
    user_uuid: str,
    client_id: str,
    nonce: str | None,
    user_record: dict[str, Any],
    ttl: int = 3600,
) -> str:
    """
    Issue an OIDC id_token JWT.

    Includes standard OIDC claims (sub, name, email, etc.).
    """
    key_row = get_active_signing_key(db)
    if key_row is None:
        raise RuntimeError("No active signing key — cannot issue id_token")

    private_pem = decrypt_private_key(key_row["private_key_encrypted"], mek_b64)

    now = datetime.now(tz=timezone.utc)
    jti = secrets.token_urlsafe(32)

    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": user_uuid,
        "aud": client_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl)).timestamp()),
        "jti": jti,
        "email": user_record.get("email", ""),
        "name": user_record.get("display_name", ""),
        "preferred_username": user_record.get("username", ""),
    }
    if nonce:
        claims["nonce"] = nonce

    token = jwt.encode(
        claims,
        private_pem.decode(),
        algorithm=key_row["algorithm"],
        headers={"kid": key_row["kid"]},
    )

    db.checkpoint_tokens.insert(
        jti=jti,
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        user_uuid=user_uuid,
        client_id=client_id,
        scopes="openid",
        token_type="id",
        expires_at=now.replace(tzinfo=None) + timedelta(seconds=ttl),
        issued_at=now.replace(tzinfo=None),
    )
    db.commit()

    return token


def issue_refresh_token(
    db: DB,
    user_uuid: str | None,
    client_id: str,
    scopes: str,
    ttl: int = 86400,
) -> str:
    """
    Issue an opaque refresh token (random bytes, stored as SHA-256 hash).

    Returns the raw token value (only time it is visible in plaintext).
    """
    raw = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    jti = secrets.token_urlsafe(32)

    now = datetime.now(tz=timezone.utc)

    db.checkpoint_tokens.insert(
        jti=jti,
        token_hash=token_hash,
        user_uuid=user_uuid,
        client_id=client_id,
        scopes=scopes,
        token_type="refresh",
        expires_at=now.replace(tzinfo=None) + timedelta(seconds=ttl),
        issued_at=now.replace(tzinfo=None),
    )
    db.commit()

    return raw


def verify_token(db: DB, issuer: str, token: str) -> dict[str, Any]:
    """
    Verify a JWT access token.

    Validates:
    - Signature against all active + grace-period public keys
    - Expiry
    - Not revoked (checked in checkpoint_tokens)

    Returns the decoded claims dict.
    Raises JWTError if validation fails.
    """
    now = datetime.now(tz=timezone.utc).replace(tzinfo=None)

    # Fetch all active and grace-period public keys
    rows = db(
        (db.checkpoint_signing_keys.is_active == True)  # noqa: E712
        | (db.checkpoint_signing_keys.grace_period_until > now)
    ).select()

    last_error: Exception | None = None
    for row in rows:
        try:
            claims = jwt.decode(
                token,
                row.public_key,
                algorithms=[row.algorithm],
                options={"verify_aud": False},
            )
            # Check revocation in DB
            jti = claims.get("jti")
            if jti:
                row_db = db(
                    (db.checkpoint_tokens.jti == jti)
                    & (db.checkpoint_tokens.revoked_at != None)  # noqa: E711
                ).select().first()
                if row_db is not None:
                    raise JWTError("Token has been revoked")
            return claims
        except JWTError as exc:
            last_error = exc
            continue

    raise JWTError(f"Token verification failed: {last_error}")


def generate_signing_keypair(algorithm: str = "RS256") -> tuple[str, str]:
    """
    Generate a new RSA-2048 or EC P-256 signing keypair.

    Returns (public_pem, private_pem) as strings.
    """
    if algorithm == "RS256":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
    else:
        from cryptography.hazmat.primitives.asymmetric import ec
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()

    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return public_pem, private_pem
