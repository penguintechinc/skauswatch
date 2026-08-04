//! Flat-key AES-256-GCM encryption at rest for `codescan_git_credentials.
//! encrypted_token` — the single canonical implementation shared by
//! `services/codescan-backend` (encrypts on write, via `POST`/`PUT
//! /api/v1/credentials`) and `services/worker-codescan` (decrypts on read,
//! via `CodeScanReviewHandler::resolve_git_credentials`), so the two
//! binaries can never drift into incompatible ciphertext formats — same
//! rationale as [`crate::EnvelopeEncryption`] for vault/worker-vault-sync,
//! just a single flat key rather than a versioned MEK/DEK envelope (this
//! column has no key-rotation requirement today, unlike vault secrets).
//!
//! Both services load the same `CREDENTIAL_ENCRYPTION_KEY` (base64-encoded,
//! 32 raw bytes — AES-256 key size); wire format is `nonce || ciphertext+tag`
//! (12-byte random nonce, no AAD). Plaintext tokens are never logged.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

/// Nonce length for AES-256-GCM, in bytes.
const NONCE_LEN: usize = 12;

/// Errors raised while encrypting/decrypting credential tokens.
#[derive(Debug, thiserror::Error)]
pub enum CredentialCipherError {
    /// `CREDENTIAL_ENCRYPTION_KEY` was not set in the environment.
    #[error("CREDENTIAL_ENCRYPTION_KEY not set")]
    MissingKey,
    /// The configured key was not valid base64-encoded 32 bytes.
    #[error("CREDENTIAL_ENCRYPTION_KEY must be base64-encoded 32 bytes")]
    InvalidKey,
    /// Encryption failed.
    #[error("encryption failed")]
    Encrypt,
    /// Decryption failed (wrong key, truncated ciphertext, or tampering).
    #[error("decryption failed")]
    Decrypt,
}

/// Encrypts/decrypts git credential tokens with a single flat AES-256-GCM
/// key loaded once at startup from `CREDENTIAL_ENCRYPTION_KEY`.
pub struct CredentialCipher {
    cipher: Aes256Gcm,
}

impl CredentialCipher {
    /// Loads the encryption key from `CREDENTIAL_ENCRYPTION_KEY`
    /// (base64-encoded, 32 raw bytes — AES-256 key size).
    pub fn from_env() -> Result<Self, CredentialCipherError> {
        let raw = std::env::var("CREDENTIAL_ENCRYPTION_KEY")
            .map_err(|_| CredentialCipherError::MissingKey)?;
        Self::from_base64_key(raw.trim())
    }

    /// Builds a cipher from an explicit base64-encoded key (used by tests and
    /// by `from_env`).
    pub fn from_base64_key(encoded: &str) -> Result<Self, CredentialCipherError> {
        let key_bytes = B64
            .decode(encoded)
            .map_err(|_| CredentialCipherError::InvalidKey)?;
        if key_bytes.len() != 32 {
            return Err(CredentialCipherError::InvalidKey);
        }
        let cipher =
            Aes256Gcm::new_from_slice(&key_bytes).map_err(|_| CredentialCipherError::InvalidKey)?;
        Ok(Self { cipher })
    }

    /// Encrypts a plaintext token. Output is `nonce || ciphertext`, suitable
    /// for storage in the `encrypted_token BYTEA` column.
    pub fn encrypt(&self, plaintext: &str) -> Result<Vec<u8>, CredentialCipherError> {
        // 96-bit random nonce drawn from the OS CSPRNG via aes-gcm's AeadCore —
        // the idiomatic AEAD nonce source, so this crate needs no direct `rand` dep.
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| CredentialCipherError::Encrypt)?;
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(nonce.as_ref());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypts a `nonce || ciphertext` blob produced by [`encrypt`](Self::encrypt).
    pub fn decrypt(&self, data: &[u8]) -> Result<String, CredentialCipherError> {
        if data.len() < NONCE_LEN {
            return Err(CredentialCipherError::Decrypt);
        }
        let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
        // nonce_bytes has length exactly NONCE_LEN by construction above, so
        // this conversion cannot fail.
        let nonce_arr: [u8; NONCE_LEN] = nonce_bytes
            .try_into()
            .map_err(|_| CredentialCipherError::Decrypt)?;
        let nonce = Nonce::from(nonce_arr);
        let plaintext = self
            .cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| CredentialCipherError::Decrypt)?;
        String::from_utf8(plaintext).map_err(|_| CredentialCipherError::Decrypt)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;

    fn test_key() -> String {
        B64.encode([7u8; 32])
    }

    #[test]
    fn round_trips_a_token() {
        let cipher = CredentialCipher::from_base64_key(&test_key())
            .unwrap_or_else(|e| panic!("cipher: {e:?}"));
        let encrypted = cipher
            .encrypt("ghp_supersecrettoken")
            .unwrap_or_else(|e| panic!("encrypt: {e:?}"));
        assert_ne!(encrypted, b"ghp_supersecrettoken");
        let decrypted = cipher
            .decrypt(&encrypted)
            .unwrap_or_else(|e| panic!("decrypt: {e:?}"));
        assert_eq!(decrypted, "ghp_supersecrettoken");
    }

    #[test]
    fn each_encryption_uses_a_fresh_nonce() {
        let cipher = CredentialCipher::from_base64_key(&test_key())
            .unwrap_or_else(|e| panic!("cipher: {e:?}"));
        let a = cipher
            .encrypt("same-plaintext")
            .unwrap_or_else(|e| panic!("encrypt: {e:?}"));
        let b = cipher
            .encrypt("same-plaintext")
            .unwrap_or_else(|e| panic!("encrypt: {e:?}"));
        assert_ne!(a, b, "ciphertext must differ across calls (fresh nonce)");
    }

    #[test]
    fn rejects_key_of_wrong_length() {
        let short = B64.encode([1u8; 16]);
        match CredentialCipher::from_base64_key(&short) {
            Err(CredentialCipherError::InvalidKey) => {}
            Ok(_) => panic!("expected InvalidKey, got Ok"),
            Err(other) => panic!("expected InvalidKey, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_base64_key() {
        match CredentialCipher::from_base64_key("not-valid-base64!!") {
            Err(CredentialCipherError::InvalidKey) => {}
            Ok(_) => panic!("expected InvalidKey, got Ok"),
            Err(other) => panic!("expected InvalidKey, got {other:?}"),
        }
    }

    #[test]
    fn decrypt_rejects_truncated_ciphertext() {
        let cipher = CredentialCipher::from_base64_key(&test_key())
            .unwrap_or_else(|e| panic!("cipher: {e:?}"));
        match cipher.decrypt(&[1, 2, 3]) {
            Err(CredentialCipherError::Decrypt) => {}
            other => panic!("expected Decrypt error, got {other:?}"),
        }
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let cipher = CredentialCipher::from_base64_key(&test_key())
            .unwrap_or_else(|e| panic!("cipher: {e:?}"));
        let mut encrypted = cipher
            .encrypt("token-value")
            .unwrap_or_else(|e| panic!("encrypt: {e:?}"));
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        match cipher.decrypt(&encrypted) {
            Err(CredentialCipherError::Decrypt) => {}
            other => panic!("expected Decrypt error, got {other:?}"),
        }
    }

    #[test]
    fn decrypt_rejects_ciphertext_from_a_different_key() {
        let other_key_cipher = CredentialCipher::from_base64_key(&B64.encode([9u8; 32]))
            .unwrap_or_else(|e| panic!("cipher: {e:?}"));
        let encrypted = other_key_cipher
            .encrypt("token-value")
            .unwrap_or_else(|e| panic!("encrypt: {e:?}"));

        let cipher = CredentialCipher::from_base64_key(&test_key())
            .unwrap_or_else(|e| panic!("cipher: {e:?}"));
        match cipher.decrypt(&encrypted) {
            Err(CredentialCipherError::Decrypt) => {}
            other => panic!("expected Decrypt error, got {other:?}"),
        }
    }

    #[test]
    fn from_env_reports_missing_key() {
        assert!(
            std::env::var("CREDENTIAL_ENCRYPTION_KEY").is_err(),
            "test assumes CREDENTIAL_ENCRYPTION_KEY is unset in this process"
        );
        // `CredentialCipher` deliberately has no `Debug` impl (it would risk
        // formatting key material into a log line), so the failure branch
        // below only reports the error variant, not the full `Result`.
        match CredentialCipher::from_env() {
            Err(CredentialCipherError::MissingKey) => {}
            Ok(_) => panic!("expected MissingKey, got Ok"),
            Err(other) => panic!("expected MissingKey, got {other:?}"),
        }
    }
}
