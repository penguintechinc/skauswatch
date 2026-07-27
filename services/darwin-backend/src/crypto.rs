//! AES-256-GCM encryption at rest for git credential tokens
//! (`darwin_git_credentials.encrypted_token`). Replaces the v1 Flask
//! backend's `cryptography.fernet.Fernet` (`app/git/credentials.py`) with a
//! pure-Rust, no-C-deps equivalent. Plaintext tokens are never logged.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use rand::RngCore;

/// Nonce length for AES-256-GCM, in bytes.
const NONCE_LEN: usize = 12;

/// Errors raised while encrypting/decrypting credential tokens.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
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

/// Encrypts/decrypts git credential tokens with a single AES-256-GCM key
/// loaded once at startup from `CREDENTIAL_ENCRYPTION_KEY`.
pub struct CredentialCipher {
    cipher: Aes256Gcm,
}

impl CredentialCipher {
    /// Loads the encryption key from `CREDENTIAL_ENCRYPTION_KEY`
    /// (base64-encoded, 32 raw bytes — AES-256 key size).
    pub fn from_env() -> Result<Self, CryptoError> {
        let raw =
            std::env::var("CREDENTIAL_ENCRYPTION_KEY").map_err(|_| CryptoError::MissingKey)?;
        Self::from_base64_key(raw.trim())
    }

    /// Builds a cipher from an explicit base64-encoded key (used by tests and
    /// by `from_env`).
    pub fn from_base64_key(encoded: &str) -> Result<Self, CryptoError> {
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| CryptoError::InvalidKey)?;
        if key_bytes.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }
        let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { cipher })
    }

    /// Encrypts a plaintext token. Output is `nonce || ciphertext`, suitable
    /// for storage in the `encrypted_token BYTEA` column.
    pub fn encrypt(&self, plaintext: &str) -> Result<Vec<u8>, CryptoError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| CryptoError::Encrypt)?;
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypts a `nonce || ciphertext` blob produced by [`encrypt`].
    ///
    /// Not called by this service today — darwin-backend only writes
    /// encrypted tokens; worker-darwin (a separate binary) is the consumer
    /// that decrypts them to perform git operations. Kept as the symmetric
    /// counterpart to `encrypt` (round-trip tested below) and for the
    /// future admin "reveal credential" flow.
    ///
    /// [`encrypt`]: Self::encrypt
    #[allow(dead_code)]
    pub fn decrypt(&self, data: &[u8]) -> Result<String, CryptoError> {
        if data.len() < NONCE_LEN {
            return Err(CryptoError::Decrypt);
        }
        let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
        // nonce_bytes has length exactly NONCE_LEN by construction above, so
        // this conversion cannot fail.
        let nonce_arr: [u8; NONCE_LEN] =
            nonce_bytes.try_into().map_err(|_| CryptoError::Decrypt)?;
        let nonce = Nonce::from(nonce_arr);
        let plaintext = self
            .cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| CryptoError::Decrypt)?;
        String::from_utf8(plaintext).map_err(|_| CryptoError::Decrypt)
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    fn test_key() -> String {
        base64::engine::general_purpose::STANDARD.encode([7u8; 32])
    }

    #[test]
    fn round_trips_a_token() {
        let cipher = match CredentialCipher::from_base64_key(&test_key()) {
            Ok(c) => c,
            Err(e) => panic!("cipher: {e:?}"),
        };
        let encrypted = match cipher.encrypt("ghp_supersecrettoken") {
            Ok(e) => e,
            Err(e) => panic!("encrypt: {e:?}"),
        };
        assert_ne!(encrypted, b"ghp_supersecrettoken");
        let decrypted = match cipher.decrypt(&encrypted) {
            Ok(d) => d,
            Err(e) => panic!("decrypt: {e:?}"),
        };
        assert_eq!(decrypted, "ghp_supersecrettoken");
    }

    #[test]
    fn each_encryption_uses_a_fresh_nonce() {
        let cipher = match CredentialCipher::from_base64_key(&test_key()) {
            Ok(c) => c,
            Err(e) => panic!("cipher: {e:?}"),
        };
        let a = match cipher.encrypt("same-plaintext") {
            Ok(v) => v,
            Err(e) => panic!("encrypt: {e:?}"),
        };
        let b = match cipher.encrypt("same-plaintext") {
            Ok(v) => v,
            Err(e) => panic!("encrypt: {e:?}"),
        };
        assert_ne!(a, b, "ciphertext must differ across calls (fresh nonce)");
    }

    #[test]
    fn rejects_key_of_wrong_length() {
        // CredentialCipher intentionally has no Debug impl (it would risk
        // formatting key material into a log line), so the failure branch
        // below only reports the error variant, not the full Result.
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        match CredentialCipher::from_base64_key(&short) {
            Err(CryptoError::InvalidKey) => {}
            Ok(_) => panic!("expected InvalidKey, got Ok"),
            Err(other) => panic!("expected InvalidKey, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_base64_key() {
        match CredentialCipher::from_base64_key("not-valid-base64!!") {
            Err(CryptoError::InvalidKey) => {}
            Ok(_) => panic!("expected InvalidKey, got Ok"),
            Err(other) => panic!("expected InvalidKey, got {other:?}"),
        }
    }

    #[test]
    fn decrypt_rejects_truncated_ciphertext() {
        let cipher = match CredentialCipher::from_base64_key(&test_key()) {
            Ok(c) => c,
            Err(e) => panic!("cipher: {e:?}"),
        };
        match cipher.decrypt(&[1, 2, 3]) {
            Err(CryptoError::Decrypt) => {}
            other => panic!("expected Decrypt error, got {other:?}"),
        }
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let cipher = match CredentialCipher::from_base64_key(&test_key()) {
            Ok(c) => c,
            Err(e) => panic!("cipher: {e:?}"),
        };
        let mut encrypted = match cipher.encrypt("token-value") {
            Ok(v) => v,
            Err(e) => panic!("encrypt: {e:?}"),
        };
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        match cipher.decrypt(&encrypted) {
            Err(CryptoError::Decrypt) => {}
            other => panic!("expected Decrypt error, got {other:?}"),
        }
    }
}
