//! AES-256-GCM decryption for git credential tokens
//! (`codescan_git_credentials.encrypted_token`).
//!
//! Deliberately duplicated from
//! `services/codescan-backend/src/crypto.rs` rather than shared via a
//! workspace crate: this phase's scope discipline is "edit only
//! services/codescan-backend + services/worker-codescan" (no changes under
//! `crates/`), and `codescan-backend` exposes only a `[[bin]]` target, so
//! there is no library crate this binary could depend on without adding one.
//! Both copies must use the same `CREDENTIAL_ENCRYPTION_KEY`-derived key and
//! `nonce || ciphertext` wire format — see that file's doc comment for the
//! encrypt side. Plaintext tokens are never logged.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;

/// Nonce length for AES-256-GCM, in bytes.
const NONCE_LEN: usize = 12;

/// Errors raised while decrypting credential tokens.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The configured key was not valid base64-encoded 32 bytes.
    #[error("CREDENTIAL_ENCRYPTION_KEY must be base64-encoded 32 bytes")]
    InvalidKey,
    /// Decryption failed (wrong key, truncated ciphertext, or tampering).
    #[error("decryption failed")]
    Decrypt,
}

/// Decrypts git credential tokens with a single AES-256-GCM key — the
/// worker only ever reads credentials codescan-backend already encrypted, so
/// no `encrypt` method is exposed outside tests. Unlike codescan-backend's
/// copy, this has no `from_env` constructor: `WorkerConfig::from_env`
/// (`crate::config`) already centralizes reading `CREDENTIAL_ENCRYPTION_KEY`
/// once at startup (see that module's doc comment), and
/// `handler::CodeScanReviewHandler::resolve_git_credentials` builds the
/// cipher on demand from `WorkerConfig::credential_encryption_key` — this
/// type only needs [`from_base64_key`](Self::from_base64_key).
pub struct CredentialCipher {
    cipher: Aes256Gcm,
}

impl CredentialCipher {
    /// Builds a cipher from an explicit base64-encoded key.
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

    /// Test-only fixture builder mirroring codescan-backend's
    /// `CredentialCipher::encrypt` — lets other test modules in this crate
    /// (e.g. `handler`'s credential-resolution tests) build a realistic
    /// `encrypted_token` blob without duplicating AES-GCM setup at every
    /// call site. Never compiled into a release binary.
    #[cfg(test)]
    #[allow(clippy::expect_used)]
    pub fn encrypt(&self, plaintext: &str) -> Vec<u8> {
        use aes_gcm::aead::{AeadCore, OsRng};
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .expect("AES-GCM encryption is infallible for this key/nonce combination");
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(nonce.as_ref());
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Decrypts a `nonce || ciphertext` blob produced by codescan-backend's
    /// `CredentialCipher::encrypt`.
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use aes_gcm::aead::{AeadCore, OsRng};

    fn test_key() -> String {
        base64::engine::general_purpose::STANDARD.encode([7u8; 32])
    }

    /// Test-only encrypt helper mirroring codescan-backend's
    /// `CredentialCipher::encrypt`, so these tests can build fixtures without
    /// importing that crate (it isn't a dependency — see module docs).
    fn encrypt_fixture(cipher: &Aes256Gcm, plaintext: &str) -> Vec<u8> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .unwrap_or_else(|e| panic!("encrypt fixture: {e}"));
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(nonce.as_ref());
        out.extend_from_slice(&ciphertext);
        out
    }

    fn raw_cipher() -> Aes256Gcm {
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(test_key())
            .unwrap_or_else(|e| panic!("decode test key: {e}"));
        Aes256Gcm::new_from_slice(&key_bytes).unwrap_or_else(|e| panic!("cipher: {e}"))
    }

    #[test]
    fn decrypts_a_token_encrypted_with_the_same_key() {
        let raw = raw_cipher();
        let encrypted = encrypt_fixture(&raw, "ghp_supersecrettoken");

        let cipher = match CredentialCipher::from_base64_key(&test_key()) {
            Ok(c) => c,
            Err(e) => panic!("cipher: {e:?}"),
        };
        let decrypted = match cipher.decrypt(&encrypted) {
            Ok(d) => d,
            Err(e) => panic!("decrypt: {e:?}"),
        };
        assert_eq!(decrypted, "ghp_supersecrettoken");
    }

    #[test]
    fn rejects_key_of_wrong_length() {
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
    fn decrypt_rejects_ciphertext_from_a_different_key() {
        let other_key_cipher = {
            let key_bytes = base64::engine::general_purpose::STANDARD
                .decode(base64::engine::general_purpose::STANDARD.encode([9u8; 32]))
                .unwrap_or_else(|e| panic!("decode: {e}"));
            Aes256Gcm::new_from_slice(&key_bytes).unwrap_or_else(|e| panic!("cipher: {e}"))
        };
        let encrypted = encrypt_fixture(&other_key_cipher, "token-value");

        let cipher = match CredentialCipher::from_base64_key(&test_key()) {
            Ok(c) => c,
            Err(e) => panic!("cipher: {e:?}"),
        };
        match cipher.decrypt(&encrypted) {
            Err(CryptoError::Decrypt) => {}
            other => panic!("expected Decrypt error, got {other:?}"),
        }
    }
}
