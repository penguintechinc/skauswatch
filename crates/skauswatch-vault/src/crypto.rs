//! Vault envelope encryption — byte-exact Rust port of the v1 Python
//! `crypto/envelope.py` (`EnvelopeEncryption`).
//!
//! Construction (unchanged from v1 — see `docs/v2-port/vault-crypto-gate.md`
//! for the cross-language proof):
//!   - `secret_value` is encrypted with a fresh per-secret 32-byte DEK
//!     (AES-256-GCM, 12-byte random nonce, no AAD): `nonce || ciphertext+tag`.
//!   - The DEK is wrapped with the current Master Encryption Key (MEK) using
//!     the same construction: `nonce || wrapped_dek+tag`.
//!   - Both fields are base64-standard-encoded for storage; `dek_version`
//!     records which MEK wrapped the DEK.
//!   - Key rotation only re-wraps `encrypted_dek` under a new MEK version —
//!     secret ciphertext is never re-encrypted.

use std::collections::HashMap;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

/// Nonce length for AES-GCM (bytes) — matches v1's `os.urandom(12)`.
const NONCE_LEN: usize = 12;
/// MEK/DEK key length for AES-256 (bytes).
const KEY_LEN: usize = 32;

/// Errors raised by envelope encryption/decryption.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    /// A required `VAULT_MEK_V{n}` (or `VAULT_MEK`) env var was not set.
    #[error("{0} (or VAULT_MEK) environment variable not set")]
    MissingMek(String),
    /// A configured MEK did not base64-decode to exactly 32 bytes.
    #[error("{0} must be a base64-encoded 32-byte key")]
    InvalidMekLength(String),
    /// `dek_version`/MEK version requested is not loaded in this instance.
    #[error("MEK version {0} not loaded")]
    MekVersionNotLoaded(u32),
    /// Base64 decoding of a stored ciphertext/DEK field failed.
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
    /// The stored field was shorter than the mandatory nonce prefix.
    #[error("ciphertext shorter than the {NONCE_LEN}-byte nonce prefix")]
    Truncated,
    /// AES-GCM authentication or decryption failure (tampered ciphertext,
    /// wrong key, or corrupt data) — deliberately opaque, matching v1's bare
    /// `cryptography.exceptions.InvalidTag`.
    #[error("AES-GCM operation failed (authentication or decryption error)")]
    Crypto,
    /// Decrypted plaintext bytes were not valid UTF-8.
    #[error("decrypted plaintext is not valid UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    /// The MEK version requested for rotation has not been loaded.
    #[error("MEK version {0} not loaded — cannot rotate")]
    RotateTargetNotLoaded(u32),
    /// JSON (de)serialization failed while encrypting/decrypting a
    /// structured credential blob (see [`EnvelopeEncryption::encrypt_json`]).
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    /// A decrypted/stored JSON credential blob was missing the mandatory
    /// `ciphertext`/`dek`/`version` envelope fields.
    #[error("credential blob missing ciphertext/dek/version fields")]
    MalformedBlob,
}

/// A single versioned Master Encryption Key.
#[derive(Clone)]
pub struct MekVersion {
    /// Version number (matches `dek_version` on stored rows).
    pub version: u32,
    /// Raw 32-byte AES-256 key material.
    pub key_bytes: [u8; KEY_LEN],
}

/// One row that needs its DEK re-wrapped during MEK rotation. Mirrors the
/// v1 `admin.rotate_mek` row dict shape (`id`, `encrypted_dek`,
/// `dek_version`); the caller owns the `id`/table association and updates
/// the DB after `rotate_mek` returns.
#[derive(Debug, Clone)]
pub struct RotateRow {
    /// Row identifier (opaque to this module — caller's primary key).
    pub id: String,
    /// Base64-encoded wrapped DEK, updated in place on success.
    pub encrypted_dek: String,
    /// MEK version that wrapped `encrypted_dek`, updated in place.
    pub dek_version: u32,
}

/// Envelope encryption engine for Vault secrets. Holds every loaded MEK
/// version so decryption can service rows wrapped under an older MEK during
/// rotation.
#[derive(Clone, Default)]
pub struct EnvelopeEncryption {
    mek_versions: HashMap<u32, MekVersion>,
    current_version: u32,
}

impl EnvelopeEncryption {
    /// Builds an instance from explicit MEK versions — primarily for tests
    /// and the cross-language crypto gate fixtures.
    pub fn new(mek_versions: HashMap<u32, MekVersion>, current_version: u32) -> Self {
        Self {
            mek_versions,
            current_version,
        }
    }

    /// Loads MEK versions from the standard `VAULT_MEK*` environment
    /// variables: `VAULT_MEK_CURRENT_VERSION` (default `1`), then
    /// `VAULT_MEK_V{1..=current}` (falling back to bare `VAULT_MEK` for
    /// each), matching v1 `EnvelopeEncryption.from_env`. Thin glue over
    /// [`Self::parse_mek_versions`] — intentionally left uncovered (same
    /// convention as `WorkerConfig::from_env` elsewhere in this workspace):
    /// the actual parsing logic is pure and tested directly.
    pub fn from_env() -> Result<Self, EnvelopeError> {
        let current_version: u32 = std::env::var("VAULT_MEK_CURRENT_VERSION")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);
        let mek_versions =
            Self::parse_mek_versions(current_version, |name| std::env::var(name).ok())?;
        Ok(Self {
            mek_versions,
            current_version,
        })
    }

    /// Pure parsing logic behind [`Self::from_env`]: given `current_version`
    /// and a `lookup` closure resolving a variable name to its value
    /// (decoupled from `std::env::var` for testability), builds the MEK
    /// version map for `1..=current_version`, falling back to a bare
    /// `VAULT_MEK` lookup for any version-specific name that resolves to
    /// nothing.
    fn parse_mek_versions(
        current_version: u32,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<HashMap<u32, MekVersion>, EnvelopeError> {
        let mut mek_versions = HashMap::new();
        for v in 1..=current_version {
            let var_name = format!("VAULT_MEK_V{v}");
            let mek_b64 = lookup(&var_name)
                .or_else(|| lookup("VAULT_MEK"))
                .ok_or_else(|| EnvelopeError::MissingMek(var_name.clone()))?;
            let key_bytes = B64
                .decode(mek_b64.as_bytes())
                .map_err(EnvelopeError::Base64)?;
            let key_bytes: [u8; KEY_LEN] = key_bytes
                .try_into()
                .map_err(|_| EnvelopeError::InvalidMekLength(var_name))?;
            mek_versions.insert(
                v,
                MekVersion {
                    version: v,
                    key_bytes,
                },
            );
        }
        Ok(mek_versions)
    }

    /// The MEK version new encryptions are wrapped under.
    pub fn current_version(&self) -> u32 {
        self.current_version
    }

    /// Whether the given MEK version is loaded (used by the `/mek/rotate`
    /// route to validate the requested target before rotating).
    pub fn has_mek_version(&self, version: u32) -> bool {
        self.mek_versions.contains_key(&version)
    }

    fn get_mek(&self, version: u32) -> Result<&[u8; KEY_LEN], EnvelopeError> {
        self.mek_versions
            .get(&version)
            .map(|m| &m.key_bytes)
            .ok_or(EnvelopeError::MekVersionNotLoaded(version))
    }

    /// AES-256-GCM encrypt `plaintext` under `key`: random 12-byte nonce,
    /// no AAD, `nonce || ciphertext+tag`.
    fn aead_encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| EnvelopeError::Crypto)?;
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Reverses [`Self::aead_encrypt`]: splits the mandatory nonce prefix
    /// and decrypts+authenticates the remainder under `key`.
    fn aead_decrypt(key: &[u8; KEY_LEN], blob: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        if blob.len() < NONCE_LEN {
            return Err(EnvelopeError::Truncated);
        }
        let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
        let nonce_arr: [u8; NONCE_LEN] = nonce_bytes
            .try_into()
            .map_err(|_| EnvelopeError::Truncated)?;
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
        let nonce = Nonce::from(nonce_arr);
        cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| EnvelopeError::Crypto)
    }

    /// Generates a fresh random 32-byte Data Encryption Key.
    fn generate_dek() -> [u8; KEY_LEN] {
        Aes256Gcm::generate_key(&mut OsRng).into()
    }

    /// Encrypts a secret value via envelope encryption. Returns
    /// `(encrypted_value_b64, encrypted_dek_b64, mek_version)`, matching v1
    /// `EnvelopeEncryption.encrypt`.
    pub fn encrypt(&self, plaintext: &str) -> Result<(String, String, u32), EnvelopeError> {
        let dek = Self::generate_dek();
        let mek = self.get_mek(self.current_version)?;

        let ciphertext = Self::aead_encrypt(&dek, plaintext.as_bytes())?;
        let wrapped_dek = Self::aead_encrypt(mek, &dek)?;

        Ok((
            B64.encode(ciphertext),
            B64.encode(wrapped_dek),
            self.current_version,
        ))
    }

    /// Decrypts a secret value via envelope encryption, matching v1
    /// `EnvelopeEncryption.decrypt`.
    pub fn decrypt(
        &self,
        encrypted_value_b64: &str,
        encrypted_dek_b64: &str,
        dek_version: u32,
    ) -> Result<String, EnvelopeError> {
        let mek = self.get_mek(dek_version)?;

        let ciphertext = B64.decode(encrypted_value_b64.as_bytes())?;
        let wrapped_dek = B64.decode(encrypted_dek_b64.as_bytes())?;

        let dek_bytes = Self::aead_decrypt(mek, &wrapped_dek)?;
        let dek: [u8; KEY_LEN] = dek_bytes.try_into().map_err(|_| EnvelopeError::Truncated)?;

        let plaintext = Self::aead_decrypt(&dek, &ciphertext)?;
        Ok(String::from_utf8(plaintext)?)
    }

    /// Encrypts `value` (compact JSON) via envelope encryption and bundles
    /// the three envelope fields into one JSON blob suitable for a single
    /// TEXT column: `{"ciphertext","dek","version"}`. Matches the storage
    /// shape already used by `vault_cloud_integrations.encrypted_credentials`
    /// (see `worker-vault-sync`) — callers with more than one related secret
    /// field (e.g. an access-key-id/secret-access-key pair) bundle them into
    /// one JSON object first rather than encrypting each field separately.
    pub fn encrypt_json(&self, value: &serde_json::Value) -> Result<String, EnvelopeError> {
        let plaintext = serde_json::to_string(value)?;
        let (ciphertext, dek, version) = self.encrypt(&plaintext)?;
        let blob = serde_json::json!({"ciphertext": ciphertext, "dek": dek, "version": version});
        Ok(serde_json::to_string(&blob)?)
    }

    /// Reverses [`Self::encrypt_json`]: unwraps the `{ciphertext,dek,version}`
    /// blob, decrypts, and parses the recovered plaintext back into JSON.
    pub fn decrypt_json(&self, blob: &str) -> Result<serde_json::Value, EnvelopeError> {
        let envelope_fields: serde_json::Value = serde_json::from_str(blob)?;
        let ciphertext = envelope_fields
            .get("ciphertext")
            .and_then(serde_json::Value::as_str)
            .ok_or(EnvelopeError::MalformedBlob)?;
        let dek = envelope_fields
            .get("dek")
            .and_then(serde_json::Value::as_str)
            .ok_or(EnvelopeError::MalformedBlob)?;
        let version = envelope_fields
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or(EnvelopeError::MalformedBlob)?;
        let plaintext = self.decrypt(ciphertext, dek, version)?;
        Ok(serde_json::from_str(&plaintext)?)
    }

    /// Re-wraps every row's DEK under `new_version`'s MEK, mutating `rows`
    /// in place and returning the count actually re-wrapped. Rows already
    /// on `new_version` are left untouched. Matches v1
    /// `EnvelopeEncryption.rotate_mek`.
    pub fn rotate_mek(
        &mut self,
        new_version: u32,
        rows: &mut [RotateRow],
    ) -> Result<usize, EnvelopeError> {
        if !self.mek_versions.contains_key(&new_version) {
            return Err(EnvelopeError::RotateTargetNotLoaded(new_version));
        }
        let new_mek = *self.get_mek(new_version)?;
        let mut updated = 0usize;

        for row in rows.iter_mut() {
            if row.dek_version == new_version {
                continue;
            }
            let old_mek = *self.get_mek(row.dek_version)?;
            let wrapped = B64.decode(row.encrypted_dek.as_bytes())?;
            let dek_bytes = Self::aead_decrypt(&old_mek, &wrapped)?;
            let new_wrapped = Self::aead_encrypt(&new_mek, &dek_bytes)?;

            row.encrypted_dek = B64.encode(new_wrapped);
            row.dek_version = new_version;
            updated += 1;
        }

        self.current_version = new_version;
        Ok(updated)
    }
}

/// Generates a new random MEK and returns it base64-encoded. For key setup
/// tooling only (matches v1 `generate_mek_b64`).
pub fn generate_mek_b64() -> String {
    B64.encode(random_32_bytes())
}

/// 32 cryptographically random bytes from the OS CSPRNG. Exposed so callers
/// needing secure randomness (e.g. one-time-secret share tokens) reuse this
/// crate's already-audited RNG plumbing instead of adding a second random
/// number generator dependency.
pub fn random_32_bytes() -> [u8; KEY_LEN] {
    Aes256Gcm::generate_key(&mut OsRng).into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn enc_with_mek(key_bytes: [u8; KEY_LEN]) -> EnvelopeEncryption {
        let mut versions = HashMap::new();
        versions.insert(
            1,
            MekVersion {
                version: 1,
                key_bytes,
            },
        );
        EnvelopeEncryption::new(versions, 1)
    }

    fn test_mek() -> EnvelopeEncryption {
        enc_with_mek([7u8; KEY_LEN])
    }

    #[test]
    fn roundtrip_short_value() {
        let enc = test_mek();
        let plaintext = "my-api-key-abc123";
        let (ct, dek, v) = enc.encrypt(plaintext).expect("encrypt");
        assert_eq!(enc.decrypt(&ct, &dek, v).expect("decrypt"), plaintext);
    }

    #[test]
    fn roundtrip_long_value() {
        let enc = test_mek();
        let plaintext = format!("{{\"key\": \"{}\"}}", "x".repeat(4000));
        let (ct, dek, v) = enc.encrypt(&plaintext).expect("encrypt");
        assert_eq!(enc.decrypt(&ct, &dek, v).expect("decrypt"), plaintext);
    }

    #[test]
    fn roundtrip_empty_value() {
        let enc = test_mek();
        let (ct, dek, v) = enc.encrypt("").expect("encrypt");
        assert_eq!(enc.decrypt(&ct, &dek, v).expect("decrypt"), "");
    }

    #[test]
    fn roundtrip_unicode_value() {
        let enc = test_mek();
        let plaintext = "密钥-секрет-🔐";
        let (ct, dek, v) = enc.encrypt(plaintext).expect("encrypt");
        assert_eq!(enc.decrypt(&ct, &dek, v).expect("decrypt"), plaintext);
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        let enc = test_mek();
        let plaintext = "super-secret-value-12345";
        let (ct, _, _) = enc.encrypt(plaintext).expect("encrypt");
        assert!(!ct.contains(plaintext));
    }

    #[test]
    fn different_encryptions_produce_different_ciphertext() {
        let enc = test_mek();
        let (ct1, dek1, _) = enc.encrypt("same-value").expect("encrypt");
        let (ct2, dek2, _) = enc.encrypt("same-value").expect("encrypt");
        assert!(ct1 != ct2 || dek1 != dek2);
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let enc = test_mek();
        let (ct, dek, v) = enc.encrypt("real-secret").expect("encrypt");
        let mut raw = B64.decode(&ct).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        let tampered = B64.encode(raw);
        assert!(enc.decrypt(&tampered, &dek, v).is_err());
    }

    #[test]
    fn tampered_dek_fails_unwrap() {
        let enc = test_mek();
        let (ct, dek, v) = enc.encrypt("real-secret").expect("encrypt");
        let mut raw = B64.decode(&dek).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        let tampered = B64.encode(raw);
        assert!(enc.decrypt(&ct, &tampered, v).is_err());
    }

    #[test]
    fn decrypt_rejects_ciphertext_shorter_than_nonce_prefix() {
        let enc = test_mek();
        let (_, dek, v) = enc.encrypt("real-secret").expect("encrypt");
        let short = B64.encode([1u8; 5]); // shorter than the mandatory 12-byte nonce
        assert!(matches!(
            enc.decrypt(&short, &dek, v),
            Err(EnvelopeError::Truncated)
        ));
    }

    #[test]
    fn decrypt_rejects_wrapped_dek_shorter_than_nonce_prefix() {
        let enc = test_mek();
        let (ct, _, v) = enc.encrypt("real-secret").expect("encrypt");
        let short_dek = B64.encode([1u8; 3]); // shorter than the mandatory 12-byte nonce
        assert!(matches!(
            enc.decrypt(&ct, &short_dek, v),
            Err(EnvelopeError::Truncated)
        ));
    }

    #[test]
    fn mek_rotation_allows_decrypt_with_new_mek_and_blocks_old() {
        let old_key = [1u8; KEY_LEN];
        let new_key = [2u8; KEY_LEN];
        let mut enc = enc_with_mek(old_key);
        enc.mek_versions.insert(
            2,
            MekVersion {
                version: 2,
                key_bytes: new_key,
            },
        );

        let plaintext = "rotatable-secret";
        let (ct, dek, v) = enc.encrypt(plaintext).expect("encrypt");
        assert_eq!(v, 1);

        let mut rows = [RotateRow {
            id: "row-1".to_owned(),
            encrypted_dek: dek.clone(),
            dek_version: v,
        }];
        let updated = enc.rotate_mek(2, &mut rows).expect("rotate");
        assert_eq!(updated, 1);
        assert_eq!(rows[0].dek_version, 2);
        assert_ne!(rows[0].encrypted_dek, dek);

        assert_eq!(
            enc.decrypt(&ct, &rows[0].encrypted_dek, 2)
                .expect("decrypt with new mek"),
            plaintext
        );

        // The MEK-1-only view can no longer unwrap the rewrapped DEK.
        let old_only = enc_with_mek(old_key);
        assert!(old_only.decrypt(&ct, &rows[0].encrypted_dek, 2).is_err());
    }

    #[test]
    fn rotate_mek_rejects_unloaded_target_version() {
        let mut enc = test_mek();
        let mut rows: Vec<RotateRow> = vec![];
        assert!(matches!(
            enc.rotate_mek(99, &mut rows),
            Err(EnvelopeError::RotateTargetNotLoaded(99))
        ));
    }

    #[test]
    fn rotate_mek_propagates_base64_decode_error_for_malformed_encrypted_dek() {
        let mut enc = enc_with_mek([1u8; KEY_LEN]);
        enc.mek_versions.insert(
            2,
            MekVersion {
                version: 2,
                key_bytes: [2u8; KEY_LEN],
            },
        );
        let mut rows = [RotateRow {
            id: "row-1".to_owned(),
            encrypted_dek: "not valid base64 !!!".to_owned(),
            dek_version: 1,
        }];
        assert!(matches!(
            enc.rotate_mek(2, &mut rows),
            Err(EnvelopeError::Base64(_))
        ));
    }

    #[test]
    fn dek_version_starts_at_configured_current_version() {
        let enc = test_mek();
        let (_, _, v) = enc.encrypt("test").expect("encrypt");
        assert_eq!(v, 1);
    }

    #[test]
    fn generate_mek_b64_produces_32_bytes() {
        let mek = generate_mek_b64();
        let decoded = B64.decode(&mek).expect("valid base64");
        assert_eq!(decoded.len(), KEY_LEN);
    }

    // ── parse_mek_versions (pure logic behind `from_env`) ───────────────────

    #[test]
    fn parse_mek_versions_builds_map_for_each_version_specific_var() {
        let mek1 = B64.encode([1u8; KEY_LEN]);
        let mek2 = B64.encode([2u8; KEY_LEN]);
        let vars = HashMap::from([
            ("VAULT_MEK_V1".to_owned(), mek1),
            ("VAULT_MEK_V2".to_owned(), mek2),
        ]);
        let result =
            EnvelopeEncryption::parse_mek_versions(2, |k| vars.get(k).cloned()).expect("parse");
        assert_eq!(result.len(), 2);
        assert_eq!(result[&1].key_bytes, [1u8; KEY_LEN]);
        assert_eq!(result[&2].key_bytes, [2u8; KEY_LEN]);
    }

    #[test]
    fn parse_mek_versions_falls_back_to_bare_vault_mek() {
        let vars = HashMap::from([("VAULT_MEK".to_owned(), B64.encode([9u8; KEY_LEN]))]);
        let result =
            EnvelopeEncryption::parse_mek_versions(1, |k| vars.get(k).cloned()).expect("parse");
        assert_eq!(result[&1].key_bytes, [9u8; KEY_LEN]);
    }

    #[test]
    fn parse_mek_versions_missing_both_names_errors() {
        let result = EnvelopeEncryption::parse_mek_versions(1, |_| None);
        assert!(matches!(result, Err(EnvelopeError::MissingMek(name)) if name == "VAULT_MEK_V1"));
    }

    #[test]
    fn parse_mek_versions_rejects_wrong_length_key() {
        let vars = HashMap::from([("VAULT_MEK_V1".to_owned(), B64.encode([1u8; 16]))]);
        let result = EnvelopeEncryption::parse_mek_versions(1, |k| vars.get(k).cloned());
        assert!(matches!(result, Err(EnvelopeError::InvalidMekLength(_))));
    }

    #[test]
    fn parse_mek_versions_rejects_invalid_base64() {
        let vars = HashMap::from([("VAULT_MEK_V1".to_owned(), "not valid base64 !!!".to_owned())]);
        let result = EnvelopeEncryption::parse_mek_versions(1, |k| vars.get(k).cloned());
        assert!(matches!(result, Err(EnvelopeError::Base64(_))));
    }

    #[test]
    fn parse_mek_versions_zero_current_version_is_empty() {
        let result = EnvelopeEncryption::parse_mek_versions(0, |_| None).expect("parse");
        assert!(result.is_empty());
    }

    #[test]
    fn encrypt_json_decrypt_json_roundtrip() {
        let enc = test_mek();
        let value = serde_json::json!({
            "access_key_id": "AKIAEXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        });
        let blob = enc.encrypt_json(&value).expect("encrypt_json");
        // Blob is itself well-formed JSON with the expected envelope shape.
        let parsed: serde_json::Value = serde_json::from_str(&blob).expect("blob is json");
        assert!(parsed.get("ciphertext").is_some());
        assert!(parsed.get("dek").is_some());
        assert!(parsed.get("version").is_some());
        // The plaintext never appears in the stored blob.
        assert!(!blob.contains("AKIAEXAMPLE"));
        assert!(!blob.contains("wJalrXUtnFEMI"));

        let decrypted = enc.decrypt_json(&blob).expect("decrypt_json");
        assert_eq!(decrypted, value);
    }

    #[test]
    fn decrypt_json_rejects_malformed_blob() {
        let enc = test_mek();
        for bad in [
            "not json at all",
            "{}",
            r#"{"ciphertext": "x"}"#,
            r#"{"ciphertext": "x", "dek": "y"}"#,
            r#"{"ciphertext": "x", "dek": "y", "version": "not-a-number"}"#,
        ] {
            assert!(
                matches!(
                    enc.decrypt_json(bad),
                    Err(EnvelopeError::MalformedBlob) | Err(EnvelopeError::Json(_))
                ),
                "expected malformed/json error for {bad:?}"
            );
        }
    }

    #[test]
    fn decrypt_json_rejects_tampered_ciphertext() {
        let enc = test_mek();
        let blob = enc
            .encrypt_json(&serde_json::json!({"k": "v"}))
            .expect("encrypt_json");
        let mut parsed: serde_json::Value = serde_json::from_str(&blob).expect("json");
        let mut raw = B64
            .decode(parsed["ciphertext"].as_str().expect("ciphertext str"))
            .expect("b64 decode");
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        parsed["ciphertext"] = serde_json::Value::String(B64.encode(raw));
        let tampered = parsed.to_string();
        assert!(matches!(
            enc.decrypt_json(&tampered),
            Err(EnvelopeError::Crypto)
        ));
    }
}
