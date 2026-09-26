//! Shared Vault logic used by both `services/vault` (REST vault backend)
//! and `services/worker-vault-sync` (cloud sync worker): envelope
//! encryption is the single canonical implementation so the two binaries
//! can never drift into incompatible ciphertext formats.
//!
//! [`credential_cipher`] is a second, unrelated canonical cipher shared by
//! `services/codescan-backend`/`services/worker-codescan` for
//! `codescan_git_credentials.encrypted_token` — a flat single-key AES-256-GCM
//! scheme (no MEK/DEK envelope, no rotation), kept in this crate purely so
//! the AES-GCM math lives in exactly one audited place workspace-wide, not
//! because it shares the envelope model with [`EnvelopeEncryption`].

pub mod credential_cipher;
pub mod crypto;

pub use credential_cipher::{CredentialCipher, CredentialCipherError};
pub use crypto::{
    EnvelopeEncryption, EnvelopeError, MekVersion, RotateRow, generate_mek_b64, random_32_bytes,
};
