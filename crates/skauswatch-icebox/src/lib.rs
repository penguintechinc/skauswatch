//! Shared IceBox logic used by both `services/icebox` (REST vault backend)
//! and `services/worker-icebox-sync` (cloud sync worker): envelope
//! encryption is the single canonical implementation so the two binaries
//! can never drift into incompatible ciphertext formats.

pub mod crypto;

pub use crypto::{
    EnvelopeEncryption, EnvelopeError, MekVersion, RotateRow, generate_mek_b64, random_32_bytes,
};
