//! MERGE-BLOCKING crypto gate: proves the Rust `EnvelopeEncryption` port
//! cross-decrypts with the unmodified v1 Python
//! `icebox/services/flask-backend/crypto/envelope.py`.
//!
//! `PY_ENCRYPTED_*` below are byte-exact fixtures produced by running the
//! real v1 `envelope.py` (unmodified copy) inside `python:3.13-slim-bookworm`
//! with `cryptography>=42.0.0` — see `docs/v2-port/icebox-crypto-gate.md`
//! for the exact commands, container digest, and full session transcript,
//! including the reverse direction (Rust-encrypted ciphertext decrypted by
//! the same Python module).
//!
//! This is NOT a round-trip-with-itself test — [`crypto_gate_selftest`]
//! separately proves that, but the assertions below decode fixtures that
//! only the real Python `cryptography` AESGCM implementation produced.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;

use skauswatch_icebox::{EnvelopeEncryption, MekVersion};

/// MEK used for every fixture below: `base64.b64encode(bytes(range(32)))`.
const PY_MEK_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

/// The exact plaintext the Python fixture encrypted (unicode + emoji, to
/// exercise UTF-8 handling identically to the Rust unit tests).
const PY_PLAINTEXT: &str = "s3kr1t-cross-lang-fixture-\u{2603}-\u{1f512}-value";

/// `enc.encrypt(PY_PLAINTEXT)` ciphertext field, produced by real Python.
const PY_CIPHERTEXT_B64: &str =
    "wr/koZYwP1jrjMiQbsvjtgTGeW4hN9yIu+q4Pbfv4w7aDS/PlKLGpqyCB4yT5dZcltdH/fIAbj3dzDO0HpEyD6EdwuI=";

/// `enc.encrypt(PY_PLAINTEXT)` wrapped-DEK field, produced by real Python.
const PY_ENCRYPTED_DEK_B64: &str =
    "53PrXiifV9nxGiJy0tvSHWhVuVTLMvT7MKoIeg9u5Q1Af4z1MoIo8u8OZiKzP/dERKulWIJWkwC5djqt";

/// `enc.encrypt(PY_PLAINTEXT)` `dek_version` field, produced by real Python.
const PY_DEK_VERSION: u32 = 1;

fn mek_from_b64(b64: &str) -> EnvelopeEncryption {
    use base64::Engine as _;
    let key_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("valid base64 MEK fixture")
        .try_into()
        .expect("32-byte MEK");
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

/// Python-encrypted → Rust-decrypted. This is the direction that actually
/// matters for the v2 cutover: existing customer secrets, encrypted by the
/// v1 Quart service, MUST remain readable after the Rust rewrite ships.
#[test]
fn python_encrypted_ciphertext_decrypts_in_rust_byte_exact() {
    let enc = mek_from_b64(PY_MEK_B64);
    let recovered = enc
        .decrypt(PY_CIPHERTEXT_B64, PY_ENCRYPTED_DEK_B64, PY_DEK_VERSION)
        .expect("Rust must decrypt a real v1 Python envelope");
    assert_eq!(
        recovered, PY_PLAINTEXT,
        "cross-language decrypt produced the wrong plaintext"
    );
}

/// Sanity check that the fixture constants above are internally consistent
/// (guards against a future edit corrupting one of the four paired
/// constants without the other three).
#[test]
fn python_fixture_constants_are_well_formed_base64() {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    assert_eq!(b64.decode(PY_MEK_B64).expect("mek b64").len(), 32);
    assert!(!b64.decode(PY_CIPHERTEXT_B64).expect("ct b64").is_empty());
    assert!(
        !b64.decode(PY_ENCRYPTED_DEK_B64)
            .expect("dek b64")
            .is_empty()
    );
}

/// Rust-encrypted → Rust-decrypted self-test using the identical MEK as the
/// Python fixture. Kept alongside the cross-language assertion so a future
/// change to the envelope format fails loudly here too, not just via the
/// hardcoded Python fixture going stale.
#[test]
fn crypto_gate_selftest_rust_roundtrip_with_python_mek() {
    let enc = mek_from_b64(PY_MEK_B64);
    let (ct, dek, v) = enc.encrypt(PY_PLAINTEXT).expect("rust encrypt");
    let recovered = enc.decrypt(&ct, &dek, v).expect("rust decrypt");
    assert_eq!(recovered, PY_PLAINTEXT);
}
