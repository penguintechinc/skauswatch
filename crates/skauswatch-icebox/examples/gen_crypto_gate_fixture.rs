//! Reproducibility tool for `docs/v2-port/icebox-crypto-gate.md`: encrypts
//! the shared cross-language fixture plaintext with the Rust
//! `EnvelopeEncryption` under the same MEK used by the Python-side fixture
//! generator (`base64.b64encode(bytes(range(32)))`), and prints the
//! envelope fields as JSON so they can be fed to the v1 Python
//! `envelope.py` for the Rust-encrypted -> Python-decrypted direction of
//! the crypto gate.
//!
//! Run: `cargo run --example gen_crypto_gate_fixture -p skauswatch-icebox`
//!
//! Dev-only reproducibility tool, never invoked by the running service —
//! `.expect()` is acceptable here (house rule scopes the no-`.expect()`
//! rule to service/library code, not one-shot developer scripts).

#![allow(clippy::expect_used)]

use std::collections::HashMap;

use base64::Engine as _;
use skauswatch_icebox::{EnvelopeEncryption, MekVersion};

const MEK_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const PLAINTEXT: &str = "s3kr1t-cross-lang-fixture-\u{2603}-\u{1f512}-value";

fn main() {
    let key_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(MEK_B64)
        .expect("valid base64 MEK")
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
    let enc = EnvelopeEncryption::new(versions, 1);

    let (ciphertext_b64, encrypted_dek_b64, dek_version) =
        enc.encrypt(PLAINTEXT).expect("rust encrypt");

    println!(
        "{{\"mek_b64\": \"{MEK_B64}\", \"plaintext\": {plaintext:?}, \"ciphertext_b64\": \"{ciphertext_b64}\", \"encrypted_dek_b64\": \"{encrypted_dek_b64}\", \"dek_version\": {dek_version}}}",
        plaintext = PLAINTEXT,
    );
}
