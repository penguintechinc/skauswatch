//! Shared test-only RSA keypair generation, used by `crate::provenance`'s
//! and `crate::bundle`'s test modules. Generated fresh at test-run time
//! rather than committed as static PEM fixture files, matching
//! `services/worker-vault-sync/src/providers/mod.rs::generate_rsa_private_key_pem`'s
//! precedent in this exact workspace — a static `"-----BEGIN ... PRIVATE
//! KEY-----"` literal in source is exactly the shape gitleaks' `private-key`
//! rule flags, even for an inert test-only key with no real security value.

// This whole module is `#[cfg(test)]`-only (see `main.rs`'s `mod` list) —
// per this workspace's convention (`#[allow(clippy::expect_used, clippy::panic)]
// // tests fail loudly by design`, repeated on every `#[cfg(test)] mod tests`
// block), a panic here means the test run's own fixture setup is broken,
// which should surface loudly rather than be propagated as a `Result`.
#![allow(clippy::expect_used)]

use std::sync::LazyLock;

use rsa::RsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _, LineEnding};

/// A process-wide RSA-2048 test keypair `(private_pkcs8_pem, public_spki_pem)`,
/// generated once per test binary run — 2048-bit RSA keygen isn't free, and
/// every caller in a run wants the same keypair to sign with / verify
/// against.
pub(crate) fn test_keypair() -> &'static (String, String) {
    static KEYPAIR: LazyLock<(String, String)> = LazyLock::new(|| {
        let key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)
            .expect("generate 2048-bit RSA test key");
        let private_pem = key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode RSA test private key to PKCS#8 PEM")
            .to_string();
        let public_pem = key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode RSA test public key to SPKI PEM");
        (private_pem, public_pem)
    });
    &KEYPAIR
}

/// A second, unrelated public key — for tests proving verification is
/// rejected against the wrong key.
pub(crate) fn other_test_public_key_pem() -> String {
    let key =
        RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("generate second RSA test key");
    key.to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("encode RSA test public key to SPKI PEM")
}
