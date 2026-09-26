# Vault crypto gate — verdict: PASS (byte-exact, both directions)

MERGE-BLOCKING gate for the Vault port. Existing customer secrets were
encrypted by the v1 Python service; the v2 Rust service must decrypt them
unchanged, and any newly-Rust-encrypted secret must remain decryptable by
an unreplaced v1 instance during a rolling deploy. Both directions are
proven below with real ciphertext produced by the actual v1 module and the
actual Rust port — not a description of the algorithm.

## v1 construction (read from `icebox/services/flask-backend/crypto/envelope.py`)

Envelope encryption, `EnvelopeEncryption`:

- **MEK** (Master Encryption Key): 32 bytes, base64-encoded, sourced from
  `VAULT_MEK_V{version}` (fallback `VAULT_MEK`) env vars. Multiple
  versions may be loaded simultaneously to support rotation.
- **DEK** (Data Encryption Key): fresh random 32 bytes per secret
  (`os.urandom(32)`).
- **Wrap** (`_wrap_dek`): `AESGCM(mek).encrypt(nonce, dek, None)` where
  `nonce = os.urandom(12)`. Stored as `nonce (12 bytes) || ciphertext+tag
  (32+16=48 bytes)` = 60 bytes, base64-encoded → `encrypted_dek`.
- **Encrypt** (`_encrypt_with_dek`): `AESGCM(dek).encrypt(nonce,
  plaintext_utf8, None)` where `nonce = os.urandom(12)`. Stored as `nonce
  (12 bytes) || ciphertext+tag`, base64-encoded → `encrypted_value`.
- **AAD**: `None` in both calls — the Python `cryptography` library treats
  `None` identically to an empty (zero-length) AAD.
- **Tag placement**: appended to the ciphertext by `AESGCM.encrypt`
  (RustCrypto's `aes-gcm` crate does the same) — never stored separately.
- **dek_version**: the MEK version used to wrap the DEK; stored alongside
  `encrypted_value`/`encrypted_dek` so decryption knows which MEK to load.
- **Rotation** (`rotate_mek`): re-wraps `encrypted_dek` under a new MEK
  version; `encrypted_value` (the secret ciphertext itself) is never
  re-encrypted.

## Rust port

`crates/skauswatch-vault/src/crypto.rs` (`EnvelopeEncryption`) — RustCrypto
`aes-gcm = "=0.10.3"`, pinned exact per house rules. Identical construction:
`Aes256Gcm::generate_nonce` (12 bytes) prepended to `cipher.encrypt(nonce,
plaintext)` output (ciphertext+tag appended, no AAD), base64-standard
encoding, same `nonce || ciphertext+tag` layout for both the DEK wrap and
the secret-value encryption. `EnvelopeEncryption::from_env`,
`::encrypt`, `::decrypt`, and `::rotate_mek` mirror the Python API 1:1 (see
module doc comments for the full mapping).

## Fixture generation (reproducible)

Shared test MEK: `base64.b64encode(bytes(range(32)))` →
`AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=`.

Shared plaintext (includes non-ASCII + astral-plane emoji to stress UTF-8
handling): `s3kr1t-cross-lang-fixture-☃-🔒-value`.

### Direction A — Python encrypts, Rust decrypts (the direction that matters for existing customer data)

Ran the **unmodified** `crypto/envelope.py` copied verbatim into a throwaway
directory, inside `python:3.13-slim-bookworm` with `cryptography>=42.0.0`
(same pin as `icebox/services/flask-backend/requirements.txt`):

```
$ docker run --rm -v <scratch>:/w -w /w python:3.13-slim-bookworm \
    bash -c "pip install --quiet 'cryptography>=42.0.0' && python3 py_encrypt.py"
{"mek_b64": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
 "plaintext": "s3kr1t-cross-lang-fixture-☃-🔒-value",
 "ciphertext_b64": "wr/koZYwP1jrjMiQbsvjtgTGeW4hN9yIu+q4Pbfv4w7aDS/PlKLGpqyCB4yT5dZcltdH/fIAbj3dzDO0HpEyD6EdwuI=",
 "encrypted_dek_b64": "53PrXiifV9nxGiJy0tvSHWhVuVTLMvT7MKoIeg9u5Q1Af4z1MoIo8u8OZiKzP/dERKulWIJWkwC5djqt",
 "dek_version": 1}
```

These four fields are hardcoded as constants in
`crates/skauswatch-vault/tests/crypto_gate.rs`
(`python_encrypted_ciphertext_decrypts_in_rust_byte_exact`), which calls
the Rust `EnvelopeEncryption::decrypt` on them and asserts the recovered
plaintext equals `PY_PLAINTEXT` exactly. This test runs — and must pass —
on every `cargo test`, so a future accidental change to the Rust envelope
format (nonce size/placement, AAD, base64 variant, tag handling) fails the
build immediately rather than silently breaking access to existing
customer secrets.

**Result: PASS.** `cargo test -p skauswatch-vault
python_encrypted_ciphertext_decrypts_in_rust_byte_exact` — recovered
plaintext byte-equal to the original.

### Direction B — Rust encrypts, Python decrypts (proves the new format doesn't diverge, e.g. during a mixed-version rollout)

Generated with the checked-in reproducibility tool
`crates/skauswatch-vault/examples/gen_crypto_gate_fixture.rs`:

```
$ cargo run --example gen_crypto_gate_fixture -p skauswatch-vault
{"mek_b64": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
 "plaintext": "s3kr1t-cross-lang-fixture-☃-🔒-value",
 "ciphertext_b64": "bj4Ny04CdA+VaSHcoJVJB7xnKSVV857u40k9TBMqVqsh0nxBZCt+03b5ztPFMNzLZtb/ZdY2N3XY6nh/P9rBydIySig=",
 "encrypted_dek_b64": "1lujg5OmcHx7/J+OtlNGYepbY45jde0CSgVXjN70rq5/RDUj7zx8O7n9yUuDQt2o6twhRINXUkcXKYYD",
 "dek_version": 1}
```

Fed directly into the unmodified `envelope.py` (`py_decrypt.py` harness,
same container/pin as Direction A):

```
$ docker run --rm -v <scratch>:/w -w /w python:3.13-slim-bookworm \
    bash -c "pip install --quiet 'cryptography>=42.0.0' && \
             python3 py_decrypt.py \
               'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=' \
               'bj4Ny04CdA+VaSHcoJVJB7xnKSVV857u40k9TBMqVqsh0nxBZCt+03b5ztPFMNzLZtb/ZdY2N3XY6nh/P9rBydIySig=' \
               '1lujg5OmcHx7/J+OtlNGYepbY45jde0CSgVXjN70rq5/RDUj7zx8O7n9yUuDQt2o6twhRINXUkcXKYYD' \
               1"
s3kr1t-cross-lang-fixture-☃-🔒-value
```

Output matches the input plaintext exactly, character for character
(including the snowman and the lock emoji).

**Result: PASS.** Real v1 `cryptography.hazmat...AESGCM` decrypted the
Rust-produced envelope and recovered the exact plaintext.

This direction is not re-asserted automatically on every `cargo test` (the
v1 Python service is deleted from the v2 tree by this same change — there
is no Python runtime left in the repo to re-run it against), so it is
recorded here as a point-in-time proof rather than a regression test. The
customer-data-safety-critical direction (A) *is* a standing, always-run
Rust test.

## Verdict

**GO.** Both directions byte-exact. The v1 envelope format
(nonce-prepended AES-256-GCM, no AAD, tag appended, base64-standard
encoding, versioned MEK) is faithfully reproduced by
`crates/skauswatch-vault`. Existing customer secrets encrypted by v1
remain fully readable by the v2 Rust Vault service; MEK rotation
(`rotate_mek`) semantics — re-wrap the DEK only, never re-encrypt the
secret value — are preserved.

Proceeded to port the Vault REST backend (`services/vault`) and
sync-worker on the strength of this result.
