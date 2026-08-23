//! Air-gap bundle export/import (`docs/v2-port/v2.1-depgate.md` §6b) — a
//! single portable `.zip` archive containing `manifest.json` (the vetted
//! artifact index: sha256/ecosystem/name/reference/verdict/scanner
//! version) plus one `artifacts/<sha256>` entry per unique blob. Export
//! runs on a connected system (real scanning already happened at ingest);
//! import verifies everything — manifest checksum, optional HMAC
//! signature, and every artifact's own content hash — before admitting
//! anything: **all-or-nothing, no partial trust**.
//!
//! Signing (P4, `docs/v2-port/v2.1-depgate.md` §9/§11): manifests are signed
//! asymmetrically — RSASSA-PKCS1-v1_5-SHA256 over the manifest checksum,
//! using `RsaPrivateKey`/`RsaPublicKey` (same primitives `src/provenance.rs`
//! uses for cosign verification, and `services/worker-vault-sync/src/
//! providers/oracle.rs` already uses for OCI request signing — no new
//! crypto stack for this crate). This is the correct shape for a bundle
//! crossing a trust boundary: the exporting/connected side holds
//! `DEPGATE_BUNDLE_SIGNING_PRIVATE_KEY_PEM`, the air-gapped importer needs
//! only `DEPGATE_BUNDLE_VERIFY_PUBLIC_KEY_PEM`.
//!
//! **Backward compatibility with P3's HMAC-signed bundles is preserved on
//! import**: `manifest.signature_algorithm` (added in [`BUNDLE_VERSION`] 2,
//! `#[serde(default)]` so an old v1 manifest simply has `None`) selects
//! which scheme to verify a present `signature` against —
//! `None`/`Some("hmac-sha256")` still verifies via
//! `DEPGATE_BUNDLE_SIGNING_KEY` (the P3 symmetric key), exactly as before;
//! `Some("rsa-pkcs1v15-sha256")` verifies via the new asymmetric public key.
//! Export always signs with RSA when a private key is configured — HMAC is
//! verify-only from here on.
//!
//! Scope: only `verdict = clean` artifacts are ever bundled — quarantined/
//! infected content has no reason to travel into an air-gapped,
//! zero-egress environment.

use std::io::{Read, Write};

use aws_sdk_s3::Client as S3Client;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::PgPool;
use uuid::Uuid;

use crate::cache::{self, CacheError};
use crate::db::{self, ArtifactRow};

type HmacSha256 = Hmac<Sha256>;

/// Bundle format version this build EXPORTS — bumped from 1 to 2 by P4's
/// `signature_algorithm` field addition.
pub const BUNDLE_VERSION: u32 = 2;

/// Oldest bundle format version this build still IMPORTS — kept at 1 so a
/// P3-exported (HMAC-only, no `signature_algorithm` field) bundle continues
/// to verify exactly as it did before P4.
pub const MIN_SUPPORTED_BUNDLE_VERSION: u32 = 1;

/// `manifest.signature_algorithm` value for the legacy P3 symmetric scheme —
/// also the assumed value when the field is absent (a v1 manifest).
const HMAC_ALGO: &str = "hmac-sha256";
/// `manifest.signature_algorithm` value for the P4 asymmetric scheme.
const RSA_ALGO: &str = "rsa-pkcs1v15-sha256";

/// Failures from exporting or importing a bundle.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// Filesystem I/O failure (open/read/write the bundle file itself).
    #[error("bundle I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Zip container read/write failure.
    #[error("bundle archive is malformed: {0}")]
    Zip(#[from] zip::result::ZipError),
    /// `manifest.json` didn't parse.
    #[error("bundle manifest is malformed: {0}")]
    Manifest(#[from] serde_json::Error),
    /// The bundle has no `manifest.json` entry at all.
    #[error("bundle has no manifest.json")]
    MissingManifest,
    /// `manifest.json` declares a `version` this build doesn't understand.
    #[error("bundle format version {found} is not supported (expected {expected})")]
    UnsupportedVersion {
        /// Version found in the bundle.
        found: u32,
        /// Version this build understands.
        expected: u32,
    },
    /// The manifest's own `manifest_sha256` doesn't match its recomputed
    /// hash — the bundle's entry list was tampered with or corrupted.
    #[error("manifest checksum mismatch: bundle claims {claimed}, computed {computed}")]
    ManifestChecksumMismatch {
        /// Checksum recorded in the bundle.
        claimed: String,
        /// Checksum actually computed over the entries.
        computed: String,
    },
    /// A verification key is configured but the bundle carries no
    /// signature — refused rather than silently skipping verification.
    #[error("importer requires a signed bundle, but this bundle is unsigned")]
    MissingSignature,
    /// The bundle's signature does not verify against the configured key.
    #[error("bundle signature does not verify")]
    SignatureMismatch,
    /// `manifest.signature_algorithm` names a scheme this build doesn't
    /// understand.
    #[error("bundle signature algorithm {0:?} is not supported")]
    UnsupportedSignatureAlgorithm(String),
    /// An asymmetric signing/verification key failed to parse (malformed
    /// PEM, wrong key type) — a configuration error, not a signature
    /// mismatch.
    #[error("invalid RSA key for bundle signing: {0}")]
    InvalidSigningKey(String),
    /// A manifest entry references an artifact the bundle doesn't contain.
    #[error("bundle is missing artifact bytes for sha256 {0}")]
    MissingArtifact(String),
    /// An artifact's actual bytes don't hash to its manifest-declared
    /// sha256 — content tampering or corruption. The whole bundle is
    /// refused (all-or-nothing), never just this one entry.
    #[error("artifact content hash mismatch for sha256 {claimed}: computed {computed}")]
    ArtifactHashMismatch {
        /// The sha256 the manifest/filename claims.
        claimed: String,
        /// The sha256 actually computed over the entry's bytes.
        computed: String,
    },
    /// Database failure.
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    /// S3/cache-store failure.
    #[error(transparent)]
    Cache(#[from] CacheError),
}

/// One artifact entry in a bundle manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct BundleManifestEntry {
    /// Ecosystem discriminator.
    pub ecosystem: String,
    /// Package/repo name.
    pub name: String,
    /// Tag/version/reference string.
    pub reference: String,
    /// Content digest hex — the `artifacts/<sha256>` entry this row maps
    /// to.
    pub sha256: String,
    /// Verdict at export time (always `"clean"` — see module docs).
    pub verdict: String,
    /// `skauswatch-scan-core::SCANNER_VERSION` at scan time.
    pub scanner_version: String,
    /// Stored `Content-Type`.
    pub content_type: Option<String>,
    /// Size in bytes.
    pub size_bytes: i64,
}

impl From<&ArtifactRow> for BundleManifestEntry {
    fn from(r: &ArtifactRow) -> Self {
        Self {
            ecosystem: r.ecosystem.clone(),
            name: r.name.clone(),
            reference: r.reference.clone(),
            sha256: r.sha256.clone(),
            verdict: r.verdict.clone(),
            scanner_version: r.scanner_version.clone(),
            content_type: r.content_type.clone(),
            size_bytes: r.size_bytes,
        }
    }
}

/// The full `manifest.json` document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Bundle format version.
    pub version: u32,
    /// RFC 3339 export timestamp.
    pub created_at: String,
    /// Every bundled artifact.
    pub entries: Vec<BundleManifestEntry>,
    /// sha256 over the canonical (sorted) serialization of `entries`,
    /// computed before `signature` is populated.
    pub manifest_sha256: String,
    /// Hex-encoded signature over `manifest_sha256`, present only when
    /// export was given a signing key. Scheme is named by
    /// [`Self::signature_algorithm`].
    pub signature: Option<String>,
    /// Which scheme `signature` was produced with. `#[serde(default)]` so a
    /// P3-exported (`BUNDLE_VERSION` 1) manifest — which has no such field
    /// at all — parses with this as `None`, treated identically to
    /// `Some("hmac-sha256")` on import (see module docs).
    #[serde(default)]
    pub signature_algorithm: Option<String>,
}

/// Serializes `entries` (sorted for determinism — export/import order must
/// never affect the checksum) to canonical JSON bytes for hashing/signing.
fn canonical_entries_bytes(entries: &[BundleManifestEntry]) -> Vec<u8> {
    let mut sorted = entries.to_vec();
    sorted.sort();
    // `serde_json::to_vec` is deterministic for a fixed struct field order
    // (it does not reorder map keys for a struct, only for `Value`/maps),
    // so this is stable across runs/platforms given the same sorted input.
    serde_json::to_vec(&sorted).unwrap_or_default()
}

/// sha256 over `entries`' canonical bytes.
fn compute_manifest_hash(entries: &[BundleManifestEntry]) -> String {
    skauswatch_scan_core::compute_hashes(&canonical_entries_bytes(entries)).sha256
}

// Signing (not just verifying) via HMAC has no production caller since P4
// moved export to `rsa_sign` exclusively — kept only to construct
// legacy-shaped (`signature_algorithm: "hmac-sha256"`) fixtures in this
// module's own backward-compatibility tests below.
#[cfg(test)]
fn hmac_hex(key: &str, message: &str) -> Result<String, BundleError> {
    // A key that fails `Hmac::new_from_slice` (wrong length) never happens
    // for HMAC-SHA256, which accepts any key length — infallible in
    // practice, but propagate rather than panic per this workspace's
    // no-`.unwrap()` convention.
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .map_err(|e| BundleError::Io(std::io::Error::other(e.to_string())))?;
    mac.update(message.as_bytes());
    Ok(hex_lower(&mac.finalize().into_bytes()))
}

fn hmac_verify(key: &str, message: &str, signature_hex: &str) -> bool {
    let Ok(expected) = hex_decode(signature_hex) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(key.as_bytes()) else {
        return false;
    };
    mac.update(message.as_bytes());
    mac.verify_slice(&expected).is_ok()
}

/// Signs `message` with `private_key_pem` (accepts PKCS#8 or PKCS#1 PEM) —
/// `RSASSA-PKCS1-v1_5`-SHA256, the same scheme+primitives
/// `src/provenance.rs` uses to verify cosign signatures.
fn rsa_sign(private_key_pem: &str, message: &str) -> Result<String, BundleError> {
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::DecodeRsaPrivateKey as _;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey as _;
    use rsa::sha2::Sha256;
    use rsa::signature::{SignatureEncoding as _, Signer as _};

    let key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(private_key_pem))
        .map_err(|e| BundleError::InvalidSigningKey(e.to_string()))?;
    let signing_key = SigningKey::<Sha256>::new(key);
    let signature = signing_key.sign(message.as_bytes());
    Ok(hex_lower(&signature.to_bytes()))
}

/// Verifies `signature_hex` against `message` using `public_key_pem`
/// (accepts PKCS#8 SPKI or PKCS#1 PEM). `false` for any parse or
/// cryptographic failure.
fn rsa_verify(public_key_pem: &str, message: &str, signature_hex: &str) -> bool {
    use rsa::RsaPublicKey;
    use rsa::pkcs1::DecodeRsaPublicKey as _;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::DecodePublicKey as _;
    use rsa::sha2::Sha256;
    use rsa::signature::Verifier as _;

    let Ok(pub_key) = RsaPublicKey::from_public_key_pem(public_key_pem)
        .or_else(|_| RsaPublicKey::from_pkcs1_pem(public_key_pem))
    else {
        return false;
    };
    let Ok(sig_bytes) = hex_decode(signature_hex) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(sig_bytes.as_slice()) else {
        return false;
    };
    let verifying_key = VerifyingKey::<Sha256>::new(pub_key);
    verifying_key.verify(message.as_bytes(), &signature).is_ok()
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

/// Export/import summary returned to the CLI.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BundleStats {
    /// Number of `(ecosystem, name, reference)` manifest entries.
    pub entry_count: usize,
    /// Number of unique artifact blobs (`entries` may share a `sha256`).
    pub unique_blob_count: usize,
    /// The manifest checksum.
    pub manifest_sha256: String,
    /// Whether the bundle was signed (export) / signature verified
    /// (import).
    pub signed: bool,
}

/// Exports every `verdict = clean` artifact (fleet-wide — export is a
/// connected-side maintenance operation, not a per-tenant one) into a
/// `.zip` bundle at `out_path`.
///
/// # Errors
/// See [`BundleError`].
pub async fn export_bundle(
    pool: &PgPool,
    s3: &S3Client,
    bucket: &str,
    cache_prefix: &str,
    out_path: &std::path::Path,
    signing_private_key_pem: Option<&str>,
) -> Result<BundleStats, BundleError> {
    let rows = db::list_clean_artifacts_all_tenants(pool).await?;
    let entries: Vec<BundleManifestEntry> = rows.iter().map(BundleManifestEntry::from).collect();

    let file = std::fs::File::create(out_path)?;
    let mut writer = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default();

    let mut written = std::collections::HashSet::new();
    let mut bundled_entries = Vec::with_capacity(entries.len());
    for entry in entries {
        if written.contains(&entry.sha256) {
            bundled_entries.push(entry);
            continue;
        }
        let key = cache::object_key(cache_prefix, &entry.sha256);
        let Some(obj) = cache::get_object(s3, bucket, &key).await? else {
            tracing::warn!(sha256 = %entry.sha256, "bundle export: cache object missing, skipping entry");
            continue;
        };
        writer.start_file(format!("artifacts/{}", entry.sha256), options)?;
        writer.write_all(&obj.bytes)?;
        written.insert(entry.sha256.clone());
        bundled_entries.push(entry);
    }

    let manifest_sha256 = compute_manifest_hash(&bundled_entries);
    let (signature, signature_algorithm) = match signing_private_key_pem {
        Some(pem) => (
            Some(rsa_sign(pem, &manifest_sha256)?),
            Some(RSA_ALGO.to_owned()),
        ),
        None => (None, None),
    };
    let manifest = BundleManifest {
        version: BUNDLE_VERSION,
        created_at: chrono::Utc::now().to_rfc3339(),
        entries: bundled_entries,
        manifest_sha256: manifest_sha256.clone(),
        signature: signature.clone(),
        signature_algorithm,
    };
    writer.start_file("manifest.json", options)?;
    writer.write_all(&serde_json::to_vec_pretty(&manifest).unwrap_or_default())?;
    writer.finish()?;

    Ok(BundleStats {
        entry_count: manifest.entries.len(),
        unique_blob_count: written.len(),
        manifest_sha256,
        signed: signature.is_some(),
    })
}

/// Imports a `.zip` bundle from `in_path`, verifying the manifest checksum,
/// optional signature, and every artifact's own content hash **before**
/// admitting anything to the cache/DB — all-or-nothing.
///
/// # Errors
/// See [`BundleError`]. On any verification failure, nothing is written to
/// S3 or the database.
// One argument per distinct piece of data this entry point needs — mirrors
// `src/config.rs::resolve_depgate`'s identical allow: a params struct would
// just move the same fields without adding clarity for a single call site
// (`src/main.rs::run_bundle`).
#[allow(clippy::too_many_arguments)]
pub async fn import_bundle(
    pool: &PgPool,
    s3: &S3Client,
    bucket: &str,
    cache_prefix: &str,
    tenant_id: Uuid,
    in_path: &std::path::Path,
    hmac_verify_key: Option<&str>,
    rsa_verify_public_key_pem: Option<&str>,
    bundle_name: &str,
) -> Result<BundleStats, BundleError> {
    let file = std::fs::File::open(in_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    let mut manifest_bytes = Vec::new();
    archive
        .by_name("manifest.json")
        .map_err(|_| BundleError::MissingManifest)?
        .read_to_end(&mut manifest_bytes)?;
    let manifest: BundleManifest = serde_json::from_slice(&manifest_bytes)?;
    if manifest.version < MIN_SUPPORTED_BUNDLE_VERSION || manifest.version > BUNDLE_VERSION {
        return Err(BundleError::UnsupportedVersion {
            found: manifest.version,
            expected: BUNDLE_VERSION,
        });
    }

    let computed = compute_manifest_hash(&manifest.entries);
    if computed != manifest.manifest_sha256 {
        return Err(BundleError::ManifestChecksumMismatch {
            claimed: manifest.manifest_sha256,
            computed,
        });
    }

    // Backward compatibility (module docs): a v1 manifest (or any manifest
    // omitting the field) is treated as HMAC-signed, exactly as P3 verified
    // it; only an explicit `"rsa-pkcs1v15-sha256"` switches to the new
    // asymmetric path.
    let signature_verified = match &manifest.signature {
        Some(sig) => {
            let algo = manifest.signature_algorithm.as_deref().unwrap_or(HMAC_ALGO);
            match algo {
                HMAC_ALGO => match hmac_verify_key {
                    Some(key) => {
                        if !hmac_verify(key, &manifest.manifest_sha256, sig) {
                            return Err(BundleError::SignatureMismatch);
                        }
                        true
                    }
                    None => false,
                },
                RSA_ALGO => match rsa_verify_public_key_pem {
                    Some(pem) => {
                        if !rsa_verify(pem, &manifest.manifest_sha256, sig) {
                            return Err(BundleError::SignatureMismatch);
                        }
                        true
                    }
                    None => false,
                },
                other => {
                    return Err(BundleError::UnsupportedSignatureAlgorithm(other.to_owned()));
                }
            }
        }
        None => {
            if hmac_verify_key.is_some() || rsa_verify_public_key_pem.is_some() {
                return Err(BundleError::MissingSignature);
            }
            false
        }
    };

    // Pre-flight: verify EVERY unique artifact's content hash before
    // writing anything — all-or-nothing, no partial trust.
    let mut unique_sha256s: Vec<&str> =
        manifest.entries.iter().map(|e| e.sha256.as_str()).collect();
    unique_sha256s.sort_unstable();
    unique_sha256s.dedup();

    let mut verified: std::collections::HashMap<String, bytes::Bytes> =
        std::collections::HashMap::with_capacity(unique_sha256s.len());
    for sha256 in &unique_sha256s {
        let mut buf = Vec::new();
        let entry_name = format!("artifacts/{sha256}");
        archive
            .by_name(&entry_name)
            .map_err(|_| BundleError::MissingArtifact((*sha256).to_owned()))?
            .read_to_end(&mut buf)?;
        let computed = skauswatch_scan_core::compute_hashes(&buf).sha256;
        if &computed != sha256 {
            return Err(BundleError::ArtifactHashMismatch {
                claimed: (*sha256).to_owned(),
                computed,
            });
        }
        verified.insert((*sha256).to_owned(), bytes::Bytes::from(buf));
    }

    // Every check passed — now, and only now, admit the bundle.
    for sha256 in &unique_sha256s {
        let Some(bytes) = verified.get(*sha256) else {
            continue;
        };
        let entry = manifest
            .entries
            .iter()
            .find(|e| e.sha256 == *sha256)
            .ok_or_else(|| BundleError::MissingArtifact((*sha256).to_owned()))?;
        let key = cache::object_key(cache_prefix, sha256);
        let content_type = entry
            .content_type
            .as_deref()
            .unwrap_or("application/octet-stream");
        cache::put_object(s3, bucket, &key, bytes.clone(), content_type).await?;
        cache::put_tags(
            s3,
            bucket,
            &key,
            &[
                ("threat".to_owned(), "clean".to_owned()),
                ("scannerVersion".to_owned(), entry.scanner_version.clone()),
            ],
        )
        .await?;
    }
    for entry in &manifest.entries {
        db::upsert_artifact(
            pool,
            &db::UpsertArtifact {
                ecosystem: &entry.ecosystem,
                name: &entry.name,
                reference: &entry.reference,
                sha256: &entry.sha256,
                upstream: &format!("bundle:{bundle_name}"),
                content_type: entry.content_type.as_deref(),
                size_bytes: entry.size_bytes,
                verdict: "clean",
                scanner_version: &entry.scanner_version,
                pinned: true,
                tenant_id,
            },
        )
        .await?;
    }

    db::insert_bundle_import(
        pool,
        tenant_id,
        bundle_name,
        &manifest.manifest_sha256,
        signature_verified,
        i32::try_from(manifest.entries.len()).unwrap_or(i32::MAX),
    )
    .await?;

    Ok(BundleStats {
        entry_count: manifest.entries.len(),
        unique_blob_count: unique_sha256s.len(),
        manifest_sha256: manifest.manifest_sha256,
        signed: signature_verified,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;

    fn sample_entries() -> Vec<BundleManifestEntry> {
        vec![
            BundleManifestEntry {
                ecosystem: "npm".to_owned(),
                name: "left-pad".to_owned(),
                reference: "1.3.0".to_owned(),
                sha256: "a".repeat(64),
                verdict: "clean".to_owned(),
                scanner_version: "1.0.0".to_owned(),
                content_type: Some("application/octet-stream".to_owned()),
                size_bytes: 42,
            },
            BundleManifestEntry {
                ecosystem: "oci".to_owned(),
                name: "library/nginx".to_owned(),
                reference: "latest".to_owned(),
                sha256: "b".repeat(64),
                verdict: "clean".to_owned(),
                scanner_version: "1.0.0".to_owned(),
                content_type: None,
                size_bytes: 100,
            },
        ]
    }

    #[test]
    fn manifest_hash_is_order_independent() {
        let mut a = sample_entries();
        let mut b = sample_entries();
        b.reverse();
        assert_eq!(compute_manifest_hash(&a), compute_manifest_hash(&b));
        a.push(a[0].clone());
        assert_ne!(compute_manifest_hash(&a), compute_manifest_hash(&b));
    }

    #[test]
    fn hmac_sign_and_verify_round_trips() {
        let sig = hmac_hex("test-key", "deadbeef").expect("sign");
        assert!(hmac_verify("test-key", "deadbeef", &sig));
    }

    #[test]
    fn hmac_verify_rejects_wrong_key() {
        let sig = hmac_hex("test-key", "deadbeef").expect("sign");
        assert!(!hmac_verify("other-key", "deadbeef", &sig));
    }

    #[test]
    fn hmac_verify_rejects_tampered_message() {
        let sig = hmac_hex("test-key", "deadbeef").expect("sign");
        assert!(!hmac_verify("test-key", "tampered", &sig));
    }

    #[test]
    fn hmac_verify_rejects_malformed_hex() {
        assert!(!hmac_verify("test-key", "deadbeef", "not-hex!!"));
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0xde, 0xad, 0xbe, 0xef];
        let hex = hex_lower(&bytes);
        assert_eq!(hex, "deadbeef");
        assert_eq!(hex_decode(&hex).expect("decode"), bytes.to_vec());
    }

    #[test]
    fn hex_decode_rejects_odd_length() {
        assert!(hex_decode("abc").is_err());
    }

    // -- export/import integration tests --------------------------------

    use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
    use sqlx::PgPool;
    use wiremock::matchers::{method, path as wpath};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn test_pool() -> PgPool {
        skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")).await
    }

    fn mock_s3_client(uri: &str) -> S3Client {
        let creds = Credentials::new("AKTEST", "SKTEST", None, None, "depgate-test");
        let cfg = aws_sdk_s3::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .endpoint_url(uri)
            .force_path_style(true)
            .credentials_provider(creds)
            .build();
        S3Client::from_conf(cfg)
    }

    fn s3_error_xml(code: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <Error><Code>{code}</Code><Message>not found</Message>\
             <RequestId>r</RequestId><HostId>h</HostId></Error>"
        )
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("depgate-bundle-test-{}-{name}", Uuid::new_v4()))
    }

    /// Rewrites the zip at `src`, flipping the first byte of the
    /// `artifacts/{sha256}` entry, and writes the result to `dest` — the
    /// tamper step for the export -> tamper -> import-must-reject test.
    fn tamper_artifact_byte(src: &std::path::Path, dest: &std::path::Path, sha256: &str) {
        let mut archive = zip::ZipArchive::new(std::fs::File::open(src).expect("open source zip"))
            .expect("read source zip");
        let target_name = format!("artifacts/{sha256}");
        let mut writer = zip::ZipWriter::new(std::fs::File::create(dest).expect("create dest zip"));
        let options = zip::write::SimpleFileOptions::default();
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).expect("read entry");
            let name = entry.name().to_owned();
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).expect("read entry bytes");
            if name == target_name {
                buf[0] ^= 0xFF;
            }
            writer.start_file(&name, options).expect("start_file");
            writer.write_all(&buf).expect("write entry");
        }
        writer.finish().expect("finish zip");
    }

    #[tokio::test]
    async fn export_then_import_round_trips_a_clean_artifact() {
        let pool = test_pool().await;
        let tenant = Uuid::new_v4();
        let body = b"hello depgate bundle".to_vec();
        let hex = skauswatch_scan_core::compute_hashes(&body).sha256;

        db::upsert_artifact(
            &pool,
            &db::UpsertArtifact {
                ecosystem: "npm",
                name: "left-pad",
                reference: "left-pad-1.3.0.tgz",
                sha256: &hex,
                upstream: "https://registry.npmjs.org",
                content_type: Some("application/octet-stream"),
                size_bytes: body.len() as i64,
                verdict: "clean",
                scanner_version: "1.0.0",
                pinned: true,
                tenant_id: tenant,
            },
        )
        .await
        .expect("seed artifact");

        let source_s3 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wpath(format!("/bkt/sha256/{hex}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(body.clone()),
            )
            .mount(&source_s3)
            .await;

        let out_path = temp_path("export.zip");
        let stats = export_bundle(
            &pool,
            &mock_s3_client(&source_s3.uri()),
            "bkt",
            "sha256/",
            &out_path,
            Some(&crate::test_support::test_keypair().0),
        )
        .await
        .expect("export succeeds");
        assert_eq!(stats.entry_count, 1);
        assert_eq!(stats.unique_blob_count, 1);
        assert!(stats.signed);

        // Import into a fresh "air-gapped" pool + fresh S3 destination.
        let dest_pool = test_pool().await;
        let dest_tenant = Uuid::new_v4();
        let dest_s3 = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(wpath(format!("/bkt2/sha256/{hex}")))
            .respond_with(ResponseTemplate::new(200))
            .mount(&dest_s3)
            .await;

        let import_stats = import_bundle(
            &dest_pool,
            &mock_s3_client(&dest_s3.uri()),
            "bkt2",
            "sha256/",
            dest_tenant,
            &out_path,
            None,
            Some(&crate::test_support::test_keypair().1),
            "test-bundle.zip",
        )
        .await
        .expect("import succeeds");
        assert_eq!(import_stats.entry_count, 1);
        assert!(import_stats.signed);

        let row = db::find_by_reference(&dest_pool, "npm", "left-pad", "left-pad-1.3.0.tgz")
            .await
            .expect("query")
            .expect("row imported");
        assert_eq!(row.sha256, hex);
        assert_eq!(row.verdict, "clean");
        assert!(row.pinned, "imported artifacts are always pinned");

        let _ = std::fs::remove_file(&out_path);
    }

    #[tokio::test]
    async fn import_rejects_a_bundle_missing_the_required_signature() {
        let pool = test_pool().await;
        let tenant = Uuid::new_v4();
        let body = b"unsigned bundle content".to_vec();
        let hex = skauswatch_scan_core::compute_hashes(&body).sha256;
        db::upsert_artifact(
            &pool,
            &db::UpsertArtifact {
                ecosystem: "oci",
                name: "library/nginx",
                reference: "latest",
                sha256: &hex,
                upstream: "https://registry-1.docker.io",
                content_type: None,
                size_bytes: body.len() as i64,
                verdict: "clean",
                scanner_version: "1.0.0",
                pinned: false,
                tenant_id: tenant,
            },
        )
        .await
        .expect("seed artifact");

        let source_s3 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wpath(format!("/bkt/sha256/{hex}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&source_s3)
            .await;

        let out_path = temp_path("unsigned.zip");
        export_bundle(
            &pool,
            &mock_s3_client(&source_s3.uri()),
            "bkt",
            "sha256/",
            &out_path,
            None, // no signing key configured on export
        )
        .await
        .expect("export succeeds");

        let dest_pool = test_pool().await;
        let dest_s3 = MockServer::start().await;
        let err = import_bundle(
            &dest_pool,
            &mock_s3_client(&dest_s3.uri()),
            "bkt2",
            "sha256/",
            Uuid::new_v4(),
            &out_path,
            Some("importer-requires-a-key"),
            None,
            "unsigned.zip",
        )
        .await
        .expect_err("must refuse an unsigned bundle when a key is configured");
        assert!(matches!(err, BundleError::MissingSignature));

        assert!(
            db::find_by_reference(&dest_pool, "oci", "library/nginx", "latest")
                .await
                .expect("query")
                .is_none(),
            "nothing should be admitted on a rejected import"
        );

        let _ = std::fs::remove_file(&out_path);
    }

    #[tokio::test]
    async fn import_rejects_the_whole_bundle_when_one_artifact_byte_is_tampered() {
        let pool = test_pool().await;
        let tenant = Uuid::new_v4();
        let body_a = b"artifact A bytes".to_vec();
        let body_b = b"artifact B bytes, a different length entirely".to_vec();
        let hex_a = skauswatch_scan_core::compute_hashes(&body_a).sha256;
        let hex_b = skauswatch_scan_core::compute_hashes(&body_b).sha256;

        for (name, hex, body) in [("pkg-a", &hex_a, &body_a), ("pkg-b", &hex_b, &body_b)] {
            db::upsert_artifact(
                &pool,
                &db::UpsertArtifact {
                    ecosystem: "npm",
                    name,
                    reference: "1.0.0.tgz",
                    sha256: hex,
                    upstream: "https://registry.npmjs.org",
                    content_type: None,
                    size_bytes: body.len() as i64,
                    verdict: "clean",
                    scanner_version: "1.0.0",
                    pinned: false,
                    tenant_id: tenant,
                },
            )
            .await
            .expect("seed artifact");
        }

        let source_s3 = MockServer::start().await;
        for (hex, body) in [(&hex_a, &body_a), (&hex_b, &body_b)] {
            Mock::given(method("GET"))
                .and(wpath(format!("/bkt/sha256/{hex}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
                .mount(&source_s3)
                .await;
        }

        let clean_path = temp_path("clean.zip");
        export_bundle(
            &pool,
            &mock_s3_client(&source_s3.uri()),
            "bkt",
            "sha256/",
            &clean_path,
            None,
        )
        .await
        .expect("export succeeds");

        let tampered_path = temp_path("tampered.zip");
        tamper_artifact_byte(&clean_path, &tampered_path, &hex_a);

        let dest_pool = test_pool().await;
        let dest_s3 = MockServer::start().await;
        let err = import_bundle(
            &dest_pool,
            &mock_s3_client(&dest_s3.uri()),
            "bkt2",
            "sha256/",
            Uuid::new_v4(),
            &tampered_path,
            None,
            None,
            "tampered.zip",
        )
        .await
        .expect_err("tampered artifact must be rejected");
        assert!(matches!(err, BundleError::ArtifactHashMismatch { .. }));

        // All-or-nothing: neither artifact was admitted, not even the
        // untampered one.
        assert!(
            db::find_by_reference(&dest_pool, "npm", "pkg-a", "1.0.0.tgz")
                .await
                .expect("query")
                .is_none()
        );
        assert!(
            db::find_by_reference(&dest_pool, "npm", "pkg-b", "1.0.0.tgz")
                .await
                .expect("query")
                .is_none()
        );

        let _ = std::fs::remove_file(&clean_path);
        let _ = std::fs::remove_file(&tampered_path);
    }

    #[tokio::test]
    async fn import_rejects_a_bundle_with_a_missing_artifact_entry() {
        // A manifest that references an artifact the archive simply never
        // contains (e.g. a truncated transfer) — `MissingArtifact`, not a
        // hash-mismatch, and still refused before anything is written.
        let manifest_bytes;
        {
            let entries = vec![BundleManifestEntry {
                ecosystem: "oci".to_owned(),
                name: "library/ghost".to_owned(),
                reference: "latest".to_owned(),
                sha256: "c".repeat(64),
                verdict: "clean".to_owned(),
                scanner_version: "1.0.0".to_owned(),
                content_type: None,
                size_bytes: 5,
            }];
            let manifest_sha256 = compute_manifest_hash(&entries);
            let manifest = BundleManifest {
                version: BUNDLE_VERSION,
                created_at: chrono::Utc::now().to_rfc3339(),
                entries,
                manifest_sha256,
                signature: None,
                signature_algorithm: None,
            };
            manifest_bytes = serde_json::to_vec_pretty(&manifest).expect("serialize manifest");
        }

        let path = temp_path("missing-artifact.zip");
        {
            let mut writer = zip::ZipWriter::new(std::fs::File::create(&path).expect("create"));
            let options = zip::write::SimpleFileOptions::default();
            writer
                .start_file("manifest.json", options)
                .expect("start_file");
            writer.write_all(&manifest_bytes).expect("write manifest");
            writer.finish().expect("finish");
        }

        let pool = test_pool().await;
        let s3 = MockServer::start().await;
        let err = import_bundle(
            &pool,
            &mock_s3_client(&s3.uri()),
            "bkt",
            "sha256/",
            Uuid::new_v4(),
            &path,
            None,
            None,
            "missing-artifact.zip",
        )
        .await
        .expect_err("must refuse a bundle with a missing artifact entry");
        assert!(matches!(err, BundleError::MissingArtifact(_)));

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn import_rejects_a_tampered_manifest_checksum() {
        let path = temp_path("bad-manifest.zip");
        let manifest = BundleManifest {
            version: BUNDLE_VERSION,
            created_at: chrono::Utc::now().to_rfc3339(),
            entries: sample_entries(),
            manifest_sha256: "not-the-real-checksum".to_owned(),
            signature: None,
            signature_algorithm: None,
        };
        {
            let mut writer = zip::ZipWriter::new(std::fs::File::create(&path).expect("create"));
            let options = zip::write::SimpleFileOptions::default();
            writer
                .start_file("manifest.json", options)
                .expect("start_file");
            writer
                .write_all(&serde_json::to_vec_pretty(&manifest).expect("serialize"))
                .expect("write manifest");
            writer.finish().expect("finish");
        }

        let pool = test_pool().await;
        let s3 = MockServer::start().await;
        let err = import_bundle(
            &pool,
            &mock_s3_client(&s3.uri()),
            "bkt",
            "sha256/",
            Uuid::new_v4(),
            &path,
            None,
            None,
            "bad-manifest.zip",
        )
        .await
        .expect_err("must refuse a checksum mismatch");
        assert!(matches!(err, BundleError::ManifestChecksumMismatch { .. }));

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn export_skips_an_artifact_whose_cache_object_was_evicted() {
        let pool = test_pool().await;
        let tenant = Uuid::new_v4();
        db::upsert_artifact(
            &pool,
            &db::UpsertArtifact {
                ecosystem: "oci",
                name: "library/gone",
                reference: "latest",
                sha256: "deadbeef",
                upstream: "https://registry-1.docker.io",
                content_type: None,
                size_bytes: 0,
                verdict: "clean",
                scanner_version: "1.0.0",
                pinned: false,
                tenant_id: tenant,
            },
        )
        .await
        .expect("seed artifact");

        let s3 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wpath("/bkt/sha256/deadbeef"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_raw(s3_error_xml("NoSuchKey"), "application/xml"),
            )
            .mount(&s3)
            .await;

        let out_path = temp_path("skip-evicted.zip");
        let stats = export_bundle(
            &pool,
            &mock_s3_client(&s3.uri()),
            "bkt",
            "sha256/",
            &out_path,
            None,
        )
        .await
        .expect("export succeeds even with a missing object");
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.unique_blob_count, 0);

        let _ = std::fs::remove_file(&out_path);
    }

    // -- P4: asymmetric signing + backward compatibility ------------------

    fn write_manifest_zip(path: &std::path::Path, manifest_json: &serde_json::Value) {
        let mut writer = zip::ZipWriter::new(std::fs::File::create(path).expect("create"));
        let options = zip::write::SimpleFileOptions::default();
        writer
            .start_file("manifest.json", options)
            .expect("start_file");
        writer
            .write_all(&serde_json::to_vec_pretty(manifest_json).expect("serialize"))
            .expect("write manifest");
        writer.finish().expect("finish");
    }

    #[test]
    fn rsa_sign_and_verify_round_trips() {
        let (private_pem, public_pem) = crate::test_support::test_keypair();
        let sig = rsa_sign(private_pem, "deadbeef").expect("sign");
        assert!(rsa_verify(public_pem, "deadbeef", &sig));
    }

    #[test]
    fn rsa_verify_rejects_wrong_key() {
        let (private_pem, _) = crate::test_support::test_keypair();
        let sig = rsa_sign(private_pem, "deadbeef").expect("sign");
        let other_pub = crate::test_support::other_test_public_key_pem();
        assert!(!rsa_verify(&other_pub, "deadbeef", &sig));
    }

    #[test]
    fn rsa_verify_rejects_tampered_message() {
        let (private_pem, public_pem) = crate::test_support::test_keypair();
        let sig = rsa_sign(private_pem, "deadbeef").expect("sign");
        assert!(!rsa_verify(public_pem, "tampered", &sig));
    }

    #[test]
    fn rsa_verify_rejects_malformed_hex() {
        let (_, public_pem) = crate::test_support::test_keypair();
        assert!(!rsa_verify(public_pem, "deadbeef", "not-hex!!"));
    }

    #[test]
    fn export_bundle_with_no_signing_key_writes_no_signature_algorithm() {
        // Distinct from the round-trip test above: proves the *shape* of an
        // unsigned export, not just that import tolerates it.
        let entries = sample_entries();
        let manifest_sha256 = compute_manifest_hash(&entries);
        let manifest = BundleManifest {
            version: BUNDLE_VERSION,
            created_at: chrono::Utc::now().to_rfc3339(),
            entries,
            manifest_sha256,
            signature: None,
            signature_algorithm: None,
        };
        let json = serde_json::to_value(&manifest).expect("serialize");
        assert!(json["signature_algorithm"].is_null());
    }

    #[tokio::test]
    async fn import_accepts_a_legacy_v1_manifest_with_no_signature_algorithm_field_in_json() {
        // Simulates an actual bundle exported by the pre-P4 build: the JSON
        // object has NO `signature_algorithm` key at all (not merely a
        // `null` value) — `#[serde(default)]` must still parse it and
        // `import_bundle` must still verify it via the legacy HMAC key.
        let hmac_key = "legacy-hmac-key";
        let entries = sample_entries();
        let manifest_sha256 = compute_manifest_hash(&entries);
        let signature = hmac_hex(hmac_key, &manifest_sha256).expect("sign");
        let raw_json = serde_json::json!({
            "version": 1,
            "created_at": chrono::Utc::now().to_rfc3339(),
            "entries": entries,
            "manifest_sha256": manifest_sha256,
            "signature": signature,
            // deliberately no "signature_algorithm" key
        });

        let path = temp_path("legacy-v1.zip");
        write_manifest_zip(&path, &raw_json);

        // No artifact bytes needed for this assertion — the manifest/
        // signature verification happens before any artifact is read, and
        // `sample_entries()`'s bytes were never uploaded anywhere; expect a
        // `MissingArtifact` failure AFTER signature verification succeeds,
        // proving the legacy signature path itself was accepted.
        let pool = test_pool().await;
        let s3 = MockServer::start().await;
        let err = import_bundle(
            &pool,
            &mock_s3_client(&s3.uri()),
            "bkt",
            "sha256/",
            Uuid::new_v4(),
            &path,
            Some(hmac_key),
            None,
            "legacy-v1.zip",
        )
        .await
        .expect_err("no artifact bytes are present in this synthetic bundle");
        assert!(
            matches!(err, BundleError::MissingArtifact(_)),
            "expected to get past signature verification and fail on missing artifact \
             bytes instead, got {err:?}"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn import_rejects_an_rsa_signature_that_does_not_verify() {
        let entries = sample_entries();
        let manifest_sha256 = compute_manifest_hash(&entries);
        let (private_pem, _) = crate::test_support::test_keypair();
        let signature = rsa_sign(private_pem, &manifest_sha256).expect("sign");
        let manifest = BundleManifest {
            version: BUNDLE_VERSION,
            created_at: chrono::Utc::now().to_rfc3339(),
            entries,
            manifest_sha256,
            signature: Some(signature),
            signature_algorithm: Some(RSA_ALGO.to_owned()),
        };
        let path = temp_path("rsa-wrong-key.zip");
        write_manifest_zip(&path, &serde_json::to_value(&manifest).expect("serialize"));

        let pool = test_pool().await;
        let s3 = MockServer::start().await;
        let other_pub = crate::test_support::other_test_public_key_pem();
        let err = import_bundle(
            &pool,
            &mock_s3_client(&s3.uri()),
            "bkt",
            "sha256/",
            Uuid::new_v4(),
            &path,
            None,
            Some(&other_pub),
            "rsa-wrong-key.zip",
        )
        .await
        .expect_err("must refuse an RSA signature that doesn't verify against this key");
        assert!(matches!(err, BundleError::SignatureMismatch));

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn import_rejects_an_unsupported_signature_algorithm() {
        let entries = sample_entries();
        let manifest_sha256 = compute_manifest_hash(&entries);
        let manifest = BundleManifest {
            version: BUNDLE_VERSION,
            created_at: chrono::Utc::now().to_rfc3339(),
            entries,
            manifest_sha256,
            signature: Some("deadbeef".to_owned()),
            signature_algorithm: Some("ed25519".to_owned()),
        };
        let path = temp_path("unsupported-algo.zip");
        write_manifest_zip(&path, &serde_json::to_value(&manifest).expect("serialize"));

        let pool = test_pool().await;
        let s3 = MockServer::start().await;
        let err = import_bundle(
            &pool,
            &mock_s3_client(&s3.uri()),
            "bkt",
            "sha256/",
            Uuid::new_v4(),
            &path,
            Some("whatever"),
            Some("whatever"),
            "unsupported-algo.zip",
        )
        .await
        .expect_err("must refuse a signature algorithm this build doesn't understand");
        assert!(matches!(
            err,
            BundleError::UnsupportedSignatureAlgorithm(ref a) if a == "ed25519"
        ));

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn import_rejects_a_bundle_version_below_the_minimum_supported() {
        let entries = sample_entries();
        let manifest_sha256 = compute_manifest_hash(&entries);
        let manifest = BundleManifest {
            version: 0,
            created_at: chrono::Utc::now().to_rfc3339(),
            entries,
            manifest_sha256,
            signature: None,
            signature_algorithm: None,
        };
        let path = temp_path("version-too-old.zip");
        write_manifest_zip(&path, &serde_json::to_value(&manifest).expect("serialize"));

        let pool = test_pool().await;
        let s3 = MockServer::start().await;
        let err = import_bundle(
            &pool,
            &mock_s3_client(&s3.uri()),
            "bkt",
            "sha256/",
            Uuid::new_v4(),
            &path,
            None,
            None,
            "version-too-old.zip",
        )
        .await
        .expect_err("version 0 predates this build's minimum supported version");
        assert!(matches!(
            err,
            BundleError::UnsupportedVersion { found: 0, .. }
        ));

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn import_rejects_a_bundle_version_above_what_this_build_understands() {
        let entries = sample_entries();
        let manifest_sha256 = compute_manifest_hash(&entries);
        let manifest = BundleManifest {
            version: BUNDLE_VERSION + 1,
            created_at: chrono::Utc::now().to_rfc3339(),
            entries,
            manifest_sha256,
            signature: None,
            signature_algorithm: None,
        };
        let path = temp_path("version-too-new.zip");
        write_manifest_zip(&path, &serde_json::to_value(&manifest).expect("serialize"));

        let pool = test_pool().await;
        let s3 = MockServer::start().await;
        let err = import_bundle(
            &pool,
            &mock_s3_client(&s3.uri()),
            "bkt",
            "sha256/",
            Uuid::new_v4(),
            &path,
            None,
            None,
            "version-too-new.zip",
        )
        .await
        .expect_err("a version newer than this build supports must be refused");
        assert!(matches!(
            err,
            BundleError::UnsupportedVersion { found, .. } if found == BUNDLE_VERSION + 1
        ));

        let _ = std::fs::remove_file(&path);
    }
}
