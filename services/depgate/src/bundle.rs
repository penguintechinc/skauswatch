//! Air-gap bundle export/import (`docs/v2-port/v2.1-depgate.md` §6b) — a
//! single portable `.zip` archive containing `manifest.json` (the vetted
//! artifact index: sha256/ecosystem/name/reference/verdict/scanner
//! version) plus one `artifacts/<sha256>` entry per unique blob. Export
//! runs on a connected system (real scanning already happened at ingest);
//! import verifies everything — manifest checksum, optional HMAC
//! signature, and every artifact's own content hash — before admitting
//! anything: **all-or-nothing, no partial trust**.
//!
//! Signing is HMAC-SHA256 over the manifest checksum, keyed by
//! `DEPGATE_BUNDLE_SIGNING_KEY` (`crate::config::DepgateConfig::
//! bundle_signing_key`) — a symmetric MAC standing in for the spec's
//! eventual cosign/sigstore asymmetric signing (deferred to P4,
//! `docs/v2-port/v2.1-depgate.md` §9/§11). Reuses this workspace's existing
//! `hmac`+`sha2` dependencies (see
//! `services/manager/src/routes/endpoint.rs` for the same pattern) rather
//! than adding a new signing stack for P3.
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

/// Bundle format version — bump on any breaking manifest-shape change so an
/// importer can refuse an incompatible bundle outright instead of
/// misparsing it.
pub const BUNDLE_VERSION: u32 = 1;

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
    /// Base64-free hex HMAC-SHA256 of `manifest_sha256`, present only when
    /// export was given a signing key.
    pub signature: Option<String>,
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
    signing_key: Option<&str>,
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
    let signature = signing_key
        .map(|key| hmac_hex(key, &manifest_sha256))
        .transpose()?;
    let manifest = BundleManifest {
        version: BUNDLE_VERSION,
        created_at: chrono::Utc::now().to_rfc3339(),
        entries: bundled_entries,
        manifest_sha256: manifest_sha256.clone(),
        signature: signature.clone(),
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
    verify_key: Option<&str>,
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
    if manifest.version != BUNDLE_VERSION {
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

    let signature_verified = match (verify_key, &manifest.signature) {
        (Some(key), Some(sig)) => {
            if !hmac_verify(key, &manifest.manifest_sha256, sig) {
                return Err(BundleError::SignatureMismatch);
            }
            true
        }
        (Some(_), None) => return Err(BundleError::MissingSignature),
        (None, _) => false,
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
            Some("test-signing-key"),
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
            Some("test-signing-key"),
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
}
