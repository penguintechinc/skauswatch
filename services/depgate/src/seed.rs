//! `skauswatch-depgate seed` — warm-starts the vetted cache from a seed
//! manifest (`docs/v2-port/v2.1-depgate.md` §2/§9). Pulls, scans, tags, and
//! pins every listed OCI image/npm package/PyPI package ahead of demand —
//! the air-gap warm-start (§6b) across all three P1+P2 ecosystems.

use serde::Deserialize;
use uuid::Uuid;

use crate::scanpipe::PipelineError;
use crate::state::AppState;

/// System-attributed tenant for seed-triggered ingestion — no end-user
/// request initiates this, so there is no caller tenant claim to attribute
/// to. Matches the workspace-wide bootstrap-tenant literal seeded by
/// manager's own migrations (`docs/v2-port/tenancy-model.md`).
pub const BOOTSTRAP_TENANT: &str = "00000000-0000-0000-0000-000000000001";

/// One OCI image entry in a seed manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct SeedImage {
    /// Repository name (e.g. `library/nginx`).
    pub name: String,
    /// Tag or digest to seed.
    pub reference: String,
}

/// One npm package entry in a seed manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct SeedNpmPackage {
    /// Package name (unscoped `left-pad` or scoped `@scope/name`).
    pub name: String,
    /// Exact version to seed.
    pub version: String,
}

/// One PyPI package entry in a seed manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct SeedPypiPackage {
    /// Project name (PyPI's normalization rules apply upstream; passed
    /// through as written).
    pub name: String,
    /// Exact version to seed.
    pub version: String,
}

/// A seed manifest file (see `seeds/penguintech.yaml`). Every list defaults
/// to empty so a manifest can seed any subset of ecosystems.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SeedManifest {
    /// OCI images to warm-start.
    #[serde(default)]
    pub images: Vec<SeedImage>,
    /// npm packages to warm-start.
    #[serde(default)]
    pub npm: Vec<SeedNpmPackage>,
    /// PyPI packages to warm-start.
    #[serde(default)]
    pub pypi: Vec<SeedPypiPackage>,
}

impl SeedManifest {
    /// Parses a manifest from its raw YAML contents.
    ///
    /// # Errors
    /// Returns a `serde_yaml::Error` on malformed YAML.
    pub fn parse(raw: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(raw)
    }
}

/// Runs the seed manifest at `manifest_path` against `state`, logging a
/// per-entry outcome and continuing past individual failures (one bad
/// upstream package must not abort the whole warm-start run).
///
/// # Errors
/// Returns an error only for a manifest-level failure (file unreadable, not
/// valid YAML) — per-entry scan/fetch failures are logged and skipped.
pub async fn run(state: &AppState, manifest_path: &str) -> anyhow::Result<()> {
    let raw = tokio::fs::read_to_string(manifest_path)
        .await
        .map_err(|e| anyhow::anyhow!("read seed manifest {manifest_path}: {e}"))?;
    let manifest = SeedManifest::parse(&raw)
        .map_err(|e| anyhow::anyhow!("parse seed manifest {manifest_path}: {e}"))?;

    let tenant_id: Uuid = BOOTSTRAP_TENANT
        .parse()
        .map_err(|e| anyhow::anyhow!("bootstrap tenant literal is not a valid UUID: {e}"))?;

    let pipeline = state.pipeline();
    let max_bytes = state.cfg.max_artifact_bytes;

    let mut seeded = 0usize;
    let mut failed = 0usize;
    let total = manifest.images.len() + manifest.npm.len() + manifest.pypi.len();

    for image in &manifest.images {
        match pipeline
            .seed_manifest(&image.name, &image.reference, tenant_id)
            .await
        {
            Ok(artifact) => {
                seeded += 1;
                tracing::info!(
                    ecosystem = "oci",
                    name = %image.name,
                    reference = %image.reference,
                    sha256 = %artifact.sha256,
                    "seeded artifact"
                );
            }
            Err(e) => {
                failed += 1;
                tracing::error!(
                    ecosystem = "oci",
                    name = %image.name,
                    reference = %image.reference,
                    error = %e,
                    "seed failed"
                );
            }
        }
    }

    for pkg in &manifest.npm {
        match seed_npm_package(&pipeline, &state.npm, pkg, tenant_id, max_bytes).await {
            Ok(artifact) => {
                seeded += 1;
                tracing::info!(
                    ecosystem = "npm",
                    name = %pkg.name,
                    version = %pkg.version,
                    sha256 = %artifact.sha256,
                    "seeded artifact"
                );
            }
            Err(e) => {
                failed += 1;
                tracing::error!(
                    ecosystem = "npm",
                    name = %pkg.name,
                    version = %pkg.version,
                    error = %e,
                    "seed failed"
                );
            }
        }
    }

    for pkg in &manifest.pypi {
        match seed_pypi_package(&pipeline, &state.pypi, pkg, tenant_id, max_bytes).await {
            Ok(artifact) => {
                seeded += 1;
                tracing::info!(
                    ecosystem = "pypi",
                    name = %pkg.name,
                    version = %pkg.version,
                    sha256 = %artifact.sha256,
                    "seeded artifact"
                );
            }
            Err(e) => {
                failed += 1;
                tracing::error!(
                    ecosystem = "pypi",
                    name = %pkg.name,
                    version = %pkg.version,
                    error = %e,
                    "seed failed"
                );
            }
        }
    }

    tracing::info!(seeded, failed, total, "seed run complete");
    Ok(())
}

/// Resolves `pkg`'s tarball path from its packument, then seeds it through
/// the shared `ScanPipeline::seed_named` path. Takes `npm` as an explicit
/// reference (not the full `AppState`) so it — like every `ScanPipeline`
/// consumer — is independently testable against a wiremock npm registry;
/// see `src/scanpipe.rs` module docs for the same "explicit references over
/// a state god-object" rationale.
async fn seed_npm_package(
    pipeline: &crate::scanpipe::ScanPipeline<'_>,
    npm: &crate::npm::NpmUpstreamClient,
    pkg: &SeedNpmPackage,
    tenant_id: Uuid,
    max_bytes: u64,
) -> Result<crate::scanpipe::ResolvedArtifact, PipelineError> {
    let doc = npm.fetch_packument(&pkg.name, max_bytes).await?;
    let upstream_path =
        crate::npm::tarball_path_for_version(&doc, &pkg.version).ok_or_else(|| {
            PipelineError::BadRequest(format!(
                "npm packument for {} has no tarball for version {}",
                pkg.name, pkg.version
            ))
        })?;
    let filename = upstream_path
        .rsplit('/')
        .next()
        .unwrap_or(&upstream_path)
        .to_owned();
    let upstream_label = npm.base_url().to_owned();
    let path_for_fetch = upstream_path.clone();
    pipeline
        .seed_named(
            "npm",
            &pkg.name,
            &filename,
            &upstream_label,
            tenant_id,
            move || async move {
                npm.fetch_tarball(&path_for_fetch, max_bytes)
                    .await
                    .map(|f| (f.bytes, f.content_type))
                    .map_err(PipelineError::from)
            },
        )
        .await
}

/// Resolves `pkg`'s first release file path from its PyPI JSON API document,
/// then seeds it through the shared `ScanPipeline::seed_named` path. Same
/// explicit-reference rationale as [`seed_npm_package`].
async fn seed_pypi_package(
    pipeline: &crate::scanpipe::ScanPipeline<'_>,
    pypi: &crate::pypi::PypiUpstreamClient,
    pkg: &SeedPypiPackage,
    tenant_id: Uuid,
    max_bytes: u64,
) -> Result<crate::scanpipe::ResolvedArtifact, PipelineError> {
    let doc = pypi.fetch_json_api(&pkg.name, max_bytes).await?;
    let upstream_path =
        crate::pypi::file_path_for_version(&doc, &pkg.version).ok_or_else(|| {
            PipelineError::BadRequest(format!(
                "PyPI JSON API for {} has no release files for version {}",
                pkg.name, pkg.version
            ))
        })?;
    let filename = upstream_path
        .rsplit('/')
        .next()
        .unwrap_or(&upstream_path)
        .to_owned();
    let upstream_label = pypi.index_url().to_owned();
    let path_for_fetch = upstream_path.clone();
    pipeline
        .seed_named(
            "pypi",
            &upstream_path,
            &filename,
            &upstream_label,
            tenant_id,
            move || async move {
                pypi.fetch_file(&path_for_fetch, max_bytes)
                    .await
                    .map(|f| (f.bytes, f.content_type))
                    .map_err(PipelineError::from)
            },
        )
        .await
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;

    #[test]
    fn parses_the_shipped_manifest_shape() {
        let raw = "images:\n  - name: library/nginx\n    reference: latest\n  - name: library/redis\n    reference: \"7\"\n";
        let manifest = SeedManifest::parse(raw).expect("parse");
        assert_eq!(manifest.images.len(), 2);
        assert_eq!(manifest.images[0].name, "library/nginx");
        assert_eq!(manifest.images[0].reference, "latest");
        assert_eq!(manifest.images[1].reference, "7");
        assert!(manifest.npm.is_empty());
        assert!(manifest.pypi.is_empty());
    }

    #[test]
    fn parses_npm_and_pypi_entries() {
        let raw = "npm:\n  - name: left-pad\n    version: \"1.3.0\"\n  - name: \"@types/node\"\n    version: \"20.0.0\"\npypi:\n  - name: requests\n    version: \"2.34.2\"\n";
        let manifest = SeedManifest::parse(raw).expect("parse");
        assert!(manifest.images.is_empty());
        assert_eq!(manifest.npm.len(), 2);
        assert_eq!(manifest.npm[0].name, "left-pad");
        assert_eq!(manifest.npm[0].version, "1.3.0");
        assert_eq!(manifest.npm[1].name, "@types/node");
        assert_eq!(manifest.pypi.len(), 1);
        assert_eq!(manifest.pypi[0].name, "requests");
        assert_eq!(manifest.pypi[0].version, "2.34.2");
    }

    #[test]
    fn the_shipped_penguintech_manifest_parses_and_covers_all_three_ecosystems() {
        let raw = include_str!("../seeds/penguintech.yaml");
        let manifest = SeedManifest::parse(raw).expect("shipped manifest must parse");
        assert!(!manifest.images.is_empty());
        assert!(!manifest.npm.is_empty());
        assert!(!manifest.pypi.is_empty());
    }

    #[test]
    fn rejects_malformed_yaml() {
        assert!(SeedManifest::parse("not: [valid").is_err());
    }

    #[test]
    fn bootstrap_tenant_is_a_valid_uuid() {
        assert!(Uuid::parse_str(BOOTSTRAP_TENANT).is_ok());
    }

    // -- seed_npm_package / seed_pypi_package integration tests ---------
    //
    // Same technique as `crate::scanpipe`'s own tests: a real (isolated-
    // schema) Postgres pool, a wiremock S3 endpoint, a wiremock upstream
    // registry, and a real no-op `ScanEngine` (no clamd sidecar in this
    // environment) wired directly — no full `AppState` needed, since both
    // functions take explicit client references rather than the state
    // god-object.

    use aws_sdk_s3::Client as S3Client;
    use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
    use skauswatch_scan_core::{ScanEngine, ScanEngineConfig};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::config::{NpmUpstreamConfig, PypiUpstreamConfig};
    use crate::npm::NpmUpstreamClient;
    use crate::pypi::PypiUpstreamClient;
    use crate::scanpipe::ScanPipeline;
    use crate::state::CacheStats;

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

    async fn clean_engine() -> ScanEngine {
        ScanEngine::new(ScanEngineConfig {
            clamd_socket: None,
            clamd_tcp: None,
            clamd_timeout: std::time::Duration::from_secs(1),
            yara_rules_path: None,
        })
        .await
        .expect("engine with no configured backends is infallible")
    }

    async fn test_pool() -> sqlx::PgPool {
        skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")).await
    }

    fn s3_error_xml(code: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <Error><Code>{code}</Code><Message>not found</Message>\
             <RequestId>req-1</RequestId><HostId>host-1</HostId></Error>"
        )
    }

    #[tokio::test]
    async fn seed_npm_package_resolves_tarball_from_packument_and_pins_it() {
        let body = b"fake tarball bytes".to_vec();
        let hex = skauswatch_scan_core::compute_hashes(&body).sha256;

        let registry = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/left-pad"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "left-pad",
                "versions": {
                    "1.3.0": {
                        "dist": {"tarball": format!("{}/left-pad/-/left-pad-1.3.0.tgz", registry.uri())}
                    }
                }
            })))
            .mount(&registry)
            .await;
        Mock::given(method("GET"))
            .and(path("/left-pad/-/left-pad-1.3.0.tgz"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(body.clone()),
            )
            .mount(&registry)
            .await;

        let s3 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/bkt/sha256/{hex}")))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_raw(s3_error_xml("NoSuchKey"), "application/xml"),
            )
            .mount(&s3)
            .await;
        Mock::given(method("PUT"))
            .and(path(format!("/bkt/sha256/{hex}")))
            .respond_with(ResponseTemplate::new(200))
            .mount(&s3)
            .await;

        let engine = clean_engine().await;
        let pool = test_pool().await;
        let stats = CacheStats::default();
        let upstream = crate::upstream::UpstreamClient::new(
            reqwest::Client::new(),
            crate::config::UpstreamConfig::from_env(),
        );
        let pipeline = ScanPipeline {
            upstream: &upstream,
            s3: &mock_s3_client(&s3.uri()),
            bucket: "bkt",
            cache_prefix: "sha256/",
            quarantine_prefix: "quarantine/",
            scan_engine: &engine,
            db: &pool,
            max_artifact_bytes: 1024,
            cache_stats: &stats,
            offline_mode: false,
            fail_posture: crate::config::FailPosture::Closed,
        };
        let npm = NpmUpstreamClient::new(
            reqwest::Client::new(),
            NpmUpstreamConfig {
                registry_url: registry.uri(),
                token: None,
            },
        );
        let pkg = SeedNpmPackage {
            name: "left-pad".to_owned(),
            version: "1.3.0".to_owned(),
        };
        let tenant: Uuid = BOOTSTRAP_TENANT.parse().expect("valid uuid");

        let artifact = seed_npm_package(&pipeline, &npm, &pkg, tenant, 1024)
            .await
            .expect("seed succeeds");
        assert_eq!(artifact.sha256, hex);

        let row = crate::db::find_by_reference(&pool, "npm", "left-pad", "left-pad-1.3.0.tgz")
            .await
            .expect("query")
            .expect("row indexed");
        assert!(row.pinned, "seed_npm_package must pin the row");
        assert_eq!(row.upstream, registry.uri());
    }

    #[tokio::test]
    async fn seed_npm_package_fails_closed_when_version_is_missing_from_packument() {
        let registry = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/left-pad"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "left-pad",
                "versions": {}
            })))
            .mount(&registry)
            .await;

        let engine = clean_engine().await;
        let pool = test_pool().await;
        let stats = CacheStats::default();
        let upstream = crate::upstream::UpstreamClient::new(
            reqwest::Client::new(),
            crate::config::UpstreamConfig::from_env(),
        );
        let pipeline = ScanPipeline {
            upstream: &upstream,
            s3: &mock_s3_client("http://127.0.0.1:1"),
            bucket: "bkt",
            cache_prefix: "sha256/",
            quarantine_prefix: "quarantine/",
            scan_engine: &engine,
            db: &pool,
            max_artifact_bytes: 1024,
            cache_stats: &stats,
            offline_mode: false,
            fail_posture: crate::config::FailPosture::Closed,
        };
        let npm = NpmUpstreamClient::new(
            reqwest::Client::new(),
            NpmUpstreamConfig {
                registry_url: registry.uri(),
                token: None,
            },
        );
        let pkg = SeedNpmPackage {
            name: "left-pad".to_owned(),
            version: "9.9.9".to_owned(),
        };
        let tenant: Uuid = BOOTSTRAP_TENANT.parse().expect("valid uuid");

        let err = seed_npm_package(&pipeline, &npm, &pkg, tenant, 1024)
            .await
            .expect_err("missing version must fail");
        assert!(matches!(err, PipelineError::BadRequest(_)));
    }

    #[tokio::test]
    async fn seed_pypi_package_resolves_file_from_json_api_and_pins_it() {
        let body = b"fake wheel bytes".to_vec();
        let hex = skauswatch_scan_core::compute_hashes(&body).sha256;

        let index = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/requests/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "releases": {
                    "2.34.2": [{
                        "url": format!("{}/packages/aa/bb/requests-2.34.2.tar.gz", index.uri()),
                        "digests": {"sha256": "deadbeef"},
                    }]
                }
            })))
            .mount(&index)
            .await;
        Mock::given(method("GET"))
            .and(path("/packages/aa/bb/requests-2.34.2.tar.gz"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(body.clone()),
            )
            .mount(&index)
            .await;

        let s3 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/bkt/sha256/{hex}")))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_raw(s3_error_xml("NoSuchKey"), "application/xml"),
            )
            .mount(&s3)
            .await;
        Mock::given(method("PUT"))
            .and(path(format!("/bkt/sha256/{hex}")))
            .respond_with(ResponseTemplate::new(200))
            .mount(&s3)
            .await;

        let engine = clean_engine().await;
        let pool = test_pool().await;
        let stats = CacheStats::default();
        let upstream = crate::upstream::UpstreamClient::new(
            reqwest::Client::new(),
            crate::config::UpstreamConfig::from_env(),
        );
        let pipeline = ScanPipeline {
            upstream: &upstream,
            s3: &mock_s3_client(&s3.uri()),
            bucket: "bkt",
            cache_prefix: "sha256/",
            quarantine_prefix: "quarantine/",
            scan_engine: &engine,
            db: &pool,
            max_artifact_bytes: 1024,
            cache_stats: &stats,
            offline_mode: false,
            fail_posture: crate::config::FailPosture::Closed,
        };
        let pypi = PypiUpstreamClient::new(
            reqwest::Client::new(),
            PypiUpstreamConfig {
                index_url: index.uri(),
                files_url: index.uri(),
                username: None,
                password: None,
            },
        );
        let pkg = SeedPypiPackage {
            name: "requests".to_owned(),
            version: "2.34.2".to_owned(),
        };
        let tenant: Uuid = BOOTSTRAP_TENANT.parse().expect("valid uuid");

        let artifact = seed_pypi_package(&pipeline, &pypi, &pkg, tenant, 1024)
            .await
            .expect("seed succeeds");
        assert_eq!(artifact.sha256, hex);

        let row = crate::db::find_by_reference(
            &pool,
            "pypi",
            "/packages/aa/bb/requests-2.34.2.tar.gz",
            "requests-2.34.2.tar.gz",
        )
        .await
        .expect("query")
        .expect("row indexed");
        assert!(row.pinned, "seed_pypi_package must pin the row");
    }

    #[tokio::test]
    async fn seed_pypi_package_fails_closed_when_version_has_no_release_files() {
        let index = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/requests/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "releases": {}
            })))
            .mount(&index)
            .await;

        let engine = clean_engine().await;
        let pool = test_pool().await;
        let stats = CacheStats::default();
        let upstream = crate::upstream::UpstreamClient::new(
            reqwest::Client::new(),
            crate::config::UpstreamConfig::from_env(),
        );
        let pipeline = ScanPipeline {
            upstream: &upstream,
            s3: &mock_s3_client("http://127.0.0.1:1"),
            bucket: "bkt",
            cache_prefix: "sha256/",
            quarantine_prefix: "quarantine/",
            scan_engine: &engine,
            db: &pool,
            max_artifact_bytes: 1024,
            cache_stats: &stats,
            offline_mode: false,
            fail_posture: crate::config::FailPosture::Closed,
        };
        let pypi = PypiUpstreamClient::new(
            reqwest::Client::new(),
            PypiUpstreamConfig {
                index_url: index.uri(),
                files_url: index.uri(),
                username: None,
                password: None,
            },
        );
        let pkg = SeedPypiPackage {
            name: "requests".to_owned(),
            version: "9.9.9".to_owned(),
        };
        let tenant: Uuid = BOOTSTRAP_TENANT.parse().expect("valid uuid");

        let err = seed_pypi_package(&pipeline, &pypi, &pkg, tenant, 1024)
            .await
            .expect_err("missing release files must fail");
        assert!(matches!(err, PipelineError::BadRequest(_)));
    }

    #[tokio::test]
    async fn run_seeds_all_three_ecosystems_from_a_manifest_file() {
        let oci_body = br#"{"schemaVersion":2}"#.to_vec();
        let oci_hex = skauswatch_scan_core::compute_hashes(&oci_body).sha256;
        let npm_body = b"npm tarball".to_vec();
        let npm_hex = skauswatch_scan_core::compute_hashes(&npm_body).sha256;
        let pypi_body = b"pypi wheel".to_vec();
        let pypi_hex = skauswatch_scan_core::compute_hashes(&pypi_body).sha256;

        let oci_upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/seeded/manifests/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(oci_body.clone()))
            .mount(&oci_upstream)
            .await;

        let npm_registry = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/left-pad"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "versions": {"1.3.0": {"dist": {
                    "tarball": format!("{}/left-pad/-/left-pad-1.3.0.tgz", npm_registry.uri())
                }}}
            })))
            .mount(&npm_registry)
            .await;
        Mock::given(method("GET"))
            .and(path("/left-pad/-/left-pad-1.3.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(npm_body.clone()))
            .mount(&npm_registry)
            .await;

        let pypi_index = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/requests/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "releases": {"2.34.2": [{
                    "url": format!("{}/packages/aa/requests-2.34.2.tar.gz", pypi_index.uri())
                }]}
            })))
            .mount(&pypi_index)
            .await;
        Mock::given(method("GET"))
            .and(path("/packages/aa/requests-2.34.2.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(pypi_body.clone()))
            .mount(&pypi_index)
            .await;

        let s3 = MockServer::start().await;
        for hex in [&oci_hex, &npm_hex, &pypi_hex] {
            Mock::given(method("GET"))
                .and(path(format!("/bkt/sha256/{hex}")))
                .respond_with(
                    ResponseTemplate::new(404)
                        .set_body_raw(s3_error_xml("NoSuchKey"), "application/xml"),
                )
                .mount(&s3)
                .await;
            Mock::given(method("PUT"))
                .and(path(format!("/bkt/sha256/{hex}")))
                .respond_with(ResponseTemplate::new(200))
                .mount(&s3)
                .await;
        }

        let pool = test_pool().await;
        let license = skauswatch_testkit::license::dev_license("skauswatch");
        let mut state = crate::state::AppStateInner::for_tests_with_npm(
            pool,
            license,
            NpmUpstreamClient::new(
                reqwest::Client::new(),
                NpmUpstreamConfig {
                    registry_url: npm_registry.uri(),
                    token: None,
                },
            ),
            "https://depgate.internal",
        );
        // `for_tests_with_npm` only overrides npm — rebuild `pypi`/`upstream`/
        // `s3`/`cache_bucket` in place via `Arc::get_mut`, since this is the
        // one test needing every client pointed at a wiremock server
        // simultaneously and no single test constructor covers all four.
        {
            let inner = std::sync::Arc::get_mut(&mut state).expect("sole owner in test");
            inner.pypi = PypiUpstreamClient::new(
                reqwest::Client::new(),
                PypiUpstreamConfig {
                    index_url: pypi_index.uri(),
                    files_url: pypi_index.uri(),
                    username: None,
                    password: None,
                },
            );
            inner.upstream = crate::upstream::UpstreamClient::new(
                reqwest::Client::new(),
                crate::config::UpstreamConfig {
                    base_url: oci_upstream.uri(),
                    auth_url: format!("{}/token", oci_upstream.uri()),
                    service: "test-registry".to_owned(),
                    username: None,
                    password: None,
                },
            );
            inner.s3 = mock_s3_client(&s3.uri());
            inner.cfg.cache_bucket = "bkt".to_owned();
        }

        let manifest_path =
            std::env::temp_dir().join(format!("depgate-seed-test-{}.yaml", Uuid::new_v4()));
        tokio::fs::write(
            &manifest_path,
            "images:\n  - name: library/seeded\n    reference: latest\nnpm:\n  - name: left-pad\n    version: \"1.3.0\"\npypi:\n  - name: requests\n    version: \"2.34.2\"\n",
        )
        .await
        .expect("write temp manifest");

        let result = run(&state, manifest_path.to_str().expect("utf8 temp path")).await;
        let _ = tokio::fs::remove_file(&manifest_path).await;
        result.expect("seed run succeeds");

        let (_, total) = crate::db::list_artifacts(
            &state.db,
            BOOTSTRAP_TENANT.parse().expect("valid uuid"),
            &crate::db::ArtifactFilters::default(),
        )
        .await
        .expect("list artifacts");
        assert_eq!(total, 3, "all three ecosystems must be indexed");
    }
}
