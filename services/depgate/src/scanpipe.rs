//! The scan-on-ingest pipeline: resolve a request -> serve from cache if a
//! clean verdict is already tagged -> else fetch from upstream, scan via
//! `skauswatch-scan-core`, and store clean content under the
//! content-addressed key (or quarantine anything else) — the flow diagram
//! in `docs/v2-port/v2.1-depgate.md` §1/§2.
//!
//! Tenant scoping: `resolve_manifest`/`resolve_blob` take a `tenant_id` used
//! ONLY for attribution on the `depgate_artifacts`/`depgate_quarantine` rows
//! this call may write — cache-hit/lookup reads are never tenant-filtered.
//! See the migration file's design note for the full rationale (shared,
//! content-addressed cache; dedup is the point).
//!
//! All dependencies are taken as explicit references rather than a single
//! `AppState` god-object, so each piece is independently testable against a
//! wiremock upstream / mock S3 endpoint / real test-schema Postgres without
//! constructing a full service state.

use aws_sdk_s3::Client as S3Client;
use bytes::Bytes;
use skauswatch_scan_core::{ScanEngine, ScanError, Verdict, verdict_tags};
use sqlx::PgPool;
use uuid::Uuid;

use crate::cache::{self, CacheError};
use crate::db::{self, QuarantineInsert, UpsertArtifact};
use crate::state::CacheStats;
use crate::upstream::{UpstreamClient, UpstreamError};

/// A successfully resolved, servable artifact.
#[derive(Debug, Clone)]
pub struct ResolvedArtifact {
    /// Content digest hex (no `sha256:` prefix).
    pub sha256: String,
    /// Artifact bytes.
    pub bytes: Bytes,
    /// `Content-Type` to answer with.
    pub content_type: String,
}

/// Failures from resolving/ingesting one artifact.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// The request itself was malformed (e.g. a blob digest that isn't a
    /// well-formed `sha256:<hex>` string).
    #[error("{0}")]
    BadRequest(String),
    /// The scan verdict fails policy — fail-closed per §6: anything other
    /// than `clean` is refused (no policy engine to make finer-grained
    /// allow/deny decisions yet; that's P3).
    #[error("blocked by scan policy: verdict={verdict} threat={threat}")]
    Blocked {
        /// The offending verdict.
        verdict: String,
        /// Threat/rule names, comma-joined (empty for a bare scan error).
        threat: String,
    },
    /// The bytes fetched for a digest-addressed request don't hash to the
    /// digest that was requested — a data-integrity failure, never served
    /// or cached under either key.
    #[error("digest verification failed: requested {requested}, computed {computed}")]
    IntegrityMismatch {
        /// The digest the caller asked for.
        requested: String,
        /// The digest actually computed over the fetched bytes.
        computed: String,
    },
    /// Upstream registry/token-endpoint failure.
    #[error(transparent)]
    Upstream(#[from] UpstreamError),
    /// S3/cache-store failure.
    #[error(transparent)]
    Cache(#[from] CacheError),
    /// Database failure.
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    /// The YARA-X engine itself failed mid-scan.
    #[error(transparent)]
    Scan(#[from] ScanError),
    /// npm/PyPI upstream fetch failure (`crate::fetch`) — the P2 ecosystem
    /// clients' error type, distinct from [`PipelineError::Upstream`]'s OCI
    /// `UpstreamError` since neither shares the Bearer-challenge machinery.
    #[error(transparent)]
    Fetch(#[from] crate::fetch::FetchError),
}

/// Bundles every dependency `resolve_manifest`/`resolve_blob` need. Built
/// fresh (cheap — all borrows/clones of `Arc`-backed handles) per request
/// from `AppState` in `src/routes/oci.rs`.
pub struct ScanPipeline<'a> {
    /// OCI upstream client.
    pub upstream: &'a UpstreamClient,
    /// S3/MinIO client for the cache bucket.
    pub s3: &'a S3Client,
    /// Cache bucket name.
    pub bucket: &'a str,
    /// Servable-object key prefix (e.g. `sha256/`).
    pub cache_prefix: &'a str,
    /// Quarantined-object key prefix (e.g. `quarantine/`).
    pub quarantine_prefix: &'a str,
    /// Shared malware-scan engine.
    pub scan_engine: &'a ScanEngine,
    /// DB pool.
    pub db: &'a PgPool,
    /// Size guard applied to every upstream fetch.
    pub max_artifact_bytes: u64,
    /// In-process cache hit/miss counters.
    pub cache_stats: &'a CacheStats,
}

impl ScanPipeline<'_> {
    /// Resolves `GET|HEAD /v2/{name}/manifests/{reference}`.
    ///
    /// # Errors
    /// See [`PipelineError`].
    pub async fn resolve_manifest(
        &self,
        name: &str,
        reference: &str,
        tenant_id: Uuid,
    ) -> Result<ResolvedArtifact, PipelineError> {
        if let Some(hex) = crate::oci_path::parse_sha256_digest(reference) {
            if let Some(obj) = self.try_serve(hex).await? {
                return Ok(obj);
            }
            let fetched = self
                .upstream
                .fetch_manifest(name, reference, self.max_artifact_bytes)
                .await?;
            verify_digest(hex, &fetched.bytes)?;
            return self
                .ingest(
                    fetched.bytes,
                    &fetched.content_type,
                    "oci",
                    name,
                    reference,
                    self.upstream.base_url(),
                    tenant_id,
                )
                .await;
        }

        // Tag-addressed: consult the tag-index first so a previously
        // ingested `infected`/`pup` reference short-circuits without ever
        // re-hitting upstream or S3.
        if let Some(row) = db::find_by_reference(self.db, "oci", name, reference).await? {
            if row.verdict == Verdict::Clean.as_str() {
                if let Some(obj) = self.try_serve(&row.sha256).await? {
                    return Ok(obj);
                }
                // Cache entry evicted since the row was written — fall
                // through to a fresh ingest below.
            } else {
                return Err(PipelineError::Blocked {
                    verdict: row.verdict,
                    threat: String::new(),
                });
            }
        }

        let fetched = self
            .upstream
            .fetch_manifest(name, reference, self.max_artifact_bytes)
            .await?;
        self.ingest(
            fetched.bytes,
            &fetched.content_type,
            "oci",
            name,
            reference,
            self.upstream.base_url(),
            tenant_id,
        )
        .await
    }

    /// Resolves `GET|HEAD /v2/{name}/blobs/{digest}`. `digest` must already
    /// be a well-formed `sha256:<hex>` string — blobs are always
    /// digest-addressed per the OCI spec.
    ///
    /// # Errors
    /// See [`PipelineError`].
    pub async fn resolve_blob(
        &self,
        name: &str,
        digest: &str,
        tenant_id: Uuid,
    ) -> Result<ResolvedArtifact, PipelineError> {
        let hex = crate::oci_path::parse_sha256_digest(digest).ok_or_else(|| {
            PipelineError::BadRequest(format!("not a valid sha256 digest: {digest}"))
        })?;

        if let Some(obj) = self.try_serve(hex).await? {
            return Ok(obj);
        }

        let fetched = self
            .upstream
            .fetch_blob(name, digest, self.max_artifact_bytes)
            .await?;

        // Integrity check BEFORE scanning/storing anything — the requested
        // digest is a known-good value the caller already committed to
        // (it came from a manifest DepGate itself already vetted), so a
        // mismatch here means upstream served the wrong bytes.
        verify_digest(hex, &fetched.bytes)?;

        self.ingest(
            fetched.bytes,
            &fetched.content_type,
            "oci",
            name,
            digest,
            self.upstream.base_url(),
            tenant_id,
        )
        .await
    }

    /// Proxies `GET /v2/{name}/tags/list` — no binary content, so this
    /// never touches the cache, scanner, or DB.
    ///
    /// # Errors
    /// See [`PipelineError`].
    pub async fn list_tags(&self, name: &str) -> Result<serde_json::Value, PipelineError> {
        Ok(self.upstream.list_tags(name).await?)
    }

    /// Warm-start entry point for `skauswatch-depgate seed`
    /// (`docs/v2-port/v2.1-depgate.md` §2/§9): resolves `name:reference`
    /// exactly like a normal manifest pull (fetch/scan/store/index if not
    /// already cached), then marks the resulting index row `pinned`, which
    /// exempts it from any future TTL-eviction sweep (P3).
    ///
    /// # Errors
    /// See [`PipelineError`].
    pub async fn seed_manifest(
        &self,
        name: &str,
        reference: &str,
        tenant_id: Uuid,
    ) -> Result<ResolvedArtifact, PipelineError> {
        let artifact = self.resolve_manifest(name, reference, tenant_id).await?;
        sqlx::query(
            "UPDATE depgate_artifacts SET pinned = true WHERE ecosystem = 'oci' AND name = $1 AND reference = $2",
        )
        .bind(name)
        .bind(reference)
        .execute(self.db)
        .await?;
        Ok(artifact)
    }

    /// Attempts to serve `hex` purely from the S3 cache: reads the tag set
    /// (no DB round-trip), refuses if the tagged verdict isn't `clean`, and
    /// only then fetches the body. `Ok(None)` is a cache miss.
    async fn try_serve(&self, hex: &str) -> Result<Option<ResolvedArtifact>, PipelineError> {
        let key = cache::object_key(self.cache_prefix, hex);
        let Some(tags) = cache::get_tags(self.s3, self.bucket, &key).await? else {
            self.cache_stats.record_miss();
            return Ok(None);
        };
        let threat = tags
            .iter()
            .find(|(k, _)| k == "threat")
            .map(|(_, v)| v.as_str());
        if threat != Some("clean") {
            // Defense in depth: nothing this service writes should ever
            // land a non-clean object under the servable prefix, but if one
            // is somehow found there, refuse rather than serve it.
            return Err(PipelineError::Blocked {
                verdict: threat.unwrap_or("unknown").to_owned(),
                threat: threat.unwrap_or("unknown").to_owned(),
            });
        }
        self.cache_stats.record_hit();
        let obj = cache::get_object(self.s3, self.bucket, &key)
            .await?
            .ok_or_else(|| {
                PipelineError::Cache(CacheError::Get(
                    "tag set present but object body missing".to_owned(),
                ))
            })?;
        Ok(Some(ResolvedArtifact {
            sha256: hex.to_owned(),
            bytes: obj.bytes,
            content_type: obj.content_type,
        }))
    }

    /// Scans `bytes`, then either caches+tags+indexes them as clean or
    /// quarantines+indexes them as blocked. `reference` is the tag/digest/
    /// filename the caller originally asked for (recorded on the index row
    /// so `find_by_reference` can resolve it next time). `ecosystem`
    /// discriminates the index row (`"oci"`/`"npm"`/`"pypi"`) — every
    /// front end funnels through this one scan/cache/quarantine/index path
    /// regardless of which upstream client fetched the bytes.
    ///
    /// `upstream` is recorded on the index row for audit — each caller
    /// passes its own upstream client's base/index URL (`ScanPipeline` has
    /// no ecosystem-specific client of its own to read one from beyond
    /// `self.upstream` for OCI, since npm/PyPI clients live on `AppState`
    /// instead — see [`Self::resolve_named`]'s docs).
    // One argument per distinct piece of data this shared scan/cache/
    // quarantine/index path needs — mirrors `src/config.rs::resolve_depgate`'s
    // identical allow: a params struct would just move the same fields
    // without adding clarity for a private fn.
    #[allow(clippy::too_many_arguments)]
    async fn ingest(
        &self,
        bytes: Bytes,
        content_type: &str,
        ecosystem: &str,
        name: &str,
        reference: &str,
        upstream: &str,
        tenant_id: Uuid,
    ) -> Result<ResolvedArtifact, PipelineError> {
        let outcome = self.scan_engine.scan_bytes(&bytes).await?;
        let sha256 = outcome.hashes.sha256.clone();
        let size_bytes = i64::try_from(bytes.len()).unwrap_or(i64::MAX);
        let scanner_version = skauswatch_scan_core::SCANNER_VERSION;

        if outcome.verdict == Verdict::Clean {
            let key = cache::object_key(self.cache_prefix, &sha256);
            cache::put_object(self.s3, self.bucket, &key, bytes.clone(), content_type).await?;
            cache::put_tags(self.s3, self.bucket, &key, &verdict_tags(&outcome)).await?;
            db::upsert_artifact(
                self.db,
                &UpsertArtifact {
                    ecosystem,
                    name,
                    reference,
                    sha256: &sha256,
                    upstream,
                    content_type: Some(content_type),
                    size_bytes,
                    verdict: Verdict::Clean.as_str(),
                    scanner_version,
                    pinned: false,
                    tenant_id,
                },
            )
            .await?;
            return Ok(ResolvedArtifact {
                sha256,
                bytes,
                content_type: content_type.to_owned(),
            });
        }

        // Fail-closed for anything that isn't a clean verdict (infected,
        // pup, error, skipped) — §6's default policy. Stored under the
        // quarantine prefix, never `cache_prefix`, and never served.
        let key = cache::object_key(self.quarantine_prefix, &sha256);
        cache::put_object(self.s3, self.bucket, &key, bytes, content_type).await?;
        cache::put_tags(self.s3, self.bucket, &key, &verdict_tags(&outcome)).await?;
        let threat = outcome.threat_names.join(",");
        db::insert_quarantine(
            self.db,
            &QuarantineInsert {
                sha256: &sha256,
                ecosystem,
                name,
                reference,
                reason: if threat.is_empty() {
                    outcome.verdict.as_str()
                } else {
                    &threat
                },
                threat: outcome.verdict.as_str(),
                tenant_id,
            },
        )
        .await?;
        db::upsert_artifact(
            self.db,
            &UpsertArtifact {
                ecosystem,
                name,
                reference,
                sha256: &sha256,
                upstream,
                content_type: Some(content_type),
                size_bytes,
                verdict: outcome.verdict.as_str(),
                scanner_version,
                pinned: false,
                tenant_id,
            },
        )
        .await?;
        Err(PipelineError::Blocked {
            verdict: outcome.verdict.as_str().to_owned(),
            threat,
        })
    }

    /// Resolves a tag/name-addressed artifact for ecosystems that, like OCI
    /// tags, don't know the content digest ahead of the fetch: consults the
    /// `(ecosystem, name, reference)` index first — serving from cache on a
    /// prior-clean hit, refusing outright on a prior-blocked hit — and only
    /// calls `fetch` (the caller's ecosystem-specific upstream client) on a
    /// genuine miss, then runs the result through the same
    /// [`Self::ingest`] scan/cache/quarantine/index path every ecosystem
    /// shares. This is the npm/PyPI equivalent of `resolve_manifest`'s
    /// tag-addressed branch; OCI keeps its own inline copy since it also
    /// has a digest-addressed branch this generic form doesn't need to
    /// cover.
    ///
    /// `upstream` is the caller's upstream client's base/index URL, recorded
    /// on the index row for audit — `ScanPipeline` holds no npm/PyPI client
    /// of its own (those live on `AppState`, since only OCI needs one on
    /// every construction site), so the caller supplies the label instead
    /// of this method deriving it from `ecosystem`.
    ///
    /// # Errors
    /// See [`PipelineError`].
    pub async fn resolve_named<F, Fut>(
        &self,
        ecosystem: &str,
        name: &str,
        reference: &str,
        upstream: &str,
        tenant_id: Uuid,
        fetch: F,
    ) -> Result<ResolvedArtifact, PipelineError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(Bytes, String), PipelineError>>,
    {
        if let Some(row) = db::find_by_reference(self.db, ecosystem, name, reference).await? {
            if row.verdict == Verdict::Clean.as_str() {
                if let Some(obj) = self.try_serve(&row.sha256).await? {
                    return Ok(obj);
                }
                // Cache entry evicted since the row was written — fall
                // through to a fresh fetch+ingest below.
            } else {
                return Err(PipelineError::Blocked {
                    verdict: row.verdict,
                    threat: String::new(),
                });
            }
        }
        let (bytes, content_type) = fetch().await?;
        self.ingest(
            bytes,
            &content_type,
            ecosystem,
            name,
            reference,
            upstream,
            tenant_id,
        )
        .await
    }

    /// Warm-start entry point for npm/PyPI seed entries — see
    /// [`Self::seed_manifest`]'s OCI equivalent. Resolves via
    /// [`Self::resolve_named`], then pins the resulting row.
    ///
    /// # Errors
    /// See [`PipelineError`].
    pub async fn seed_named<F, Fut>(
        &self,
        ecosystem: &str,
        name: &str,
        reference: &str,
        upstream: &str,
        tenant_id: Uuid,
        fetch: F,
    ) -> Result<ResolvedArtifact, PipelineError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(Bytes, String), PipelineError>>,
    {
        let artifact = self
            .resolve_named(ecosystem, name, reference, upstream, tenant_id, fetch)
            .await?;
        sqlx::query(
            "UPDATE depgate_artifacts SET pinned = true \
             WHERE ecosystem = $1 AND name = $2 AND reference = $3",
        )
        .bind(ecosystem)
        .bind(name)
        .bind(reference)
        .execute(self.db)
        .await?;
        Ok(artifact)
    }
}

/// Verifies `bytes` hashes to `requested_hex`, the shared integrity check
/// used by every digest-addressed fetch (blobs always; manifests when
/// `reference` is itself a digest rather than a tag).
fn verify_digest(requested_hex: &str, bytes: &Bytes) -> Result<(), PipelineError> {
    let computed = skauswatch_scan_core::compute_hashes(bytes).sha256;
    if computed == requested_hex {
        Ok(())
    } else {
        Err(PipelineError::IntegrityMismatch {
            requested: requested_hex.to_owned(),
            computed,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;

    #[test]
    fn verify_digest_accepts_matching_hash() {
        let bytes = Bytes::from_static(b"abc");
        let hex = skauswatch_scan_core::compute_hashes(&bytes).sha256;
        assert!(verify_digest(&hex, &bytes).is_ok());
    }

    #[test]
    fn verify_digest_rejects_mismatch() {
        let bytes = Bytes::from_static(b"abc");
        let err = verify_digest("not-the-real-hash", &bytes).expect_err("must mismatch");
        assert!(matches!(err, PipelineError::IntegrityMismatch { .. }));
    }

    // -- full-pipeline integration tests -------------------------------
    //
    // Wire a real (isolated-schema) Postgres pool, a wiremock S3 endpoint
    // (same technique as crate::cache's own tests), a wiremock upstream
    // registry, and a real ScanEngine (YARA-only — no clamd sidecar in
    // this environment) together behind `ScanPipeline`, so the actual
    // resolve/ingest/quarantine control flow gets exercised end-to-end
    // rather than only its pure helpers.

    use std::time::Duration;

    use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
    use skauswatch_scan_core::{ScanEngineConfig, Verdict};
    use wiremock::matchers::{method, path, query_param, query_param_is_missing};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::config::UpstreamConfig;
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

    fn upstream_client(base_url: &str) -> UpstreamClient {
        UpstreamClient::new(
            reqwest::Client::new(),
            UpstreamConfig {
                base_url: base_url.to_owned(),
                auth_url: format!("{base_url}/token"),
                service: "test-registry".to_owned(),
                username: None,
                password: None,
            },
        )
    }

    /// A `ScanEngine` with neither ClamAV nor YARA configured — every scan
    /// is unconditionally `Verdict::Clean` (no engine runs at all).
    async fn clean_engine() -> ScanEngine {
        ScanEngine::new(ScanEngineConfig {
            clamd_socket: None,
            clamd_tcp: None,
            clamd_timeout: Duration::from_secs(1),
            yara_rules_path: None,
        })
        .await
        .expect("engine with no configured backends is infallible")
    }

    /// A YARA-only `ScanEngine` loaded with this repo's shared test corpus
    /// (same rules path `skauswatch-scan-core`'s own tests use) — detects
    /// the EICAR test string as `Verdict::Infected`.
    async fn yara_engine() -> ScanEngine {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/yara_rules");
        ScanEngine::new(ScanEngineConfig {
            clamd_socket: None,
            clamd_tcp: None,
            clamd_timeout: Duration::from_secs(1),
            yara_rules_path: Some(path.to_owned()),
        })
        .await
        .expect("shared yara corpus loads")
    }

    async fn test_pool() -> PgPool {
        skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")).await
    }

    const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    fn s3_error_xml(code: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <Error><Code>{code}</Code><Message>not found</Message>\
             <RequestId>req-1</RequestId><HostId>host-1</HostId></Error>"
        )
    }

    #[tokio::test]
    async fn resolve_blob_serves_from_cache_without_touching_a_reachable_upstream() {
        let s3 = MockServer::start().await;
        let tagging = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <Tagging><TagSet><Tag><Key>threat</Key><Value>clean</Value></Tag></TagSet></Tagging>";
        // GetObjectTagging and GetObject are both plain GETs on the same
        // path, distinguished only by the `?tagging` subresource query
        // string — must match on that too, or wiremock can't tell them
        // apart and may answer either mock for either call.
        Mock::given(method("GET"))
            .and(path(
                "/bkt/sha256/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            ))
            .and(query_param("tagging", ""))
            .respond_with(ResponseTemplate::new(200).set_body_raw(tagging, "application/xml"))
            .mount(&s3)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/bkt/sha256/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            ))
            .and(query_param_is_missing("tagging"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(b"cached bytes".to_vec()),
            )
            .mount(&s3)
            .await;

        let engine = clean_engine().await;
        let pool = test_pool().await;
        // Nothing listens here — if the pipeline mistakenly fell through to
        // an upstream fetch, this would fail the call with a connection
        // error, so a successful result proves the cache path was taken.
        let upstream = upstream_client("http://127.0.0.1:1");
        let stats = CacheStats::default();
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
        };

        let got = pipeline
            .resolve_blob(
                "library/nginx",
                "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                Uuid::new_v4(),
            )
            .await
            .expect("cache hit");
        assert_eq!(got.bytes.as_ref(), b"cached bytes");
        assert_eq!(stats.snapshot(), (1, 0));
    }

    #[tokio::test]
    async fn resolve_blob_fetches_scans_caches_and_indexes_on_a_miss() {
        let body = b"hello depgate".to_vec();
        let hex = skauswatch_scan_core::compute_hashes(&body).sha256;
        let digest = format!("sha256:{hex}");

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

        let upstream_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v2/library/nginx/blobs/{digest}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(body.clone()),
            )
            .mount(&upstream_server)
            .await;

        let engine = clean_engine().await;
        let pool = test_pool().await;
        let upstream = upstream_client(&upstream_server.uri());
        let stats = CacheStats::default();
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
        };

        let tenant = Uuid::new_v4();
        let got = pipeline
            .resolve_blob("library/nginx", &digest, tenant)
            .await
            .expect("miss -> ingest");
        assert_eq!(got.sha256, hex);
        assert_eq!(got.bytes.as_ref(), body.as_slice());

        let row = db::find_by_reference(&pool, "oci", "library/nginx", &digest)
            .await
            .expect("query")
            .expect("row indexed");
        assert_eq!(row.sha256, hex);
        assert_eq!(row.verdict, Verdict::Clean.as_str());
        assert_eq!(row.tenant_id, tenant);
    }

    #[tokio::test]
    async fn resolve_blob_rejects_a_digest_mismatch_without_caching_anything() {
        let requested_hex = "0".repeat(64);
        let digest = format!("sha256:{requested_hex}");

        let s3 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/bkt/sha256/{requested_hex}")))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_raw(s3_error_xml("NoSuchKey"), "application/xml"),
            )
            .mount(&s3)
            .await;
        // Deliberately NO mock for PUT — if the pipeline tried to cache
        // the mismatched bytes anyway, the unmatched PUT would 404 from
        // wiremock and surface as a different (Cache) error, failing this
        // assertion.

        let upstream_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v2/library/nginx/blobs/{digest}")))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(b"not what you asked for".to_vec()),
            )
            .mount(&upstream_server)
            .await;

        let engine = clean_engine().await;
        let pool = test_pool().await;
        let upstream = upstream_client(&upstream_server.uri());
        let stats = CacheStats::default();
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
        };

        let err = pipeline
            .resolve_blob("library/nginx", &digest, Uuid::new_v4())
            .await
            .expect_err("digest must not match");
        assert!(matches!(err, PipelineError::IntegrityMismatch { .. }));
    }

    #[tokio::test]
    async fn resolve_manifest_by_tag_indexes_the_reference_on_first_pull() {
        let body = br#"{"schemaVersion":2}"#.to_vec();
        let hex = skauswatch_scan_core::compute_hashes(&body).sha256;

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

        let upstream_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/manifests/latest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/vnd.oci.image.manifest.v1+json")
                    .set_body_bytes(body.clone()),
            )
            .up_to_n_times(1)
            .mount(&upstream_server)
            .await;

        let engine = clean_engine().await;
        let pool = test_pool().await;
        let upstream = upstream_client(&upstream_server.uri());
        let stats = CacheStats::default();
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
        };

        let tenant = Uuid::new_v4();
        let got = pipeline
            .resolve_manifest("library/nginx", "latest", tenant)
            .await
            .expect("tag resolves on first pull");
        assert_eq!(got.sha256, hex);

        let row = db::find_by_reference(&pool, "oci", "library/nginx", "latest")
            .await
            .expect("query")
            .expect("row indexed");
        assert_eq!(row.sha256, hex);
        assert_eq!(row.reference, "latest");
    }

    #[tokio::test]
    async fn resolve_blob_quarantines_infected_content_and_never_serves_it() {
        let hex = skauswatch_scan_core::compute_hashes(EICAR).sha256;
        let digest = format!("sha256:{hex}");

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
            .and(path(format!("/bkt/quarantine/{hex}")))
            .respond_with(ResponseTemplate::new(200))
            .mount(&s3)
            .await;

        let upstream_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v2/library/eicar/blobs/{digest}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(EICAR.to_vec()))
            .mount(&upstream_server)
            .await;

        let engine = yara_engine().await;
        let pool = test_pool().await;
        let upstream = upstream_client(&upstream_server.uri());
        let stats = CacheStats::default();
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
        };

        let tenant = Uuid::new_v4();
        let err = pipeline
            .resolve_blob("library/eicar", &digest, tenant)
            .await
            .expect_err("must be blocked");
        assert!(matches!(err, PipelineError::Blocked { .. }));

        let (rows, total) = db::list_quarantine(&pool, tenant, 10, 0)
            .await
            .expect("list quarantine");
        assert_eq!(total, 1);
        assert_eq!(rows[0].sha256, hex);
        assert_eq!(rows[0].threat, Verdict::Infected.as_str());
    }

    #[tokio::test]
    async fn seed_manifest_pins_the_resolved_row() {
        let body = br#"{"schemaVersion":2,"seed":true}"#.to_vec();
        let hex = skauswatch_scan_core::compute_hashes(&body).sha256;

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

        let upstream_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/seeded/manifests/pinned"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&upstream_server)
            .await;

        let engine = clean_engine().await;
        let pool = test_pool().await;
        let upstream = upstream_client(&upstream_server.uri());
        let stats = CacheStats::default();
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
        };

        pipeline
            .seed_manifest("library/seeded", "pinned", Uuid::new_v4())
            .await
            .expect("seed succeeds");

        let row = db::find_by_reference(&pool, "oci", "library/seeded", "pinned")
            .await
            .expect("query")
            .expect("row present");
        assert!(row.pinned, "seed_manifest must pin the row");
    }

    #[tokio::test]
    async fn list_tags_proxies_the_upstream_response_untouched() {
        let upstream_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/tags/list"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "library/nginx", "tags": ["latest"]
            })))
            .mount(&upstream_server)
            .await;

        let engine = clean_engine().await;
        let pool = test_pool().await;
        let upstream = upstream_client(&upstream_server.uri());
        let stats = CacheStats::default();
        let s3 = MockServer::start().await;
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
        };

        let got = pipeline
            .list_tags("library/nginx")
            .await
            .expect("list tags");
        assert_eq!(got["tags"][0], "latest");
    }
}
