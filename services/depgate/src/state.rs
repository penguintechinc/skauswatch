//! Shared application state: DB pool, S3 cache client, upstream OCI client,
//! shared scan engine, JWT secret, and the license/flag client.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use aws_sdk_s3::Client as S3Client;
use penguin_licensing::LicenseClient;
use skauswatch_identity::IdentityProvider;
use skauswatch_scan_core::ScanEngine;
use sqlx::PgPool;

use crate::config::DepgateConfig;
use crate::npm::NpmUpstreamClient;
use crate::pypi::PypiUpstreamClient;
use crate::scanpipe::ScanPipeline;
use crate::upstream::UpstreamClient;

/// In-process cache hit/miss counters backing the admin `/stats` endpoint's
/// hit-rate figure. Reset on process restart — a lightweight, single-process
/// approximation; `depgate_cache_lookups_total` (Prometheus, recorded
/// alongside each increment here) is the durable, multi-replica-aggregable
/// time series for real dashboards/alerts.
#[derive(Debug, Default)]
pub struct CacheStats {
    hits: AtomicU64,
    misses: AtomicU64,
}

impl CacheStats {
    /// Records a cache hit.
    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("depgate_cache_lookups_total", "result" => "hit").increment(1);
    }

    /// Records a cache miss.
    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("depgate_cache_lookups_total", "result" => "miss").increment(1);
    }

    /// Returns `(hits, misses)` since process start.
    #[must_use]
    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }
}

/// Inner state shared across all handlers via `Arc`.
pub struct AppStateInner {
    /// Postgres pool (index/audit tables — see `src/db.rs`).
    pub db: PgPool,
    /// S3/MinIO client for the cache bucket.
    pub s3: S3Client,
    /// Cache-bucket + scan-engine + serving settings.
    pub cfg: DepgateConfig,
    /// OCI upstream client.
    pub upstream: UpstreamClient,
    /// npm upstream client (P2).
    pub npm: NpmUpstreamClient,
    /// PyPI upstream client (P2).
    pub pypi: PypiUpstreamClient,
    /// Shared ClamAV+YARA-X scan engine.
    pub scan_engine: Arc<ScanEngine>,
    /// Shared `JWT_SECRET_KEY` — every route (OCI proxy and admin API
    /// alike) requires a valid bearer token carrying a `tenant` claim; see
    /// `src/routes/mod.rs`.
    pub jwt_secret: String,
    /// License entitlement + PostHog flag client.
    pub license: Arc<LicenseClient>,
    /// In-process cache hit/miss counters.
    pub cache_stats: Arc<CacheStats>,
    /// SPIFFE Workload API identity (`docs/v2-port/service-auth-model.md`
    /// §1's `spiffe://penguintech.io/<env>/depgate`) — presents depgate's own
    /// X.509-SVID and verifies peer SVIDs on the mesh-only mTLS admin
    /// listener (`crate::mesh_admin`), the *alongside*-JWT SPIFFE-readiness
    /// path for the admin/report API. Mirrors `services/pki`/`services/
    /// manager`'s `AppStateInner::identity`: `None` only in test
    /// constructors that don't exercise mTLS at all; real `from_env()`
    /// startup always populates `Some`, and production hard-fails inside
    /// `IdentityProvider::connect` itself before this field would ever be
    /// `None` in prod. The `/v2/*` OCI proxy never consults this field —
    /// docker/npm clients are not mesh peers and cannot present a workload
    /// SVID, so that surface stays JWT/tenant-only (see `crate::routes`
    /// module docs).
    pub identity: Option<Arc<IdentityProvider>>,
}

/// Cheap-to-clone handle used as axum state.
pub type AppState = Arc<AppStateInner>;

impl skauswatch_auth::JwtSecretSource for AppStateInner {
    fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }
}

impl AppStateInner {
    /// Builds state from the environment: connects Postgres (with retry),
    /// builds the S3 client (MinIO-aware via `skauswatch_s3`), builds the
    /// scan engine (fails fast on a bad `YARA_RULES_PATH`, same posture as
    /// `services/s3scan`), and resolves the license client.
    pub async fn from_env() -> anyhow::Result<AppState> {
        let jwt_secret = skauswatch_auth::load_jwt_secret().map_err(|e| anyhow::anyhow!("{e}"))?;

        let license_cfg = penguin_licensing::LicenseConfig::from_env("skauswatch")
            .map_err(|e| anyhow::anyhow!("license config: {e}"))?
            .with_bypass_domain("skauswatch.app");
        let license =
            LicenseClient::new(license_cfg).map_err(|e| anyhow::anyhow!("license client: {e}"))?;
        let _ = license.refresh().await;

        let db_cfg =
            skauswatch_db::DbConfig::from_env().map_err(|e| anyhow::anyhow!("db config: {e}"))?;
        let db = skauswatch_db::connect_postgres(&db_cfg)
            .await
            .map_err(|e| anyhow::anyhow!("db connect: {e}"))?;

        let s3_cfg =
            skauswatch_s3::S3Config::from_env().map_err(|e| anyhow::anyhow!("s3 config: {e}"))?;
        let s3 = skauswatch_s3::client(&s3_cfg).await;

        let cfg = DepgateConfig::from_env();
        let upstream_cfg = crate::config::UpstreamConfig::from_env();
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| anyhow::anyhow!("http client: {e}"))?;
        let upstream = UpstreamClient::new(http.clone(), upstream_cfg);
        let npm =
            NpmUpstreamClient::new(http.clone(), crate::config::NpmUpstreamConfig::from_env());
        let pypi = PypiUpstreamClient::new(http, crate::config::PypiUpstreamConfig::from_env());

        let scan_engine = Arc::new(
            ScanEngine::new(skauswatch_scan_core::ScanEngineConfig {
                clamd_socket: cfg.clamd_socket.clone(),
                clamd_tcp: None,
                clamd_timeout: std::time::Duration::from_secs(cfg.clamd_timeout_secs),
                yara_rules_path: cfg.yara_rules_path.clone(),
            })
            .await
            .map_err(|e| anyhow::anyhow!("scan engine init failed: {e}"))?,
        );

        // SPIFFE Workload API identity for the mesh-only mTLS admin listener
        // (`docs/v2-port/service-auth-model.md` §1). Deliberately `connect()`,
        // not a domain-gated variant — identity is authentication, and per
        // `general.md`'s Feature Toggling & License Enforcement a
        // deployment-domain bypass is for license/feature-flag gating only,
        // never for exempting authentication. Fails fast in production if no
        // SPIRE agent is attestable — same fail-safe posture as pki/manager.
        let identity = Arc::new(
            IdentityProvider::connect()
                .await
                .map_err(|e| anyhow::anyhow!("identity provider: {e}"))?,
        );

        Ok(Arc::new(Self {
            db,
            s3,
            cfg,
            upstream,
            npm,
            pypi,
            scan_engine,
            jwt_secret,
            license,
            cache_stats: Arc::new(CacheStats::default()),
            identity: Some(identity),
        }))
    }

    /// Shared build behind [`Self::for_tests_with_db`] and
    /// [`Self::for_tests_with_identity`]: a real, migrated Postgres pool plus
    /// a lazily unreachable S3 endpoint (only DB-driven code paths — admin
    /// routes, `crate::db` — are exercised via these constructors; S3/
    /// upstream-driven paths use `crate::scanpipe::ScanPipeline` directly
    /// with wiremock handles instead, per that module's doc comment).
    #[cfg(test)]
    fn build_test_state(
        db: PgPool,
        license: Arc<LicenseClient>,
        identity: Option<Arc<IdentityProvider>>,
    ) -> Self {
        let s3_cfg = aws_sdk_s3::config::Builder::new()
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .endpoint_url("http://127.0.0.1:1")
            .force_path_style(true)
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test",
                "test",
                None,
                None,
                "depgate-test",
            ))
            .build();
        let cfg = crate::config::DepgateConfig {
            http_port: crate::config::DEFAULT_HTTP_PORT,
            public_base_url: "http://localhost:5050".to_owned(),
            cache_bucket: "depgate-test".to_owned(),
            cache_prefix: "sha256/".to_owned(),
            quarantine_prefix: "quarantine/".to_owned(),
            max_artifact_bytes: 512 * 1024 * 1024,
            clamd_socket: None,
            clamd_timeout_secs: 30,
            yara_rules_path: None,
            offline_mode: false,
            fail_posture: crate::config::FailPosture::Closed,
            bundle_signing_key: None,
        };
        Self {
            db,
            s3: S3Client::from_conf(s3_cfg),
            cfg,
            upstream: UpstreamClient::new(
                reqwest::Client::new(),
                crate::config::UpstreamConfig::from_env(),
            ),
            npm: NpmUpstreamClient::new(
                reqwest::Client::new(),
                crate::config::NpmUpstreamConfig::from_env(),
            ),
            pypi: PypiUpstreamClient::new(
                reqwest::Client::new(),
                crate::config::PypiUpstreamConfig::from_env(),
            ),
            scan_engine: Arc::new(ScanEngine::clamav_only(
                &skauswatch_scan_core::ScanEngineConfig {
                    clamd_socket: None,
                    clamd_tcp: None,
                    clamd_timeout: std::time::Duration::from_secs(1),
                    yara_rules_path: None,
                },
            )),
            jwt_secret: "test-secret".to_owned(),
            license,
            cache_stats: Arc::new(CacheStats::default()),
            identity,
        }
    }

    /// Test constructor: see [`Self::build_test_state`]. `identity` is
    /// `None` — the shortcut every DB-driven test uses that doesn't
    /// specifically exercise SPIFFE-identity-aware code paths.
    #[cfg(test)]
    pub fn for_tests_with_db(db: PgPool, license: Arc<LicenseClient>) -> AppState {
        Arc::new(Self::build_test_state(db, license, None))
    }

    /// Like [`Self::for_tests_with_db`], but overriding the npm upstream
    /// client and `public_base_url` — used by `crate::routes::npm`'s tests,
    /// which (unlike most P1 route tests) need the packument-rewrite
    /// dispatch path exercised against a wiremock npm registry rather than
    /// just tenant/auth plumbing.
    #[cfg(test)]
    pub fn for_tests_with_npm(
        db: PgPool,
        license: Arc<LicenseClient>,
        npm: NpmUpstreamClient,
        public_base_url: &str,
    ) -> AppState {
        let mut inner = Self::build_test_state(db, license, None);
        inner.npm = npm;
        inner.cfg.public_base_url = public_base_url.to_owned();
        Arc::new(inner)
    }

    /// Like [`Self::for_tests_with_npm`], but overriding the S3 client —
    /// used by `crate::routes::admin`'s quarantine-release test, the one
    /// admin-API code path (`update_quarantine`'s `released` branch) that
    /// actually talks to S3 rather than only DB-driven code paths.
    #[cfg(test)]
    pub fn for_tests_with_s3(db: PgPool, license: Arc<LicenseClient>, s3: S3Client) -> AppState {
        let mut inner = Self::build_test_state(db, license, None);
        inner.s3 = s3;
        Arc::new(inner)
    }

    /// Like [`Self::for_tests_with_npm`], for `crate::routes::pypi`'s tests.
    #[cfg(test)]
    pub fn for_tests_with_pypi(
        db: PgPool,
        license: Arc<LicenseClient>,
        pypi: PypiUpstreamClient,
        public_base_url: &str,
    ) -> AppState {
        let mut inner = Self::build_test_state(db, license, None);
        inner.pypi = pypi;
        inner.cfg.public_base_url = public_base_url.to_owned();
        Arc::new(inner)
    }

    /// Like [`Self::for_tests_with_db`], but with a caller-supplied
    /// [`IdentityProvider`] — used by `mesh_admin`'s tests that need to
    /// exercise the SPIFFE-identity-aware code paths (degraded-provider
    /// fallback, matcher wiring, real mTLS handshake) rather than the
    /// `identity: None` shortcut every other test constructor uses, which
    /// skips the identity check entirely instead of exercising its degraded
    /// branch. Mirrors `services/pki`'s `AppStateInner::for_tests_with_identity`.
    #[cfg(test)]
    pub fn for_tests_with_identity(
        db: PgPool,
        license: Arc<LicenseClient>,
        identity: Arc<IdentityProvider>,
    ) -> AppState {
        Arc::new(Self::build_test_state(db, license, Some(identity)))
    }

    /// Builds a [`ScanPipeline`] bundling this state's DB/S3/scan-engine
    /// handles — the one construction site every route module
    /// (`crate::routes::oci`, `crate::routes::npm`, `crate::routes::pypi`)
    /// and `crate::seed` share, replacing what P1 had inlined separately in
    /// `crate::routes::oci::pipeline_for` and `crate::seed::run`.
    #[must_use]
    pub fn pipeline(&self) -> ScanPipeline<'_> {
        ScanPipeline {
            upstream: &self.upstream,
            s3: &self.s3,
            bucket: &self.cfg.cache_bucket,
            cache_prefix: &self.cfg.cache_prefix,
            quarantine_prefix: &self.cfg.quarantine_prefix,
            scan_engine: &self.scan_engine,
            db: &self.db,
            max_artifact_bytes: self.cfg.max_artifact_bytes,
            cache_stats: &self.cache_stats,
            offline_mode: self.cfg.offline_mode,
            fail_posture: self.cfg.fail_posture,
        }
    }
}
