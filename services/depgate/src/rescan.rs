//! Background/CLI re-scan sweep (`docs/v2-port/v2.1-depgate.md` §6):
//! re-scans cached artifacts whose recorded `scanner_version` no longer
//! matches the running build's `skauswatch_scan_core::SCANNER_VERSION` —
//! triggered by `skauswatch-depgate rescan-sweep` (or an external
//! scheduler invoking the same subcommand), **never** on the hot serve
//! path (`crate::scanpipe`'s `try_serve` never calls into this module).

use skauswatch_scan_core::Verdict;

use crate::cache;
use crate::db::{self, QuarantineInsert, UpsertArtifact};
use crate::state::AppState;

/// Sweep run summary, returned to the CLI and logged.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SweepStats {
    /// Artifacts whose `scanner_version` was stale.
    pub examined: usize,
    /// Artifacts successfully re-scanned (verdict changed or not).
    pub rescanned: usize,
    /// Artifacts whose verdict flipped (clean<->non-clean) as a result.
    pub verdict_changed: usize,
    /// Artifacts that failed to re-scan (object missing, scan error) —
    /// logged individually, never aborts the rest of the sweep.
    pub errors: usize,
}

/// Runs one full sweep against `state`'s DB/cache/scan engine.
///
/// # Errors
/// Only the initial candidate-list query can fail the whole sweep;
/// per-artifact failures are counted in [`SweepStats::errors`] and logged,
/// never propagated.
pub async fn sweep(state: &AppState) -> anyhow::Result<SweepStats> {
    let current_version = skauswatch_scan_core::SCANNER_VERSION;
    let stale = db::artifacts_with_stale_scanner_version(&state.db, current_version).await?;
    let mut stats = SweepStats {
        examined: stale.len(),
        ..Default::default()
    };

    for row in &stale {
        match rescan_one(state, row, current_version).await {
            Ok(changed) => {
                stats.rescanned += 1;
                if changed {
                    stats.verdict_changed += 1;
                }
            }
            Err(e) => {
                stats.errors += 1;
                tracing::error!(
                    sha256 = %row.sha256,
                    error = %e,
                    "rescan sweep: failed to re-scan artifact"
                );
            }
        }
    }

    tracing::info!(
        examined = stats.examined,
        rescanned = stats.rescanned,
        verdict_changed = stats.verdict_changed,
        errors = stats.errors,
        "rescan sweep complete"
    );
    Ok(stats)
}

/// Re-scans one artifact, moving its S3 object between the cache/quarantine
/// prefixes and updating `depgate_artifacts`/`depgate_quarantine` if the
/// verdict flipped. Returns whether the verdict changed.
async fn rescan_one(
    state: &AppState,
    row: &db::ArtifactRow,
    current_version: &str,
) -> anyhow::Result<bool> {
    let was_clean = row.verdict == Verdict::Clean.as_str();
    let source_prefix = if was_clean {
        &state.cfg.cache_prefix
    } else {
        &state.cfg.quarantine_prefix
    };
    let key = cache::object_key(source_prefix, &row.sha256);
    let Some(obj) = cache::get_object(&state.s3, &state.cfg.cache_bucket, &key).await? else {
        anyhow::bail!("object missing from expected prefix {source_prefix:?}");
    };

    let outcome = state.scan_engine.scan_bytes(&obj.bytes).await?;
    let now_clean = outcome.verdict == Verdict::Clean;
    let changed = now_clean != was_clean;

    if changed {
        let dest_prefix = if now_clean {
            &state.cfg.cache_prefix
        } else {
            &state.cfg.quarantine_prefix
        };
        let dest_key = cache::object_key(dest_prefix, &row.sha256);
        cache::put_object(
            &state.s3,
            &state.cfg.cache_bucket,
            &dest_key,
            obj.bytes.clone(),
            &obj.content_type,
        )
        .await?;
        cache::put_tags(
            &state.s3,
            &state.cfg.cache_bucket,
            &dest_key,
            &skauswatch_scan_core::verdict_tags(&outcome),
        )
        .await?;
        if !now_clean {
            let threat = outcome.threat_names.join(",");
            db::insert_quarantine(
                &state.db,
                &QuarantineInsert {
                    sha256: &row.sha256,
                    ecosystem: &row.ecosystem,
                    name: &row.name,
                    reference: &row.reference,
                    reason: if threat.is_empty() {
                        outcome.verdict.as_str()
                    } else {
                        &threat
                    },
                    threat: outcome.verdict.as_str(),
                    policy_rule_id: None,
                    tenant_id: row.tenant_id,
                },
            )
            .await?;
        }
    }

    db::upsert_artifact(
        &state.db,
        &UpsertArtifact {
            ecosystem: &row.ecosystem,
            name: &row.name,
            reference: &row.reference,
            sha256: &row.sha256,
            upstream: &row.upstream,
            content_type: row.content_type.as_deref(),
            size_bytes: row.size_bytes,
            verdict: outcome.verdict.as_str(),
            scanner_version: current_version,
            pinned: row.pinned,
            tenant_id: row.tenant_id,
        },
    )
    .await?;

    Ok(changed)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use aws_sdk_s3::Client as S3Client;
    use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
    use penguin_licensing::LicenseClient;
    use skauswatch_scan_core::{ScanEngine, ScanEngineConfig};
    use sqlx::PgPool;
    use uuid::Uuid;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::db::UpsertArtifact;
    use crate::state::AppStateInner;

    async fn test_pool() -> PgPool {
        skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")).await
    }

    fn dev_license() -> Arc<LicenseClient> {
        skauswatch_testkit::license::dev_license("skauswatch")
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

    const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

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

    fn state_with(pool: PgPool, s3: S3Client, engine: ScanEngine) -> AppState {
        let mut inner = AppStateInner::for_tests_with_db(pool, dev_license());
        let state = Arc::get_mut(&mut inner).expect("sole owner in test");
        state.s3 = s3;
        state.scan_engine = Arc::new(engine);
        state.cfg.cache_bucket = "bkt".to_owned();
        inner
    }

    #[tokio::test]
    async fn sweep_with_nothing_stale_is_a_no_op() {
        let pool = test_pool().await;
        let s3 = MockServer::start().await;
        let state = state_with(pool, mock_s3_client(&s3.uri()), clean_engine().await);
        let stats = sweep(&state).await.expect("sweep");
        assert_eq!(stats.examined, 0);
        assert_eq!(stats.rescanned, 0);
    }

    #[tokio::test]
    async fn sweep_updates_scanner_version_when_verdict_is_unchanged() {
        let pool = test_pool().await;
        let tenant = Uuid::new_v4();
        db::upsert_artifact(
            &pool,
            &UpsertArtifact {
                ecosystem: "oci",
                name: "library/nginx",
                reference: "latest",
                sha256: "cafe",
                upstream: "https://registry-1.docker.io",
                content_type: Some("application/octet-stream"),
                size_bytes: 5,
                verdict: "clean",
                scanner_version: "old-version",
                pinned: false,
                tenant_id: tenant,
            },
        )
        .await
        .expect("seed");

        let s3 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bkt/sha256/cafe"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(b"hello".to_vec()),
            )
            .mount(&s3)
            .await;
        Mock::given(method("PUT"))
            .and(path("/bkt/sha256/cafe"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&s3)
            .await;

        let state = state_with(
            pool.clone(),
            mock_s3_client(&s3.uri()),
            clean_engine().await,
        );
        let stats = sweep(&state).await.expect("sweep");
        assert_eq!(stats.examined, 1);
        assert_eq!(stats.rescanned, 1);
        assert_eq!(stats.verdict_changed, 0);

        let row = db::find_by_reference(&pool, "oci", "library/nginx", "latest")
            .await
            .expect("query")
            .expect("row");
        assert_eq!(row.scanner_version, skauswatch_scan_core::SCANNER_VERSION);
        assert_eq!(row.verdict, "clean");
    }

    #[tokio::test]
    async fn sweep_quarantines_a_previously_clean_artifact_that_now_scans_infected() {
        let pool = test_pool().await;
        let tenant = Uuid::new_v4();
        let hex = skauswatch_scan_core::compute_hashes(EICAR).sha256;
        db::upsert_artifact(
            &pool,
            &UpsertArtifact {
                ecosystem: "oci",
                name: "library/eicar",
                reference: "latest",
                sha256: &hex,
                upstream: "https://registry-1.docker.io",
                content_type: Some("application/octet-stream"),
                size_bytes: EICAR.len() as i64,
                verdict: "clean",
                scanner_version: "old-version",
                pinned: false,
                tenant_id: tenant,
            },
        )
        .await
        .expect("seed");

        let s3 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/bkt/sha256/{hex}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(EICAR.to_vec()),
            )
            .mount(&s3)
            .await;
        Mock::given(method("PUT"))
            .and(path(format!("/bkt/quarantine/{hex}")))
            .respond_with(ResponseTemplate::new(200))
            .mount(&s3)
            .await;

        let state = state_with(pool.clone(), mock_s3_client(&s3.uri()), yara_engine().await);
        let stats = sweep(&state).await.expect("sweep");
        assert_eq!(stats.verdict_changed, 1);

        let row = db::find_by_reference(&pool, "oci", "library/eicar", "latest")
            .await
            .expect("query")
            .expect("row");
        assert_eq!(row.verdict, "infected");

        let (rows, total) = db::list_quarantine(&pool, tenant, 10, 0)
            .await
            .expect("list quarantine");
        assert_eq!(total, 1);
        assert_eq!(rows[0].sha256, hex);
    }

    #[tokio::test]
    async fn sweep_counts_a_missing_cache_object_as_an_error_without_aborting() {
        let pool = test_pool().await;
        let tenant = Uuid::new_v4();
        db::upsert_artifact(
            &pool,
            &UpsertArtifact {
                ecosystem: "oci",
                name: "library/gone",
                reference: "latest",
                sha256: "missing",
                upstream: "https://registry-1.docker.io",
                content_type: None,
                size_bytes: 0,
                verdict: "clean",
                scanner_version: "old-version",
                pinned: false,
                tenant_id: tenant,
            },
        )
        .await
        .expect("seed");

        let s3 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bkt/sha256/missing"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_raw(s3_error_xml("NoSuchKey"), "application/xml"),
            )
            .mount(&s3)
            .await;

        let state = state_with(pool, mock_s3_client(&s3.uri()), clean_engine().await);
        let stats = sweep(&state).await.expect("sweep");
        assert_eq!(stats.examined, 1);
        assert_eq!(stats.rescanned, 0);
        assert_eq!(stats.errors, 1);
    }
}
