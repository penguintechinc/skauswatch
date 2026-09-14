//! Stream consumer handler for scanner tasks.

use crate::config::WorkerConfig;
use crate::message::ScannerResult;
use crate::yara::YaraScanner;
use skauswatch_streams::{
    HandlerError, STREAM_SCANNER_RESULTS, StreamEntry, StreamHandler, StreamProducer,
};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

/// Handler for scanner stream entries.
pub struct ScannerHandler {
    pool: PgPool,
    producer: StreamProducer,
    config: WorkerConfig,
    yara_scanner: Option<Arc<YaraScanner>>,
    /// ASM screenshot S3 uploader, or `None` when the screenshot stage is
    /// disabled/unconfigured (`ASM_SCREENSHOT_ENABLED=false` or no bucket —
    /// see `crate::config::WorkerConfig`). Built once in `main.rs::serve`
    /// (needs an `.await` for `skauswatch_s3::client`, so it is constructed
    /// by the caller rather than here — keeps `new` synchronous, matching
    /// every other test call site in this module).
    screenshot_uploader: Option<crate::asm::ScreenshotUploader>,
}

impl ScannerHandler {
    /// Creates a new scanner handler.
    pub fn new(
        pool: PgPool,
        producer: StreamProducer,
        config: WorkerConfig,
        screenshot_uploader: Option<crate::asm::ScreenshotUploader>,
    ) -> Self {
        let yara_scanner = if config.yara_enabled {
            match futures::executor::block_on(YaraScanner::load(&config.yara_rules_path)) {
                Ok(scanner) => {
                    info!("YARA scanner loaded successfully");
                    Some(Arc::new(scanner))
                }
                Err(e) => {
                    error!("failed to load YARA scanner: {}", e);
                    None
                }
            }
        } else {
            info!("YARA scanning disabled");
            None
        };

        Self {
            pool,
            producer,
            config,
            yara_scanner,
            screenshot_uploader,
        }
    }
}

#[async_trait::async_trait]
impl StreamHandler for ScannerHandler {
    async fn handle(&self, entry: &StreamEntry) -> Result<(), HandlerError> {
        let fields = &entry.fields;

        // Parse task message from stream entry.
        let job_id = fields.get("job_id").map(|s| s.to_string());
        let scan_type = fields.get("scan_type").map(|s| s.to_string());
        let target = fields.get("target").map(|s| s.to_string());
        let file_path = fields.get("file_path").map(|s| s.to_string());
        let tenant_id = fields.get("tenant_id").map(|s| s.to_string());
        let params_json = fields
            .get("params")
            .cloned()
            .unwrap_or_else(|| "{}".to_string());
        let params: serde_json::Value =
            serde_json::from_str(&params_json).unwrap_or_else(|_| serde_json::json!({}));

        let job_id = match job_id {
            Some(id) if !id.is_empty() => id,
            _ => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "missing or empty job_id",
                )));
            }
        };

        let scan_type = match scan_type {
            Some(st) if !st.is_empty() => st,
            _ => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "missing or empty scan_type",
                )));
            }
        };

        let target = match target {
            Some(t) if !t.is_empty() => t,
            _ => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "missing or empty target",
                )));
            }
        };

        // Tenant provenance: the `tenant_id` stream field only, never
        // trusted from anywhere else. Missing or unparseable is a fail-closed
        // rejection (see docs/v2-port/tenancy-model.md §3) — the message is
        // left un-acked (`Err`) so it is retried and eventually dead-lettered
        // rather than silently processed without tenant scoping.
        let tenant_id: uuid::Uuid = match tenant_id.as_deref().map(str::parse) {
            Some(Ok(id)) => id,
            _ => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "missing or invalid tenant_id",
                )));
            }
        };

        info!(job_id = %job_id, scan_type = %scan_type, target = %target, tenant_id = %tenant_id, "processing scanner task");

        // ASM has its own pipeline (masscan -> banner -> cert -> diff),
        // writes its own tables (asm_*, owned by services/manager's
        // migrations), and — unlike yara/clamav — never fails at the Rust
        // level (every outcome, including a masscan spawn failure, comes
        // back as a `ScannerResult` with `status: "error"`), so it bypasses
        // `crate::scan::execute_scan` entirely.
        let mut result = if scan_type == "asm" {
            if self.config.asm_enabled {
                // Screenshot stage only runs when both this worker enables
                // it and an uploader was actually built (bucket configured)
                // at startup — see `screenshot_uploader`'s doc.
                let screenshot = if self.config.asm_screenshot_enabled {
                    self.screenshot_uploader.clone().map(|uploader| {
                        crate::asm::ScreenshotStageConfig {
                            chromium_bin: self.config.chromium_bin.clone(),
                            timeout: Duration::from_secs(self.config.asm_screenshot_timeout_sec),
                            window_width: self.config.asm_screenshot_window_width,
                            window_height: self.config.asm_screenshot_window_height,
                            uploader,
                        }
                    })
                } else {
                    None
                };
                let cfg = crate::asm::AsmPipelineConfig {
                    masscan_bin: self.config.masscan_bin.clone(),
                    masscan_timeout: Duration::from_secs(self.config.asm_masscan_timeout_sec),
                    banner_timeout: Duration::from_secs(self.config.asm_banner_timeout_sec),
                    cert_timeout: Duration::from_secs(self.config.asm_cert_timeout_sec),
                    screenshot,
                };
                crate::asm::run_asm_scan(&self.pool, tenant_id, &target, &params, &cfg).await
            } else {
                ScannerResult {
                    job_id: job_id.clone(),
                    scan_type: scan_type.clone(),
                    findings_count: 0,
                    findings: serde_json::json!({}),
                    duration_sec: 0.0,
                    status: "error".to_string(),
                    error_message: Some("ASM scanning disabled".to_string()),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }
            }
        } else {
            let clamav_timeout = Duration::from_secs(self.config.clamav_timeout_sec);
            match crate::scan::execute_scan(
                &scan_type,
                &target,
                file_path.as_deref(),
                &params,
                self.yara_scanner.as_deref(),
                if self.config.clamav_enabled {
                    Some(&self.config.clamav_host)
                } else {
                    None
                },
                if self.config.clamav_enabled {
                    Some(self.config.clamav_port)
                } else {
                    None
                },
                clamav_timeout,
            )
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    error!(job_id = %job_id, error = %e, "scan execution failed");
                    ScannerResult {
                        job_id: job_id.clone(),
                        scan_type: scan_type.clone(),
                        findings_count: 0,
                        findings: serde_json::json!({}),
                        duration_sec: 0.0,
                        status: "error".to_string(),
                        error_message: Some(e.to_string()),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    }
                }
            }
        };
        result.job_id = job_id.clone();

        // Write result to database, stamped with the tenant derived from the
        // stream message above — never re-derived or trusted from `result`.
        if let Err(e) = crate::db::insert_scan_result(
            &self.pool,
            tenant_id,
            &result.job_id,
            &result.scan_type,
            &target,
            result.findings_count as i32,
            &serde_json::to_string(&result.findings).unwrap_or_default(),
            result.duration_sec,
            &result.status,
            result.error_message.as_deref(),
        )
        .await
        {
            error!(job_id = %job_id, error = %e, "failed to write result to database");
            // Don't fail the message — it's already computed; ack it.
        }

        // Publish result to onward stream.
        if let Err(e) = self
            .producer
            .publish(STREAM_SCANNER_RESULTS, result.to_entry_fields())
            .await
        {
            error!(job_id = %job_id, error = %e, "failed to publish result to stream");
            // Don't fail — result is in DB, stream publish is nice-to-have.
        } else {
            info!(job_id = %job_id, "result published to scanner results stream");
        }

        metrics::counter!("scanner_tasks_processed_total", "scan_type" => scan_type).increment(1);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;
    use fred::interfaces::{ClientLike, StreamsInterface};
    use fred::types::streams::XReadValue;
    use skauswatch_streams::STREAM_SCANNER_RESULTS;
    use sqlx::Row;
    use std::collections::HashMap;

    fn redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379/0".to_owned())
    }

    /// A fresh, uniquely-prefixed config per test so parallel test runs
    /// never collide on the same Redis stream keys.
    fn test_config(prefix: &str) -> WorkerConfig {
        WorkerConfig {
            health_port: 0,
            redis_url: redis_url(),
            redis_password: None,
            redis_prefix: prefix.to_owned(),
            consumer_group: "test-group".to_owned(),
            consumer_name: "test-consumer".to_owned(),
            max_concurrent_tasks: 1,
            clamav_host: "127.0.0.1".to_owned(),
            clamav_port: 1, // nothing listens here — exercises the degrade-to-clean path
            clamav_timeout_sec: 1,
            clamav_enabled: true,
            yara_rules_path: concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/yara_rules")
                .to_owned(),
            yara_enabled: true,
            asm_enabled: true,
            masscan_bin: "masscan".to_owned(),
            asm_masscan_timeout_sec: 5,
            asm_banner_timeout_sec: 1,
            asm_cert_timeout_sec: 1,
            // Screenshot stage exercised via `screenshot_uploader` passed
            // directly to `ScannerHandler::new` in the tests that need it —
            // most tests pass `None` there and never reach this config.
            asm_screenshot_enabled: true,
            chromium_bin: "chromium".to_owned(),
            asm_screenshot_timeout_sec: 1,
            asm_screenshot_window_width: 1280,
            asm_screenshot_window_height: 800,
            asm_screenshot_bucket: None,
        }
    }

    async fn db_pool() -> sqlx::PgPool {
        skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")).await
    }

    /// Like [`db_pool`] but also layers in `services/manager`'s migrations
    /// (`asm_*` tables — owned by manager, not this crate; see
    /// `crate::asm` module docs) — for the `scan_type: "asm"` dispatch
    /// tests below.
    async fn db_pool_with_manager() -> sqlx::PgPool {
        skauswatch_testkit::db::test_pool_multi(&[
            std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")),
            std::path::Path::new(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../manager/migrations"
            )),
        ])
        .await
    }

    async fn test_producer(prefix: &str) -> StreamProducer {
        StreamProducer::connect(&redis_url(), None, prefix)
            .await
            .expect("connect test producer")
    }

    /// Reads back the most recently published entry on the scanner results
    /// stream via a raw client — proves `handle` actually XADDed, not just
    /// that `publish()` didn't return an error.
    async fn latest_published_result(prefix: &str) -> HashMap<String, String> {
        let config = fred::types::config::Config::from_url(&redis_url()).expect("parse redis url");
        let client = fred::types::Builder::from_config(config)
            .build()
            .expect("build raw client");
        let _connect_task = client.init().await.expect("connect raw client");
        let key = format!("{prefix}:{STREAM_SCANNER_RESULTS}");
        let entries: Vec<XReadValue<String, String, String>> = client
            .xrevrange_values(key, "+", "-", Some(1))
            .await
            .expect("xrevrange");
        entries
            .into_iter()
            .next()
            .expect("a result was published")
            .1
    }

    fn entry(fields: &[(&str, &str)]) -> StreamEntry {
        StreamEntry {
            id: "1-0".to_owned(),
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    fn unique_prefix() -> String {
        format!("test-scanner-{}", uuid::Uuid::new_v4())
    }

    /// Fixed, distinct tenant UUIDs for handler-level tests — never the
    /// well-known bootstrap tenant seeded by the migration. Kept as string
    /// literals (the wire shape a stream field actually carries); parsed to
    /// `Uuid` at bind sites via [`tenant_uuid`] for query filtering.
    const TENANT_A: &str = "00000000-0000-0000-0000-0000000000aa";
    const TENANT_B: &str = "00000000-0000-0000-0000-0000000000bb";

    fn tenant_uuid(s: &str) -> uuid::Uuid {
        s.parse().expect("valid uuid literal")
    }

    #[tokio::test]
    async fn handle_rejects_missing_job_id() {
        let prefix = unique_prefix();
        let handler = ScannerHandler::new(
            db_pool().await,
            test_producer(&prefix).await,
            test_config(&prefix),
            None,
        );
        let e = entry(&[("scan_type", "yara"), ("target", "t")]);
        let err = handler
            .handle(&e)
            .await
            .expect_err("missing job_id must error");
        assert!(err.to_string().contains("job_id"));
    }

    #[tokio::test]
    async fn handle_rejects_missing_scan_type() {
        let prefix = unique_prefix();
        let handler = ScannerHandler::new(
            db_pool().await,
            test_producer(&prefix).await,
            test_config(&prefix),
            None,
        );
        let e = entry(&[("job_id", "job-1"), ("target", "t")]);
        let err = handler
            .handle(&e)
            .await
            .expect_err("missing scan_type must error");
        assert!(err.to_string().contains("scan_type"));
    }

    #[tokio::test]
    async fn handle_rejects_missing_target() {
        let prefix = unique_prefix();
        let handler = ScannerHandler::new(
            db_pool().await,
            test_producer(&prefix).await,
            test_config(&prefix),
            None,
        );
        let e = entry(&[("job_id", "job-1"), ("scan_type", "yara")]);
        let err = handler
            .handle(&e)
            .await
            .expect_err("missing target must error");
        assert!(err.to_string().contains("target"));
    }

    #[tokio::test]
    async fn handle_rejects_empty_string_fields_same_as_missing() {
        let prefix = unique_prefix();
        let handler = ScannerHandler::new(
            db_pool().await,
            test_producer(&prefix).await,
            test_config(&prefix),
            None,
        );
        let e = entry(&[("job_id", ""), ("scan_type", "yara"), ("target", "t")]);
        let err = handler
            .handle(&e)
            .await
            .expect_err("empty job_id must error same as absent");
        assert!(err.to_string().contains("job_id"));
    }

    #[tokio::test]
    async fn handle_rejects_missing_tenant_id() {
        let prefix = unique_prefix();
        let handler = ScannerHandler::new(
            db_pool().await,
            test_producer(&prefix).await,
            test_config(&prefix),
            None,
        );
        // All other required fields present and valid — only tenant_id is
        // absent — proves the rejection is specifically the tenant check,
        // not a fall-through from an earlier missing-field error.
        let e = entry(&[("job_id", "job-1"), ("scan_type", "yara"), ("target", "t")]);
        let err = handler
            .handle(&e)
            .await
            .expect_err("missing tenant_id must error");
        assert!(err.to_string().contains("tenant_id"));
    }

    #[tokio::test]
    async fn handle_rejects_unparseable_tenant_id() {
        let prefix = unique_prefix();
        let handler = ScannerHandler::new(
            db_pool().await,
            test_producer(&prefix).await,
            test_config(&prefix),
            None,
        );
        let e = entry(&[
            ("job_id", "job-1"),
            ("scan_type", "yara"),
            ("target", "t"),
            ("tenant_id", "not-a-uuid"),
        ]);
        let err = handler
            .handle(&e)
            .await
            .expect_err("non-UUID tenant_id must error same as absent");
        assert!(err.to_string().contains("tenant_id"));
    }

    #[tokio::test]
    async fn handle_yara_success_persists_row_and_publishes_result() {
        let prefix = unique_prefix();
        let db = db_pool().await;
        let handler = ScannerHandler::new(
            db.clone(),
            test_producer(&prefix).await,
            test_config(&prefix),
            None,
        );

        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        std::io::Write::write_all(&mut f, b"benign content, nothing malicious here")
            .expect("write tempfile");
        let path = f.path().to_str().expect("utf8 path").to_owned();

        let e = entry(&[
            ("job_id", "job-yara-1"),
            ("scan_type", "yara"),
            ("target", "benign.txt"),
            ("file_path", &path),
            ("tenant_id", TENANT_A),
        ]);
        handler.handle(&e).await.expect("handle succeeds");

        let row = sqlx::query(
            "SELECT status, findings_count, target FROM scanner_scan_results WHERE job_id = $1 AND tenant_id = $2",
        )
        .bind("job-yara-1")
        .bind(tenant_uuid(TENANT_A))
        .fetch_one(&db)
        .await
        .expect("row written to db, scoped to the submitting tenant");
        assert_eq!(row.get::<String, _>("status"), "success");
        assert_eq!(row.get::<i32, _>("findings_count"), 0);
        assert_eq!(row.get::<String, _>("target"), "benign.txt");

        let published = latest_published_result(&prefix).await;
        assert_eq!(published.get("job_id"), Some(&"job-yara-1".to_owned()));
        assert_eq!(published.get("status"), Some(&"success".to_owned()));
        assert_eq!(published.get("scan_type"), Some(&"yara".to_owned()));
    }

    #[tokio::test]
    async fn handle_unknown_scan_type_still_acks_persists_error_status() {
        let prefix = unique_prefix();
        let db = db_pool().await;
        let mut cfg = test_config(&prefix);
        cfg.yara_enabled = false; // this path never touches yara — keep the test light
        let handler = ScannerHandler::new(db.clone(), test_producer(&prefix).await, cfg, None);

        let e = entry(&[
            ("job_id", "job-bad"),
            ("scan_type", "bogus"),
            ("target", "t"),
            ("tenant_id", TENANT_A),
        ]);
        // Scan-level failures are not handler-level failures: the message
        // is still acked (Ok) because a result — even an error result — was
        // successfully computed and recorded.
        handler
            .handle(&e)
            .await
            .expect("handler acks scan-level errors");

        let row = sqlx::query(
            "SELECT status, error_message FROM scanner_scan_results WHERE job_id = $1 AND tenant_id = $2",
        )
        .bind("job-bad")
        .bind(tenant_uuid(TENANT_A))
        .fetch_one(&db)
        .await
        .expect("row written to db");
        assert_eq!(row.get::<String, _>("status"), "error");
        assert_eq!(
            row.get::<Option<String>, _>("error_message"),
            Some("unknown scan type: bogus".to_owned())
        );

        let published = latest_published_result(&prefix).await;
        assert_eq!(published.get("status"), Some(&"error".to_owned()));
    }

    #[tokio::test]
    async fn handle_clamav_unreachable_daemon_persists_clean_success_row() {
        let prefix = unique_prefix();
        let db = db_pool().await;
        let mut cfg = test_config(&prefix);
        cfg.yara_enabled = false;
        let handler = ScannerHandler::new(db.clone(), test_producer(&prefix).await, cfg, None);

        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        std::io::Write::write_all(&mut f, b"whatever").expect("write tempfile");
        let path = f.path().to_str().expect("utf8 path").to_owned();

        let e = entry(&[
            ("job_id", "job-clam-1"),
            ("scan_type", "clamav"),
            ("target", "t"),
            ("file_path", &path),
            ("tenant_id", TENANT_A),
        ]);
        handler.handle(&e).await.expect("handle succeeds");

        let row = sqlx::query(
            "SELECT status, error_message FROM scanner_scan_results WHERE job_id = $1 AND tenant_id = $2",
        )
        .bind("job-clam-1")
        .bind(tenant_uuid(TENANT_A))
        .fetch_one(&db)
        .await
        .expect("row written to db");
        assert_eq!(row.get::<String, _>("status"), "success");
        assert_eq!(row.get::<Option<String>, _>("error_message"), None);
    }

    #[tokio::test]
    async fn handle_asm_disabled_reports_error_without_running_pipeline() {
        let prefix = unique_prefix();
        let db = db_pool().await;
        let mut cfg = test_config(&prefix);
        cfg.asm_enabled = false;
        let handler = ScannerHandler::new(db.clone(), test_producer(&prefix).await, cfg, None);

        let e = entry(&[
            ("job_id", "job-asm-disabled"),
            ("scan_type", "asm"),
            ("target", "example.com"),
            ("params", r#"{"scan_id": 1}"#),
            ("tenant_id", TENANT_A),
        ]);
        handler
            .handle(&e)
            .await
            .expect("handler acks disabled-asm as a computed error result");

        let row = sqlx::query(
            "SELECT status, error_message FROM scanner_scan_results WHERE job_id = $1 AND tenant_id = $2",
        )
        .bind("job-asm-disabled")
        .bind(tenant_uuid(TENANT_A))
        .fetch_one(&db)
        .await
        .expect("row written to db");
        assert_eq!(row.get::<String, _>("status"), "error");
        assert_eq!(
            row.get::<Option<String>, _>("error_message"),
            Some("ASM scanning disabled".to_owned())
        );
    }

    #[tokio::test]
    async fn handle_asm_enabled_dispatches_to_pipeline_and_persists_both_rows() {
        let prefix = unique_prefix();
        let db = db_pool_with_manager().await;

        // Seed the tenant row (asm_scans.tenant_id FK-references it — this
        // is a manager-owned table) then a pending asm_scans row (manager's
        // job — done here via raw SQL since this test only exercises the
        // scanner-side consumer).
        sqlx::query(
            "INSERT INTO tenants (id, slug, name, status) \
             VALUES ($1, 'asm-handler-test', 'ASM Handler Test', 'active') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant_uuid(TENANT_A))
        .execute(&db)
        .await
        .expect("seed tenant");

        let scan_id: i64 = sqlx::query_scalar(
            "INSERT INTO asm_scans (tenant_id, target, mode, status, created_at) \
             VALUES ($1, 'example.com', 'external', 'pending', now()) RETURNING id",
        )
        .bind(tenant_uuid(TENANT_A))
        .fetch_one(&db)
        .await
        .expect("seed asm scan");

        // Reserve a unique path, then write+close through a separate,
        // explicitly-scoped handle before chmod/exec — executing a path
        // that still has any open write handle (even one nominally
        // "closed" via `into_temp_path` alone) proved flaky under this
        // container's overlay filesystem (intermittent `ETXTBSY`).
        let masscan_path = tempfile::NamedTempFile::new()
            .expect("tempfile")
            .into_temp_path();
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&masscan_path)
                .expect("open for write");
            std::io::Write::write_all(&mut file, b"#!/bin/sh\necho '[]'\n")
                .expect("write fake masscan");
            file.sync_all().expect("sync");
        }
        let mut perms = std::fs::metadata(&masscan_path)
            .expect("metadata")
            .permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&masscan_path, perms).expect("chmod");
        let masscan_bin = masscan_path.to_str().expect("utf8 path").to_owned();

        let mut cfg = test_config(&prefix);
        cfg.masscan_bin = masscan_bin;
        let handler = ScannerHandler::new(db.clone(), test_producer(&prefix).await, cfg, None);

        let e = entry(&[
            ("job_id", "job-asm-1"),
            ("scan_type", "asm"),
            ("target", "example.com"),
            ("params", &format!(r#"{{"scan_id": {scan_id}}}"#)),
            ("tenant_id", TENANT_A),
        ]);
        handler.handle(&e).await.expect("handle succeeds");

        let generic_row = sqlx::query(
            "SELECT status, scan_type FROM scanner_scan_results WHERE job_id = $1 AND tenant_id = $2",
        )
        .bind("job-asm-1")
        .bind(tenant_uuid(TENANT_A))
        .fetch_one(&db)
        .await
        .expect("generic result row written");
        assert_eq!(generic_row.get::<String, _>("status"), "success");
        assert_eq!(generic_row.get::<String, _>("scan_type"), "asm");

        let scan_status: String = sqlx::query_scalar("SELECT status FROM asm_scans WHERE id = $1")
            .bind(scan_id)
            .fetch_one(&db)
            .await
            .expect("asm_scans row");
        assert_eq!(scan_status, "completed");
    }

    #[tokio::test]
    async fn handle_stamps_rows_with_the_submitting_tenant_only() {
        let prefix = unique_prefix();
        let db = db_pool().await;
        let handler = ScannerHandler::new(
            db.clone(),
            test_producer(&prefix).await,
            test_config(&prefix),
            None,
        );

        // Same job_id from two different tenants — proves the row is
        // isolated by tenant, not just present in the table.
        let e_a = entry(&[
            ("job_id", "job-shared"),
            ("scan_type", "bogus"),
            ("target", "target-a"),
            ("tenant_id", TENANT_A),
        ]);
        let e_b = entry(&[
            ("job_id", "job-shared"),
            ("scan_type", "bogus"),
            ("target", "target-b"),
            ("tenant_id", TENANT_B),
        ]);
        handler
            .handle(&e_a)
            .await
            .expect("tenant A handle succeeds");
        handler
            .handle(&e_b)
            .await
            .expect("tenant B handle succeeds");

        let a_row = sqlx::query(
            "SELECT target FROM scanner_scan_results WHERE job_id = $1 AND tenant_id = $2",
        )
        .bind("job-shared")
        .bind(tenant_uuid(TENANT_A))
        .fetch_one(&db)
        .await
        .expect("tenant A row exists");
        assert_eq!(a_row.get::<String, _>("target"), "target-a");

        let b_row = sqlx::query(
            "SELECT target FROM scanner_scan_results WHERE job_id = $1 AND tenant_id = $2",
        )
        .bind("job-shared")
        .bind(tenant_uuid(TENANT_B))
        .fetch_one(&db)
        .await
        .expect("tenant B row exists");
        assert_eq!(b_row.get::<String, _>("target"), "target-b");
    }

    #[tokio::test]
    async fn new_disables_yara_scanner_when_config_flag_is_false() {
        let prefix = unique_prefix();
        let mut cfg = test_config(&prefix);
        cfg.yara_enabled = false;
        let handler = ScannerHandler::new(db_pool().await, test_producer(&prefix).await, cfg, None);
        assert!(handler.yara_scanner.is_none());
    }

    #[tokio::test]
    async fn new_yara_scanner_is_none_when_rules_path_is_invalid() {
        let prefix = unique_prefix();
        let mut cfg = test_config(&prefix);
        cfg.yara_rules_path = "/nonexistent/rules/path".to_owned();
        let handler = ScannerHandler::new(db_pool().await, test_producer(&prefix).await, cfg, None);
        assert!(handler.yara_scanner.is_none());
    }

    #[tokio::test]
    async fn new_loads_yara_scanner_when_enabled_and_path_is_valid() {
        let prefix = unique_prefix();
        let handler = ScannerHandler::new(
            db_pool().await,
            test_producer(&prefix).await,
            test_config(&prefix),
            None,
        );
        assert!(handler.yara_scanner.is_some());
    }
}
