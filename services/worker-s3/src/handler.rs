//! The [`StreamHandler`] that turns one `s3scan:tasks` entry into scan work.
//!
//! Flow by task variant (see `message.rs`):
//! - **Enumerate** (empty object key): resolve the job + bucket config, list
//!   the bucket (prefix + filters + size skip), set the job `running` with a
//!   total, bump `skipped_objects`, then re-dispatch one per-object task per
//!   surviving object. All fallible DB/list work happens *before* any dispatch
//!   so a transient failure is safe to retry without double-dispatching.
//! - **BucketObject**: download, scan, insert a result row, bump job counters,
//!   tag the object, publish an onward result event, and complete the job when
//!   the last object lands.
//! - **InlineObject** (gRPC full task, inline creds): scan; persist only when a
//!   matching job row exists; always publish the onward event.
//! - **Adhoc**: best-effort — scan the upload from the configured ad-hoc bucket
//!   or mark the row `error` (the manager does not persist upload bytes today).
//!
//! Handler errors are classified: [`ProcessError::Permanent`] entries (poison,
//! unknown job/bucket, scanning disabled) are acked after a warning;
//! [`ProcessError::Transient`] entries (DB/S3/publish failures) are left
//! pending for the harness to retry and eventually dead-letter.

use std::time::Instant;

use skauswatch_streams::{
    EntryFields, HandlerError, STREAM_S3_SCAN_RESULTS, STREAM_S3_SCAN_TASKS, StreamEntry,
    StreamHandler, StreamProducer, py_bool, py_now_isoformat,
};
use sqlx::PgPool;

use crate::clamav;
use crate::config::WorkerConfig;
use crate::db;
use crate::enumerate::{Decision, classify_object, dispatch_fields};
use crate::message::{
    AdhocTask, BucketObjectTask, EnumerateTask, InlineObjectTask, ParseError, Task,
};
use crate::s3ops;
use crate::scan::{self, Hashes};
use crate::ti;

/// Classified processing failure.
enum ProcessError {
    /// Non-retryable — ack the entry after logging.
    Permanent(String),
    /// Retryable — leave the entry pending for retry/DLQ.
    Transient(String),
}

impl From<ParseError> for ProcessError {
    fn from(e: ParseError) -> Self {
        ProcessError::Permanent(e.to_string())
    }
}

/// Aggregated content-scan outcome for one object's bytes.
struct Verdict {
    file_type: String,
    hashes: Hashes,
    is_malware: bool,
    is_pup: bool,
    is_threat: bool,
    threat_names: Vec<String>,
    clamav_result: Option<serde_json::Value>,
    ti_enrichment: Option<serde_json::Value>,
}

/// Worker task handler holding the shared DB pool, stream producer (re-dispatch
/// + onward events), an HTTP client for TI, and the loaded config.
pub struct S3ScanHandler {
    pool: PgPool,
    producer: StreamProducer,
    http: reqwest::Client,
    cfg: WorkerConfig,
}

impl S3ScanHandler {
    /// Builds a handler from its dependencies.
    pub fn new(pool: PgPool, producer: StreamProducer, cfg: WorkerConfig) -> Self {
        Self {
            pool,
            producer,
            http: reqwest::Client::new(),
            cfg,
        }
    }

    /// Runs the content pipeline (file type, hashes, ClamAV, TI) over `data`.
    /// ClamAV/TI degrade to "clean"/empty when unavailable, and the whole
    /// external-scan phase is bounded by `SCAN_TIMEOUT_SEC` (v1 parity); a
    /// timeout yields a clean verdict with default enrichment.
    async fn scan_content(&self, data: &[u8]) -> Verdict {
        let file_type = scan::detect_file_type(data);
        let hashes = scan::compute_hashes(data);

        let external = async {
            let (is_malware, is_pup, threat_names, clamav_result) = match clamav::scan_bytes(
                &self.cfg.clamd_socket,
                std::time::Duration::from_secs(self.cfg.clamd_timeout),
                data,
            )
            .await
            {
                Ok(v) => {
                    let clamav_json = serde_json::json!({
                        "is_malware": v.is_malware,
                        "is_pup": v.is_pup,
                        "threats": v.threat_names,
                    });
                    (v.is_malware, v.is_pup, v.threat_names, Some(clamav_json))
                }
                Err(e) => {
                    tracing::debug!(error = %e, "ClamAV unavailable — scanning skipped (clean)");
                    (false, false, Vec::new(), None)
                }
            };
            let ti_enrichment = if self.cfg.ti_enabled {
                Some(
                    ti::enrich(
                        &self.http,
                        self.cfg.virustotal_api_key.as_deref(),
                        self.cfg.otx_api_key.as_deref(),
                        &hashes,
                        &threat_names,
                    )
                    .await,
                )
            } else {
                None
            };
            (
                is_malware,
                is_pup,
                threat_names,
                clamav_result,
                ti_enrichment,
            )
        };

        let timeout = std::time::Duration::from_secs(self.cfg.scan_timeout_sec);
        let (is_malware, is_pup, threat_names, clamav_result, ti_enrichment) =
            match tokio::time::timeout(timeout, external).await {
                Ok(t) => t,
                Err(_) => {
                    tracing::warn!("content scan timed out — recording clean verdict");
                    let ti = self.cfg.ti_enabled.then(|| ti::default_result(&[]));
                    (false, false, Vec::new(), None, ti)
                }
            };

        Verdict {
            file_type,
            hashes,
            is_malware,
            is_pup,
            is_threat: is_malware || is_pup,
            threat_names,
            clamav_result,
            ti_enrichment,
        }
    }

    /// Top-level dispatch, converting parse errors into permanent failures.
    async fn process(&self, entry: &StreamEntry) -> Result<(), ProcessError> {
        match Task::parse(entry)? {
            Task::Enumerate(t) => self.enumerate(&t).await,
            Task::BucketObject(t) => self.scan_bucket_object(&t).await,
            Task::InlineObject(t) => self.scan_inline_object(&t).await,
            Task::Adhoc(t) => self.scan_adhoc(&t).await,
        }
    }

    /// Enumerates a bucket and re-dispatches per-object tasks.
    async fn enumerate(&self, t: &EnumerateTask) -> Result<(), ProcessError> {
        let job = self
            .lookup_job(&t.job_id)
            .await?
            .ok_or_else(|| ProcessError::Permanent(format!("unknown job {}", t.job_id)))?;
        let bucket = self
            .lookup_bucket(t.bucket_config_id)
            .await?
            .ok_or_else(|| {
                ProcessError::Permanent(format!("unknown bucket_config {}", t.bucket_config_id))
            })?;
        if !bucket.scan_enabled {
            return Err(ProcessError::Permanent(format!(
                "scanning disabled for bucket {}",
                bucket.id
            )));
        }

        let client = s3ops::client_from_credentials(
            &bucket.endpoint_url,
            &bucket.access_key_id,
            &bucket.secret_access_key,
            &bucket.region,
            bucket.path_style,
        );
        let prefix = job
            .prefix_override
            .clone()
            .or_else(|| bucket.prefix_filter.clone());
        let objects = s3ops::list_all_objects(&client, &bucket.bucket_name, prefix.as_deref())
            .await
            .map_err(ProcessError::Transient)?;

        let max_bytes = (bucket.max_file_size_mb.max(0) as u64) * 1024 * 1024;
        let mut to_scan: Vec<s3ops::ObjectMeta> = Vec::new();
        let mut skipped: i32 = 0;
        for obj in objects {
            match classify_object(&obj.key, obj.size, &bucket.file_types_filter, max_bytes) {
                Decision::Scan => to_scan.push(obj),
                Decision::SkipTooLarge | Decision::SkipFiltered => skipped += 1,
            }
        }
        let total = i32::try_from(to_scan.len())
            .unwrap_or(i32::MAX)
            .saturating_add(skipped);

        // All fallible DB work first — dispatch (non-idempotent) happens last.
        db::set_job_running(&self.pool, job.pk, total)
            .await
            .map_err(|e| ProcessError::Transient(e.to_string()))?;
        if skipped > 0 {
            db::bump_job_skipped(&self.pool, job.pk, skipped)
                .await
                .map_err(|e| ProcessError::Transient(e.to_string()))?;
        }

        // The bucket's YARA policy applies to every enumerated object (v1 read
        // it off the bucket config); OR it with any per-task request.
        let yara_enabled = t.yara_enabled || bucket.yara_enabled;
        for obj in &to_scan {
            let fields = dispatch_fields(
                &t.job_id,
                t.bucket_config_id,
                &obj.key,
                obj.size,
                &obj.etag,
                yara_enabled,
            );
            if let Err(e) = self.producer.publish(STREAM_S3_SCAN_TASKS, fields).await {
                tracing::warn!(object = %obj.key, error = %e, "per-object dispatch failed");
            }
        }

        // Complete immediately when nothing needs scanning (all skipped/empty).
        if let Err(e) = db::maybe_complete_job(&self.pool, job.pk).await {
            tracing::warn!(job = %t.job_id, error = %e, "job completion check failed");
        }
        tracing::info!(
            job = %t.job_id, bucket = %bucket.bucket_name,
            dispatched = to_scan.len(), skipped, "bucket enumerated"
        );
        Ok(())
    }

    /// Scans one object addressed by a stored bucket config.
    async fn scan_bucket_object(&self, t: &BucketObjectTask) -> Result<(), ProcessError> {
        let job = self
            .lookup_job(&t.job_id)
            .await?
            .ok_or_else(|| ProcessError::Permanent(format!("unknown job {}", t.job_id)))?;
        let bucket = self
            .lookup_bucket(t.bucket_config_id)
            .await?
            .ok_or_else(|| {
                ProcessError::Permanent(format!("unknown bucket_config {}", t.bucket_config_id))
            })?;
        let client = s3ops::client_from_credentials(
            &bucket.endpoint_url,
            &bucket.access_key_id,
            &bucket.secret_access_key,
            &bucket.region,
            bucket.path_style,
        );
        let max_bytes = (bucket.max_file_size_mb.max(0) as u64) * 1024 * 1024;

        let start = Instant::now();
        let bytes = s3ops::download_object(&client, &bucket.bucket_name, &t.object_key, max_bytes)
            .await
            .map_err(ProcessError::Transient)?;
        let Some(bytes) = bytes else {
            return self.record_skipped(job.pk, t).await;
        };

        let verdict = self.scan_content(&bytes).await;
        let duration_ms = i32::try_from(start.elapsed().as_millis()).unwrap_or(i32::MAX);
        let record = self.result_record(
            job.pk,
            bucket.id,
            t,
            i32::try_from(bytes.len()).unwrap_or(i32::MAX),
            &verdict,
            duration_ms,
        );
        db::insert_result(&self.pool, &record)
            .await
            .map_err(|e| ProcessError::Transient(e.to_string()))?;
        db::bump_job_counters(
            &self.pool,
            job.pk,
            verdict.is_malware,
            verdict.is_pup,
            false,
        )
        .await
        .map_err(|e| ProcessError::Transient(e.to_string()))?;
        if let Err(e) = db::maybe_complete_job(&self.pool, job.pk).await {
            tracing::warn!(job = %t.job_id, error = %e, "job completion check failed");
        }

        // Best-effort side effects.
        let tags = scan::scan_tags(
            verdict.is_malware,
            verdict.is_pup,
            &verdict.file_type,
            chrono::Utc::now().timestamp_millis(),
        );
        if !s3ops::put_object_tags(&client, &bucket.bucket_name, &t.object_key, &tags).await {
            tracing::debug!(object = %t.object_key, "tagging failed (best-effort)");
        }
        self.publish_result_event("", &t.job_id, &t.object_key, &verdict, duration_ms)
            .await;
        Ok(())
    }

    /// Scans one object using inline gRPC credentials; persists only when the
    /// job row exists (gRPC submissions may not have created one).
    async fn scan_inline_object(&self, t: &InlineObjectTask) -> Result<(), ProcessError> {
        let client = s3ops::client_from_credentials(
            &t.endpoint_url,
            &t.access_key,
            &t.secret_key,
            &t.region,
            t.path_style,
        );
        let max_bytes = self.cfg.max_file_size_bytes();
        let start = Instant::now();
        let bytes = s3ops::download_object(&client, &t.bucket_name, &t.object_key, max_bytes)
            .await
            .map_err(ProcessError::Transient)?;
        let Some(bytes) = bytes else {
            tracing::info!(object = %t.object_key, "inline object too large — skipped");
            return Ok(());
        };
        let verdict = self.scan_content(&bytes).await;
        let duration_ms = i32::try_from(start.elapsed().as_millis()).unwrap_or(i32::MAX);

        if let Some(job) = self.lookup_job(&t.job_id).await? {
            let bucket_config_id = t.bucket_config_id.unwrap_or(job.bucket_config_id);
            let bo = BucketObjectTask {
                job_id: t.job_id.clone(),
                bucket_config_id,
                object_key: t.object_key.clone(),
                object_size: t.object_size,
                object_etag: String::new(),
                yara_enabled: t.yara_enabled,
            };
            let record = self.result_record(
                job.pk,
                bucket_config_id,
                &bo,
                i32::try_from(bytes.len()).unwrap_or(i32::MAX),
                &verdict,
                duration_ms,
            );
            db::insert_result(&self.pool, &record)
                .await
                .map_err(|e| ProcessError::Transient(e.to_string()))?;
            db::bump_job_counters(
                &self.pool,
                job.pk,
                verdict.is_malware,
                verdict.is_pup,
                false,
            )
            .await
            .map_err(|e| ProcessError::Transient(e.to_string()))?;
            let _ = db::maybe_complete_job(&self.pool, job.pk).await;
        }
        self.publish_result_event(&t.task_id, &t.job_id, &t.object_key, &verdict, duration_ms)
            .await;
        Ok(())
    }

    /// Best-effort ad-hoc scan. Without a configured ad-hoc bucket the upload
    /// bytes are unavailable (the manager stores only hashes), so the row is
    /// marked `error`.
    async fn scan_adhoc(&self, t: &AdhocTask) -> Result<(), ProcessError> {
        let Some(bucket) = self.cfg.adhoc_bucket.clone() else {
            tracing::warn!(scan_id = %t.scan_id, "no ad-hoc bucket configured — marking error");
            db::set_adhoc_error(&self.pool, &t.scan_id)
                .await
                .map_err(|e| ProcessError::Transient(e.to_string()))?;
            return Ok(());
        };

        let client = self.adhoc_client().await;
        let start = Instant::now();
        let bytes = match s3ops::download_object(
            &client,
            &bucket,
            &t.object_key,
            self.cfg.max_file_size_bytes(),
        )
        .await
        {
            Ok(Some(b)) => b,
            Ok(None) | Err(_) => {
                tracing::warn!(scan_id = %t.scan_id, "ad-hoc content unavailable — marking error");
                db::set_adhoc_error(&self.pool, &t.scan_id)
                    .await
                    .map_err(|e| ProcessError::Transient(e.to_string()))?;
                return Ok(());
            }
        };

        let verdict = self.scan_content(&bytes).await;
        let duration_ms = i32::try_from(start.elapsed().as_millis()).unwrap_or(i32::MAX);
        db::finish_adhoc(
            &self.pool,
            &t.scan_id,
            db::scan_status_for(verdict.is_malware, verdict.is_pup),
            verdict.is_malware,
            verdict.is_pup,
            verdict.is_threat,
            &verdict.file_type,
            &serde_json::Value::from(verdict.threat_names.clone()),
            verdict.clamav_result.as_ref(),
            duration_ms,
        )
        .await
        .map_err(|e| ProcessError::Transient(e.to_string()))?;
        Ok(())
    }

    /// Records a `skipped` result row for an object too large at download time.
    async fn record_skipped(&self, job_pk: i32, t: &BucketObjectTask) -> Result<(), ProcessError> {
        let record = db::ResultRecord {
            job_pk,
            bucket_config_id: t.bucket_config_id,
            object_key: t.object_key.clone(),
            object_size: i32::try_from(t.object_size).unwrap_or(i32::MAX),
            object_etag: (!t.object_etag.is_empty()).then(|| t.object_etag.clone()),
            detected_file_type: scan::UNKNOWN_MIME.to_owned(),
            scan_status: "skipped".to_owned(),
            is_malware: false,
            is_pup: false,
            is_threat: false,
            threat_names: serde_json::Value::Array(vec![]),
            clamav_result: None,
            ti_enrichment: None,
            file_md5: None,
            file_sha1: None,
            file_sha256: None,
            tags_applied: None,
            scan_duration_ms: 0,
        };
        db::insert_result(&self.pool, &record)
            .await
            .map_err(|e| ProcessError::Transient(e.to_string()))?;
        db::bump_job_skipped(&self.pool, job_pk, 1)
            .await
            .map_err(|e| ProcessError::Transient(e.to_string()))?;
        let _ = db::maybe_complete_job(&self.pool, job_pk).await;
        Ok(())
    }

    /// Builds a result row from a verdict and object metadata.
    fn result_record(
        &self,
        job_pk: i32,
        bucket_config_id: i32,
        t: &BucketObjectTask,
        object_size: i32,
        v: &Verdict,
        duration_ms: i32,
    ) -> db::ResultRecord {
        let tags = scan::scan_tags(v.is_malware, v.is_pup, &v.file_type, 0);
        db::ResultRecord {
            job_pk,
            bucket_config_id,
            object_key: t.object_key.clone(),
            object_size,
            object_etag: (!t.object_etag.is_empty()).then(|| t.object_etag.clone()),
            detected_file_type: v.file_type.clone(),
            scan_status: db::scan_status_for(v.is_malware, v.is_pup).to_owned(),
            is_malware: v.is_malware,
            is_pup: v.is_pup,
            is_threat: v.is_threat,
            threat_names: serde_json::Value::from(v.threat_names.clone()),
            clamav_result: v.clamav_result.clone(),
            ti_enrichment: v.ti_enrichment.clone(),
            file_md5: Some(v.hashes.md5.clone()),
            file_sha1: Some(v.hashes.sha1.clone()),
            file_sha256: Some(v.hashes.sha256.clone()),
            tags_applied: Some(serde_json::Value::from(
                tags.iter()
                    .map(|(k, val)| format!("{k}={val}"))
                    .collect::<Vec<_>>(),
            )),
            scan_duration_ms: duration_ms,
        }
    }

    /// Publishes an onward result event to `s3scan:results` (best-effort, v1
    /// redis-py field encodings).
    async fn publish_result_event(
        &self,
        task_id: &str,
        job_id: &str,
        object_key: &str,
        v: &Verdict,
        duration_ms: i32,
    ) {
        let fields: EntryFields = vec![
            ("task_id".to_owned(), task_id.to_owned()),
            ("job_id".to_owned(), job_id.to_owned()),
            ("object_key".to_owned(), object_key.to_owned()),
            (
                "scan_status".to_owned(),
                db::scan_status_for(v.is_malware, v.is_pup).to_owned(),
            ),
            ("is_malware".to_owned(), py_bool(v.is_malware).to_owned()),
            ("is_pup".to_owned(), py_bool(v.is_pup).to_owned()),
            ("is_threat".to_owned(), py_bool(v.is_threat).to_owned()),
            ("detected_file_type".to_owned(), v.file_type.clone()),
            ("file_md5".to_owned(), v.hashes.md5.clone()),
            ("file_sha1".to_owned(), v.hashes.sha1.clone()),
            ("file_sha256".to_owned(), v.hashes.sha256.clone()),
            ("threat_count".to_owned(), v.threat_names.len().to_string()),
            (
                "threats".to_owned(),
                v.threat_names
                    .iter()
                    .take(10)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            ("scan_duration_ms".to_owned(), duration_ms.to_string()),
            ("timestamp".to_owned(), py_now_isoformat()),
        ];
        if let Err(e) = self.producer.publish(STREAM_S3_SCAN_RESULTS, fields).await {
            tracing::warn!(job = %job_id, error = %e, "onward result publish failed");
        }
    }

    /// Builds the ad-hoc S3 client from the worker's `S3_*` settings, resolving
    /// credentials through the AWS provider chain.
    async fn adhoc_client(&self) -> aws_sdk_s3::Client {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(self.cfg.s3_region.clone()));
        if let Some(ep) = &self.cfg.s3_endpoint_url {
            loader = loader.endpoint_url(ep);
        }
        let shared = loader.load().await;
        let s3_cfg = aws_sdk_s3::config::Builder::from(&shared)
            .force_path_style(self.cfg.s3_force_path_style)
            .build();
        aws_sdk_s3::Client::from_conf(s3_cfg)
    }

    /// DB job lookup mapping errors to transient failures.
    async fn lookup_job(&self, job_uuid: &str) -> Result<Option<db::JobRef>, ProcessError> {
        db::fetch_job(&self.pool, job_uuid)
            .await
            .map_err(|e| ProcessError::Transient(e.to_string()))
    }

    /// DB bucket-config lookup mapping errors to transient failures.
    async fn lookup_bucket(&self, id: i32) -> Result<Option<db::BucketConfig>, ProcessError> {
        db::fetch_bucket_config(&self.pool, id)
            .await
            .map_err(|e| ProcessError::Transient(e.to_string()))
    }
}

#[async_trait::async_trait]
impl StreamHandler for S3ScanHandler {
    async fn handle(&self, entry: &StreamEntry) -> Result<(), HandlerError> {
        match self.process(entry).await {
            Ok(()) => Ok(()),
            Err(ProcessError::Permanent(msg)) => {
                tracing::warn!(id = %entry.id, reason = %msg, "permanent failure — acking poison entry");
                Ok(())
            }
            Err(ProcessError::Transient(msg)) => Err(msg.into()),
        }
    }
}
