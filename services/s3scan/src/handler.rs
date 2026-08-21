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
use skauswatch_vault::EnvelopeEncryption;
use sqlx::PgPool;

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

/// This worker's own-AWS JWT-SVID federation config for [`S3ScanHandler::adhoc_client`]
/// — dal2's IRSA equivalent (see `docs/v2-port/aws-identity-runbook.md`).
/// `identity` is a trait object (not the concrete
/// `skauswatch_identity::IdentityProvider`) purely so this module's own
/// tests can substitute a hermetic fake; the real binary always wires the
/// genuine `IdentityProvider`. Absent entirely (the default via
/// [`S3ScanHandler::new`]) means `adhoc_client` behaves exactly as before
/// this feature existed.
#[derive(Clone)]
struct Federation {
    identity: std::sync::Arc<dyn skauswatch_s3::credentials::JwtSvidSource>,
    /// This worker's own service-owned IAM role ARN — never a customer's.
    role_arn: String,
}

/// Worker task handler holding the shared DB pool, stream producer
/// (re-dispatch and onward events), an HTTP client for TI, the loaded
/// config, the shared ClamAV+YARA-X scan engine, and the envelope-encryption
/// engine used to decrypt `static`-mode stored bucket credentials (security
/// finding #2 — see `skauswatch_s3::credentials`).
pub struct S3ScanHandler {
    pool: PgPool,
    producer: StreamProducer,
    http: reqwest::Client,
    cfg: WorkerConfig,
    envelope: EnvelopeEncryption,
    /// Shared ClamAV+YARA-X engine (`skauswatch-scan-core`). Built once in
    /// `main.rs::serve` (YARA rule compilation happens there, not per
    /// request) and handed in — see [`S3ScanHandler::new`].
    scan_engine: skauswatch_scan_core::ScanEngine,
    /// Own-AWS federation for `adhoc_client`'s default-chain fallback.
    /// `None` (the only value [`S3ScanHandler::new`] ever sets) preserves
    /// today's behavior exactly — see [`S3ScanHandler::with_federation`].
    federation: Option<Federation>,
}

impl S3ScanHandler {
    /// Builds a handler from its dependencies.
    pub fn new(
        pool: PgPool,
        producer: StreamProducer,
        cfg: WorkerConfig,
        envelope: EnvelopeEncryption,
        scan_engine: skauswatch_scan_core::ScanEngine,
    ) -> Self {
        Self {
            pool,
            producer,
            http: reqwest::Client::new(),
            cfg,
            envelope,
            scan_engine,
            federation: None,
        }
    }

    /// Enables JWT-SVID-&gt;STS federation for `adhoc_client`'s own-AWS
    /// access (`docs/v2-port/aws-identity-runbook.md` §1) — dal2 has no
    /// IRSA/instance-profile identity to fall back to, so without this the
    /// default AWS credential-provider chain has nothing to resolve to.
    ///
    /// Fail-safe by construction: `adhoc_client` only *attempts*
    /// federation when this has been called; if the underlying
    /// `identity` source itself has no attested identity (or the STS
    /// exchange fails), `adhoc_client` logs a warning and falls back to
    /// the default AWS credential-provider chain — the caller here never
    /// needs to pre-check identity health.
    #[must_use]
    pub fn with_federation(
        mut self,
        identity: std::sync::Arc<dyn skauswatch_s3::credentials::JwtSvidSource>,
        role_arn: String,
    ) -> Self {
        self.federation = Some(Federation { identity, role_arn });
        self
    }

    /// Resolves a stored bucket config's hybrid credentials
    /// (`assume_role`/`static`) into a ready-to-use S3 client. Any failure
    /// here — bad config shape, decrypt failure, STS error — is transient
    /// from the harness's point of view unless the underlying
    /// `CredentialError` is itself classified permanent (config-shape
    /// errors that will never succeed on retry).
    async fn client_for_bucket(
        &self,
        bucket: &db::BucketConfig,
    ) -> Result<aws_sdk_s3::Client, ProcessError> {
        let identity_mode = skauswatch_s3::credentials::AwsIdentityMode::from_kind(
            self.cfg.aws_identity_mode,
            self.federation
                .as_ref()
                .map(|f| (f.identity.as_ref(), f.role_arn.as_str())),
        );
        skauswatch_s3::credentials::resolve_client(
            &self.envelope,
            &bucket.credential_config(),
            &identity_mode,
        )
        .await
        .map_err(|e| {
            if e.is_permanent() {
                ProcessError::Permanent(format!(
                    "bucket {} credential resolution failed: {e}",
                    bucket.id
                ))
            } else {
                ProcessError::Transient(format!(
                    "bucket {} credential resolution failed: {e}",
                    bucket.id
                ))
            }
        })
    }

    /// Runs the content pipeline (file type, hashes, ClamAV, YARA, TI) over
    /// `data`, delegating malware detection to the shared
    /// [`skauswatch_scan_core::ScanEngine`]. `yara_enabled` is the caller's
    /// per-task/per-bucket flag (`t.yara_enabled`, already OR'd with the
    /// bucket's own flag at dispatch time — see `enumerate`); YARA only
    /// actually runs when this is `true` *and* the engine has rules loaded
    /// (`YARA_RULES_PATH` configured). ClamAV/YARA/TI degrade to
    /// "clean"/empty when unavailable, and the whole external-scan phase is
    /// bounded by `SCAN_TIMEOUT_SEC` (v1 parity); a timeout yields a clean
    /// verdict with default enrichment.
    async fn scan_content(&self, data: &[u8], yara_enabled: bool) -> Verdict {
        let options = skauswatch_scan_core::ScanOptions {
            run_clamav: true,
            run_yara: yara_enabled,
        };

        let external = async {
            let outcome = match self
                .scan_engine
                .scan_bytes_with_options(data, options)
                .await
            {
                Ok(o) => o,
                Err(e) => {
                    // Only a mechanical YARA-execution failure reaches here
                    // (ClamAV daemon failures already degrade to clean
                    // inside the engine) — treat it the same way: log and
                    // fall back to a clean verdict for this attempt, still
                    // carrying real file type/hashes.
                    tracing::warn!(error = %e, "scan engine error — recording clean verdict");
                    skauswatch_scan_core::ScanOutcome {
                        verdict: skauswatch_scan_core::Verdict::Clean,
                        is_malware: false,
                        is_pup: false,
                        is_threat: false,
                        threat_names: Vec::new(),
                        file_type: scan::detect_file_type(data),
                        hashes: scan::compute_hashes(data),
                        clamav_result: None,
                        yara_matches: Vec::new(),
                        engines_run: skauswatch_scan_core::EnginesRun::default(),
                        scan_time_ms: 0,
                    }
                }
            };
            let ti_enrichment = if self.cfg.ti_enabled {
                Some(
                    ti::enrich(
                        &self.http,
                        self.cfg.virustotal_api_key.as_deref(),
                        self.cfg.otx_api_key.as_deref(),
                        &outcome.hashes,
                        &outcome.threat_names,
                    )
                    .await,
                )
            } else {
                None
            };
            (outcome, ti_enrichment)
        };

        let timeout = std::time::Duration::from_secs(self.cfg.scan_timeout_sec);
        let (file_type, hashes, is_malware, is_pup, threat_names, clamav_result, ti_enrichment) =
            match tokio::time::timeout(timeout, external).await {
                Ok((outcome, ti_enrichment)) => (
                    outcome.file_type,
                    outcome.hashes,
                    outcome.is_malware,
                    outcome.is_pup,
                    outcome.threat_names,
                    outcome.clamav_result,
                    ti_enrichment,
                ),
                Err(_) => {
                    tracing::warn!("content scan timed out — recording clean verdict");
                    let ti = self.cfg.ti_enabled.then(|| ti::default_result(&[]));
                    (
                        scan::detect_file_type(data),
                        scan::compute_hashes(data),
                        false,
                        false,
                        Vec::new(),
                        None,
                        ti,
                    )
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
            .lookup_job(&t.job_id, t.tenant_id)
            .await?
            .ok_or_else(|| ProcessError::Permanent(format!("unknown job {}", t.job_id)))?;
        let bucket = self
            .lookup_bucket(t.bucket_config_id, t.tenant_id)
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

        let client = self.client_for_bucket(&bucket).await?;
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
        db::set_job_running(&self.pool, job.pk, t.tenant_id, total)
            .await
            .map_err(|e| ProcessError::Transient(e.to_string()))?;
        if skipped > 0 {
            db::bump_job_skipped(&self.pool, job.pk, t.tenant_id, skipped)
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
                t.tenant_id,
            );
            if let Err(e) = self.producer.publish(STREAM_S3_SCAN_TASKS, fields).await {
                tracing::warn!(object = %obj.key, error = %e, "per-object dispatch failed");
            }
        }

        // Complete immediately when nothing needs scanning (all skipped/empty).
        if let Err(e) = db::maybe_complete_job(&self.pool, job.pk, t.tenant_id).await {
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
            .lookup_job(&t.job_id, t.tenant_id)
            .await?
            .ok_or_else(|| ProcessError::Permanent(format!("unknown job {}", t.job_id)))?;
        let bucket = self
            .lookup_bucket(t.bucket_config_id, t.tenant_id)
            .await?
            .ok_or_else(|| {
                ProcessError::Permanent(format!("unknown bucket_config {}", t.bucket_config_id))
            })?;
        let client = self.client_for_bucket(&bucket).await?;
        let max_bytes = (bucket.max_file_size_mb.max(0) as u64) * 1024 * 1024;

        let start = Instant::now();
        let bytes = s3ops::download_object(&client, &bucket.bucket_name, &t.object_key, max_bytes)
            .await
            .map_err(ProcessError::Transient)?;
        let Some(bytes) = bytes else {
            return self.record_skipped(job.pk, t).await;
        };

        let verdict = self.scan_content(&bytes, t.yara_enabled).await;
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
            t.tenant_id,
            verdict.is_malware,
            verdict.is_pup,
            false,
        )
        .await
        .map_err(|e| ProcessError::Transient(e.to_string()))?;
        if let Err(e) = db::maybe_complete_job(&self.pool, job.pk, t.tenant_id).await {
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
        let verdict = self.scan_content(&bytes, t.yara_enabled).await;
        let duration_ms = i32::try_from(start.elapsed().as_millis()).unwrap_or(i32::MAX);

        if let Some(job) = self.lookup_job(&t.job_id, t.tenant_id).await? {
            let bucket_config_id = t.bucket_config_id.unwrap_or(job.bucket_config_id);
            let bo = BucketObjectTask {
                job_id: t.job_id.clone(),
                bucket_config_id,
                object_key: t.object_key.clone(),
                object_size: t.object_size,
                object_etag: String::new(),
                yara_enabled: t.yara_enabled,
                tenant_id: t.tenant_id,
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
                t.tenant_id,
                verdict.is_malware,
                verdict.is_pup,
                false,
            )
            .await
            .map_err(|e| ProcessError::Transient(e.to_string()))?;
            let _ = db::maybe_complete_job(&self.pool, job.pk, t.tenant_id).await;
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
            db::set_adhoc_error(&self.pool, &t.scan_id, t.tenant_id)
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
                db::set_adhoc_error(&self.pool, &t.scan_id, t.tenant_id)
                    .await
                    .map_err(|e| ProcessError::Transient(e.to_string()))?;
                return Ok(());
            }
        };

        let verdict = self.scan_content(&bytes, t.yara_enabled).await;
        let duration_ms = i32::try_from(start.elapsed().as_millis()).unwrap_or(i32::MAX);
        db::finish_adhoc(
            &self.pool,
            &t.scan_id,
            t.tenant_id,
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
            tenant_id: t.tenant_id,
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
        db::bump_job_skipped(&self.pool, job_pk, t.tenant_id, 1)
            .await
            .map_err(|e| ProcessError::Transient(e.to_string()))?;
        let _ = db::maybe_complete_job(&self.pool, job_pk, t.tenant_id).await;
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
            tenant_id: t.tenant_id,
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

    /// Builds the ad-hoc S3 client from the worker's `S3_*` settings,
    /// resolving credentials through this worker's own-AWS JWT-SVID
    /// federation when configured (see [`S3ScanHandler::with_federation`]),
    /// else the standard AWS provider chain — unchanged from before this
    /// feature existed when no federation is configured or it fails.
    async fn adhoc_client(&self) -> aws_sdk_s3::Client {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(self.cfg.s3_region.clone()));
        if let Some(ep) = &self.cfg.s3_endpoint_url {
            loader = loader.endpoint_url(ep);
        }
        if let Some(federation) = &self.federation {
            match skauswatch_s3::credentials::federated_base_credentials(
                federation.identity.as_ref(),
                &federation.role_arn,
                &self.cfg.s3_region,
            )
            .await
            {
                Ok(creds) => loader = loader.credentials_provider(creds),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "own-AWS JWT-SVID federation unavailable for ad-hoc S3 client — \
                         falling back to the default AWS credential-provider chain"
                    );
                }
            }
        }
        let shared = loader.load().await;
        let s3_cfg = aws_sdk_s3::config::Builder::from(&shared)
            .force_path_style(self.cfg.s3_force_path_style)
            .build();
        aws_sdk_s3::Client::from_conf(s3_cfg)
    }

    /// DB job lookup mapping errors to transient failures, scoped to
    /// `tenant_id`.
    async fn lookup_job(
        &self,
        job_uuid: &str,
        tenant_id: uuid::Uuid,
    ) -> Result<Option<db::JobRef>, ProcessError> {
        db::fetch_job(&self.pool, job_uuid, tenant_id)
            .await
            .map_err(|e| ProcessError::Transient(e.to_string()))
    }

    /// DB bucket-config lookup mapping errors to transient failures, scoped
    /// to `tenant_id`.
    async fn lookup_bucket(
        &self,
        id: i32,
        tenant_id: uuid::Uuid,
    ) -> Result<Option<db::BucketConfig>, ProcessError> {
        db::fetch_bucket_config(&self.pool, id, tenant_id)
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

// ── full-pipeline tests ─────────────────────────────────────────────────
//
// Drives the worker end-to-end through the only public entry point
// (`StreamHandler::handle`) against real infrastructure: an isolated
// Postgres schema (`skauswatch_testkit::db::test_pool`), a real Valkey
// stream producer (`REDIS_URL`), a wiremock S3 endpoint (`aws-sdk-s3`
// against a mock HTTP server — see `s3ops.rs` for the same technique in
// isolation), and a real Unix-socket fake `clamd` (see `clamav.rs`) for the
// one test that needs an actual malware verdict. Every test gets its own
// Redis key prefix (`unique_prefix`) since the DB harness isolates schemas
// per test but Valkey has no equivalent per-test namespace built in.
#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used, clippy::too_many_lines)]
mod tests {
    use std::collections::HashMap;

    use fred::interfaces::{ClientLike, StreamsInterface};
    use skauswatch_vault::MekVersion;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::config::WorkerConfig;

    fn redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/0".to_owned())
    }

    fn unique_prefix() -> String {
        format!("s3scantest:{}", uuid::Uuid::new_v4().simple())
    }

    async fn db_pool() -> PgPool {
        skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")).await
    }

    /// Fixed single-MEK envelope shared by every test in this module (mirrors
    /// `skauswatch-vault`'s own crypto test fixture) — good enough since
    /// nothing here tests MEK rotation/mismatch (that's covered in
    /// `crates/skauswatch-s3/src/credentials.rs` and `skauswatch-vault`).
    fn test_envelope() -> EnvelopeEncryption {
        EnvelopeEncryption::new(
            HashMap::from([(
                1,
                MekVersion {
                    version: 1,
                    key_bytes: [4u8; 32],
                },
            )]),
            1,
        )
    }

    /// Envelope-encrypts `{access_key_id, secret_access_key}` the same way
    /// `manager`'s bucket-create/update handlers do, for seeding `static`-mode
    /// bucket rows that resolve to a real (wiremock) S3 client.
    fn encrypt_static_credential(access_key: &str, secret_key: &str) -> String {
        test_envelope()
            .encrypt_json(&serde_json::json!({
                "access_key_id": access_key,
                "secret_access_key": secret_key,
            }))
            .expect("encrypt static credential")
    }

    async fn build_handler(pool: PgPool, cfg: WorkerConfig, prefix: &str) -> S3ScanHandler {
        let producer = StreamProducer::connect(&redis_url(), None, prefix)
            .await
            .expect("producer connect");
        let scan_engine = test_scan_engine(&cfg).await;
        S3ScanHandler::new(pool, producer, cfg, test_envelope(), scan_engine)
    }

    /// Builds the scan engine from a test [`WorkerConfig`] the same way
    /// `main.rs::serve` does — `clamd_socket` points nowhere by default
    /// (ClamAV degrades to clean), and `yara_rules_path` is `None` unless a
    /// test explicitly sets it (see `handles_yara_hit_as_infected` below).
    async fn test_scan_engine(cfg: &WorkerConfig) -> skauswatch_scan_core::ScanEngine {
        skauswatch_scan_core::ScanEngine::new(skauswatch_scan_core::ScanEngineConfig {
            clamd_socket: Some(cfg.clamd_socket.clone()),
            clamd_tcp: None,
            clamd_timeout: std::time::Duration::from_secs(cfg.clamd_timeout),
            yara_rules_path: cfg.yara_rules_path.clone(),
        })
        .await
        .expect("test scan engine config must build")
    }

    async fn raw_client() -> fred::clients::Client {
        let config = fred::types::config::Config::from_url(&redis_url()).expect("valid redis url");
        let client = fred::types::Builder::from_config(config)
            .build()
            .expect("build client");
        client.init().await.expect("connect");
        client
    }

    /// Reads every entry currently on `{prefix}:{stream}` (test-only — no
    /// consumer group involved, just direct inspection of what the handler
    /// published).
    async fn stream_entries(
        client: &fred::clients::Client,
        prefix: &str,
        stream: &str,
    ) -> Vec<(String, HashMap<String, String>)> {
        let key = skauswatch_streams::prefixed_key(prefix, stream);
        client
            .xrange_values(key, "-", "+", None)
            .await
            .expect("xrange")
    }

    fn stream_entry(fields: &[(&str, &str)]) -> StreamEntry {
        StreamEntry {
            id: "1-0".to_owned(),
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    /// Fixed tenant for tests that don't specifically exercise cross-tenant
    /// isolation.
    fn test_tenant() -> uuid::Uuid {
        "33333333-3333-3333-3333-333333333333"
            .parse()
            .expect("valid uuid literal")
    }

    /// A second, distinct tenant for cross-tenant-isolation tests.
    fn other_tenant() -> uuid::Uuid {
        "44444444-4444-4444-4444-444444444444"
            .parse()
            .expect("valid uuid literal")
    }

    fn enumerate_entry(job_id: &str, bucket_config_id: i32, tenant_id: uuid::Uuid) -> StreamEntry {
        let bcid = bucket_config_id.to_string();
        let tid = tenant_id.to_string();
        stream_entry(&[
            ("job_id", job_id),
            ("bucket_config_id", &bcid),
            ("object_key", ""),
            ("object_size", "0"),
            ("object_etag", ""),
            ("yara_enabled", "False"),
            ("tenant_id", &tid),
        ])
    }

    fn bucket_object_entry(
        job_id: &str,
        bucket_config_id: i32,
        object_key: &str,
        tenant_id: uuid::Uuid,
    ) -> StreamEntry {
        let bcid = bucket_config_id.to_string();
        let tid = tenant_id.to_string();
        stream_entry(&[
            ("job_id", job_id),
            ("bucket_config_id", &bcid),
            ("object_key", object_key),
            ("object_size", "5"),
            ("object_etag", "\"etag\""),
            ("yara_enabled", "False"),
            ("tenant_id", &tid),
        ])
    }

    #[allow(clippy::too_many_arguments)]
    fn inline_object_entry(
        task_id: &str,
        job_id: &str,
        bucket_config_id: Option<i32>,
        object_key: &str,
        endpoint_url: &str,
        bucket_name: &str,
        tenant_id: uuid::Uuid,
    ) -> StreamEntry {
        let bcid = bucket_config_id.map_or_else(String::new, |v| v.to_string());
        let tid = tenant_id.to_string();
        stream_entry(&[
            ("task_id", task_id),
            ("job_id", job_id),
            ("bucket_config_id", &bcid),
            ("object_key", object_key),
            ("object_size", "0"),
            ("endpoint_url", endpoint_url),
            ("bucket_name", bucket_name),
            ("access_key", "AKINLINE"),
            ("secret_key", "SKINLINE"),
            ("region", "us-east-1"),
            ("use_ssl", "False"),
            ("path_style", "True"),
            ("yara_enabled", "False"),
            ("tenant_id", &tid),
        ])
    }

    fn adhoc_entry(scan_id: &str, object_key: &str, tenant_id: uuid::Uuid) -> StreamEntry {
        let tid = tenant_id.to_string();
        stream_entry(&[
            ("job_id", scan_id),
            ("bucket_config_id", ""),
            ("object_key", object_key),
            ("object_size", "0"),
            ("yara_enabled", "False"),
            ("tenant_id", &tid),
        ])
    }

    /// Seeds one `s3_bucket_configs` row pointed at `endpoint` (typically a
    /// wiremock server URI), path-style always on (matches how the
    /// `s3ops.rs` mocks are addressed). `credential_mode='static'` with a
    /// real envelope-encrypted blob — these tests exercise the actual
    /// decrypt-and-build-client path (`S3ScanHandler::client_for_bucket`),
    /// not just a bucket-config field mapping.
    #[allow(clippy::too_many_arguments)]
    async fn seed_bucket(
        pool: &PgPool,
        tenant_id: uuid::Uuid,
        endpoint: &str,
        bucket_name: &str,
        max_file_size_mb: i32,
        scan_enabled: bool,
        yara_enabled: bool,
        prefix_filter: Option<&str>,
    ) -> i32 {
        let credential_enc = encrypt_static_credential("AKTEST", "SKTEST");
        let row: (i32,) = sqlx::query_as(
            "INSERT INTO s3_bucket_configs \
             (name, tenant_id, endpoint_url, bucket_name, credential_mode, credential_enc, \
              region, path_style, prefix_filter, max_file_size_mb, scan_enabled, yara_enabled, \
              created_by) \
             VALUES ($1, $2, $3, $4, 'static', $5, 'us-east-1', true, $6, $7, $8, $9, 1) \
             RETURNING id",
        )
        .bind(format!("bucket-{}", uuid::Uuid::new_v4()))
        .bind(tenant_id)
        .bind(endpoint)
        .bind(bucket_name)
        .bind(credential_enc)
        .bind(prefix_filter)
        .bind(max_file_size_mb)
        .bind(scan_enabled)
        .bind(yara_enabled)
        .fetch_one(pool)
        .await
        .expect("seed bucket");
        row.0
    }

    /// Seeds one `s3_scan_jobs` row (`pending`), returning its primary key.
    async fn seed_job(
        pool: &PgPool,
        tenant_id: uuid::Uuid,
        bucket_config_id: i32,
        job_uuid: &str,
        metadata: serde_json::Value,
    ) -> i32 {
        let row: (i32,) = sqlx::query_as(
            "INSERT INTO s3_scan_jobs (job_id, tenant_id, bucket_config_id, job_type, status, \
             triggered_by, metadata) VALUES ($1, $2, $3, 'manual', 'pending', 1, $4) RETURNING id",
        )
        .bind(job_uuid)
        .bind(tenant_id)
        .bind(bucket_config_id)
        .bind(metadata)
        .fetch_one(pool)
        .await
        .expect("seed job");
        row.0
    }

    /// Seeds a job already transitioned to `running` with the given total.
    async fn seed_running_job(
        pool: &PgPool,
        tenant_id: uuid::Uuid,
        bucket_config_id: i32,
        job_uuid: &str,
        total: i32,
    ) -> i32 {
        let pk = seed_job(
            pool,
            tenant_id,
            bucket_config_id,
            job_uuid,
            serde_json::json!({}),
        )
        .await;
        db::set_job_running(pool, pk, tenant_id, total)
            .await
            .expect("set running");
        pk
    }

    async fn seed_adhoc(pool: &PgPool, tenant_id: uuid::Uuid, scan_id: &str) {
        sqlx::query(
            "INSERT INTO adhoc_scan_results (scan_id, tenant_id, uploaded_by, original_filename) \
             VALUES ($1, $2, 1, 'upload.bin')",
        )
        .bind(scan_id)
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("seed adhoc");
    }

    fn list_bucket_result(bucket: &str, contents: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Name>{bucket}</Name><Prefix></Prefix><MaxKeys>1000</MaxKeys>\
             <IsTruncated>false</IsTruncated>{contents}</ListBucketResult>"
        )
    }

    fn contents_xml(key: &str, size: i64) -> String {
        format!(
            "<Contents><Key>{key}</Key><LastModified>2024-01-01T00:00:00.000Z</LastModified>\
             <ETag>&quot;e1&quot;</ETag><Size>{size}</Size><StorageClass>STANDARD</StorageClass></Contents>"
        )
    }

    fn s3_error_xml() -> &'static str {
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>InternalError</Code>\
         <Message>boom</Message><RequestId>r</RequestId><HostId>h</HostId></Error>"
    }

    /// Binds a Unix-socket fake `clamd`: accepts one connection, drains the
    /// `INSTREAM` frames, then writes back `reply` (see `clamav.rs` for the
    /// wire-protocol details this mirrors).
    fn spawn_fake_clamd(path: std::path::PathBuf, reply: &'static [u8]) {
        let listener = UnixListener::bind(&path).expect("bind fake clamd");
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut cmd = [0u8; 10];
            if stream.read_exact(&mut cmd).await.is_err() {
                return;
            }
            loop {
                let mut len_buf = [0u8; 4];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let len = u32::from_be_bytes(len_buf);
                if len == 0 {
                    break;
                }
                let mut chunk = vec![0u8; len as usize];
                if stream.read_exact(&mut chunk).await.is_err() {
                    return;
                }
            }
            let _ = stream.write_all(reply).await;
            let _ = stream.flush().await;
        });
    }

    fn unique_socket_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "s3scan-handler-clamd-{}.sock",
            uuid::Uuid::new_v4()
        ))
    }

    // ── Enumerate ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn enumerate_unknown_job_is_permanent_ack() {
        let pool = db_pool().await;
        let prefix = unique_prefix();
        let handler = build_handler(pool, WorkerConfig::for_tests(), &prefix).await;

        let result = handler
            .handle(&enumerate_entry("no-such-job", 1, test_tenant()))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn enumerate_unknown_bucket_is_permanent_ack() {
        let pool = db_pool().await;
        let tenant = test_tenant();
        let bucket_id =
            seed_bucket(&pool, tenant, "http://unused", "b", 100, true, false, None).await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        seed_job(&pool, tenant, bucket_id, &job_uuid, serde_json::json!({})).await;
        let prefix = unique_prefix();
        let handler = build_handler(pool, WorkerConfig::for_tests(), &prefix).await;

        // bucket_config_id on the *task* points at a bucket that doesn't exist.
        let result = handler
            .handle(&enumerate_entry(&job_uuid, 999_999, tenant))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn enumerate_wrong_tenant_bucket_is_permanent_ack() {
        // Regression: an enumerate task stamped with tenant B must not
        // resolve tenant A's bucket config, even though the id is real and
        // the job row (also tenant A's) exists.
        let pool = db_pool().await;
        let tenant = test_tenant();
        let bucket_id =
            seed_bucket(&pool, tenant, "http://unused", "b", 100, true, false, None).await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        let pk = seed_job(&pool, tenant, bucket_id, &job_uuid, serde_json::json!({})).await;
        let prefix = unique_prefix();
        let handler = build_handler(pool.clone(), WorkerConfig::for_tests(), &prefix).await;

        // Same job_id/bucket_config_id, but the *task* claims tenant B.
        let result = handler
            .handle(&enumerate_entry(&job_uuid, bucket_id, other_tenant()))
            .await;
        assert!(result.is_ok(), "expected permanent-ack, got {result:?}");

        let row: (String,) = sqlx::query_as("SELECT status FROM s3_scan_jobs WHERE id = $1")
            .bind(pk)
            .fetch_one(&pool)
            .await
            .expect("select");
        assert_eq!(row.0, "pending");
    }

    #[tokio::test]
    async fn enumerate_scanning_disabled_is_permanent_ack_and_leaves_job_untouched() {
        let pool = db_pool().await;
        let tenant = test_tenant();
        let bucket_id =
            seed_bucket(&pool, tenant, "http://unused", "b", 100, false, false, None).await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        let pk = seed_job(&pool, tenant, bucket_id, &job_uuid, serde_json::json!({})).await;
        let prefix = unique_prefix();
        let handler = build_handler(pool.clone(), WorkerConfig::for_tests(), &prefix).await;

        let result = handler
            .handle(&enumerate_entry(&job_uuid, bucket_id, tenant))
            .await;
        assert!(result.is_ok());

        let row: (String,) = sqlx::query_as("SELECT status FROM s3_scan_jobs WHERE id = $1")
            .bind(pk)
            .fetch_one(&pool)
            .await
            .expect("select");
        assert_eq!(row.0, "pending");
    }

    #[tokio::test]
    async fn enumerate_dispatches_surviving_objects_and_sets_running() {
        let server = MockServer::start().await;
        let contents = format!(
            "{}{}",
            contents_xml("keep.bin", 5),
            contents_xml("skip.bin", 2_000_000)
        );
        Mock::given(method("GET"))
            .and(path("/enum-bucket/"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                list_bucket_result("enum-bucket", &contents),
                "application/xml",
            ))
            .mount(&server)
            .await;

        let pool = db_pool().await;
        let tenant = test_tenant();
        // Job metadata prefix override must win over the bucket's own prefix.
        let bucket_id = seed_bucket(
            &pool,
            tenant,
            &server.uri(),
            "enum-bucket",
            1,
            true,
            true,
            Some("bucket-prefix/"),
        )
        .await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        let pk = seed_job(
            &pool,
            tenant,
            bucket_id,
            &job_uuid,
            serde_json::json!({"prefix_filter": null}),
        )
        .await;
        let prefix = unique_prefix();
        let handler = build_handler(pool.clone(), WorkerConfig::for_tests(), &prefix).await;

        let result = handler
            .handle(&enumerate_entry(&job_uuid, bucket_id, tenant))
            .await;
        assert!(result.is_ok(), "{result:?}");

        let row: (String, i32, i32) = sqlx::query_as(
            "SELECT status, total_objects, skipped_objects FROM s3_scan_jobs WHERE id = $1",
        )
        .bind(pk)
        .fetch_one(&pool)
        .await
        .expect("select");
        assert_eq!(row.0, "running"); // scanned=0, skipped=1 < total=2
        assert_eq!(row.1, 2);
        assert_eq!(row.2, 1);

        let client = raw_client().await;
        let dispatched = stream_entries(&client, &prefix, STREAM_S3_SCAN_TASKS).await;
        assert_eq!(dispatched.len(), 1);
        assert_eq!(
            dispatched[0].1.get("object_key"),
            Some(&"keep.bin".to_owned())
        );
        assert_eq!(dispatched[0].1.get("job_id"), Some(&job_uuid));
        assert_eq!(
            dispatched[0].1.get("yara_enabled"),
            Some(&"True".to_owned())
        ); // bucket.yara_enabled
        // The re-dispatched per-object task must carry the same tenant
        // forward — see enumerate::dispatch_fields.
        assert_eq!(dispatched[0].1.get("tenant_id"), Some(&tenant.to_string()));
    }

    #[tokio::test]
    async fn enumerate_all_skipped_completes_job_immediately() {
        let server = MockServer::start().await;
        let contents = contents_xml("only.bin", 5);
        Mock::given(method("GET"))
            .and(path("/tiny-bucket/"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                list_bucket_result("tiny-bucket", &contents),
                "application/xml",
            ))
            .mount(&server)
            .await;

        let pool = db_pool().await;
        let tenant = test_tenant();
        // max_file_size_mb = 0 ⇒ max_bytes = 0 ⇒ every non-empty object skips.
        let bucket_id = seed_bucket(
            &pool,
            tenant,
            &server.uri(),
            "tiny-bucket",
            0,
            true,
            false,
            None,
        )
        .await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        let pk = seed_job(&pool, tenant, bucket_id, &job_uuid, serde_json::json!({})).await;
        let prefix = unique_prefix();
        let handler = build_handler(pool.clone(), WorkerConfig::for_tests(), &prefix).await;

        let result = handler
            .handle(&enumerate_entry(&job_uuid, bucket_id, tenant))
            .await;
        assert!(result.is_ok());

        let row: (String, Option<chrono::NaiveDateTime>) =
            sqlx::query_as("SELECT status, completed_at FROM s3_scan_jobs WHERE id = $1")
                .bind(pk)
                .fetch_one(&pool)
                .await
                .expect("select");
        assert_eq!(row.0, "completed");
        assert!(row.1.is_some());

        let client = raw_client().await;
        assert!(
            stream_entries(&client, &prefix, STREAM_S3_SCAN_TASKS)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn enumerate_s3_list_failure_is_transient() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/broken-bucket/"))
            .respond_with(
                ResponseTemplate::new(500).set_body_raw(s3_error_xml(), "application/xml"),
            )
            .mount(&server)
            .await;

        let pool = db_pool().await;
        let tenant = test_tenant();
        let bucket_id = seed_bucket(
            &pool,
            tenant,
            &server.uri(),
            "broken-bucket",
            100,
            true,
            false,
            None,
        )
        .await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        seed_job(&pool, tenant, bucket_id, &job_uuid, serde_json::json!({})).await;
        let prefix = unique_prefix();
        let handler = build_handler(pool, WorkerConfig::for_tests(), &prefix).await;

        let result = handler
            .handle(&enumerate_entry(&job_uuid, bucket_id, tenant))
            .await;
        assert!(result.is_err());
    }

    /// Seeds an `assume_role`-mode bucket (no `credential_enc`) at an
    /// arbitrary S3-compatible `endpoint_url` — used to exercise the
    /// `AssumeRoleRequiresAwsEndpoint` guard end to end through
    /// `S3ScanHandler::client_for_bucket`, without any STS network call.
    async fn seed_assume_role_bucket(
        pool: &PgPool,
        tenant_id: uuid::Uuid,
        endpoint: &str,
        bucket_name: &str,
    ) -> i32 {
        let row: (i32,) = sqlx::query_as(
            "INSERT INTO s3_bucket_configs \
             (name, tenant_id, endpoint_url, bucket_name, credential_mode, role_arn, region, \
              path_style, max_file_size_mb, scan_enabled, yara_enabled, created_by) \
             VALUES ($1, $2, $3, $4, 'assume_role', 'arn:aws:iam::123456789012:role/test', \
                     'us-east-1', true, 100, true, false, 1) RETURNING id",
        )
        .bind(format!("bucket-{}", uuid::Uuid::new_v4()))
        .bind(tenant_id)
        .bind(endpoint)
        .bind(bucket_name)
        .fetch_one(pool)
        .await
        .expect("seed assume_role bucket");
        row.0
    }

    #[tokio::test]
    async fn enumerate_assume_role_against_non_aws_endpoint_is_permanent_ack() {
        let pool = db_pool().await;
        let tenant = test_tenant();
        // A non-AWS S3-compatible endpoint has no STS — the resolver's guard
        // must reject this *before* any network call, and the handler must
        // classify it as a permanent (non-retryable) failure.
        let bucket_id =
            seed_assume_role_bucket(&pool, tenant, "http://minio.example:9000", "role-bucket")
                .await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        let pk = seed_job(&pool, tenant, bucket_id, &job_uuid, serde_json::json!({})).await;
        let prefix = unique_prefix();
        let handler = build_handler(pool.clone(), WorkerConfig::for_tests(), &prefix).await;

        let result = handler
            .handle(&enumerate_entry(&job_uuid, bucket_id, tenant))
            .await;
        assert!(result.is_ok(), "expected permanent-ack, got {result:?}");

        // Permanent ack means the job is left untouched (never transitions
        // to running), same as the scanning-disabled case above.
        let row: (String,) = sqlx::query_as("SELECT status FROM s3_scan_jobs WHERE id = $1")
            .bind(pk)
            .fetch_one(&pool)
            .await
            .expect("select");
        assert_eq!(row.0, "pending");
    }

    // ── BucketObject ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn bucket_object_unknown_job_is_permanent_ack() {
        let pool = db_pool().await;
        let prefix = unique_prefix();
        let handler = build_handler(pool, WorkerConfig::for_tests(), &prefix).await;

        let result = handler
            .handle(&bucket_object_entry(
                "no-such-job",
                1,
                "a.bin",
                test_tenant(),
            ))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn bucket_object_unknown_bucket_is_permanent_ack() {
        let pool = db_pool().await;
        let tenant = test_tenant();
        let bucket_id =
            seed_bucket(&pool, tenant, "http://unused", "b", 100, true, false, None).await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        seed_job(&pool, tenant, bucket_id, &job_uuid, serde_json::json!({})).await;
        let prefix = unique_prefix();
        let handler = build_handler(pool, WorkerConfig::for_tests(), &prefix).await;

        let result = handler
            .handle(&bucket_object_entry(&job_uuid, 999_999, "a.bin", tenant))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn bucket_object_wrong_tenant_job_is_permanent_ack() {
        // Regression: a per-object task stamped with tenant B must not
        // resolve tenant A's job, even with the real job_id/bucket_config_id.
        let pool = db_pool().await;
        let tenant = test_tenant();
        let bucket_id =
            seed_bucket(&pool, tenant, "http://unused", "b", 100, true, false, None).await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        seed_running_job(&pool, tenant, bucket_id, &job_uuid, 1).await;
        let prefix = unique_prefix();
        let handler = build_handler(pool.clone(), WorkerConfig::for_tests(), &prefix).await;

        let result = handler
            .handle(&bucket_object_entry(
                &job_uuid,
                bucket_id,
                "uploads/a.bin",
                other_tenant(),
            ))
            .await;
        assert!(result.is_ok(), "expected permanent-ack, got {result:?}");

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM s3_scan_results")
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(count.0, 0);
    }

    #[tokio::test]
    async fn bucket_object_clean_scan_persists_bumps_counters_completes_and_publishes() {
        let server = MockServer::start().await;
        let body = b"hello".to_vec();
        Mock::given(method("GET"))
            .and(path("/scan-bucket/uploads/a.bin"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/scan-bucket/uploads/a.bin"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let pool = db_pool().await;
        let tenant = test_tenant();
        let bucket_id = seed_bucket(
            &pool,
            tenant,
            &server.uri(),
            "scan-bucket",
            100,
            true,
            false,
            None,
        )
        .await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        let pk = seed_running_job(&pool, tenant, bucket_id, &job_uuid, 1).await;
        let prefix = unique_prefix();
        let handler = build_handler(pool.clone(), WorkerConfig::for_tests(), &prefix).await;

        let result = handler
            .handle(&bucket_object_entry(
                &job_uuid,
                bucket_id,
                "uploads/a.bin",
                tenant,
            ))
            .await;
        assert!(result.is_ok(), "{result:?}");

        let expected_hashes = scan::compute_hashes(&body);
        let row: (String, bool, Option<String>, uuid::Uuid) = sqlx::query_as(
            "SELECT scan_status, is_malware, file_sha256, tenant_id FROM s3_scan_results \
             WHERE job_id = $1",
        )
        .bind(pk)
        .fetch_one(&pool)
        .await
        .expect("select result");
        assert_eq!(row.0, "clean");
        assert!(!row.1);
        assert_eq!(row.2, Some(expected_hashes.sha256.clone()));
        assert_eq!(row.3, tenant);

        let job: (String, i32, i32, i32) = sqlx::query_as(
            "SELECT status, scanned_objects, infected_objects, pup_objects FROM s3_scan_jobs WHERE id = $1",
        )
        .bind(pk)
        .fetch_one(&pool)
        .await
        .expect("select job");
        assert_eq!(job, ("completed".to_owned(), 1, 0, 0));

        let client = raw_client().await;
        let published = stream_entries(&client, &prefix, STREAM_S3_SCAN_RESULTS).await;
        assert_eq!(published.len(), 1);
        let fields = &published[0].1;
        assert_eq!(fields.get("scan_status"), Some(&"clean".to_owned()));
        assert_eq!(fields.get("is_malware"), Some(&"False".to_owned()));
        assert_eq!(fields.get("file_sha256"), Some(&expected_hashes.sha256));
        assert_eq!(fields.get("job_id"), Some(&job_uuid));
    }

    #[tokio::test]
    async fn bucket_object_too_large_at_download_records_skipped() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/small-limit-bucket/big.bin"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![1u8; 64]))
            .mount(&server)
            .await;

        let pool = db_pool().await;
        let tenant = test_tenant();
        // max_file_size_mb = 0 ⇒ max_bytes = 0 ⇒ any non-empty body skips.
        let bucket_id = seed_bucket(
            &pool,
            tenant,
            &server.uri(),
            "small-limit-bucket",
            0,
            true,
            false,
            None,
        )
        .await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        let pk = seed_running_job(&pool, tenant, bucket_id, &job_uuid, 1).await;
        let prefix = unique_prefix();
        let handler = build_handler(pool.clone(), WorkerConfig::for_tests(), &prefix).await;

        let result = handler
            .handle(&bucket_object_entry(
                &job_uuid, bucket_id, "big.bin", tenant,
            ))
            .await;
        assert!(result.is_ok(), "{result:?}");

        let row: (String,) =
            sqlx::query_as("SELECT scan_status FROM s3_scan_results WHERE job_id = $1")
                .bind(pk)
                .fetch_one(&pool)
                .await
                .expect("select result");
        assert_eq!(row.0, "skipped");

        let job: (String, i32, i32) = sqlx::query_as(
            "SELECT status, scanned_objects, skipped_objects FROM s3_scan_jobs WHERE id = $1",
        )
        .bind(pk)
        .fetch_one(&pool)
        .await
        .expect("select job");
        assert_eq!(job, ("completed".to_owned(), 0, 1));
    }

    #[tokio::test]
    async fn bucket_object_download_error_is_transient() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/err-bucket/a.bin"))
            .respond_with(
                ResponseTemplate::new(500).set_body_raw(s3_error_xml(), "application/xml"),
            )
            .mount(&server)
            .await;

        let pool = db_pool().await;
        let tenant = test_tenant();
        let bucket_id = seed_bucket(
            &pool,
            tenant,
            &server.uri(),
            "err-bucket",
            100,
            true,
            false,
            None,
        )
        .await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        seed_running_job(&pool, tenant, bucket_id, &job_uuid, 1).await;
        let prefix = unique_prefix();
        let handler = build_handler(pool, WorkerConfig::for_tests(), &prefix).await;

        let result = handler
            .handle(&bucket_object_entry(&job_uuid, bucket_id, "a.bin", tenant))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn bucket_object_malware_verdict_via_real_clamd_bumps_infected() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/malware-bucket/evil.bin"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"X5O!P%".to_vec()))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/malware-bucket/evil.bin"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let sock = unique_socket_path();
        spawn_fake_clamd(sock.clone(), b"stream: Win.Test.EICAR_HDB-1 FOUND\0");
        tokio::task::yield_now().await;

        let pool = db_pool().await;
        let tenant = test_tenant();
        let bucket_id = seed_bucket(
            &pool,
            tenant,
            &server.uri(),
            "malware-bucket",
            100,
            true,
            false,
            None,
        )
        .await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        let pk = seed_running_job(&pool, tenant, bucket_id, &job_uuid, 1).await;
        let prefix = unique_prefix();
        let cfg = WorkerConfig {
            clamd_socket: sock.to_str().expect("utf8 path").to_owned(),
            ..WorkerConfig::for_tests()
        };
        let handler = build_handler(pool.clone(), cfg, &prefix).await;

        let result = handler
            .handle(&bucket_object_entry(
                &job_uuid, bucket_id, "evil.bin", tenant,
            ))
            .await;
        assert!(result.is_ok(), "{result:?}");

        let row: (String, bool) =
            sqlx::query_as("SELECT scan_status, is_malware FROM s3_scan_results WHERE job_id = $1")
                .bind(pk)
                .fetch_one(&pool)
                .await
                .expect("select result");
        assert_eq!(row.0, "infected");
        assert!(row.1);

        let job: (i32,) = sqlx::query_as("SELECT infected_objects FROM s3_scan_jobs WHERE id = $1")
            .bind(pk)
            .fetch_one(&pool)
            .await
            .expect("select job");
        assert_eq!(job.0, 1);
    }

    /// Regression: fixes dead `yara_enabled` (v2.1-depgate.md §3) — before
    /// the `skauswatch-scan-core` adoption, this flag was parsed all the way
    /// through to `BucketObjectTask::yara_enabled` and then never consulted;
    /// ClamAV was the only engine that ever ran. This proves YARA now
    /// actually executes against real (EICAR) content and its hit lands as
    /// an `infected` verdict, exactly like a ClamAV hit does above.
    #[tokio::test]
    async fn bucket_object_yara_hit_bumps_infected_when_task_requests_it() {
        const EICAR: &[u8] =
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/yara-bucket/eicar.bin"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(EICAR.to_vec()))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/yara-bucket/eicar.bin"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let pool = db_pool().await;
        let tenant = test_tenant();
        // `bucket.yara_enabled=true` here documents intent only — this test
        // dispatches a pre-built `BucketObjectTask`-shaped entry directly
        // (bypassing `enumerate`'s own `t.yara_enabled || bucket.yara_enabled`
        // OR), so the entry's own `yara_enabled` field below is what
        // actually drives `scan_content`.
        let bucket_id = seed_bucket(
            &pool,
            tenant,
            &server.uri(),
            "yara-bucket",
            100,
            true,
            true,
            None,
        )
        .await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        let pk = seed_running_job(&pool, tenant, bucket_id, &job_uuid, 1).await;
        let prefix = unique_prefix();
        let cfg = WorkerConfig {
            yara_rules_path: Some(
                concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/yara_rules").to_owned(),
            ),
            ..WorkerConfig::for_tests()
        };
        let handler = build_handler(pool.clone(), cfg, &prefix).await;

        let bcid = bucket_id.to_string();
        let tid = tenant.to_string();
        let entry = stream_entry(&[
            ("job_id", &job_uuid),
            ("bucket_config_id", &bcid),
            ("object_key", "eicar.bin"),
            ("object_size", "68"),
            ("object_etag", "\"etag\""),
            ("yara_enabled", "True"),
            ("tenant_id", &tid),
        ]);

        let result = handler.handle(&entry).await;
        assert!(result.is_ok(), "{result:?}");

        let row: (String, bool, serde_json::Value) = sqlx::query_as(
            "SELECT scan_status, is_malware, threat_names FROM s3_scan_results WHERE job_id = $1",
        )
        .bind(pk)
        .fetch_one(&pool)
        .await
        .expect("select result");
        assert_eq!(row.0, "infected");
        assert!(row.1);
        let names = row.2.as_array().expect("threat_names is a json array");
        assert!(
            names
                .iter()
                .any(|n| n.as_str() == Some("YARA.EICAR_Test_File")),
            "expected a YARA. -prefixed threat name, got {names:?}"
        );

        let job: (i32,) = sqlx::query_as("SELECT infected_objects FROM s3_scan_jobs WHERE id = $1")
            .bind(pk)
            .fetch_one(&pool)
            .await
            .expect("select job");
        assert_eq!(job.0, 1);
    }

    /// Same content, but the task does not request YARA (`yara_enabled:
    /// "False"`, the default `bucket_object_entry` shape) and no ClamAV
    /// daemon is reachable — proves YARA is opt-in per task/bucket, not
    /// always-on just because the engine has rules loaded.
    #[tokio::test]
    async fn bucket_object_yara_configured_but_not_requested_stays_clean() {
        const EICAR: &[u8] =
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/yara-bucket-off/eicar.bin"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(EICAR.to_vec()))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/yara-bucket-off/eicar.bin"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let pool = db_pool().await;
        let tenant = test_tenant();
        let bucket_id = seed_bucket(
            &pool,
            tenant,
            &server.uri(),
            "yara-bucket-off",
            100,
            true,
            false,
            None,
        )
        .await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        let pk = seed_running_job(&pool, tenant, bucket_id, &job_uuid, 1).await;
        let prefix = unique_prefix();
        let cfg = WorkerConfig {
            yara_rules_path: Some(
                concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/yara_rules").to_owned(),
            ),
            ..WorkerConfig::for_tests()
        };
        let handler = build_handler(pool.clone(), cfg, &prefix).await;

        let result = handler
            .handle(&bucket_object_entry(
                &job_uuid,
                bucket_id,
                "eicar.bin",
                tenant,
            ))
            .await;
        assert!(result.is_ok(), "{result:?}");

        let row: (String, bool) =
            sqlx::query_as("SELECT scan_status, is_malware FROM s3_scan_results WHERE job_id = $1")
                .bind(pk)
                .fetch_one(&pool)
                .await
                .expect("select result");
        assert_eq!(row.0, "clean");
        assert!(!row.1);
    }

    // ── InlineObject ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn inline_object_with_known_job_persists_and_publishes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/inline-bucket/uploads/i.bin"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"inline-body".to_vec()))
            .mount(&server)
            .await;

        let pool = db_pool().await;
        let tenant = test_tenant();
        let bucket_id =
            seed_bucket(&pool, tenant, "http://unused", "b", 100, true, false, None).await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        let pk = seed_running_job(&pool, tenant, bucket_id, &job_uuid, 1).await;
        let prefix = unique_prefix();
        let handler = build_handler(pool.clone(), WorkerConfig::for_tests(), &prefix).await;

        let entry = inline_object_entry(
            "task-1",
            &job_uuid,
            None, // falls back to the job's own bucket_config_id
            "uploads/i.bin",
            &server.uri(),
            "inline-bucket",
            tenant,
        );
        let result = handler.handle(&entry).await;
        assert!(result.is_ok(), "{result:?}");

        let row: (i32, String, uuid::Uuid) = sqlx::query_as(
            "SELECT bucket_config_id, scan_status, tenant_id FROM s3_scan_results \
             WHERE job_id = $1",
        )
        .bind(pk)
        .fetch_one(&pool)
        .await
        .expect("select result");
        assert_eq!(row.0, bucket_id);
        assert_eq!(row.1, "clean");
        assert_eq!(row.2, tenant);

        let client = raw_client().await;
        let published = stream_entries(&client, &prefix, STREAM_S3_SCAN_RESULTS).await;
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].1.get("task_id"), Some(&"task-1".to_owned()));
    }

    #[tokio::test]
    async fn inline_object_wrong_tenant_job_does_not_persist() {
        // Regression: an inline task stamped with tenant B must not match
        // tenant A's job row, even with the real job_id — falls through to
        // the "no matching job" best-effort publish-only path.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/inline-cross-bucket/x.bin"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"x".to_vec()))
            .mount(&server)
            .await;

        let pool = db_pool().await;
        let tenant = test_tenant();
        let bucket_id =
            seed_bucket(&pool, tenant, "http://unused", "b", 100, true, false, None).await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        seed_running_job(&pool, tenant, bucket_id, &job_uuid, 1).await;
        let prefix = unique_prefix();
        let handler = build_handler(pool.clone(), WorkerConfig::for_tests(), &prefix).await;

        let entry = inline_object_entry(
            "task-cross",
            &job_uuid,
            None,
            "x.bin",
            &server.uri(),
            "inline-cross-bucket",
            other_tenant(),
        );
        let result = handler.handle(&entry).await;
        assert!(result.is_ok(), "{result:?}");

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM s3_scan_results")
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(count.0, 0);
    }

    #[tokio::test]
    async fn inline_object_without_matching_job_still_publishes_but_does_not_persist() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ghost-bucket/g.bin"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ghost".to_vec()))
            .mount(&server)
            .await;

        let pool = db_pool().await;
        let prefix = unique_prefix();
        let handler = build_handler(pool.clone(), WorkerConfig::for_tests(), &prefix).await;

        let entry = inline_object_entry(
            "task-ghost",
            "no-such-job",
            None,
            "g.bin",
            &server.uri(),
            "ghost-bucket",
            test_tenant(),
        );
        let result = handler.handle(&entry).await;
        assert!(result.is_ok(), "{result:?}");

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM s3_scan_results")
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(count.0, 0);

        let client = raw_client().await;
        let published = stream_entries(&client, &prefix, STREAM_S3_SCAN_RESULTS).await;
        assert_eq!(published.len(), 1);
        assert_eq!(
            published[0].1.get("task_id"),
            Some(&"task-ghost".to_owned())
        );
    }

    #[tokio::test]
    async fn inline_object_too_large_is_skipped_without_persist_or_publish() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/limit-bucket/big.bin"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![9u8; 64]))
            .mount(&server)
            .await;

        let pool = db_pool().await;
        let prefix = unique_prefix();
        let cfg = WorkerConfig {
            max_file_size_mb: 0, // max_file_size_bytes() == 0
            ..WorkerConfig::for_tests()
        };
        let handler = build_handler(pool.clone(), cfg, &prefix).await;

        let entry = inline_object_entry(
            "task-big",
            "irrelevant-job",
            None,
            "big.bin",
            &server.uri(),
            "limit-bucket",
            test_tenant(),
        );
        let result = handler.handle(&entry).await;
        assert!(result.is_ok(), "{result:?}");

        let client = raw_client().await;
        assert!(
            stream_entries(&client, &prefix, STREAM_S3_SCAN_RESULTS)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn inline_object_download_error_is_transient() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/inline-err-bucket/a.bin"))
            .respond_with(
                ResponseTemplate::new(500).set_body_raw(s3_error_xml(), "application/xml"),
            )
            .mount(&server)
            .await;

        let pool = db_pool().await;
        let prefix = unique_prefix();
        let handler = build_handler(pool, WorkerConfig::for_tests(), &prefix).await;

        let entry = inline_object_entry(
            "task-err",
            "irrelevant-job",
            None,
            "a.bin",
            &server.uri(),
            "inline-err-bucket",
            test_tenant(),
        );
        let result = handler.handle(&entry).await;
        assert!(result.is_err());
    }

    // ── Adhoc ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn adhoc_without_configured_bucket_marks_error() {
        let pool = db_pool().await;
        let tenant = test_tenant();
        let scan_id = uuid::Uuid::new_v4().to_string();
        seed_adhoc(&pool, tenant, &scan_id).await;
        let prefix = unique_prefix();
        // cfg.adhoc_bucket is None by default in for_tests().
        let handler = build_handler(pool.clone(), WorkerConfig::for_tests(), &prefix).await;

        let result = handler
            .handle(&adhoc_entry(
                &scan_id,
                &format!("{scan_id}/upload.bin"),
                tenant,
            ))
            .await;
        assert!(result.is_ok());

        let row: (String,) =
            sqlx::query_as("SELECT scan_status FROM adhoc_scan_results WHERE scan_id = $1")
                .bind(&scan_id)
                .fetch_one(&pool)
                .await
                .expect("select");
        assert_eq!(row.0, "error");
    }

    #[tokio::test]
    async fn adhoc_wrong_tenant_leaves_row_untouched() {
        // Regression: a task claiming tenant B for tenant A's scan_id must
        // not be able to mark that row `error` (or anything else).
        let pool = db_pool().await;
        let scan_id = uuid::Uuid::new_v4().to_string();
        seed_adhoc(&pool, test_tenant(), &scan_id).await;
        let prefix = unique_prefix();
        let handler = build_handler(pool.clone(), WorkerConfig::for_tests(), &prefix).await;

        let result = handler
            .handle(&adhoc_entry(
                &scan_id,
                &format!("{scan_id}/upload.bin"),
                other_tenant(),
            ))
            .await;
        assert!(result.is_ok());

        let row: (Option<String>,) =
            sqlx::query_as("SELECT scan_status FROM adhoc_scan_results WHERE scan_id = $1")
                .bind(&scan_id)
                .fetch_one(&pool)
                .await
                .expect("select");
        assert_eq!(row.0, None);
    }

    #[tokio::test]
    async fn adhoc_content_unavailable_marks_error() {
        let server = MockServer::start().await;
        let tenant = test_tenant();
        let scan_id = uuid::Uuid::new_v4().to_string();
        Mock::given(method("GET"))
            .and(path(format!("/adhoc-bucket/{scan_id}/upload.bin")))
            .respond_with(
                ResponseTemplate::new(404).set_body_raw(s3_error_xml(), "application/xml"),
            )
            .mount(&server)
            .await;

        let pool = db_pool().await;
        seed_adhoc(&pool, tenant, &scan_id).await;
        let prefix = unique_prefix();
        let cfg = WorkerConfig {
            adhoc_bucket: Some("adhoc-bucket".to_owned()),
            s3_endpoint_url: Some(server.uri()),
            s3_force_path_style: true,
            ..WorkerConfig::for_tests()
        };
        let handler = build_handler(pool.clone(), cfg, &prefix).await;

        let result = handler
            .handle(&adhoc_entry(
                &scan_id,
                &format!("{scan_id}/upload.bin"),
                tenant,
            ))
            .await;
        // Content-unavailable is handled internally (not a ProcessError) —
        // the handler always acks.
        assert!(result.is_ok(), "{result:?}");

        let row: (String,) =
            sqlx::query_as("SELECT scan_status FROM adhoc_scan_results WHERE scan_id = $1")
                .bind(&scan_id)
                .fetch_one(&pool)
                .await
                .expect("select");
        assert_eq!(row.0, "error");
    }

    /// `scan_adhoc`'s success path (`adhoc_client()` + `db::finish_adhoc`).
    /// Unlike every other code path, `adhoc_client()` resolves credentials
    /// through `aws_config::defaults()` (the standard SDK provider chain)
    /// rather than the explicit stored/inline creds `s3ops::client_from_credentials`
    /// takes elsewhere — there is no test seam to inject a client directly.
    /// Requires `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` in the process
    /// environment so the SDK's environment-variable credentials provider
    /// resolves quickly without a network round trip; skips itself (rather
    /// than failing) when they are absent so this doesn't become a flaky
    /// requirement for every environment `cargo test` runs in.
    #[tokio::test]
    async fn adhoc_success_scans_and_finishes() {
        if std::env::var("AWS_ACCESS_KEY_ID").is_err() {
            eprintln!("skipping adhoc_success_scans_and_finishes: AWS_ACCESS_KEY_ID not set");
            return;
        }

        let server = MockServer::start().await;
        let scan_id = uuid::Uuid::new_v4().to_string();
        Mock::given(method("GET"))
            .and(path(format!("/adhoc-ok-bucket/{scan_id}/upload.bin")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"clean-adhoc-body".to_vec()))
            .mount(&server)
            .await;

        let pool = db_pool().await;
        let tenant = test_tenant();
        seed_adhoc(&pool, tenant, &scan_id).await;
        let prefix = unique_prefix();
        let cfg = WorkerConfig {
            adhoc_bucket: Some("adhoc-ok-bucket".to_owned()),
            s3_endpoint_url: Some(server.uri()),
            s3_force_path_style: true,
            ..WorkerConfig::for_tests()
        };
        let handler = build_handler(pool.clone(), cfg, &prefix).await;

        let result = handler
            .handle(&adhoc_entry(
                &scan_id,
                &format!("{scan_id}/upload.bin"),
                tenant,
            ))
            .await;
        assert!(result.is_ok(), "{result:?}");

        let row: (String, bool, Option<chrono::NaiveDateTime>) = sqlx::query_as(
            "SELECT scan_status, is_malware, scanned_at FROM adhoc_scan_results WHERE scan_id = $1",
        )
        .bind(&scan_id)
        .fetch_one(&pool)
        .await
        .expect("select");
        assert_eq!(row.0, "clean");
        assert!(!row.1);
        assert!(row.2.is_some());
    }

    // ── own-AWS federation (adhoc_client) ───────────────────────────────
    //
    // `federated_base_credentials`'s success path (JWT flows through to a
    // real `sts:AssumeRoleWithWebIdentity` call) is exhaustively covered in
    // `crates/skauswatch-s3::credentials`'s own tests via its
    // `sts_endpoint_override` seam, which is private to that crate — the
    // public `federated_base_credentials` entry point this worker calls
    // always targets the real STS endpoint, so it can't be hermetically
    // redirected from here. What *is* this worker's own responsibility to
    // prove is the fail-safe wiring: a degraded identity source must make
    // `adhoc_client` fall back to the default AWS credential-provider
    // chain rather than erroring or hanging.

    /// A [`skauswatch_s3::credentials::JwtSvidSource`] double that always
    /// reports "no identity held" — mirrors what a degraded/unattested
    /// `IdentityProvider` (no SPIRE agent reachable) would surface.
    struct DegradedJwtSource;

    #[async_trait::async_trait]
    impl skauswatch_s3::credentials::JwtSvidSource for DegradedJwtSource {
        async fn fetch_jwt_svid_token(
            &self,
            _audience: &str,
        ) -> Result<String, skauswatch_s3::credentials::CredentialError> {
            Err(skauswatch_s3::credentials::CredentialError::Identity(
                "no identity held (test double)".to_owned(),
            ))
        }
    }

    /// Same shape as `adhoc_success_scans_and_finishes`, but with
    /// federation configured against a degraded identity source —
    /// `adhoc_client` must fall back to the default credential-provider
    /// chain (same as if federation were never configured at all) and
    /// still complete the scan, never error or hang on the failed
    /// federation attempt.
    #[tokio::test]
    async fn adhoc_client_falls_back_to_default_chain_when_federation_degraded() {
        if std::env::var("AWS_ACCESS_KEY_ID").is_err() {
            eprintln!(
                "skipping adhoc_client_falls_back_to_default_chain_when_federation_degraded: \
                 AWS_ACCESS_KEY_ID not set"
            );
            return;
        }

        let server = MockServer::start().await;
        let scan_id = uuid::Uuid::new_v4().to_string();
        Mock::given(method("GET"))
            .and(path(format!("/adhoc-fed-bucket/{scan_id}/upload.bin")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"clean-adhoc-body".to_vec()))
            .mount(&server)
            .await;

        let pool = db_pool().await;
        let tenant = test_tenant();
        seed_adhoc(&pool, tenant, &scan_id).await;
        let prefix = unique_prefix();
        let cfg = WorkerConfig {
            adhoc_bucket: Some("adhoc-fed-bucket".to_owned()),
            s3_endpoint_url: Some(server.uri()),
            s3_force_path_style: true,
            ..WorkerConfig::for_tests()
        };
        let handler = build_handler(pool.clone(), cfg, &prefix)
            .await
            .with_federation(
                std::sync::Arc::new(DegradedJwtSource),
                "arn:aws:iam::123456789012:role/skauswatch-base".to_owned(),
            );

        let result = handler
            .handle(&adhoc_entry(
                &scan_id,
                &format!("{scan_id}/upload.bin"),
                tenant,
            ))
            .await;
        assert!(result.is_ok(), "{result:?}");

        let row: (String,) =
            sqlx::query_as("SELECT scan_status FROM adhoc_scan_results WHERE scan_id = $1")
                .bind(&scan_id)
                .fetch_one(&pool)
                .await
                .expect("select");
        assert_eq!(
            row.0, "clean",
            "degraded federation must fall back to the default credential chain, not fail the scan"
        );
    }
}
