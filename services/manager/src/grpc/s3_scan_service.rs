//! `skauswatch.s3scan.S3ScanService` — v1 wrote this servicer
//! (services/manager/grpc/s3_scan_server.py) but never registered it at
//! runtime; the contract's v2 decision is to serve it (workers need it).
//! Ported per contract defect #1: the DB schema is authoritative, so
//! results land in the real s3_scan_results/adhoc_scan_results columns
//! (v1's save path referenced columns that don't exist and could never
//! have committed a row).

use tonic::{Request, Response, Status, Streaming};

use skauswatch_proto::s3scan::s3_scan_service_server::S3ScanService;
use skauswatch_proto::s3scan::{
    AdhocScanRequest, AdhocScanResponse, ResultAck, ScanResult, ScanStatusRequest,
    ScanStatusResponse, ScanTask, StreamAck, TaskAck,
};

use super::{check_api_version, require_jwt, require_tenant_metadata};
use crate::state::AppState;

/// S3ScanService servicer backed by the shared AppState (DB + streams).
pub struct S3ScanGrpc {
    state: AppState,
}

impl S3ScanGrpc {
    /// Wraps the shared state for the tonic service registration.
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

/// v1 `S3ScanPublisher.publish_scan_task` wire fields for a gRPC-submitted
/// task: the request fields in dict order plus `submitted_at`, stringified
/// redis-py style (ints → decimal, bools → "True"/"False"), plus the
/// tenancy-retrofit `tenant_id` field appended at the end (additive — see
/// docs/v2-port/tenancy-model.md §3). `tenant` comes from the caller-
/// supplied `x-tenant-id` gRPC metadata ([`require_tenant_metadata`]),
/// never from the request message itself.
fn submit_task_fields(
    req: &ScanTask,
    submitted_at: &str,
    tenant: uuid::Uuid,
) -> skauswatch_streams::EntryFields {
    vec![
        ("task_id".to_owned(), req.task_id.clone()),
        ("job_id".to_owned(), req.job_id.clone()),
        (
            "bucket_config_id".to_owned(),
            req.bucket_config_id.to_string(),
        ),
        ("object_key".to_owned(), req.object_key.clone()),
        ("object_size".to_owned(), req.object_size.to_string()),
        ("endpoint_url".to_owned(), req.endpoint_url.clone()),
        ("bucket_name".to_owned(), req.bucket_name.clone()),
        ("access_key".to_owned(), req.access_key.clone()),
        ("secret_key".to_owned(), req.secret_key.clone()),
        ("region".to_owned(), req.region.clone()),
        (
            "use_ssl".to_owned(),
            skauswatch_streams::py_bool(req.use_ssl).to_owned(),
        ),
        (
            "path_style".to_owned(),
            skauswatch_streams::py_bool(req.path_style).to_owned(),
        ),
        (
            "yara_enabled".to_owned(),
            skauswatch_streams::py_bool(req.yara_enabled).to_owned(),
        ),
        ("submitted_at".to_owned(), submitted_at.to_owned()),
        ("tenant_id".to_owned(), tenant.to_string()),
    ]
}

/// Ad-hoc dispatch fields — same shape as the REST /upload dispatch (the
/// v2 convention: empty bucket_config_id, `{scan_id}/{filename}` key,
/// scan+yara enabled) so workers see one ad-hoc task format. `tenant` comes
/// from the caller-supplied `x-tenant-id` gRPC metadata
/// ([`require_tenant_metadata`]) — see [`submit_task_fields`] docs.
fn adhoc_task_fields(
    scan_id: &str,
    object_key: &str,
    object_size: i64,
    submitted_at: &str,
    tenant: uuid::Uuid,
) -> skauswatch_streams::EntryFields {
    vec![
        ("job_id".to_owned(), scan_id.to_owned()),
        ("bucket_config_id".to_owned(), String::new()),
        ("object_key".to_owned(), object_key.to_owned()),
        ("object_size".to_owned(), object_size.to_string()),
        ("object_etag".to_owned(), String::new()),
        (
            "scan_enabled".to_owned(),
            skauswatch_streams::py_bool(true).to_owned(),
        ),
        (
            "yara_enabled".to_owned(),
            skauswatch_streams::py_bool(true).to_owned(),
        ),
        ("submitted_at".to_owned(), submitted_at.to_owned()),
        ("tenant_id".to_owned(), tenant.to_string()),
    ]
}

/// Non-empty JSON payload string → jsonb value; invalid JSON is stored as
/// a JSON string (pydal json fields serialized whatever they were given).
fn parse_json_field(s: &str) -> Option<serde_json::Value> {
    if s.is_empty() {
        return None;
    }
    Some(serde_json::from_str(s).unwrap_or_else(|_| serde_json::Value::String(s.to_owned())))
}

/// `""` → NULL for optional text columns (v1 `x if x else None`).
fn opt_str(s: &str) -> Option<&str> {
    (!s.is_empty()).then_some(s)
}

/// Lowercase hex rendering for digest bytes.
fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Persists one worker-reported result and bumps the job counters. Returns
/// v1 ack semantics: any validation or DB failure → `false` (never a gRPC
/// error status), success → `true`.
async fn handle_scan_result(state: &AppState, res: &ScanResult) -> bool {
    // v1 field validation: missing task_id or job_id → accepted=False.
    if res.task_id.is_empty() {
        tracing::warn!("ReportScanResult: missing task_id");
        return false;
    }
    if res.job_id.is_empty() {
        tracing::warn!(task_id = %res.task_id, "ReportScanResult: missing job_id");
        return false;
    }

    // v1 looked the job up for bucket_config_id (falling back to an FK-
    // breaking 0); the real-schema port requires the job row. The job's own
    // `tenant_id` (stamped when the job was created by a tenant-scoped REST
    // caller — see `routes/s3_scan.rs::trigger_scan`/`upload_file`) is the
    // authoritative tenant for the result row this reports against, never a
    // value the reporting worker could supply itself.
    let job: Option<(i32, i32, uuid::Uuid)> = match sqlx::query_as(
        "SELECT id, bucket_config_id, tenant_id FROM s3_scan_jobs WHERE job_id = $1",
    )
    .bind(&res.job_id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!(job_id = %res.job_id, error = %e, "scan result job lookup failed");
            return false;
        }
    };
    let Some((job_pk, bucket_config_id, tenant_id)) = job else {
        tracing::warn!(job_id = %res.job_id, "scan result for unknown job");
        return false;
    };

    // Defect #1 port: real columns only — threat_names (v1 sent the
    // nonexistent threat_details), file_md5/sha1/sha256 (v1 dropped them),
    // clamav_result/yara_matches/ti_enrichment jsonb; error_message has no
    // backing column in s3_scan_results and is log-only.
    if !res.error_message.is_empty() {
        tracing::warn!(task_id = %res.task_id, error = %res.error_message, "worker scan error");
    }
    let threat_names = serde_json::Value::from(res.threat_names.clone());
    let insert = sqlx::query(
        "INSERT INTO s3_scan_results (job_id, bucket_config_id, object_key, \
         detected_file_type, scan_status, is_malware, is_pup, is_threat, threat_names, \
         clamav_result, yara_matches, file_md5, file_sha1, file_sha256, ti_enrichment, \
         scan_duration_ms, tenant_id, scanned_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, now())",
    )
    .bind(job_pk)
    .bind(bucket_config_id)
    .bind(&res.object_key)
    .bind(opt_str(&res.detected_file_type))
    .bind(&res.scan_status)
    .bind(res.is_malware)
    .bind(res.is_pup)
    .bind(res.is_threat)
    .bind(&threat_names)
    .bind(parse_json_field(&res.clamav_result_json))
    .bind(parse_json_field(&res.yara_matches_json))
    .bind(opt_str(&res.file_md5))
    .bind(opt_str(&res.file_sha1))
    .bind(opt_str(&res.file_sha256))
    .bind(parse_json_field(&res.ti_enrichment_json))
    .bind(res.scan_duration_ms)
    .bind(tenant_id)
    .execute(&state.db)
    .await;
    if let Err(e) = insert {
        tracing::warn!(task_id = %res.task_id, error = %e, "scan result insert failed");
        return false;
    }

    // v1 intent (its kwargs never matched, another dead-path defect):
    // scanned +1, infected/pup on flags, errors on scan_status "error".
    let update = sqlx::query(
        "UPDATE s3_scan_jobs SET \
         scanned_objects = COALESCE(scanned_objects, 0) + 1, \
         infected_objects = COALESCE(infected_objects, 0) + $2, \
         pup_objects = COALESCE(pup_objects, 0) + $3, \
         error_count = COALESCE(error_count, 0) + $4 \
         WHERE id = $1",
    )
    .bind(job_pk)
    .bind(i32::from(res.is_malware))
    .bind(i32::from(res.is_pup))
    .bind(i32::from(res.scan_status == "error"))
    .execute(&state.db)
    .await;
    if let Err(e) = update {
        tracing::warn!(job_id = %res.job_id, error = %e, "job progress update failed");
        return false;
    }
    true
}

#[tonic::async_trait]
impl S3ScanService for S3ScanGrpc {
    /// SubmitScanTask — validates task_id/job_id/object_key then publishes
    /// the task to s3scan:tasks; every failure is an accepted=false ack
    /// (v1 never surfaced a gRPC error status here).
    async fn submit_scan_task(
        &self,
        request: Request<ScanTask>,
    ) -> Result<Response<TaskAck>, Status> {
        require_jwt(request.metadata(), &self.state.auth.jwt_secret)?;
        let tenant = require_tenant_metadata(request.metadata())?;
        let req = request.into_inner();
        check_api_version(&req.api_version)?;

        for (value, field) in [
            (&req.task_id, "task_id"),
            (&req.job_id, "job_id"),
            (&req.object_key, "object_key"),
        ] {
            if value.is_empty() {
                return Ok(Response::new(TaskAck {
                    accepted: false,
                    message: format!("Missing required field: {field}"),
                }));
            }
        }

        // The ack reflects the publish outcome, so this bypasses the
        // swallow-and-warn helper and reads the producer directly.
        let fields = submit_task_fields(&req, &skauswatch_streams::py_now_isoformat(), tenant);
        let ack = match &self.state.streams {
            None => TaskAck {
                accepted: false,
                message: "Error: streams not initialized".to_owned(),
            },
            Some(producer) => match producer
                .publish(skauswatch_streams::STREAM_S3_SCAN_TASKS, fields)
                .await
            {
                Ok(_) => TaskAck {
                    accepted: true,
                    message: "Scan task published successfully".to_owned(),
                },
                Err(e) => TaskAck {
                    accepted: false,
                    message: format!("Error: {e}"),
                },
            },
        };
        Ok(Response::new(ack))
    }

    /// ReportScanResult — stores the result against the real schema and
    /// bumps job counters; failures ack accepted=false (v1 semantics).
    async fn report_scan_result(
        &self,
        request: Request<ScanResult>,
    ) -> Result<Response<ResultAck>, Status> {
        require_jwt(request.metadata(), &self.state.auth.jwt_secret)?;
        let res = request.into_inner();
        check_api_version(&res.api_version)?;
        let accepted = handle_scan_result(&self.state, &res).await;
        Ok(Response::new(ResultAck { accepted }))
    }

    /// ScanAdhocFile — stores the upload as a pending adhoc_scan_results
    /// row and dispatches an s3scan:tasks message (the v2 REST-upload
    /// convention; v1's inline Minio scan path was never live).
    async fn scan_adhoc_file(
        &self,
        request: Request<AdhocScanRequest>,
    ) -> Result<Response<AdhocScanResponse>, Status> {
        require_jwt(request.metadata(), &self.state.auth.jwt_secret)?;
        let tenant = require_tenant_metadata(request.metadata())?;
        let req = request.into_inner();
        check_api_version(&req.api_version)?;

        if req.file_content.is_empty() {
            return Err(Status::invalid_argument("Missing file content"));
        }
        if req.filename.is_empty() {
            return Err(Status::invalid_argument("Missing filename"));
        }

        // v1: request.scan_id or a fresh uuid4.
        let scan_id = if req.scan_id.is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            req.scan_id.clone()
        };
        let md5_hex = hex_lower(&<md5::Md5 as md5::Digest>::digest(&req.file_content));
        let sha256_hex = hex_lower(&<sha2::Sha256 as sha2::Digest>::digest(&req.file_content));
        let file_size = i32::try_from(req.file_content.len()).map_err(|e| {
            tracing::error!(error = %e, "s3scan gRPC internal error");
            Status::internal("Internal Server Error")
        })?;

        // uploaded_by is a NOT NULL users reference — v1 passed the raw
        // value (0 when unset) and would have failed the same way; DB
        // errors surface as INTERNAL "Error: ..." (v1 catch-all).
        sqlx::query(
            "INSERT INTO adhoc_scan_results (scan_id, uploaded_by, original_filename, \
             file_size, file_md5, file_sha256, scan_status, is_malware, is_pup, is_threat, \
             tenant_id, uploaded_at) \
             VALUES ($1, $2, $3, $4, $5, $6, 'pending', FALSE, FALSE, FALSE, $7, now())",
        )
        .bind(&scan_id)
        .bind(req.uploaded_by)
        .bind(&req.filename)
        .bind(file_size)
        .bind(&md5_hex)
        .bind(&sha256_hex)
        .bind(tenant)
        .execute(&self.state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "s3scan gRPC internal error");
            Status::internal("Internal Server Error")
        })?;

        // Dispatch to the workers; publish failures are swallowed with a
        // warning exactly like every v1 HTTP publish site.
        let object_key = format!("{scan_id}/{}", req.filename);
        self.state
            .publish_stream(
                skauswatch_streams::STREAM_S3_SCAN_TASKS,
                adhoc_task_fields(
                    &scan_id,
                    &object_key,
                    i64::from(file_size),
                    &skauswatch_streams::py_now_isoformat(),
                    tenant,
                ),
            )
            .await;

        Ok(Response::new(AdhocScanResponse {
            scan_id,
            status: "pending".to_owned(),
            result: None,
        }))
    }

    /// StreamScanResults — client-streamed results run through the same
    /// persistence path as ReportScanResult; the ack counts stored rows.
    async fn stream_scan_results(
        &self,
        request: Request<Streaming<ScanResult>>,
    ) -> Result<Response<StreamAck>, Status> {
        require_jwt(request.metadata(), &self.state.auth.jwt_secret)?;
        let mut stream = request.into_inner();
        let mut results_received: i32 = 0;
        while let Some(res) = stream.message().await? {
            // Per-message version gate: an unknown api_version fails the
            // whole RPC (each ScanResult carries the field).
            check_api_version(&res.api_version)?;
            if handle_scan_result(&self.state, &res).await {
                results_received += 1;
            } else {
                tracing::warn!(
                    task_id = %res.task_id,
                    job_id = %res.job_id,
                    "failed to process streamed result"
                );
            }
        }
        Ok(Response::new(StreamAck { results_received }))
    }

    /// GetScanStatus — INVALID_ARGUMENT "Missing job_id", NOT_FOUND
    /// "Job not found: {id}", else the job's progress counters. Tenant-
    /// scoped like every other RPC here (and the REST `get_job` equivalent
    /// in `routes/s3_scan.rs`): a cross-tenant `job_id` must read as
    /// not-found, never leak another tenant's status.
    async fn get_scan_status(
        &self,
        request: Request<ScanStatusRequest>,
    ) -> Result<Response<ScanStatusResponse>, Status> {
        require_jwt(request.metadata(), &self.state.auth.jwt_secret)?;
        let tenant = require_tenant_metadata(request.metadata())?;
        let req = request.into_inner();
        check_api_version(&req.api_version)?;

        if req.job_id.is_empty() {
            return Err(Status::invalid_argument("Missing job_id"));
        }

        let row: Option<(Option<String>, Option<i32>, Option<i32>, Option<i32>)> = sqlx::query_as(
            "SELECT status, total_objects, scanned_objects, infected_objects \
             FROM s3_scan_jobs WHERE job_id = $1 AND tenant_id = $2",
        )
        .bind(&req.job_id)
        .bind(tenant)
        .fetch_optional(&self.state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "s3scan gRPC internal error");
            Status::internal("Internal Server Error")
        })?;

        let Some((status, total, scanned, infected)) = row else {
            return Err(Status::not_found(format!("Job not found: {}", req.job_id)));
        };
        Ok(Response::new(ScanStatusResponse {
            job_id: req.job_id,
            status: status.unwrap_or_default(),
            total: total.unwrap_or(0),
            scanned: scanned.unwrap_or(0),
            infected: infected.unwrap_or(0),
        }))
    }
}

#[cfg(test)]
#[allow(clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;
    use crate::grpc::test_util::test_state;
    use tonic::Code;

    fn svc() -> S3ScanGrpc {
        S3ScanGrpc::new(test_state())
    }

    /// Wraps `msg` in a `Request` carrying a valid `test-secret`-signed
    /// bearer token, matching `test_state()`'s `AuthSettings::jwt_secret`.
    fn authed<T>(msg: T) -> Request<T> {
        let token =
            match skauswatch_auth::issue_service_token("worker", "worker", "test-secret", 300) {
                Ok(t) => t,
                Err(e) => panic!("issue test token: {e}"),
            };
        let mut req = Request::new(msg);
        let value = match format!("Bearer {token}").parse() {
            Ok(v) => v,
            Err(e) => panic!("metadata value: {e}"),
        };
        req.metadata_mut().insert("authorization", value);
        req
    }

    /// A fixed, valid tenant UUID for tests that need `x-tenant-id`
    /// metadata but don't care about its specific value.
    const TEST_TENANT: &str = "11111111-1111-1111-1111-111111111111";

    /// [`authed`] plus an `x-tenant-id` metadata entry set to `tenant` —
    /// the shape `submit_scan_task`/`scan_adhoc_file`/`get_scan_status`
    /// require per docs/v2-port/tenancy-model.md §3.
    fn authed_with_tenant_value<T>(msg: T, tenant: &str) -> Request<T> {
        let mut req = authed(msg);
        let value = match tenant.parse() {
            Ok(v) => v,
            Err(e) => panic!("metadata value: {e}"),
        };
        req.metadata_mut().insert("x-tenant-id", value);
        req
    }

    /// [`authed_with_tenant_value`] fixed to [`TEST_TENANT`] — for tests
    /// that need `x-tenant-id` metadata but don't care about its specific
    /// value.
    fn authed_with_tenant<T>(msg: T) -> Request<T> {
        authed_with_tenant_value(msg, TEST_TENANT)
    }

    fn full_task(api_version: &str) -> ScanTask {
        ScanTask {
            task_id: "task-1".to_owned(),
            job_id: "job-1".to_owned(),
            bucket_config_id: 3,
            object_key: "path/file.bin".to_owned(),
            object_size: 42,
            endpoint_url: "https://s3.example".to_owned(),
            bucket_name: "bkt".to_owned(),
            access_key: "AK".to_owned(),
            secret_key: "SK".to_owned(),
            region: "us-east-1".to_owned(),
            use_ssl: true,
            path_style: false,
            yara_enabled: true,
            api_version: api_version.to_owned(),
        }
    }

    #[tokio::test]
    async fn submit_scan_task_without_jwt_is_unauthenticated() {
        let err = match svc().submit_scan_task(Request::new(full_task(""))).await {
            Err(e) => e,
            Ok(_) => panic!("missing bearer token must be rejected"),
        };
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[tokio::test]
    async fn submit_scan_task_without_tenant_metadata_is_unauthenticated() {
        // Bearer JWT present, but no x-tenant-id — the tenancy-retrofit
        // contract (docs/v2-port/tenancy-model.md §3) rejects this the same
        // way as a missing JWT, before any field validation runs.
        let err = match svc().submit_scan_task(authed(full_task(""))).await {
            Err(e) => e,
            Ok(_) => panic!("missing x-tenant-id metadata must be rejected"),
        };
        assert_eq!(err.code(), Code::Unauthenticated);
        assert_eq!(err.message(), "missing x-tenant-id metadata");
    }

    #[tokio::test]
    async fn submit_scan_task_reports_missing_fields_in_ack() {
        for (field, mutate) in [("task_id", 0_usize), ("job_id", 1), ("object_key", 2)] {
            let mut task = full_task("");
            match mutate {
                0 => task.task_id = String::new(),
                1 => task.job_id = String::new(),
                _ => task.object_key = String::new(),
            }
            let ack = match svc().submit_scan_task(authed_with_tenant(task)).await {
                Ok(r) => r.into_inner(),
                Err(e) => panic!("validation failures must ack, not error: {e}"),
            };
            assert!(!ack.accepted, "{field}");
            assert_eq!(ack.message, format!("Missing required field: {field}"));
        }
    }

    #[tokio::test]
    async fn submit_scan_task_without_streams_acks_error() {
        // Empty api_version (old-agent path) routes to the handler; the
        // test state has no producer → v1-style "Error: ..." ack.
        let ack = match svc()
            .submit_scan_task(authed_with_tenant(full_task("")))
            .await
        {
            Ok(r) => r.into_inner(),
            Err(e) => panic!("publish failures must ack, not error: {e}"),
        };
        assert!(!ack.accepted);
        assert!(ack.message.starts_with("Error: "), "msg: {}", ack.message);
    }

    #[tokio::test]
    async fn submit_scan_task_unknown_api_version_is_unimplemented() {
        let err = match svc()
            .submit_scan_task(authed_with_tenant(full_task("v9")))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("v9 must be rejected"),
        };
        assert_eq!(err.code(), Code::Unimplemented);
        assert_eq!(err.message(), "api_version v9 not supported");
    }

    #[test]
    fn submit_task_fields_match_v1_names_order_and_encoding() {
        let tenant = uuid::Uuid::nil();
        let fields = submit_task_fields(&full_task(""), "2026-07-22T09:30:00.000042", tenant);
        let mut expected: Vec<(String, String)> = [
            ("task_id", "task-1"),
            ("job_id", "job-1"),
            ("bucket_config_id", "3"),
            ("object_key", "path/file.bin"),
            ("object_size", "42"),
            ("endpoint_url", "https://s3.example"),
            ("bucket_name", "bkt"),
            ("access_key", "AK"),
            ("secret_key", "SK"),
            ("region", "us-east-1"),
            ("use_ssl", "True"),
            ("path_style", "False"),
            ("yara_enabled", "True"),
            ("submitted_at", "2026-07-22T09:30:00.000042"),
        ]
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
        expected.push(("tenant_id".to_owned(), tenant.to_string()));
        assert_eq!(fields, expected);
    }

    #[test]
    fn adhoc_task_fields_match_rest_upload_dispatch_shape() {
        let tenant = uuid::Uuid::nil();
        let fields = adhoc_task_fields(
            "scan-1",
            "scan-1/a.bin",
            7,
            "2026-07-22T09:30:00.000042",
            tenant,
        );
        let mut expected: Vec<(String, String)> = [
            ("job_id", "scan-1"),
            ("bucket_config_id", ""),
            ("object_key", "scan-1/a.bin"),
            ("object_size", "7"),
            ("object_etag", ""),
            ("scan_enabled", "True"),
            ("yara_enabled", "True"),
            ("submitted_at", "2026-07-22T09:30:00.000042"),
        ]
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
        expected.push(("tenant_id".to_owned(), tenant.to_string()));
        assert_eq!(fields, expected);
    }

    #[tokio::test]
    async fn report_scan_result_missing_ids_ack_false() {
        let no_task = ScanResult {
            job_id: "job-1".to_owned(),
            ..Default::default()
        };
        let ack = match svc().report_scan_result(authed(no_task)).await {
            Ok(r) => r.into_inner(),
            Err(e) => panic!("validation failures must ack, not error: {e}"),
        };
        assert!(!ack.accepted);

        let no_job = ScanResult {
            task_id: "task-1".to_owned(),
            ..Default::default()
        };
        let ack = match svc().report_scan_result(authed(no_job)).await {
            Ok(r) => r.into_inner(),
            Err(e) => panic!("validation failures must ack, not error: {e}"),
        };
        assert!(!ack.accepted);
    }

    #[tokio::test]
    async fn report_scan_result_unknown_api_version_is_unimplemented() {
        let res = ScanResult {
            task_id: "task-1".to_owned(),
            job_id: "job-1".to_owned(),
            api_version: "v9".to_owned(),
            ..Default::default()
        };
        let err = match svc().report_scan_result(authed(res)).await {
            Err(e) => e,
            Ok(_) => panic!("v9 must be rejected"),
        };
        assert_eq!(err.code(), Code::Unimplemented);
    }

    #[tokio::test]
    async fn scan_adhoc_file_validates_content_and_filename() {
        let err = match svc()
            .scan_adhoc_file(authed_with_tenant(AdhocScanRequest {
                filename: "a.bin".to_owned(),
                ..Default::default()
            }))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("empty content must be rejected"),
        };
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), "Missing file content");

        let err = match svc()
            .scan_adhoc_file(authed_with_tenant(AdhocScanRequest {
                file_content: vec![1, 2, 3],
                ..Default::default()
            }))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("empty filename must be rejected"),
        };
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), "Missing filename");
    }

    #[tokio::test]
    async fn scan_adhoc_file_db_failure_is_generic_internal_error() {
        // Valid request against the unreachable test DB → INTERNAL. The
        // message must be generic (no sqlx/internal detail leaked to the
        // caller); the real cause is logged server-side only.
        let err = match svc()
            .scan_adhoc_file(authed_with_tenant(AdhocScanRequest {
                scan_id: "scan-1".to_owned(),
                file_content: vec![1, 2, 3],
                filename: "a.bin".to_owned(),
                uploaded_by: 1,
                api_version: "v1".to_owned(),
            }))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("test DB is unreachable — insert must fail"),
        };
        assert_eq!(err.code(), Code::Internal);
        assert_eq!(err.message(), "Internal Server Error");
    }

    #[tokio::test]
    async fn get_scan_status_requires_job_id() {
        let err = match svc()
            .get_scan_status(authed_with_tenant(ScanStatusRequest::default()))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("empty job_id must be rejected"),
        };
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), "Missing job_id");
    }

    #[tokio::test]
    async fn get_scan_status_unknown_api_version_is_unimplemented() {
        let err = match svc()
            .get_scan_status(authed_with_tenant(ScanStatusRequest {
                job_id: "job-1".to_owned(),
                api_version: "v9".to_owned(),
            }))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("v9 must be rejected"),
        };
        assert_eq!(err.code(), Code::Unimplemented);
        assert_eq!(err.message(), "api_version v9 not supported");
    }

    #[tokio::test]
    async fn get_scan_status_without_tenant_metadata_is_unauthenticated() {
        // Bearer JWT present, but no x-tenant-id — same contract as
        // submit_scan_task: rejected before job_id/api_version validation.
        let err = match svc()
            .get_scan_status(authed(ScanStatusRequest {
                job_id: "job-1".to_owned(),
                api_version: "v1".to_owned(),
            }))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("missing x-tenant-id metadata must be rejected"),
        };
        assert_eq!(err.code(), Code::Unauthenticated);
        assert_eq!(err.message(), "missing x-tenant-id metadata");
    }

    async fn seed_bucket_and_job(pool: &sqlx::PgPool) -> (i32, String) {
        // `assume_role` mode needs no credential_enc ciphertext — this test
        // never resolves an S3 client, only exercises job/result plumbing.
        // `tenant_id` is NOT NULL on both tables
        // (`services/s3scan/migrations/0002_s3scan_tenancy.sql`); the exact
        // value doesn't matter to these tests (they never assert isolation),
        // so both rows share the bootstrap tenant.
        let tenant_id = crate::auth::default_tenant_uuid();
        let (bucket_id,): (i32,) = sqlx::query_as(
            "INSERT INTO s3_bucket_configs \
             (name, endpoint_url, bucket_name, credential_mode, role_arn, region, \
              use_ssl, path_style, scan_enabled, yara_enabled, created_by, tenant_id, \
              created_at, updated_at) \
             VALUES ('grpc-bucket', 'http://parity-stub:9999', 'bkt', 'assume_role', \
                     'arn:aws:iam::123456789012:role/test', 'us-east-1', false, true, true, \
                     false, 1, $1, now(), now()) RETURNING id",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("seed bucket: {e}"));
        let job_uuid = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO s3_scan_jobs (job_id, bucket_config_id, job_type, status, \
             triggered_by, tenant_id, created_at) \
             VALUES ($1, $2, 'full_scan', 'running', 1, $3, now())",
        )
        .bind(&job_uuid)
        .bind(bucket_id)
        .bind(tenant_id)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("seed job: {e}"));
        (bucket_id, job_uuid)
    }

    #[tokio::test]
    async fn report_scan_result_and_get_scan_status_round_trip_against_real_db() {
        let state = crate::grpc::test_util::db_state_with_s3scan().await;
        let (_, job_uuid) = seed_bucket_and_job(&state.db).await;
        let owner_tenant = crate::auth::default_tenant_uuid().to_string();
        let svc = S3ScanGrpc::new(state);

        let ack = match svc
            .report_scan_result(authed(ScanResult {
                task_id: "task-real".to_owned(),
                job_id: job_uuid.clone(),
                object_key: "a/b.exe".to_owned(),
                is_malware: true,
                is_threat: true,
                scan_status: "infected".to_owned(),
                threat_names: vec!["Win.Trojan.Agent".to_owned()],
                file_sha256: "e".repeat(64),
                api_version: "v1".to_owned(),
                ..Default::default()
            }))
            .await
        {
            Ok(r) => r.into_inner(),
            Err(e) => panic!("report_scan_result: {e:?}"),
        };
        assert!(ack.accepted);

        let status = match svc
            .get_scan_status(authed_with_tenant_value(
                ScanStatusRequest {
                    job_id: job_uuid.clone(),
                    api_version: "v1".to_owned(),
                },
                &owner_tenant,
            ))
            .await
        {
            Ok(r) => r.into_inner(),
            Err(e) => panic!("get_scan_status: {e:?}"),
        };
        assert_eq!(status.job_id, job_uuid);
        assert_eq!(status.scanned, 1);
        assert_eq!(status.infected, 1);

        let missing = match svc
            .get_scan_status(authed_with_tenant_value(
                ScanStatusRequest {
                    job_id: "no-such-job".to_owned(),
                    api_version: "v1".to_owned(),
                },
                &owner_tenant,
            ))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("expected not found"),
        };
        assert_eq!(missing.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn get_scan_status_rejects_cross_tenant_job_id() {
        // Regression for the tenancy gap this RPC had: job_id alone was
        // enough to read another tenant's scan-job status. A caller
        // authenticated as a different tenant (TEST_TENANT) than the job's
        // owner (default_tenant_uuid) must see NotFound, never the row.
        let state = crate::grpc::test_util::db_state_with_s3scan().await;
        let (_, job_uuid) = seed_bucket_and_job(&state.db).await;
        assert_ne!(TEST_TENANT, crate::auth::default_tenant_uuid().to_string());
        let svc = S3ScanGrpc::new(state);

        let err = match svc
            .get_scan_status(authed_with_tenant(ScanStatusRequest {
                job_id: job_uuid,
                api_version: "v1".to_owned(),
            }))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("cross-tenant job_id must not resolve"),
        };
        assert_eq!(err.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn report_scan_result_for_unknown_job_acks_false() {
        let state = crate::grpc::test_util::db_state_with_s3scan().await;
        let svc = S3ScanGrpc::new(state);
        let ack = match svc
            .report_scan_result(authed(ScanResult {
                task_id: "task-x".to_owned(),
                job_id: "totally-unknown-job".to_owned(),
                api_version: "v1".to_owned(),
                ..Default::default()
            }))
            .await
        {
            Ok(r) => r.into_inner(),
            Err(e) => panic!("report_scan_result: {e:?}"),
        };
        assert!(!ack.accepted);
    }

    #[tokio::test]
    async fn scan_adhoc_file_succeeds_and_dispatches_against_real_db() {
        let state = crate::grpc::test_util::db_state_with_s3scan().await;
        let svc = S3ScanGrpc::new(state);
        let resp = match svc
            .scan_adhoc_file(authed_with_tenant(AdhocScanRequest {
                scan_id: String::new(),
                file_content: vec![1, 2, 3, 4],
                filename: "grpc-upload.bin".to_owned(),
                uploaded_by: 1,
                api_version: "v1".to_owned(),
            }))
            .await
        {
            Ok(r) => r.into_inner(),
            Err(e) => panic!("scan_adhoc_file: {e:?}"),
        };
        assert!(!resp.scan_id.is_empty());
        assert_eq!(resp.status, "pending");
    }

    #[test]
    fn parse_json_field_handles_empty_invalid_and_valid() {
        assert!(parse_json_field("").is_none());
        assert_eq!(
            parse_json_field("{\"a\":1}"),
            Some(serde_json::json!({"a": 1}))
        );
        // Invalid JSON persists as a JSON string (pydal serialized as-is).
        assert_eq!(
            parse_json_field("not json"),
            Some(serde_json::Value::String("not json".to_owned()))
        );
    }

    #[test]
    fn hex_lower_renders_digest_bytes() {
        assert_eq!(hex_lower(&[0x00, 0xab, 0x0f]), "00ab0f");
        assert_eq!(opt_str(""), None);
        assert_eq!(opt_str("x"), Some("x"));
    }
}
