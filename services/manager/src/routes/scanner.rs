//! /api/v1/scanner — manager-side producer for the `scanner:tasks` Redis
//! Stream (ad-hoc YARA/ClamAV malware scans). Net-new in v2, not a v1 port:
//! v1's `worker-scanner` had no REST trigger for these scan types at all —
//! only the ASM Celery path (`services/worker-scanner/api/routes/asm.py`)
//! and the separate, out-of-scope nuclei/zap/openvas job schema covered
//! non-file scanning. See
//! `docs/v2-port/phase12-scope-scan-monitor.md` §"scanner:tasks stream has
//! no producer": without this route, even the already fully-ported
//! scanner-side yara/clamav consumer (`services/scanner/src/handler.rs`,
//! EICAR-tested) is unreachable end-to-end — nothing anywhere ever
//! published to `scanner:tasks`. This is the fix.
//!
//! Deliberately minimal: this route has no v1 contract to match and no
//! confirmed caller yet, so it does not introduce a manager-owned job
//! table (unlike `s3_scan.rs`'s `s3_scan_jobs`) — it only validates input,
//! mints a `job_id`, and publishes. `services/scanner` remains the sole
//! owner of scan-result persistence (`scanner_scan_results`), matching the
//! "manager owns tables it creates work for; the worker owns tables it
//! writes results into" split established by `s3_scan.rs`/`s3scan`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;

use crate::auth::CurrentUser;
use crate::error::{ApiError, ApiJson, ErrorResponse, ValidationErrorResponse};
use crate::state::AppState;

/// `scan_type` values this route accepts. ASM has its own trigger
/// (`routes/asm.rs::create_asm_scan`, `scan_type: "asm"`); nuclei/zap/openvas
/// remain unimplemented scanner-side (`services/scanner/src/scan.rs`) and are
/// deliberately rejected here rather than accepted and silently dropped.
const SCAN_TYPES: [&str; 2] = ["yara", "clamav"];
const SCAN_TYPE_MSG: &str = "Input should be 'yara' or 'clamav'";

/// Router for /api/v1/scanner.
pub fn router() -> Router<AppState> {
    Router::new().route("/scanner/scan", post(trigger_scanner_task))
}

fn validation(field: &str, msg: &str) -> ApiError {
    ApiError::Validation(vec![serde_json::json!({
        "loc": [field], "msg": msg, "type": "value_error"
    })])
}

/// ScannerScanRequest — `target` is a free-form label for the item being
/// scanned (filename, description, ...); `file_path` is the path the
/// scanner worker should read (must be reachable from the scanner pod —
/// shared volume or an already-resolved local path; this route does no
/// file transport of its own). `params` is opaque, scan-type-specific
/// configuration forwarded verbatim to the worker.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ScannerScanBody {
    target: Option<String>,
    scan_type: Option<String>,
    file_path: Option<String>,
    params: Option<serde_json::Value>,
}

/// Documentation-only mirror of `trigger_scanner_task`'s response body.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub(crate) struct ScannerScanResponse {
    job_id: String,
    status: String,
}

/// `scanner:tasks` message field shape — must match what
/// `services/scanner/src/handler.rs::ScannerHandler::handle` parses:
/// `job_id`, `scan_type`, `target`, `file_path`, `params` (JSON string),
/// `tenant_id`, plus `submitted_at` for operational visibility (not read
/// by the handler, but consistent with every other producer in this
/// service — see `routes/s3_scan.rs::scan_task_fields`).
#[allow(clippy::too_many_arguments)]
fn scanner_task_fields(
    job_id: &str,
    scan_type: &str,
    target: &str,
    file_path: Option<&str>,
    params: &serde_json::Value,
    tenant_id: uuid::Uuid,
    submitted_at: &str,
) -> skauswatch_streams::EntryFields {
    vec![
        ("job_id".to_owned(), job_id.to_owned()),
        ("scan_type".to_owned(), scan_type.to_owned()),
        ("target".to_owned(), target.to_owned()),
        (
            "file_path".to_owned(),
            file_path.unwrap_or_default().to_owned(),
        ),
        (
            "params".to_owned(),
            serde_json::to_string(params).unwrap_or_default(),
        ),
        ("tenant_id".to_owned(), tenant_id.to_string()),
        ("submitted_at".to_owned(), submitted_at.to_owned()),
    ]
}

/// POST /scanner/scan — admin/maintainer. Queues one YARA/ClamAV scan task
/// on `scanner:tasks`, tenant-stamped from the caller's JWT (never from the
/// request body — `docs/v2-port/tenancy-model.md` §3/§4). Publish failures
/// are swallowed with a warning (`AppState::publish_stream`), matching
/// every other producer in this service — the response always reflects
/// "queued", not delivery confirmation, same as `s3_scan.rs::trigger_scan`.
#[utoipa::path(
    post,
    path = "/api/v1/scanner/scan",
    tag = "scanner",
    security(("bearer_jwt" = [])),
    request_body = ScannerScanBody,
    responses(
        (status = 202, description = "Scan task queued", body = ScannerScanResponse),
        (status = 400, description = "Validation error", body = ValidationErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
)]
pub(crate) async fn trigger_scanner_task(
    State(state): State<AppState>,
    user: CurrentUser,
    ApiJson(body): ApiJson<ScannerScanBody>,
) -> Result<(StatusCode, Json<ScannerScanResponse>), ApiError> {
    user.require_scope("scanner:write")?;

    let target = match body.target.as_deref() {
        Some(t) if !t.is_empty() => t,
        _ => return Err(validation("target", "Field required")),
    };
    let scan_type = match body.scan_type.as_deref() {
        Some(t) if !t.is_empty() => t,
        _ => return Err(validation("scan_type", "Field required")),
    };
    if !SCAN_TYPES.contains(&scan_type) {
        return Err(validation("scan_type", SCAN_TYPE_MSG));
    }

    let job_id = uuid::Uuid::new_v4().to_string();
    let params = body.params.unwrap_or_else(|| serde_json::json!({}));

    state
        .publish_stream(
            skauswatch_streams::STREAM_SCANNER_TASKS,
            scanner_task_fields(
                &job_id,
                scan_type,
                target,
                body.file_path.as_deref(),
                &params,
                user.tenant_id,
                &skauswatch_streams::py_now_isoformat(),
            ),
        )
        .await;

    Ok((
        StatusCode::ACCEPTED,
        Json(ScannerScanResponse {
            job_id,
            status: "queued".to_owned(),
        }),
    ))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)] // tests fail loudly by design
mod tests {
    use super::*;

    fn test_server() -> axum_test::TestServer {
        let cfg = match penguin_licensing::LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("config: {e}"),
        };
        let client = match penguin_licensing::LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("client: {e}"),
        };
        let state = crate::state::AppStateInner::for_tests(client);
        let app = axum::Router::new()
            .nest("/api/v1", super::router())
            .with_state(state);
        axum_test::TestServer::new(app)
    }

    fn user(role: &str) -> CurrentUser {
        CurrentUser {
            id: 1,
            email: "user@example.com".to_owned(),
            full_name: None,
            role: role.to_owned(),
            is_active: true,
            mfa_enabled: false,
            created_at: None,
            tenant_id: uuid::Uuid::nil(),
        }
    }

    #[tokio::test]
    async fn requires_auth() {
        let server = test_server();
        let res = server
            .post("/api/v1/scanner/scan")
            .json(&serde_json::json!({"target": "t", "scan_type": "yara"}))
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn viewer_forbidden() {
        let res = trigger_scanner_task(
            State(crate::state::AppStateInner::for_tests(dev_client())),
            user("viewer"),
            ApiJson(ScannerScanBody {
                target: Some("t".to_owned()),
                scan_type: Some("yara".to_owned()),
                file_path: None,
                params: None,
            }),
        )
        .await;
        match res {
            Err(ApiError::Forbidden(msg)) => assert_eq!(msg, "Insufficient permissions"),
            other => panic!("expected 403, got {other:?}"),
        }
    }

    fn dev_client() -> std::sync::Arc<penguin_licensing::LicenseClient> {
        let cfg = match penguin_licensing::LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("config: {e}"),
        };
        match penguin_licensing::LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("client: {e}"),
        }
    }

    #[tokio::test]
    async fn missing_target_is_validation_error() {
        let res = trigger_scanner_task(
            State(crate::state::AppStateInner::for_tests(dev_client())),
            user("admin"),
            ApiJson(ScannerScanBody {
                target: None,
                scan_type: Some("yara".to_owned()),
                file_path: None,
                params: None,
            }),
        )
        .await;
        match res {
            Err(ApiError::Validation(details)) => {
                assert_eq!(details[0]["loc"], serde_json::json!(["target"]));
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_target_is_validation_error() {
        let res = trigger_scanner_task(
            State(crate::state::AppStateInner::for_tests(dev_client())),
            user("admin"),
            ApiJson(ScannerScanBody {
                target: Some(String::new()),
                scan_type: Some("yara".to_owned()),
                file_path: None,
                params: None,
            }),
        )
        .await;
        assert!(matches!(res, Err(ApiError::Validation(_))));
    }

    #[tokio::test]
    async fn missing_scan_type_is_validation_error() {
        let res = trigger_scanner_task(
            State(crate::state::AppStateInner::for_tests(dev_client())),
            user("admin"),
            ApiJson(ScannerScanBody {
                target: Some("t".to_owned()),
                scan_type: None,
                file_path: None,
                params: None,
            }),
        )
        .await;
        match res {
            Err(ApiError::Validation(details)) => {
                assert_eq!(details[0]["loc"], serde_json::json!(["scan_type"]));
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_scan_type_is_rejected() {
        let res = trigger_scanner_task(
            State(crate::state::AppStateInner::for_tests(dev_client())),
            user("admin"),
            ApiJson(ScannerScanBody {
                target: Some("t".to_owned()),
                scan_type: Some("nuclei".to_owned()),
                file_path: None,
                params: None,
            }),
        )
        .await;
        match res {
            Err(ApiError::Validation(details)) => {
                assert_eq!(details[0]["msg"], SCAN_TYPE_MSG);
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn admin_and_maintainer_can_queue_yara_and_clamav() {
        for role in ["admin", "maintainer"] {
            for scan_type in ["yara", "clamav"] {
                let res = trigger_scanner_task(
                    State(crate::state::AppStateInner::for_tests(dev_client())),
                    user(role),
                    ApiJson(ScannerScanBody {
                        target: Some("file.bin".to_owned()),
                        scan_type: Some(scan_type.to_owned()),
                        file_path: Some("/tmp/file.bin".to_owned()),
                        params: Some(serde_json::json!({"k": "v"})),
                    }),
                )
                .await;
                match res {
                    Ok((status, Json(body))) => {
                        assert_eq!(status, StatusCode::ACCEPTED, "{role}/{scan_type}");
                        assert_eq!(body.status, "queued");
                        assert!(uuid::Uuid::parse_str(&body.job_id).is_ok());
                    }
                    Err(e) => panic!("expected success for {role}/{scan_type}, got {e:?}"),
                }
            }
        }
    }

    #[test]
    fn scanner_task_fields_shape() {
        let fields = scanner_task_fields(
            "job-1",
            "yara",
            "file.bin",
            Some("/tmp/x"),
            &serde_json::json!({"a": 1}),
            uuid::Uuid::nil(),
            "2026-01-01T00:00:00+00:00",
        );
        assert_eq!(
            fields,
            vec![
                ("job_id".to_owned(), "job-1".to_owned()),
                ("scan_type".to_owned(), "yara".to_owned()),
                ("target".to_owned(), "file.bin".to_owned()),
                ("file_path".to_owned(), "/tmp/x".to_owned()),
                ("params".to_owned(), "{\"a\":1}".to_owned()),
                (
                    "tenant_id".to_owned(),
                    "00000000-0000-0000-0000-000000000000".to_owned()
                ),
                (
                    "submitted_at".to_owned(),
                    "2026-01-01T00:00:00+00:00".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn scanner_task_fields_defaults_missing_file_path_to_empty_string() {
        let fields = scanner_task_fields(
            "job-2",
            "clamav",
            "target",
            None,
            &serde_json::json!({}),
            uuid::Uuid::nil(),
            "ts",
        );
        let (_, file_path) = fields
            .into_iter()
            .find(|(k, _)| k == "file_path")
            .expect("file_path field present");
        assert_eq!(file_path, "");
    }
}
