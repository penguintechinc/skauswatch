//! API-level error taxonomy for both the OCI proxy surface and the admin
//! REST API. Mirrors `services/pki/src/error.rs`'s shape (bare
//! `{"error": msg}` bodies, internal errors never echo their cause).

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Documentation-only mirror of [`ApiError`]'s bare `{"error": msg}` wire
/// shape, referenced from `#[utoipa::path]` `responses(...)` clauses.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ErrorResponse {
    /// Human-readable error message.
    pub error: String,
}

/// API-level errors.
#[derive(Debug)]
pub enum ApiError {
    /// 400 — malformed request (bad digest, unsupported path shape).
    BadRequest(String),
    /// 403 — a scan verdict fails policy: infected/pup content, or a
    /// tenant-boundary violation. Fail-closed per §6.
    Forbidden(String),
    /// 404 — no cached artifact and the upstream doesn't have it either.
    NotFound(String),
    /// 405 — push endpoints; this is a pull-through proxy only.
    MethodNotAllowed(String),
    /// 502 — the upstream registry/token endpoint failed or returned
    /// something this proxy can't use.
    UpstreamError(String),
    /// 500 — logged with full detail server-side, never echoed to the
    /// caller (matches `services/pki`'s finding #6 hardening).
    Internal(String),
}

impl ApiError {
    /// Builds an internal error, logging the real cause server-side.
    pub fn internal(context: &str, err: impl std::fmt::Display) -> Self {
        tracing::error!(error = %err, context, "depgate internal error");
        ApiError::Internal(err.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            ApiError::BadRequest(msg) => {
                (StatusCode::BAD_REQUEST, serde_json::json!({ "error": msg }))
            }
            ApiError::Forbidden(msg) => {
                (StatusCode::FORBIDDEN, serde_json::json!({ "error": msg }))
            }
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, serde_json::json!({ "error": msg })),
            ApiError::MethodNotAllowed(msg) => (
                StatusCode::METHOD_NOT_ALLOWED,
                serde_json::json!({ "error": msg }),
            ),
            ApiError::UpstreamError(msg) => {
                (StatusCode::BAD_GATEWAY, serde_json::json!({ "error": msg }))
            }
            ApiError::Internal(_msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": "Internal Server Error" }),
            ),
        };
        (status, Json(body)).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        ApiError::internal("database", e)
    }
}

impl From<crate::upstream::UpstreamError> for ApiError {
    fn from(e: crate::upstream::UpstreamError) -> Self {
        ApiError::UpstreamError(e.to_string())
    }
}

impl From<crate::cache::CacheError> for ApiError {
    fn from(e: crate::cache::CacheError) -> Self {
        ApiError::internal("cache", e)
    }
}

impl From<crate::fetch::FetchError> for ApiError {
    fn from(e: crate::fetch::FetchError) -> Self {
        use crate::fetch::FetchError;
        match e {
            FetchError::NotFound => ApiError::NotFound("artifact not found upstream".to_owned()),
            other => ApiError::UpstreamError(other.to_string()),
        }
    }
}

impl From<crate::scanpipe::PipelineError> for ApiError {
    fn from(e: crate::scanpipe::PipelineError) -> Self {
        use crate::scanpipe::PipelineError;
        match e {
            PipelineError::BadRequest(m) => ApiError::BadRequest(m),
            PipelineError::Blocked { verdict, threat } => ApiError::Forbidden(format!(
                "artifact blocked by scan policy (verdict={verdict}, threat={threat})"
            )),
            PipelineError::IntegrityMismatch { .. } => {
                ApiError::UpstreamError("digest verification failed".to_owned())
            }
            PipelineError::Upstream(crate::upstream::UpstreamError::NotFound) => {
                ApiError::NotFound("artifact not found upstream".to_owned())
            }
            PipelineError::Upstream(e) => ApiError::UpstreamError(e.to_string()),
            PipelineError::Cache(e) => ApiError::internal("cache", e),
            PipelineError::Db(e) => ApiError::internal("database", e),
            PipelineError::Scan(e) => ApiError::internal("scan", e),
            PipelineError::Fetch(e) => ApiError::from(e),
        }
    }
}

/// Extracts and validates the tenant claim as a UUID — the shared helper
/// every tenant-scoped handler (OCI proxy attribution, admin reporting)
/// uses to turn `skauswatch_auth::TenantContext` into a bindable `Uuid`.
pub(crate) fn tenant_uuid(tenant: &skauswatch_auth::Tenant) -> Result<uuid::Uuid, ApiError> {
    uuid::Uuid::parse_str(tenant.as_str())
        .map_err(|_| ApiError::Forbidden("tenant claim is not a valid identifier".to_owned()))
}

/// v1-style 404 fallback for unmatched routes.
pub async fn fallback_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "Not Found" })),
    )
        .into_response()
}

#[cfg(test)]
#[allow(clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;

    #[tokio::test]
    async fn internal_error_never_leaks_the_cause() {
        let resp = ApiError::Internal("duplicate key value violates constraint".to_owned())
            .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = match axum::body::to_bytes(resp.into_body(), usize::MAX).await {
            Ok(b) => b,
            Err(e) => panic!("read body: {e}"),
        };
        let text = String::from_utf8_lossy(&body);
        assert!(!text.contains("duplicate key"));
        let json: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => panic!("body not json: {e}"),
        };
        assert_eq!(json["error"], "Internal Server Error");
    }

    #[test]
    fn forbidden_renders_403() {
        let resp = ApiError::Forbidden("infected".to_owned()).into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn method_not_allowed_renders_405() {
        let resp = ApiError::MethodNotAllowed("push not supported".to_owned()).into_response();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn upstream_error_renders_502() {
        let resp = ApiError::UpstreamError("boom".to_owned()).into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn fallback_not_found_renders_404() {
        let resp = fallback_not_found().await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
