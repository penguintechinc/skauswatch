//! v1-parity API error bodies. Handler-raised errors in the Quart PKI service
//! are BARE `{"error": "<message>"}` objects; the enveloped
//! `{error, detail}` shape only comes from Quart's framework error handlers
//! (unknown-route 404 / uncaught 500). Validation failures answer
//! `400 {"error": "Validation error", "details": [...]}`.
//!
//! Finding #6: `Internal` no longer echoes its message to the client — raw
//! `sqlx`/CA-engine error text (schema/column names, query fragments,
//! filesystem paths from CA key I/O) is exactly what an attacker wants from
//! a 500. The real detail is always logged server-side at the point the
//! error is constructed (`ApiError::internal`, and the `From<X509Error>` /
//! `From<SshError>` impls below); the response body is a fixed generic
//! string.

use axum::Json;
use axum::extract::FromRequest;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// API-level errors carrying the v1 wire shapes.
#[derive(Debug)]
pub enum ApiError {
    /// 400 bare `{"error": msg}`.
    BadRequest(String),
    /// 400 validation form with structured details.
    Validation(Vec<serde_json::Value>),
    /// 404 bare `{"error": msg}`.
    NotFound(String),
    /// 501 bare `{"error": msg}` (v1 "not yet implemented" branches).
    NotImplemented(String),
    /// 503 bare `{"error": msg}` (manager/CA not initialized).
    ServiceUnavailable(String),
    /// 500 — v1 handlers return `{"error": str(e)}`; message preserved.
    Internal(String),
}

impl ApiError {
    /// Builds an internal error that logs its cause and echoes it (v1 returns
    /// `{"error": str(e)}` from the issuance/OCSP handlers).
    pub fn internal(context: &str, err: impl std::fmt::Display) -> Self {
        tracing::error!(error = %err, context, "pki internal error");
        ApiError::Internal(err.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            ApiError::BadRequest(msg) => {
                (StatusCode::BAD_REQUEST, serde_json::json!({ "error": msg }))
            }
            ApiError::Validation(details) => (
                StatusCode::BAD_REQUEST,
                serde_json::json!({ "error": "Validation error", "details": details }),
            ),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, serde_json::json!({ "error": msg })),
            ApiError::NotImplemented(msg) => (
                StatusCode::NOT_IMPLEMENTED,
                serde_json::json!({ "error": msg }),
            ),
            ApiError::ServiceUnavailable(msg) => (
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({ "error": msg }),
            ),
            // Finding #6: never echo `msg` (raw sqlx/CA-engine error text) to
            // the caller — it's already logged at construction time below.
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

impl From<crate::ca::x509::X509Error> for ApiError {
    fn from(e: crate::ca::x509::X509Error) -> Self {
        match e {
            crate::ca::x509::X509Error::BadRequest(m) => ApiError::BadRequest(m),
            crate::ca::x509::X509Error::Internal(m) => {
                tracing::error!(error = %m, "pki internal error (x509)");
                ApiError::Internal(m)
            }
        }
    }
}

impl From<crate::ca::ssh::SshError> for ApiError {
    fn from(e: crate::ca::ssh::SshError) -> Self {
        match e {
            crate::ca::ssh::SshError::BadRequest(m) => ApiError::BadRequest(m),
            crate::ca::ssh::SshError::Internal(m) => {
                tracing::error!(error = %m, "pki internal error (ssh)");
                ApiError::Internal(m)
            }
        }
    }
}

/// JSON body extractor with v1-shaped rejections: a missing/undecodable body
/// answers `400 {error: "Validation error", details: [...]}` like the v1
/// pydantic handlers, never axum's default 415/422 plain-text.
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, ApiError> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(ApiJson(value)),
            Err(rejection) => Err(ApiError::Validation(vec![serde_json::json!({
                "loc": [],
                "msg": rejection.body_text(),
                "type": "value_error",
            })])),
        }
    }
}

/// v1 Quart framework 404 body — served for unknown routes via the router
/// fallback (handler-raised 404s use the bare shape instead).
pub async fn fallback_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "Not Found",
            "detail": "404 Not Found: The requested URL was not found on the server. \
                       If you entered the URL manually please check your spelling and try again.",
        })),
    )
        .into_response()
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)] // tests fail loudly by design
mod tests {
    use super::*;

    /// Regression for finding #6: a 500 body must never contain the real
    /// internal error text, only the fixed generic message.
    #[tokio::test]
    async fn internal_error_body_never_leaks_the_cause() {
        let resp = ApiError::Internal(
            "duplicate key value violates unique constraint \"ca_keys_pkey\"".to_owned(),
        )
        .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = match axum::body::to_bytes(resp.into_body(), usize::MAX).await {
            Ok(b) => b,
            Err(e) => panic!("read body: {e}"),
        };
        let text = String::from_utf8_lossy(&body);
        assert!(!text.contains("duplicate key"));
        assert!(!text.contains("ca_keys_pkey"));

        let json: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => panic!("body not JSON: {e}"),
        };
        assert_eq!(json["error"], "Internal Server Error");
    }

    #[test]
    fn x509_internal_error_converts_without_altering_the_logged_message() {
        let err: ApiError = crate::ca::x509::X509Error::Internal("boom".to_owned()).into();
        match err {
            ApiError::Internal(m) => assert_eq!(m, "boom"),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn ssh_internal_error_converts_without_altering_the_logged_message() {
        let err: ApiError = crate::ca::ssh::SshError::Internal("boom".to_owned()).into();
        match err {
            ApiError::Internal(m) => assert_eq!(m, "boom"),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn service_unavailable_answers_503_with_the_given_message() {
        let resp = ApiError::ServiceUnavailable("CA not initialized".into()).into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = match axum::body::to_bytes(resp.into_body(), usize::MAX).await {
            Ok(b) => b,
            Err(e) => panic!("read body: {e}"),
        };
        let json: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => panic!("body not JSON: {e}"),
        };
        assert_eq!(json["error"], "CA not initialized");
    }

    #[tokio::test]
    async fn fallback_not_found_answers_the_v1_quart_framework_404_shape() {
        let resp = fallback_not_found().await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = match axum::body::to_bytes(resp.into_body(), usize::MAX).await {
            Ok(b) => b,
            Err(e) => panic!("read body: {e}"),
        };
        let json: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => panic!("body not JSON: {e}"),
        };
        assert_eq!(json["error"], "Not Found");
        assert!(json["detail"].as_str().unwrap().contains("404 Not Found"));
    }
}
