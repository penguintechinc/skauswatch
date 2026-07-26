//! v1-parity API error bodies. Handler-raised errors in the Quart PKI service
//! are BARE `{"error": "<message>"}` objects; the enveloped
//! `{error, detail}` shape only comes from Quart's framework error handlers
//! (unknown-route 404 / uncaught 500). Validation failures answer
//! `400 {"error": "Validation error", "details": [...]}`.

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
            ApiError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": msg }),
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
            crate::ca::x509::X509Error::Internal(m) => ApiError::Internal(m),
        }
    }
}

impl From<crate::ca::ssh::SshError> for ApiError {
    fn from(e: crate::ca::ssh::SshError) -> Self {
        match e {
            crate::ca::ssh::SshError::BadRequest(m) => ApiError::BadRequest(m),
            crate::ca::ssh::SshError::Internal(m) => ApiError::Internal(m),
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
