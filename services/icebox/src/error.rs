//! v1-parity API error bodies. The v1 Quart handlers emit bare
//! `{"error": "<message>"}` objects for most errors; a couple of endpoints
//! (license/mek admin, license-gate 402) additionally carry a `detail`
//! field — see `icebox/services/flask-backend/api/v1/admin.py` and
//! `licensing/validator.py::license_middleware`.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// API-level errors carrying the v1 wire shapes.
#[derive(Debug)]
pub enum ApiError {
    /// 400 bare `{"error": msg}`.
    BadRequest(String),
    /// 401 bare `{"error": msg}`.
    Unauthorized(String),
    /// 403 bare `{"error": msg}`.
    Forbidden(String),
    /// 403 with `required`/`missing` scope lists (v1 `require_scope`).
    InsufficientScope {
        /// Scopes the endpoint required.
        required: Vec<String>,
        /// Subset of `required` the caller's token was missing.
        missing: Vec<String>,
    },
    /// 404 bare `{"error": msg}`.
    NotFound(String),
    /// 409 bare `{"error": msg}`.
    Conflict(String),
    /// 410 bare `{"error": msg}` (one-time secret already viewed/expired).
    Gone(String),
    /// 402 `{"error", "detail", "license_server"}` — v1 license-gate body.
    LicenseRequired {
        /// License server URL, echoed for operator convenience.
        license_server: String,
    },
    /// 500 — detail intentionally not leaked (matches the v1 500 handler).
    Internal,
}

impl ApiError {
    /// Convenience: internal error that logs its cause.
    pub fn internal(context: &str, err: impl std::fmt::Display) -> Self {
        tracing::error!(error = %err, context, "internal error");
        ApiError::Internal
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            ApiError::BadRequest(msg) => {
                (StatusCode::BAD_REQUEST, serde_json::json!({"error": msg}))
            }
            ApiError::Unauthorized(msg) => {
                (StatusCode::UNAUTHORIZED, serde_json::json!({"error": msg}))
            }
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, serde_json::json!({"error": msg})),
            ApiError::InsufficientScope { required, missing } => (
                StatusCode::FORBIDDEN,
                serde_json::json!({
                    "error": "Insufficient scope",
                    "required": required,
                    "missing": missing,
                }),
            ),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, serde_json::json!({"error": msg})),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, serde_json::json!({"error": msg})),
            ApiError::Gone(msg) => (StatusCode::GONE, serde_json::json!({"error": msg})),
            ApiError::LicenseRequired { license_server } => (
                StatusCode::PAYMENT_REQUIRED,
                serde_json::json!({
                    "error": "IceBox license required",
                    "detail": "Configure a valid license via the skauswatch.icebox PostHog flag",
                    "license_server": license_server,
                }),
            ),
            ApiError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"error": "Internal Server Error"}),
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

impl From<skauswatch_icebox::EnvelopeError> for ApiError {
    fn from(e: skauswatch_icebox::EnvelopeError) -> Self {
        ApiError::internal("envelope encryption", e)
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
