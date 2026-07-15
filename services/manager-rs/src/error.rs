//! v1-parity API error envelope. Shapes match the Quart error handlers:
//! `{error: "<Title>", detail: "..."}` plus the validation form
//! `{error: "Validation error", details: [...]}`.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// API-level errors carrying the v1 wire shapes.
#[derive(Debug)]
#[allow(dead_code)] // remaining variants consumed as routers land
pub enum ApiError {
    /// 400 with detail.
    BadRequest(String),
    /// 400 validation form with structured details.
    Validation(Vec<serde_json::Value>),
    /// 401 with detail.
    Unauthorized(String),
    /// 403 with detail.
    Forbidden(String),
    /// 404 with detail.
    NotFound(String),
    /// 409 with a custom payload (v1 conflict bodies vary per router).
    Conflict(serde_json::Value),
    /// 500 — detail intentionally not leaked.
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
            ApiError::BadRequest(detail) => (
                StatusCode::BAD_REQUEST,
                serde_json::json!({"error": "Bad Request", "detail": detail}),
            ),
            ApiError::Validation(details) => (
                StatusCode::BAD_REQUEST,
                serde_json::json!({"error": "Validation error", "details": details}),
            ),
            ApiError::Unauthorized(detail) => (
                StatusCode::UNAUTHORIZED,
                serde_json::json!({"error": "Unauthorized", "detail": detail}),
            ),
            ApiError::Forbidden(detail) => (
                StatusCode::FORBIDDEN,
                serde_json::json!({"error": "Forbidden", "detail": detail}),
            ),
            ApiError::NotFound(detail) => (
                StatusCode::NOT_FOUND,
                serde_json::json!({"error": "Not Found", "detail": detail}),
            ),
            ApiError::Conflict(body) => (StatusCode::CONFLICT, body),
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
