//! API error bodies for /api/v1/darwin and /api/v1/credentials. Follows the
//! house convention proven by `services/manager/src/error.rs`: handler-raised
//! errors are bare `{"error": "<message>"}` objects; only the framework-level
//! 404 fallback carries the two-key `{error, detail}` shape.

use axum::Json;
use axum::extract::FromRequest;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// API-level errors carrying the house wire shapes.
#[derive(Debug)]
#[allow(dead_code)] // BadRequest is part of the shared envelope; not every route needs it yet
pub enum ApiError {
    /// 400 bare `{"error": msg}`.
    BadRequest(String),
    /// 400 validation form with structured details (mirrors `ApiJson`
    /// rejections and per-field validation failures).
    Validation(Vec<serde_json::Value>),
    /// 401 bare `{"error": msg}`.
    Unauthorized(String),
    /// 403 bare `{"error": msg}`.
    Forbidden(String),
    /// 404 bare `{"error": msg}`.
    NotFound(String),
    /// 409 with a custom payload.
    Conflict(serde_json::Value),
    /// 500 — detail intentionally not leaked; the cause is logged instead.
    Internal,
}

impl ApiError {
    /// Convenience: internal error that logs its cause before returning the
    /// opaque 500 body.
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
            ApiError::Validation(details) => (
                StatusCode::BAD_REQUEST,
                serde_json::json!({"error": "Validation error", "details": details}),
            ),
            ApiError::Unauthorized(msg) => {
                (StatusCode::UNAUTHORIZED, serde_json::json!({"error": msg}))
            }
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, serde_json::json!({"error": msg})),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, serde_json::json!({"error": msg})),
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

/// JSON body extractor with house-shaped rejections: a missing/undecodable
/// body answers 400 `{error: "Validation error", details: [...]}` rather than
/// axum's default 415/422 plain-text.
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

/// 404 fallback for unmatched routes — the only place the `{error, detail}`
/// two-key envelope is used, matching the manager's framework-level shape.
pub async fn fallback_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "Not Found",
            "detail": "The requested URL was not found on the server.",
        })),
    )
        .into_response()
}
