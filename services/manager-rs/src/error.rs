//! v1-parity API error bodies. Handler-raised errors in the Quart manager
//! are BARE `{"error": "<message>"}` objects (each handler calls
//! `jsonify({"error": ...})` directly); the enveloped
//! `{error: "<Title>", detail}` shape only comes from Quart's registered
//! errorhandlers (framework-level 404/500 etc.). Verified against live v1
//! by the golden parity harness (tests/parity) — see the contract's
//! "Error body shapes" note.

use axum::Json;
use axum::extract::FromRequest;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// API-level errors carrying the v1 wire shapes.
#[derive(Debug)]
#[allow(dead_code)] // remaining variants consumed as routers land
pub enum ApiError {
    /// 400 bare `{"error": msg}`.
    BadRequest(String),
    /// 400 validation form with structured details.
    Validation(Vec<serde_json::Value>),
    /// 401 bare `{"error": msg}`.
    Unauthorized(String),
    /// 403 bare `{"error": msg}`.
    Forbidden(String),
    /// 404 bare `{"error": msg}`.
    NotFound(String),
    /// 409 with a custom payload (v1 conflict bodies vary per router).
    Conflict(serde_json::Value),
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

/// JSON body extractor with v1-shaped rejections: a missing/undecodable
/// body answers 400 `{error: "Validation error", details: [...]}` like the
/// v1 pydantic handlers, never axum's default 415/422 plain-text.
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
