//! API error bodies matching house conventions (see the manager's `error.rs`).
//!
//! Handler-raised errors render bare `{"error": msg}` objects (as the v1
//! pki ssh.py handlers did via `jsonify({"error": ...})`); validation
//! failures render `{"error": "Validation error", "details": [...]}`; the
//! unknown-route fallback renders the enveloped `{error, detail}` 404 shape.
//! Internal errors never leak their cause (v1 ssh.py returned `str(e)` — a
//! deliberate deviation hardened here for a key-holding service).

use axum::Json;
use axum::extract::FromRequest;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// API-level errors carrying the house wire shapes.
#[derive(Debug)]
pub enum ApiError {
    /// 400 bare `{"error": msg}`.
    BadRequest(String),
    /// 400 validation form with structured details.
    Validation(Vec<serde_json::Value>),
    /// 404 bare `{"error": msg}`.
    NotFound(String),
    /// 500 — cause logged, never leaked to the client.
    Internal,
}

impl ApiError {
    /// Internal error that logs its cause under a context label.
    pub fn internal(context: &str, err: impl std::fmt::Display) -> Self {
        tracing::error!(error = %err, context, "internal error");
        ApiError::Internal
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
            ApiError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": "Internal Server Error" }),
            ),
        };
        (status, Json(body)).into_response()
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

/// Framework 404 body for unknown routes (matches the manager fallback).
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
