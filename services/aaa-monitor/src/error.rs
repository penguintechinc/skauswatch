//! House API error envelope: `{"error": "<category>", "detail": "<message>"}`
//! on every non-2xx response. 500s never leak the underlying cause in
//! `detail` (security.md: "errors must not leak internals") — the real
//! error is logged via `tracing::error!` and the client sees a generic
//! message.

use axum::Json;
use axum::extract::FromRequest;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// API-level errors carrying the house envelope shape.
#[derive(Debug)]
pub enum ApiError {
    /// 400 — malformed/invalid request input.
    BadRequest(String),
    /// 401 — missing, malformed, or expired credentials.
    Unauthorized(String),
    /// 403 — authenticated but not permitted, or a required claim is
    /// missing (e.g. tenant).
    Forbidden(String),
    /// 404 — resource not found.
    NotFound(String),
    /// 503 — a required backend (ES/Mongo) is not configured/reachable.
    ServiceUnavailable(String),
    /// 500 — unexpected failure; cause is logged, never returned.
    Internal,
}

impl ApiError {
    /// Builds an [`ApiError::Internal`], logging `err` with `context` so the
    /// cause is diagnosable server-side without being exposed to the caller.
    pub fn internal(context: &str, err: impl std::fmt::Display) -> Self {
        tracing::error!(error = %err, context, "internal error");
        ApiError::Internal
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error, detail) = match self {
            ApiError::BadRequest(detail) => (StatusCode::BAD_REQUEST, "Bad Request", detail),
            ApiError::Unauthorized(detail) => (StatusCode::UNAUTHORIZED, "Unauthorized", detail),
            ApiError::Forbidden(detail) => (StatusCode::FORBIDDEN, "Forbidden", detail),
            ApiError::NotFound(detail) => (StatusCode::NOT_FOUND, "Not Found", detail),
            ApiError::ServiceUnavailable(detail) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Service Unavailable",
                detail,
            ),
            ApiError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "an internal error occurred".to_owned(),
            ),
        };
        (
            status,
            Json(serde_json::json!({"error": error, "detail": detail})),
        )
            .into_response()
    }
}

/// JSON body extractor with the house envelope on rejection: a missing or
/// undecodable body answers 400 instead of axum's default plain-text.
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
            Err(rejection) => Err(ApiError::BadRequest(rejection.body_text())),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = match to_bytes(resp.into_body(), usize::MAX).await {
            Ok(b) => b,
            Err(e) => panic!("read body: {e}"),
        };
        match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => panic!("parse body: {e}"),
        }
    }

    #[tokio::test]
    async fn internal_error_never_leaks_the_cause() {
        let err = ApiError::internal("mongo query", "connection refused: 10.0.0.5:27017");
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "Internal Server Error");
        assert_eq!(body["detail"], "an internal error occurred");
        assert!(!body["detail"].to_string().contains("10.0.0.5"));
    }

    #[tokio::test]
    async fn envelope_shape_matches_error_and_detail_keys() {
        let resp = ApiError::NotFound("event not found".to_owned()).into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "Not Found");
        assert_eq!(body["detail"], "event not found");
    }
}
