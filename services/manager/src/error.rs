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

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::extract::FromRequest;

    async fn parts(resp: Response) -> (StatusCode, serde_json::Value) {
        let status = resp.status();
        let bytes = match to_bytes(resp.into_body(), usize::MAX).await {
            Ok(b) => b,
            Err(e) => panic!("body: {e}"),
        };
        let value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => panic!("non-JSON body: {e}"),
        };
        (status, value)
    }

    #[tokio::test]
    async fn bad_request_is_bare_400() {
        let (status, body) = parts(ApiError::BadRequest("bad".to_owned()).into_response()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, serde_json::json!({"error": "bad"}));
    }

    #[tokio::test]
    async fn validation_is_400_with_details() {
        let details = vec![serde_json::json!({"loc": ["x"], "msg": "m", "type": "value_error"})];
        let (status, body) = parts(ApiError::Validation(details.clone()).into_response()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body,
            serde_json::json!({"error": "Validation error", "details": details})
        );
    }

    #[tokio::test]
    async fn unauthorized_is_bare_401() {
        let (status, body) = parts(ApiError::Unauthorized("nope".to_owned()).into_response()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, serde_json::json!({"error": "nope"}));
    }

    #[tokio::test]
    async fn forbidden_is_bare_403() {
        let (status, body) = parts(ApiError::Forbidden("no".to_owned()).into_response()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, serde_json::json!({"error": "no"}));
    }

    #[tokio::test]
    async fn not_found_is_bare_404() {
        let (status, body) = parts(ApiError::NotFound("missing".to_owned()).into_response()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, serde_json::json!({"error": "missing"}));
    }

    #[tokio::test]
    async fn conflict_passes_custom_body_through() {
        let payload = serde_json::json!({"error": "dup", "existing_id": 7});
        let (status, body) = parts(ApiError::Conflict(payload.clone()).into_response()).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, payload);
    }

    #[tokio::test]
    async fn internal_never_leaks_detail() {
        let (status, body) = parts(ApiError::Internal.into_response()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, serde_json::json!({"error": "Internal Server Error"}));
    }

    #[test]
    fn internal_helper_logs_and_maps_to_internal() {
        match ApiError::internal("ctx", "boom") {
            ApiError::Internal => {}
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn sqlx_error_maps_to_internal() {
        let e: ApiError = sqlx::Error::RowNotFound.into();
        match e {
            ApiError::Internal => {}
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fallback_not_found_matches_v1_quart_body() {
        let (status, body) = parts(fallback_not_found().await).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "Not Found");
        assert!(
            body["detail"]
                .as_str()
                .unwrap_or_default()
                .starts_with("404 Not Found:")
        );
    }

    #[derive(serde::Deserialize, Debug)]
    struct Ping {
        #[allow(dead_code)]
        ok: bool,
    }

    #[tokio::test]
    async fn api_json_rejects_malformed_body_as_validation_envelope() {
        let req = axum::http::Request::builder()
            .method("POST")
            .header("content-type", "application/json")
            .body(axum::body::Body::from("not json"))
            .unwrap_or_else(|e| panic!("request: {e}"));
        let err = match ApiJson::<Ping>::from_request(req, &()).await {
            Err(e) => e,
            Ok(_) => panic!("malformed body must be rejected"),
        };
        match err {
            ApiError::Validation(details) => {
                assert_eq!(details[0]["type"], "value_error");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn api_json_accepts_valid_body() {
        let req = axum::http::Request::builder()
            .method("POST")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(r#"{"ok":true}"#))
            .unwrap_or_else(|e| panic!("request: {e}"));
        let ApiJson(ping) = match ApiJson::<Ping>::from_request(req, &()).await {
            Ok(p) => p,
            Err(e) => panic!("expected ok, got {e:?}"),
        };
        assert!(ping.ok);
    }
}
