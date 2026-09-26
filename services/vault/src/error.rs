//! v1-parity API error bodies. The v1 Quart handlers emit bare
//! `{"error": "<message>"}` objects for most errors; a couple of endpoints
//! (license/mek admin, license-gate 402) additionally carry a `detail`
//! field — see `icebox/services/flask-backend/api/v1/admin.py` and
//! `licensing/validator.py::license_middleware`.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Documentation-only mirror of `ApiError`'s bare `{"error": msg}` wire
/// shape (`BadRequest`/`Unauthorized`/`Forbidden`/`NotFound`/`Conflict`/
/// `Gone` all use it) — `ApiError` itself builds its body with
/// `serde_json::json!` rather than a typed struct, so this type exists
/// solely to give `utoipa` something to reference in `#[utoipa::path]`
/// `responses(...)` clauses.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ErrorResponse {
    /// Human-readable error message.
    pub error: String,
}

/// Documentation-only mirror of `ApiError::InsufficientScope`'s wire shape.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct InsufficientScopeResponse {
    /// Always `"Insufficient scope"`.
    pub error: String,
    /// Scopes the endpoint required.
    pub required: Vec<String>,
    /// Subset of `required` the caller's token was missing.
    pub missing: Vec<String>,
}

/// Documentation-only mirror of `ApiError::LicenseRequired`'s wire shape.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct LicenseRequiredResponse {
    /// Always `"Vault license required"`.
    pub error: String,
    /// Operator-facing remediation hint.
    pub detail: String,
    /// License server URL, echoed for operator convenience.
    pub license_server: String,
}

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
                    "error": "Vault license required",
                    "detail": "Configure a valid license via the skauswatch.vault PostHog flag",
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

impl From<skauswatch_vault::EnvelopeError> for ApiError {
    fn from(e: skauswatch_vault::EnvelopeError) -> Self {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use axum::body::to_bytes;

    use super::*;

    async fn body_json(resp: Response) -> serde_json::Value {
        let status_ok_to_read = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap_or_else(|e| panic!("read body ({status_ok_to_read}): {e}"));
        serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse json: {e}"))
    }

    #[tokio::test]
    async fn bad_request_maps_to_400_bare_body() {
        let resp = ApiError::BadRequest("bad".to_owned()).into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp).await, serde_json::json!({"error": "bad"}));
    }

    #[tokio::test]
    async fn unauthorized_maps_to_401_bare_body() {
        let resp = ApiError::Unauthorized("nope".to_owned()).into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_json(resp).await, serde_json::json!({"error": "nope"}));
    }

    #[tokio::test]
    async fn forbidden_maps_to_403_bare_body() {
        let resp = ApiError::Forbidden("no".to_owned()).into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(body_json(resp).await, serde_json::json!({"error": "no"}));
    }

    #[tokio::test]
    async fn insufficient_scope_maps_to_403_with_required_and_missing() {
        let resp = ApiError::InsufficientScope {
            required: vec!["secrets:read".to_owned()],
            missing: vec!["secrets:read".to_owned()],
        }
        .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "Insufficient scope");
        assert_eq!(body["required"], serde_json::json!(["secrets:read"]));
        assert_eq!(body["missing"], serde_json::json!(["secrets:read"]));
    }

    #[tokio::test]
    async fn not_found_maps_to_404_bare_body() {
        let resp = ApiError::NotFound("gone".to_owned()).into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(body_json(resp).await, serde_json::json!({"error": "gone"}));
    }

    #[tokio::test]
    async fn conflict_maps_to_409_bare_body() {
        let resp = ApiError::Conflict("dup".to_owned()).into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(body_json(resp).await, serde_json::json!({"error": "dup"}));
    }

    #[tokio::test]
    async fn gone_maps_to_410_bare_body() {
        let resp = ApiError::Gone("expired".to_owned()).into_response();
        assert_eq!(resp.status(), StatusCode::GONE);
        assert_eq!(
            body_json(resp).await,
            serde_json::json!({"error": "expired"})
        );
    }

    #[tokio::test]
    async fn license_required_maps_to_402_with_license_server() {
        let resp = ApiError::LicenseRequired {
            license_server: "https://license.penguintech.io".to_owned(),
        }
        .into_response();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "Vault license required");
        assert_eq!(body["license_server"], "https://license.penguintech.io");
        assert!(body.get("detail").is_some());
    }

    #[tokio::test]
    async fn internal_maps_to_500_without_leaking_detail() {
        let resp = ApiError::Internal.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_json(resp).await;
        assert_eq!(body, serde_json::json!({"error": "Internal Server Error"}));
    }

    #[tokio::test]
    async fn fallback_not_found_matches_v1_quart_shape() {
        let resp = fallback_not_found().await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "Not Found");
        assert!(
            body["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("404 Not Found")
        );
    }

    #[test]
    fn internal_helper_logs_and_returns_internal_variant() {
        assert!(matches!(
            ApiError::internal("context", "boom"),
            ApiError::Internal
        ));
    }

    #[test]
    fn sqlx_error_converts_to_internal() {
        let err: ApiError = sqlx::Error::RowNotFound.into();
        assert!(matches!(err, ApiError::Internal));
    }

    #[test]
    fn envelope_error_converts_to_internal() {
        let err: ApiError = skauswatch_vault::EnvelopeError::MekVersionNotLoaded(1).into();
        assert!(matches!(err, ApiError::Internal));
    }
}
