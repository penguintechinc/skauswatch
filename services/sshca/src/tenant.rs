//! Tenant provenance for this service (`docs/v2-port/tenancy-model.md`
//! §3), matching pki's `crate::tenant` module. sshca has no local user
//! database and mints no JWTs of its own — the bearer token verified by
//! `skauswatch_auth::AuthenticatedCaller` carries `ServiceClaims`, a
//! caller-identity shape that cannot carry a `tenant` claim. Tenant instead
//! travels as the `X-Tenant-ID` REST header, stamped by the calling
//! service (manager) — never accepted from an end-client-controlled field.
//!
//! sshca holds an SSH CA signing key and keeps its issued-certificate
//! store in memory (`crate::store::CertStore`) rather than a database, but
//! the isolation contract is identical: a request without a present,
//! well-formed tenant UUID is rejected before touching the CA or the store
//! at all.

use axum::Json;
use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

/// REST header carrying the caller's tenant (stamped by the calling
/// service — manager — never the end client).
pub const TENANT_HEADER: &str = "x-tenant-id";

/// A validated tenant identifier for the current request. The only
/// legitimate source is [`TENANT_HEADER`] via the `FromRequestParts` impl
/// below — never a path/body value the end client controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantId(pub Uuid);

/// The request carried no usable `X-Tenant-ID` header (absent, empty, or
/// not a well-formed UUID).
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
#[error("missing or invalid X-Tenant-ID header")]
pub struct TenantHeaderError;

impl IntoResponse for TenantHeaderError {
    fn into_response(self) -> Response {
        (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

fn parse_tenant(raw: Option<&str>) -> Option<Uuid> {
    raw.map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| Uuid::parse_str(s).ok())
}

impl<S> FromRequestParts<S> for TenantId
where
    S: Send + Sync,
{
    type Rejection = TenantHeaderError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parse_tenant(
            parts
                .headers
                .get(TENANT_HEADER)
                .and_then(|v| v.to_str().ok()),
        )
        .map(TenantId)
        .ok_or(TenantHeaderError)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use axum::body::Body;
    use axum::http::Request;

    use super::*;

    async fn parts_with_header(value: Option<&str>) -> Parts {
        let mut builder = Request::builder().uri("/x");
        if let Some(v) = value {
            builder = builder.header(TENANT_HEADER, v);
        }
        let (parts, _body) = builder
            .body(Body::empty())
            .unwrap_or_else(|e| panic!("request: {e}"))
            .into_parts();
        parts
    }

    #[tokio::test]
    async fn valid_header_extracts_tenant() {
        let id = Uuid::new_v4();
        let mut parts = parts_with_header(Some(&id.to_string())).await;
        let TenantId(got) = TenantId::from_request_parts(&mut parts, &())
            .await
            .unwrap_or_else(|e| panic!("extract: {e}"));
        assert_eq!(got, id);
    }

    #[tokio::test]
    async fn missing_header_is_rejected() {
        let mut parts = parts_with_header(None).await;
        assert!(TenantId::from_request_parts(&mut parts, &()).await.is_err());
    }

    #[tokio::test]
    async fn empty_header_is_rejected() {
        let mut parts = parts_with_header(Some("   ")).await;
        assert!(TenantId::from_request_parts(&mut parts, &()).await.is_err());
    }

    #[tokio::test]
    async fn malformed_header_is_rejected() {
        let mut parts = parts_with_header(Some("not-a-uuid")).await;
        assert!(TenantId::from_request_parts(&mut parts, &()).await.is_err());
    }

    #[test]
    fn tenant_header_error_renders_403() {
        let resp = TenantHeaderError.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
