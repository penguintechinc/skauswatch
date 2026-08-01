//! Tenant provenance for this service (`docs/v2-port/tenancy-model.md`
//! §3). pki has no local user database and mints no JWTs of its own — the
//! bearer token verified by `skauswatch_auth::AuthenticatedCaller` carries
//! `ServiceClaims`, a caller-identity shape that is structurally incapable
//! of carrying a `tenant` claim (see that type's docs). Tenant instead
//! travels as a value the *calling* service (manager) stamps onto the
//! request on manager's behalf: the `X-Tenant-ID` REST header / the
//! identically-named `x-tenant-id` gRPC metadata entry.
//!
//! This is safe only because the value is never accepted from an
//! end-client-controlled field — manager derives it from its own validated
//! `Claims.tenant` and stamps it here; pki/sshca simply trust their
//! upstream caller the same way they already trust the shared JWT secret.
//! A request/RPC without a present, well-formed UUID is rejected before
//! touching any certificate table: this is a certificate authority, so
//! cross-tenant issuance or visibility is a severe-impact bug, not a
//! cosmetic one.

use axum::Json;
use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

/// REST header / gRPC metadata key carrying the caller's tenant (stamped by
/// the calling service — manager — never the end client).
pub const TENANT_HEADER: &str = "x-tenant-id";

/// A validated tenant identifier for the current request/RPC. The only
/// legitimate source is [`TENANT_HEADER`] (REST, via the `FromRequestParts`
/// impl below) or the identically-named gRPC metadata entry (via
/// [`tenant_from_metadata`]) — never a path/body value the end client
/// controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantId(pub Uuid);

impl TenantId {
    /// Borrows the tenant id, e.g. for use as a query bind value.
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

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

/// Parses a raw header/metadata value into a tenant UUID, treating an
/// absent, blank, or malformed value uniformly as "no usable tenant".
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

/// gRPC counterpart of [`TenantId`]: reads the `x-tenant-id` metadata entry
/// stamped by the calling service, rejecting with `UNAUTHENTICATED` when
/// absent, empty, or not a well-formed UUID — mirrors
/// `skauswatch_auth::verify_grpc_bearer`'s metadata-extraction shape.
pub fn tenant_from_metadata(
    metadata: &tonic::metadata::MetadataMap,
) -> Result<Uuid, tonic::Status> {
    parse_tenant(metadata.get(TENANT_HEADER).and_then(|v| v.to_str().ok()))
        .ok_or_else(|| tonic::Status::unauthenticated("missing or invalid x-tenant-id metadata"))
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

    #[test]
    fn tenant_from_metadata_accepts_valid_and_rejects_missing_or_bad() {
        let id = Uuid::new_v4();
        let mut md = tonic::metadata::MetadataMap::new();
        md.insert(
            TENANT_HEADER,
            id.to_string()
                .parse()
                .unwrap_or_else(|e| panic!("meta: {e}")),
        );
        assert_eq!(
            tenant_from_metadata(&md).unwrap_or_else(|e| panic!("expected ok: {e}")),
            id
        );

        let empty = tonic::metadata::MetadataMap::new();
        assert!(tenant_from_metadata(&empty).is_err());

        let mut bad = tonic::metadata::MetadataMap::new();
        bad.insert(
            TENANT_HEADER,
            "not-a-uuid".parse().unwrap_or_else(|e| panic!("meta: {e}")),
        );
        assert!(tenant_from_metadata(&bad).is_err());
    }
}
