//! The OCI Distribution pull-through surface (`docs/v2-port/v2.1-depgate.md`
//! §1/§4, P1 scope). Implements the read-only subset a `docker pull`/OCI
//! client needs:
//!
//! - `GET /v2/` — version check
//! - `GET|HEAD /v2/{name}/manifests/{reference}`
//! - `GET|HEAD /v2/{name}/blobs/{digest}`
//! - `GET /v2/{name}/tags/list`
//!
//! **Intentionally unsupported (documented omission, not an oversight):**
//! push (`POST`/`PUT`/`PATCH` on any `/v2/...` path — this is a
//! pull-through cache only, see §2), the blob-upload session sub-resource,
//! OCI referrers (`/v2/{name}/referrers/{digest}`), and content-negotiation
//! nuances beyond the fixed `Accept` list `crate::upstream` sends. Also
//! deferred: the full OCI `{"errors":[{"code":...}]}` error envelope — every
//! error here uses this workspace's standard bare `{"error": msg}` shape
//! instead, consistent with every other REST surface in this repo.
//!
//! Every route (including the otherwise-anonymous `GET /v2/` version check)
//! sits behind the same `tenant_middleware` JWT requirement as the admin
//! API — see `src/routes/mod.rs`. A real `docker pull` therefore needs a
//! client capable of presenting a SkausWatch-issued bearer JWT as its
//! registry credential (e.g. a containerd `hosts.toml` bearer-token mirror
//! entry, or a thin credential helper); the full Docker-native
//! `docker login` challenge/token-exchange dance this would otherwise
//! require is out of scope for P1.

use axum::extract::{Path, State};
use axum::http::{Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use skauswatch_auth::TenantContext;

use crate::error::{ApiError, tenant_uuid};
use crate::oci_path::{self, OciRequest};
use crate::scanpipe::ResolvedArtifact;
use crate::state::AppState;

/// Router for the `/v2/*` OCI Distribution surface.
pub fn router() -> Router<AppState> {
    Router::new().route("/v2/", get(version_check)).route(
        "/v2/{*rest}",
        get(dispatch)
            .head(dispatch)
            .post(push_not_supported)
            .put(push_not_supported)
            .patch(push_not_supported)
            .delete(push_not_supported),
    )
}

async fn version_check(_tenant: TenantContext) -> impl IntoResponse {
    (
        StatusCode::OK,
        [("Docker-Distribution-API-Version", "registry/2.0")],
        "{}",
    )
}

async fn push_not_supported() -> ApiError {
    ApiError::MethodNotAllowed(
        "DepGate is a pull-through registry cache; push is not supported".to_owned(),
    )
}

/// Renders a resolved artifact as the HTTP response, honoring `HEAD` (empty
/// body, headers only — existence/digest checks never need the bytes).
fn artifact_response(method: &Method, artifact: ResolvedArtifact) -> Response {
    let digest_header = format!("sha256:{}", artifact.sha256);
    let len = artifact.bytes.len();
    let body = if *method == Method::HEAD {
        axum::body::Body::empty()
    } else {
        axum::body::Body::from(artifact.bytes)
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, artifact.content_type)
        .header(header::CONTENT_LENGTH, len)
        .header("Docker-Content-Digest", digest_header)
        .body(body)
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "failed to build artifact response");
            ApiError::internal("response", e).into_response()
        })
}

async fn dispatch(
    State(state): State<AppState>,
    tenant: TenantContext,
    method: Method,
    Path(rest): Path<String>,
) -> Result<Response, ApiError> {
    let tenant_id = tenant_uuid(&tenant.tenant)?;
    let parsed = oci_path::parse(&rest)
        .ok_or_else(|| ApiError::NotFound("unsupported or malformed OCI path".to_owned()))?;
    let pipeline = state.pipeline();

    match parsed {
        OciRequest::Manifest { name, reference } => {
            let artifact = pipeline
                .resolve_manifest(name, reference, tenant_id)
                .await?;
            Ok(artifact_response(&method, artifact))
        }
        OciRequest::Blob { name, digest } => {
            let artifact = pipeline.resolve_blob(name, digest, tenant_id).await?;
            Ok(artifact_response(&method, artifact))
        }
        OciRequest::TagsList { name } => {
            let body = pipeline.list_tags(name).await?;
            Ok((StatusCode::OK, Json(body)).into_response())
        }
    }
}
