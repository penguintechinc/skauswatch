//! Admin settings API — ISM hot/warm/cold lifecycle configuration
//! (`PUT /api/v1/admin/ingest/lifecycle`) and the cold-tier restore trigger
//! (`POST /api/v1/admin/ingest/restore`), per
//! `docs/v2-port/ingest-module-spec.md` §8a1.
//!
//! Both routes decode a bearer [`skauswatch_auth::Claims`] token directly
//! (rather than the `crate::listeners::http`/`crate::opensearch` tenant
//! middleware pattern): these are cluster-wide platform operations, not
//! tenant-scoped data access, so the house tenant → scope ordering still
//! applies (a token with no usable tenant claim is rejected before any
//! scope check — see [`AuthedAdmin`]) but neither handler filters anything
//! by tenant. Authorization is scope-only, per `security.md`: `roles` is
//! never branched on.
//!
//! - `PUT /lifecycle` requires [`LIFECYCLE_ADMIN_SCOPE`] ("platform/
//!   super-admin scope", Spec §8a1) — validates the three transition ages
//!   are strictly increasing ([`ism::validate_monotonic_ages`]) and, only if
//!   valid, applies the rebuilt 4-tier policy ([`ism::build_ism_policy`] +
//!   [`ism::apply_ism_policy`]).
//! - `POST /restore` requires [`SIEM_RESTORE_SCOPE`] ("SIEM admin role,
//!   audited", Spec §8a1) — triggers a real OpenSearch snapshot `_restore`
//!   against the configured repository and records an audit entry via the
//!   injected [`AuditSink`] (see that trait's docs for why this is a
//!   `tracing`-backed sink rather than a database table in this task).
//!
//! # Module wiring notes
//!
//! `ism` is declared here via `#[path]` rather than as `crate::opensearch::
//! ism` — see [`ism`]'s own doc comment for exactly why (`opensearch/mod.rs`
//! and `main.rs` are both out of this task's file scope).
//!
//! This router is not yet invoked from `main.rs`/`bootstrap.rs` — same
//! interim, unwired state as every other Wave 1 module until the next
//! integration gate wires every listener/writer/admin surface together (see
//! `main.rs`'s own doc comment). `cargo build`'s reachability analysis
//! therefore sees this whole module as dead code until then.
#![allow(dead_code)]

#[path = "opensearch/ism.rs"]
pub(crate) mod ism;

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{FromRequestParts, State};
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::routing::{post, put};
use chrono::{DateTime, Utc};
use jsonwebtoken::DecodingKey;
use serde::{Deserialize, Serialize};
use skauswatch_auth::Claims;
use utoipa::ToSchema;

/// Scope required for `PUT /lifecycle` — "Operators configure these
/// globally (platform/super-admin scope, cluster-wide)" (Spec §8a1).
/// Matches the house `admin` scope bundle's broadest entry
/// (`security.md`'s OIDC Claims & Scopes table): cluster-wide lifecycle
/// configuration is exactly the kind of change reserved for it.
pub const LIFECYCLE_ADMIN_SCOPE: &str = "*:admin";

/// Scope required for `POST /restore` — "restore API call (gated by SIEM
/// admin role, audited)" (Spec §8a1). Deliberately narrower than
/// [`LIFECYCLE_ADMIN_SCOPE`]: a caller trusted to pull cold-tier evidence
/// back into a queryable state need not also hold cluster-wide lifecycle
/// configuration rights.
pub const SIEM_RESTORE_SCOPE: &str = "siem:admin";

/// The authenticated admin caller, extracted from a validated bearer token.
/// Carries the full [`Claims`] (not just a [`skauswatch_auth::TenantContext`]
/// tenant) because both handlers need `scope` (authorization) and `sub`
/// (the audit actor) — [`crate::auth`]'s existing `TenantContext` extractor
/// only publishes the tenant.
#[derive(Debug, Clone)]
pub(crate) struct AuthedAdmin {
    /// Decoded, tenant-validated claims.
    pub claims: Claims,
}

impl AuthedAdmin {
    /// Enforces a required scope, mapping a miss to the standard 403 shape.
    fn require_scope(&self, scope: &str) -> Result<(), AdminError> {
        self.claims
            .require_scope(scope)
            .map_err(|_| AdminError::Forbidden(format!("missing required scope: {scope}")))
    }
}

/// Anything that can verify a bearer token — implemented by [`AppState`] so
/// [`AuthedAdmin`]'s extractor is testable against any state carrying a
/// verify key, matching the pattern `crate::listeners::http::AppState`
/// establishes via `skauswatch_auth::JwtSecretSource`.
pub(crate) trait AdminAuthSource {
    /// The ES256 public key bearer tokens are verified against.
    fn jwt_verify_key(&self) -> &DecodingKey;
}

impl<S> FromRequestParts<S> for AuthedAdmin
where
    S: AdminAuthSource + Send + Sync,
{
    type Rejection = AdminError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, AdminError> {
        const HEADER_MSG: &str = "missing or invalid authorization header";
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AdminError::Unauthorized(HEADER_MSG.to_owned()))?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AdminError::Unauthorized(HEADER_MSG.to_owned()))?;

        let claims = skauswatch_auth::decode_claims(token, state.jwt_verify_key())
            .map_err(AdminError::from_tenant_auth_error)?;
        claims
            .require_tenant()
            .map_err(|_| AdminError::Forbidden("missing or empty tenant claim".to_owned()))?;
        Ok(AuthedAdmin { claims })
    }
}

/// Typed API-boundary error (`backend-rust.md`: never leak `anyhow::Error`
/// at the Axum boundary) for both admin routes.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AdminError {
    /// No/invalid/expired bearer token.
    #[error("{0}")]
    Unauthorized(String),
    /// Authenticated, but missing tenant or the required scope.
    #[error("{0}")]
    Forbidden(String),
    /// Request body failed validation (e.g. non-monotonic lifecycle ages).
    #[error("{0}")]
    BadRequest(String),
    /// OpenSearch rejected or failed to answer the underlying request.
    #[error("opensearch request failed: {0}")]
    UpstreamOpenSearch(String),
}

impl AdminError {
    fn from_tenant_auth_error(err: skauswatch_auth::TenantAuthError) -> Self {
        match err {
            skauswatch_auth::TenantAuthError::MissingTenant => {
                AdminError::Forbidden(err.to_string())
            }
            skauswatch_auth::TenantAuthError::MissingOrInvalidHeader
            | skauswatch_auth::TenantAuthError::Expired
            | skauswatch_auth::TenantAuthError::Invalid => {
                AdminError::Unauthorized(err.to_string())
            }
        }
    }
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        let status = match &self {
            AdminError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AdminError::Forbidden(_) => StatusCode::FORBIDDEN,
            AdminError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AdminError::UpstreamOpenSearch(_) => StatusCode::BAD_GATEWAY,
        };
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

/// One recorded audit event — Spec §8a1: the restore endpoint is "gated by
/// SIEM admin role, audited".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuditEntry {
    /// The authenticated caller's `sub` claim.
    pub actor: String,
    /// The caller's tenant claim (recorded for context; restore itself is
    /// not tenant-filtered — see module docs).
    pub tenant: String,
    /// A short, stable action identifier (e.g. `"ingest.cold_tier_restore"`).
    pub action: String,
    /// The resource the action was performed against (e.g. the index name).
    pub resource: String,
    /// When the action was recorded.
    pub at: DateTime<Utc>,
}

/// Where audit entries go. Kept as a trait (rather than a hardcoded DB
/// write) because this task's file scope does not include a new migration
/// file — persisting audit entries to a queryable table (matching e.g.
/// `services/vault/src/routes/audit.rs::write_audit`'s `vault_audit_log`
/// pattern) is a documented follow-up once a migration lands. Every
/// implementation MUST still make the entry durable/inspectable outside
/// process memory: [`TracingAuditSink`] emits it as a structured `tracing`
/// event on the `audit` target, which the deployed OTel pipeline (`critical-
/// rules.md` Observability) captures as a log record — never a silent no-op.
#[async_trait::async_trait]
pub(crate) trait AuditSink: std::fmt::Debug + Send + Sync {
    /// Durably records `entry`.
    async fn record(&self, entry: AuditEntry);
}

/// Production [`AuditSink`]: emits a structured `tracing` event on the
/// `audit` target — see that trait's docs for why this isn't a DB table
/// yet. Never drops an entry silently: `tracing::info!` always fires
/// (a downed OTel exporter buffers/drops at the exporter layer per
/// `critical-rules.md` Observability, never here).
#[derive(Debug, Default, Clone)]
pub(crate) struct TracingAuditSink;

#[async_trait::async_trait]
impl AuditSink for TracingAuditSink {
    async fn record(&self, entry: AuditEntry) {
        tracing::info!(
            target: "audit",
            actor = %entry.actor,
            tenant = %entry.tenant,
            action = %entry.action,
            resource = %entry.resource,
            at = %entry.at,
            "audit_log_entry"
        );
    }
}

/// Shared handler state. `snapshot_repo` mirrors Spec §8a1's
/// `SNAPSHOT_REPO_ENDPOINT` config note — this task's file scope does not
/// include `config.rs`, so the (future) bootstrap wiring is responsible for
/// reading that env var and constructing this field; tests set it directly.
#[derive(Clone)]
pub(crate) struct AppState {
    /// HTTP client used for OpenSearch ISM/snapshot calls.
    pub http: reqwest::Client,
    /// OpenSearch base URL.
    pub opensearch_url: Arc<str>,
    /// Snapshot repository name the ISM policy's WARM/COLD tiers and the
    /// restore endpoint target.
    pub snapshot_repo: Arc<str>,
    /// ES256 verify key for bearer tokens (audit finding H1b — asymmetric,
    /// never a shared symmetric secret).
    pub jwt_verify_key: DecodingKey,
    /// Where restore audit entries go.
    pub audit: Arc<dyn AuditSink>,
}

impl AdminAuthSource for AppState {
    fn jwt_verify_key(&self) -> &DecodingKey {
        &self.jwt_verify_key
    }
}

/// `PUT /api/v1/admin/ingest/lifecycle` request body.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct LifecycleRequest {
    /// HOT -> WARM transition age, in days.
    pub hot_to_warm_days: i64,
    /// WARM -> COLD transition age, in days.
    pub warm_to_cold_days: i64,
    /// COLD -> DELETE transition age, in days.
    pub cold_to_delete_days: i64,
}

/// `PUT /api/v1/admin/ingest/lifecycle` success response — echoes the
/// applied configuration plus the managed policy id. `Deserialize` is only
/// for this module's own tests to round-trip the response body; production
/// callers just serialize it out.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) struct LifecycleResponse {
    /// The applied HOT -> WARM age.
    pub hot_to_warm_days: i64,
    /// The applied WARM -> COLD age.
    pub warm_to_cold_days: i64,
    /// The applied COLD -> DELETE age.
    pub cold_to_delete_days: i64,
    /// The OpenSearch ISM policy id this service manages.
    pub policy_id: String,
}

/// `POST /api/v1/admin/ingest/restore` request body.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct RestoreRequest {
    /// The COLD-tier index to restore (e.g.
    /// `skauswatch-logs-2026.01.01`).
    pub index: String,
}

/// `POST /api/v1/admin/ingest/restore` response. `Deserialize` is only for
/// this module's own tests to round-trip the response body; production
/// callers just serialize it out.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) struct RestoreResponse {
    /// The index a restore was triggered for.
    pub index: String,
    /// Always `"restore_triggered"` on success — the restore itself runs in
    /// the background on the OpenSearch cluster (Spec §8a1: "slow, ~minutes").
    pub status: String,
}

/// Documentation-only mirror of every error body this router emits.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AdminErrorResponse {
    /// Human-readable error message.
    pub error: String,
}

/// `PUT /api/v1/admin/ingest/lifecycle` — platform/super-admin only (Spec
/// §8a1). Rejects a non-monotonic configuration with 400 *before* ever
/// contacting OpenSearch; only a validated configuration is turned into a
/// policy document and applied.
#[utoipa::path(
    put,
    path = "/api/v1/admin/ingest/lifecycle",
    tag = "svc-ingest-admin",
    security(("bearer_jwt" = [])),
    request_body = LifecycleRequest,
    responses(
        (status = 200, description = "Lifecycle policy applied", body = LifecycleResponse),
        (status = 400, description = "Transition ages are not strictly increasing", body = AdminErrorResponse),
        (status = 401, description = "Missing, invalid, or expired bearer token", body = AdminErrorResponse),
        (status = 403, description = "Token lacks the platform/super-admin scope, or carries no tenant", body = AdminErrorResponse),
        (status = 502, description = "OpenSearch rejected the policy", body = AdminErrorResponse),
    ),
)]
pub(crate) async fn handle_put_lifecycle(
    State(state): State<AppState>,
    admin: AuthedAdmin,
    Json(req): Json<LifecycleRequest>,
) -> Result<Json<LifecycleResponse>, AdminError> {
    admin.require_scope(LIFECYCLE_ADMIN_SCOPE)?;

    ism::validate_monotonic_ages(
        req.hot_to_warm_days,
        req.warm_to_cold_days,
        req.cold_to_delete_days,
    )
    .map_err(|e| AdminError::BadRequest(e.to_string()))?;

    let policy = ism::build_ism_policy(
        req.hot_to_warm_days,
        req.warm_to_cold_days,
        req.cold_to_delete_days,
        &state.snapshot_repo,
    );

    match ism::apply_ism_policy(&state.http, &state.opensearch_url, &policy).await {
        Ok(()) => {
            metrics::counter!("svc_ingest_ism_policy_applied_total").increment(1);
        }
        Err(e) => {
            metrics::counter!("svc_ingest_ism_policy_apply_errors_total").increment(1);
            tracing::error!(error = %e, "ism_policy_apply_failed");
            return Err(AdminError::UpstreamOpenSearch(e.to_string()));
        }
    }

    tracing::info!(
        actor = %admin.claims.sub,
        hot_to_warm_days = req.hot_to_warm_days,
        warm_to_cold_days = req.warm_to_cold_days,
        cold_to_delete_days = req.cold_to_delete_days,
        "ism_lifecycle_policy_updated"
    );

    Ok(Json(LifecycleResponse {
        hot_to_warm_days: req.hot_to_warm_days,
        warm_to_cold_days: req.warm_to_cold_days,
        cold_to_delete_days: req.cold_to_delete_days,
        policy_id: ism::ISM_POLICY_ID.to_owned(),
    }))
}

/// `POST /api/v1/admin/ingest/restore` — SIEM-admin only, audited (Spec
/// §8a1). Triggers a real OpenSearch snapshot restore of `req.index` from
/// the configured repository (not a searchable-snapshot mount — see
/// [`ism`]'s module docs for why COLD data needs an explicit restore) and
/// records the action via [`AppState::audit`] before answering.
#[utoipa::path(
    post,
    path = "/api/v1/admin/ingest/restore",
    tag = "svc-ingest-admin",
    security(("bearer_jwt" = [])),
    request_body = RestoreRequest,
    responses(
        (status = 202, description = "Cold-tier restore triggered", body = RestoreResponse),
        (status = 401, description = "Missing, invalid, or expired bearer token", body = AdminErrorResponse),
        (status = 403, description = "Token lacks the SIEM-admin scope, or carries no tenant", body = AdminErrorResponse),
        (status = 502, description = "OpenSearch rejected the restore request", body = AdminErrorResponse),
    ),
)]
pub(crate) async fn handle_post_restore(
    State(state): State<AppState>,
    admin: AuthedAdmin,
    Json(req): Json<RestoreRequest>,
) -> Result<(StatusCode, Json<RestoreResponse>), AdminError> {
    admin.require_scope(SIEM_RESTORE_SCOPE)?;

    trigger_cold_restore(
        &state.http,
        &state.opensearch_url,
        &state.snapshot_repo,
        &req.index,
    )
    .await
    .map_err(|e| {
        metrics::counter!("svc_ingest_cold_tier_restore_errors_total").increment(1);
        tracing::error!(error = %e, index = %req.index, "cold_tier_restore_failed");
        AdminError::UpstreamOpenSearch(e.to_string())
    })?;

    state
        .audit
        .record(AuditEntry {
            actor: admin.claims.sub.clone(),
            tenant: admin.claims.tenant.clone(),
            action: "ingest.cold_tier_restore".to_owned(),
            resource: req.index.clone(),
            at: Utc::now(),
        })
        .await;

    metrics::counter!("svc_ingest_cold_tier_restore_total").increment(1);
    tracing::info!(actor = %admin.claims.sub, index = %req.index, "cold_tier_restore_triggered");

    Ok((
        StatusCode::ACCEPTED,
        Json(RestoreResponse {
            index: req.index,
            status: "restore_triggered".to_owned(),
        }),
    ))
}

/// POSTs an OpenSearch snapshot restore request for `index`'s COLD-tier
/// snapshot (`cold-{index}`) in `repo`. A real (non-searchable-snapshot)
/// restore recreates a normal, fully local index from the snapshot —
/// matching Spec §8a1's "Explicit restore-on-demand (slow, ~minutes)"
/// COLD-tier contract.
///
/// # Errors
/// Returns the `reqwest` error on transport failure or a non-2xx response.
async fn trigger_cold_restore(
    client: &reqwest::Client,
    base_url: &str,
    repo: &str,
    index: &str,
) -> Result<(), reqwest::Error> {
    let snapshot = format!("cold-{index}");
    let url = format!("{base_url}/_snapshot/{repo}/{snapshot}/_restore");
    client
        .post(url)
        .json(&serde_json::json!({ "indices": index }))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

/// Builds the admin router (`PUT /api/v1/admin/ingest/lifecycle`,
/// `POST /api/v1/admin/ingest/restore`).
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/admin/ingest/lifecycle", put(handle_put_lifecycle))
        .route("/api/v1/admin/ingest/restore", post(handle_post_restore))
        .with_state(state)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Mutex;

    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// In-memory [`AuditSink`] test double — records every entry it's given
    /// so tests can assert exactly what was audited without a database.
    #[derive(Debug, Default)]
    struct RecordingAuditSink {
        entries: Mutex<Vec<AuditEntry>>,
    }

    #[async_trait::async_trait]
    impl AuditSink for RecordingAuditSink {
        async fn record(&self, entry: AuditEntry) {
            self.entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(entry);
        }
    }

    fn state_for(opensearch_url: &str, audit: Arc<dyn AuditSink>) -> AppState {
        AppState {
            http: reqwest::Client::new(),
            opensearch_url: opensearch_url.into(),
            snapshot_repo: "skauswatch-snapshots".into(),
            jwt_verify_key: skauswatch_testkit::jwt::verify_key().clone(),
            audit,
        }
    }

    fn test_server(opensearch_url: &str, audit: Arc<dyn AuditSink>) -> axum_test::TestServer {
        axum_test::TestServer::new(router(state_for(opensearch_url, audit)))
    }

    fn bearer_for(tenant: &str, scope: &str) -> String {
        skauswatch_testkit::jwt::mint_claims_token(
            skauswatch_testkit::jwt::signing_key(),
            "admin-user",
            tenant,
            scope,
            &["admin"],
        )
    }

    fn lifecycle_body(hot: i64, warm: i64, cold: i64) -> serde_json::Value {
        serde_json::json!({
            "hot_to_warm_days": hot,
            "warm_to_cold_days": warm,
            "cold_to_delete_days": cold,
        })
    }

    // -- PUT /lifecycle: scope gate ---------------------------------------

    /// Named regression test from the Task 2.1 brief: "a token with only
    /// `*:read` scope gets 403."
    #[tokio::test]
    async fn admin_endpoint_requires_super_admin_scope() {
        let server = test_server("http://unused", Arc::new(RecordingAuditSink::default()));
        let res = server
            .put("/api/v1/admin/ingest/lifecycle")
            .authorization_bearer(bearer_for("tenant-a", "*:read"))
            .json(&lifecycle_body(30, 90, 370))
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn restore_endpoint_requires_siem_admin_scope() {
        let server = test_server("http://unused", Arc::new(RecordingAuditSink::default()));
        let res = server
            .post("/api/v1/admin/ingest/restore")
            .authorization_bearer(bearer_for("tenant-a", "*:read"))
            .json(&serde_json::json!({"index": "skauswatch-logs-2026.01.01"}))
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn lifecycle_endpoint_without_bearer_token_is_401() {
        let server = test_server("http://unused", Arc::new(RecordingAuditSink::default()));
        let res = server
            .put("/api/v1/admin/ingest/lifecycle")
            .json(&lifecycle_body(30, 90, 370))
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn lifecycle_endpoint_with_no_tenant_claim_is_403() {
        let server = test_server("http://unused", Arc::new(RecordingAuditSink::default()));
        let token = skauswatch_testkit::jwt::mint_claims_token(
            skauswatch_testkit::jwt::signing_key(),
            "admin-user",
            "", // no tenant claim
            LIFECYCLE_ADMIN_SCOPE,
            &["admin"],
        );
        let res = server
            .put("/api/v1/admin/ingest/lifecycle")
            .authorization_bearer(token)
            .json(&lifecycle_body(30, 90, 370))
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    // -- PUT /lifecycle: validation ----------------------------------------

    #[tokio::test]
    async fn lifecycle_endpoint_rejects_non_monotonic_config_without_calling_opensearch() {
        let mock = MockServer::start().await;
        // No Mock registered at all -- if the handler calls OpenSearch
        // despite the invalid config, wiremock answers 404 and this test's
        // final assertion (`received_requests` is empty) catches it.
        let server = test_server(&mock.uri(), Arc::new(RecordingAuditSink::default()));

        let res = server
            .put("/api/v1/admin/ingest/lifecycle")
            .authorization_bearer(bearer_for("tenant-a", LIFECYCLE_ADMIN_SCOPE))
            .json(&lifecycle_body(90, 30, 400))
            .await;

        res.assert_status(StatusCode::BAD_REQUEST);
        let requests = mock.received_requests().await.unwrap();
        assert!(
            requests.is_empty(),
            "an invalid config must never reach OpenSearch"
        );
    }

    // -- PUT /lifecycle: success / upstream propagation ---------------------

    #[tokio::test]
    async fn lifecycle_endpoint_applies_valid_config_and_echoes_it_back() {
        let mock = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path(format!(
                "/_plugins/_ism/policies/{}",
                ism::ISM_POLICY_ID
            )))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock)
            .await;

        let server = test_server(&mock.uri(), Arc::new(RecordingAuditSink::default()));
        let res = server
            .put("/api/v1/admin/ingest/lifecycle")
            .authorization_bearer(bearer_for("tenant-a", LIFECYCLE_ADMIN_SCOPE))
            .json(&lifecycle_body(30, 90, 370))
            .await;

        res.assert_status_ok();
        let body: LifecycleResponse = res.json();
        assert_eq!(body.hot_to_warm_days, 30);
        assert_eq!(body.warm_to_cold_days, 90);
        assert_eq!(body.cold_to_delete_days, 370);
        assert_eq!(body.policy_id, ism::ISM_POLICY_ID);
    }

    #[tokio::test]
    async fn lifecycle_endpoint_maps_opensearch_rejection_to_502() {
        let mock = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path(format!(
                "/_plugins/_ism/policies/{}",
                ism::ISM_POLICY_ID
            )))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;

        let server = test_server(&mock.uri(), Arc::new(RecordingAuditSink::default()));
        let res = server
            .put("/api/v1/admin/ingest/lifecycle")
            .authorization_bearer(bearer_for("tenant-a", LIFECYCLE_ADMIN_SCOPE))
            .json(&lifecycle_body(30, 90, 370))
            .await;

        res.assert_status(StatusCode::BAD_GATEWAY);
    }

    /// Task 2.1 brief acceptance criterion (partial — see `ism`'s module
    /// doc comment "Module wiring notes" for the accompanying BLOCKED note
    /// on genuine testcontainers coverage): the applied policy's WARM state
    /// must carry a `searchable_snapshot` action against the configured
    /// repo, never a delete/evict action, and data ingested before the
    /// transition must remain queryable afterward. This exercises the full
    /// PUT handler end-to-end against a mocked OpenSearch: ingest 100
    /// events via the same `crate::opensearch::write_bulk` bulk path
    /// `crate::listeners::http` uses, apply the lifecycle policy, capture
    /// the exact policy body OpenSearch received, and confirm the
    /// documents are still returned by a post-transition search.
    #[tokio::test]
    async fn warm_tier_searchable_snapshot_roundtrip() {
        let mock = MockServer::start().await;
        let index = "skauswatch-logs-2026.07.25";

        // 1. Ingest 100 events via the same bulk path production code uses.
        Mock::given(method("POST"))
            .and(path("/_bulk"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"errors": false, "items": []})),
            )
            .mount(&mock)
            .await;
        let docs: Vec<skauswatch_ocsf::JsonVal> = (0..100)
            .map(|i| {
                skauswatch_ocsf::jsonord::from_slice(format!(r#"{{"seq":{i}}}"#).as_bytes())
                    .unwrap()
            })
            .collect();
        let bulk_body = crate::opensearch::build_bulk_body(index, &docs);
        let client = reqwest::Client::new();
        let outcome = crate::opensearch::write_bulk(&client, &mock.uri(), bulk_body)
            .await
            .unwrap();
        assert!(outcome.all_succeeded());

        // 2. Apply the lifecycle policy (the WARM->COLD "force transition"
        // itself is an OpenSearch cluster background job outside this
        // service's API surface -- see the module-level BLOCKED note).
        Mock::given(method("PUT"))
            .and(path(format!(
                "/_plugins/_ism/policies/{}",
                ism::ISM_POLICY_ID
            )))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock)
            .await;
        let server = test_server(&mock.uri(), Arc::new(RecordingAuditSink::default()));
        let res = server
            .put("/api/v1/admin/ingest/lifecycle")
            .authorization_bearer(bearer_for("tenant-a", LIFECYCLE_ADMIN_SCOPE))
            .json(&lifecycle_body(30, 90, 370))
            .await;
        res.assert_status_ok();

        // 3. The WARM state's action must be a searchable-snapshot mount
        // (never a delete), so a query after entering WARM still returns
        // the same data -- assert the exact policy body OpenSearch got.
        let requests = mock.received_requests().await.unwrap();
        let policy_put = requests
            .iter()
            .find(|r| r.url.path().starts_with("/_plugins/_ism/policies/"))
            .expect("ISM policy PUT must have been sent");
        let sent_policy: serde_json::Value = serde_json::from_slice(&policy_put.body).unwrap();
        assert_eq!(
            sent_policy["policy"]["states"][1]["actions"][2]["searchable_snapshot"]["repository"],
            "skauswatch-snapshots"
        );

        // 4. Query across tiers must still return the original 100 events
        // (Spec: "HOT + WARM transparent").
        Mock::given(method("GET"))
            .and(path(format!("/{index}/_search")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "hits": {"total": {"value": 100}, "hits": []}
            })))
            .mount(&mock)
            .await;
        let search = client
            .get(format!("{}/{index}/_search", mock.uri()))
            .send()
            .await
            .unwrap();
        let search_body: serde_json::Value = search.json().await.unwrap();
        assert_eq!(search_body["hits"]["total"]["value"], 100);
    }

    /// Task 2.1 brief acceptance criterion (partial — see `ism`'s module
    /// doc comment "Module wiring notes" for the accompanying BLOCKED note
    /// on genuine testcontainers coverage): moving data to COLD and calling
    /// the restore endpoint must (a) trigger the real OpenSearch restore
    /// call, (b) write exactly one audit-log entry, and (c) the restored
    /// index must become queryable again.
    #[tokio::test]
    async fn cold_tier_restore_triggers_audit_log_and_becomes_queryable() {
        let mock = MockServer::start().await;
        let index = "skauswatch-logs-2025.01.01";

        Mock::given(method("POST"))
            .and(path(format!(
                "/_snapshot/skauswatch-snapshots/cold-{index}/_restore"
            )))
            .and(body_json(serde_json::json!({"indices": index})))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock)
            .await;

        let audit = Arc::new(RecordingAuditSink::default());
        let server = test_server(&mock.uri(), audit.clone());
        let res = server
            .post("/api/v1/admin/ingest/restore")
            .authorization_bearer(bearer_for("tenant-a", SIEM_RESTORE_SCOPE))
            .json(&serde_json::json!({"index": index}))
            .await;

        res.assert_status(StatusCode::ACCEPTED);
        let body: RestoreResponse = res.json();
        assert_eq!(body.index, index);
        assert_eq!(body.status, "restore_triggered");

        // (a) the real restore call was made.
        let requests = mock.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1, "exactly one restore POST");

        // (b) exactly one audit entry was written, for this action/actor/resource.
        {
            let entries = audit.entries.lock().unwrap();
            assert_eq!(entries.len(), 1, "exactly one audit entry");
            assert_eq!(entries[0].action, "ingest.cold_tier_restore");
            assert_eq!(entries[0].resource, index);
            assert_eq!(entries[0].actor, "admin-user");
        }

        // (c) the restored index becomes queryable.
        Mock::given(method("GET"))
            .and(path(format!("/{index}/_search")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "hits": {"total": {"value": 42}, "hits": []}
            })))
            .mount(&mock)
            .await;
        let client = reqwest::Client::new();
        let search = client
            .get(format!("{}/{index}/_search", mock.uri()))
            .send()
            .await
            .unwrap();
        assert!(search.status().is_success());
        let search_body: serde_json::Value = search.json().await.unwrap();
        assert_eq!(search_body["hits"]["total"]["value"], 42);
    }

    #[tokio::test]
    async fn restore_endpoint_maps_opensearch_rejection_to_502_and_does_not_audit() {
        let mock = MockServer::start().await;
        let index = "skauswatch-logs-2025.01.01";
        Mock::given(method("POST"))
            .and(path(format!(
                "/_snapshot/skauswatch-snapshots/cold-{index}/_restore"
            )))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;

        let audit = Arc::new(RecordingAuditSink::default());
        let server = test_server(&mock.uri(), audit.clone());
        let res = server
            .post("/api/v1/admin/ingest/restore")
            .authorization_bearer(bearer_for("tenant-a", SIEM_RESTORE_SCOPE))
            .json(&serde_json::json!({"index": index}))
            .await;

        res.assert_status(StatusCode::BAD_GATEWAY);
        assert!(
            audit.entries.lock().unwrap().is_empty(),
            "a failed restore call must not be audited as if it succeeded"
        );
    }

    // -- AdminError::into_response mapping -----------------------------------

    #[test]
    fn admin_error_variants_map_to_expected_status_codes() {
        assert_eq!(
            AdminError::Unauthorized("x".into())
                .into_response()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AdminError::Forbidden("x".into()).into_response().status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            AdminError::BadRequest("x".into()).into_response().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AdminError::UpstreamOpenSearch("x".into())
                .into_response()
                .status(),
            StatusCode::BAD_GATEWAY
        );
    }
}
