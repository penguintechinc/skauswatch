//! `/api/v1/depgate` — tenant-scoped report/audit surface over the
//! `depgate_artifacts`/`depgate_quarantine` index tables (§8). Distinct
//! from the OCI proxy surface (`crate::routes::oci`): this is the
//! human/operator-facing reporting API, so unlike the proxy's shared-cache
//! lookups, every query here filters on the caller's own tenant.

use axum::extract::{Path, Query, State};
use axum::routing::{get, patch};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use skauswatch_auth::TenantContext;
use uuid::Uuid;

use crate::auth::{ADMIN_SCOPE, AuthedUser, READ_SCOPE};
use crate::db::{self, ArtifactFilters, PolicyRuleInput};
use crate::error::{ApiError, tenant_uuid};
use crate::state::AppState;

/// Router for `/api/v1/depgate`.
///
/// Every route here is, at minimum, tenant-scoped (`TenantContext`, from
/// the router-wide `tenant_middleware`). On top of that, every handler
/// additionally extracts [`crate::auth::AuthedUser`] and enforces
/// [`READ_SCOPE`] (list/get endpoints) or [`ADMIN_SCOPE`] (quarantine
/// disposition + policy-rule mutations) — mutating endpoints were
/// previously reachable by any authenticated tenant member, which for the
/// quarantine-release path meant any non-admin could re-admit a quarantined
/// (malware-flagged) artifact.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/depgate/artifacts", get(list_artifacts))
        .route(
            "/depgate/artifacts/{sha256}/risk-findings",
            get(list_risk_findings),
        )
        .route("/depgate/quarantine", get(list_quarantine))
        .route("/depgate/quarantine/{id}", patch(update_quarantine))
        .route(
            "/depgate/policy-rules",
            get(list_policy_rules).post(create_policy_rule),
        )
        .route(
            "/depgate/policy-rules/{id}",
            get(get_policy_rule)
                .put(update_policy_rule)
                .delete(delete_policy_rule),
        )
        .route("/depgate/stats", get(stats))
}

fn default_limit() -> i64 {
    50
}

/// Query params for `GET /api/v1/depgate/artifacts`.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub(crate) struct ListArtifactsQuery {
    /// Exact-match verdict filter (`clean`/`infected`/`pup`/`error`/`skipped`/`quarantined`).
    verdict: Option<String>,
    /// Exact-match ecosystem filter (`oci`, `npm`, `pypi`).
    ecosystem: Option<String>,
    /// Substring match against `name`.
    name: Option<String>,
    /// Page size (default 50, max 200).
    #[serde(default = "default_limit")]
    limit: i64,
    /// Page offset (default 0).
    #[serde(default)]
    offset: i64,
}

fn clamp_limit(limit: i64) -> i64 {
    limit.clamp(1, 200)
}

fn clamp_offset(offset: i64) -> i64 {
    offset.max(0)
}

/// One artifact row, wire shape for the artifacts list.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ArtifactItem {
    id: Uuid,
    ecosystem: String,
    name: String,
    reference: String,
    sha256: String,
    upstream: String,
    content_type: Option<String>,
    size_bytes: i64,
    verdict: String,
    verdict_at: String,
    scanner_version: String,
    pinned: bool,
    first_seen: String,
    last_seen: String,
}

impl From<db::ArtifactRow> for ArtifactItem {
    fn from(r: db::ArtifactRow) -> Self {
        Self {
            id: r.id,
            ecosystem: r.ecosystem,
            name: r.name,
            reference: r.reference,
            sha256: r.sha256,
            upstream: r.upstream,
            content_type: r.content_type,
            size_bytes: r.size_bytes,
            verdict: r.verdict,
            verdict_at: r.verdict_at.and_utc().to_rfc3339(),
            scanner_version: r.scanner_version,
            pinned: r.pinned,
            first_seen: r.first_seen.and_utc().to_rfc3339(),
            last_seen: r.last_seen.and_utc().to_rfc3339(),
        }
    }
}

/// Response envelope for `GET /api/v1/depgate/artifacts`.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ArtifactListResponse {
    items: Vec<ArtifactItem>,
    total: i64,
    limit: i64,
    offset: i64,
}

#[utoipa::path(
    get,
    path = "/api/v1/depgate/artifacts",
    tag = "depgate",
    security(("bearer_jwt" = [])),
    params(ListArtifactsQuery),
    responses(
        (status = 200, description = "Tenant-scoped artifact index, newest-resolved first", body = ArtifactListResponse),
        (status = 401, description = "Missing or invalid authorization header", body = crate::error::ErrorResponse),
        (status = 403, description = "Missing or invalid tenant claim, or missing depgate:read scope", body = crate::error::ErrorResponse),
    ),
)]
pub(crate) async fn list_artifacts(
    State(state): State<AppState>,
    tenant: TenantContext,
    auth: AuthedUser,
    Query(q): Query<ListArtifactsQuery>,
) -> Result<Json<ArtifactListResponse>, ApiError> {
    auth.require_scope(READ_SCOPE)?;
    let tenant_id = tenant_uuid(&tenant.tenant)?;
    let filters = ArtifactFilters {
        verdict: q.verdict,
        ecosystem: q.ecosystem,
        name: q.name,
        limit: clamp_limit(q.limit),
        offset: clamp_offset(q.offset),
    };
    let (rows, total) = db::list_artifacts(&state.db, tenant_id, &filters).await?;
    Ok(Json(ArtifactListResponse {
        items: rows.into_iter().map(ArtifactItem::from).collect(),
        total,
        limit: filters.limit,
        offset: filters.offset,
    }))
}

/// Query params for `GET /api/v1/depgate/quarantine`.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub(crate) struct ListQuarantineQuery {
    /// Page size (default 50, max 200).
    #[serde(default = "default_limit")]
    limit: i64,
    /// Page offset (default 0).
    #[serde(default)]
    offset: i64,
}

/// One quarantine row, wire shape.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct QuarantineItem {
    id: Uuid,
    sha256: String,
    ecosystem: String,
    name: String,
    reference: String,
    reason: String,
    threat: String,
    disposition: String,
    policy_rule_id: Option<Uuid>,
    resolved_at: Option<String>,
    resolved_by: Option<String>,
    resolution_note: Option<String>,
    created_at: String,
}

impl From<db::QuarantineRow> for QuarantineItem {
    fn from(r: db::QuarantineRow) -> Self {
        Self {
            id: r.id,
            sha256: r.sha256,
            ecosystem: r.ecosystem,
            name: r.name,
            reference: r.reference,
            reason: r.reason,
            threat: r.threat,
            disposition: r.disposition,
            policy_rule_id: r.policy_rule_id,
            resolved_at: r.resolved_at.map(|t| t.and_utc().to_rfc3339()),
            resolved_by: r.resolved_by,
            resolution_note: r.resolution_note,
            created_at: r.created_at.and_utc().to_rfc3339(),
        }
    }
}

/// Response envelope for `GET /api/v1/depgate/quarantine`.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct QuarantineListResponse {
    items: Vec<QuarantineItem>,
    total: i64,
    limit: i64,
    offset: i64,
}

#[utoipa::path(
    get,
    path = "/api/v1/depgate/quarantine",
    tag = "depgate",
    security(("bearer_jwt" = [])),
    params(ListQuarantineQuery),
    responses(
        (status = 200, description = "Tenant-scoped quarantine log, newest first", body = QuarantineListResponse),
        (status = 401, description = "Missing or invalid authorization header", body = crate::error::ErrorResponse),
        (status = 403, description = "Missing or invalid tenant claim, or missing depgate:read scope", body = crate::error::ErrorResponse),
    ),
)]
pub(crate) async fn list_quarantine(
    State(state): State<AppState>,
    tenant: TenantContext,
    auth: AuthedUser,
    Query(q): Query<ListQuarantineQuery>,
) -> Result<Json<QuarantineListResponse>, ApiError> {
    auth.require_scope(READ_SCOPE)?;
    let tenant_id = tenant_uuid(&tenant.tenant)?;
    let limit = clamp_limit(q.limit);
    let offset = clamp_offset(q.offset);
    let (rows, total) = db::list_quarantine(&state.db, tenant_id, limit, offset).await?;
    Ok(Json(QuarantineListResponse {
        items: rows.into_iter().map(QuarantineItem::from).collect(),
        total,
        limit,
        offset,
    }))
}

/// One risk-finding row, wire shape.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RiskFindingItem {
    id: Uuid,
    sha256: String,
    ecosystem: String,
    name: String,
    reference: String,
    check_name: String,
    severity: String,
    detail: String,
    created_at: String,
}

impl From<db::RiskFindingRow> for RiskFindingItem {
    fn from(r: db::RiskFindingRow) -> Self {
        Self {
            id: r.id,
            sha256: r.sha256,
            ecosystem: r.ecosystem,
            name: r.name,
            reference: r.reference,
            check_name: r.check_name,
            severity: r.severity,
            detail: r.detail,
            created_at: r.created_at.and_utc().to_rfc3339(),
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/depgate/artifacts/{sha256}/risk-findings",
    tag = "depgate",
    security(("bearer_jwt" = [])),
    params(("sha256" = String, Path, description = "Content digest hex")),
    responses(
        (status = 200, description = "Package-risk heuristic findings recorded for this artifact (§5)", body = [RiskFindingItem]),
        (status = 401, description = "Missing or invalid authorization header", body = crate::error::ErrorResponse),
        (status = 403, description = "Missing or invalid tenant claim, or missing depgate:read scope", body = crate::error::ErrorResponse),
    ),
)]
pub(crate) async fn list_risk_findings(
    State(state): State<AppState>,
    tenant: TenantContext,
    auth: AuthedUser,
    Path(sha256): Path<String>,
) -> Result<Json<Vec<RiskFindingItem>>, ApiError> {
    auth.require_scope(READ_SCOPE)?;
    let tenant_id = tenant_uuid(&tenant.tenant)?;
    let rows = db::list_risk_findings(&state.db, tenant_id, &sha256).await?;
    Ok(Json(rows.into_iter().map(RiskFindingItem::from).collect()))
}

/// Request body for `PATCH /api/v1/depgate/quarantine/{id}`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateQuarantineRequest {
    /// New disposition (`confirmed`/`false_positive`/`released`) — `pending`
    /// is the initial state only, never a valid transition target.
    disposition: String,
    /// Free-text resolution note.
    resolution_note: Option<String>,
}

fn valid_disposition(d: &str) -> bool {
    matches!(d, "confirmed" | "false_positive" | "released")
}

#[utoipa::path(
    patch,
    path = "/api/v1/depgate/quarantine/{id}",
    tag = "depgate",
    security(("bearer_jwt" = [])),
    params(("id" = Uuid, Path, description = "Quarantine event id")),
    request_body = UpdateQuarantineRequest,
    responses(
        (status = 200, description = "Updated quarantine event; `released` re-admits the artifact to the vetted cache", body = QuarantineItem),
        (status = 400, description = "Invalid disposition value", body = crate::error::ErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = crate::error::ErrorResponse),
        (status = 403, description = "Missing or invalid tenant claim, or missing depgate:admin scope", body = crate::error::ErrorResponse),
        (status = 404, description = "No such quarantine event for this tenant", body = crate::error::ErrorResponse),
    ),
)]
pub(crate) async fn update_quarantine(
    State(state): State<AppState>,
    tenant: TenantContext,
    auth: AuthedUser,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateQuarantineRequest>,
) -> Result<Json<QuarantineItem>, ApiError> {
    auth.require_scope(ADMIN_SCOPE)?;
    let tenant_id = tenant_uuid(&tenant.tenant)?;
    if !valid_disposition(&body.disposition) {
        return Err(ApiError::BadRequest(format!(
            "invalid disposition {:?}: must be confirmed, false_positive, or released",
            body.disposition
        )));
    }
    let event = db::get_quarantine(&state.db, tenant_id, id)
        .await?
        .ok_or_else(|| ApiError::NotFound("no such quarantine event".to_owned()))?;

    // `released` re-admits the artifact: move the object from the
    // quarantine prefix back into the servable cache prefix and mark the
    // index row clean again — audit-logged via the same disposition update
    // below, which always runs regardless of which disposition was set.
    if body.disposition == "released" {
        let src_key = crate::cache::object_key(&state.cfg.quarantine_prefix, &event.sha256);
        if let Some(obj) =
            crate::cache::get_object(&state.s3, &state.cfg.cache_bucket, &src_key).await?
        {
            let dest_key = crate::cache::object_key(&state.cfg.cache_prefix, &event.sha256);
            crate::cache::put_object(
                &state.s3,
                &state.cfg.cache_bucket,
                &dest_key,
                obj.bytes,
                &obj.content_type,
            )
            .await?;
            crate::cache::put_tags(
                &state.s3,
                &state.cfg.cache_bucket,
                &dest_key,
                &[("threat".to_owned(), "clean".to_owned())],
            )
            .await?;
        }
        if let Some(row) =
            db::find_by_reference(&state.db, &event.ecosystem, &event.name, &event.reference)
                .await?
        {
            db::upsert_artifact(
                &state.db,
                &db::UpsertArtifact {
                    ecosystem: &event.ecosystem,
                    name: &event.name,
                    reference: &event.reference,
                    sha256: &event.sha256,
                    upstream: &row.upstream,
                    content_type: row.content_type.as_deref(),
                    size_bytes: row.size_bytes,
                    verdict: "clean",
                    scanner_version: &row.scanner_version,
                    pinned: row.pinned,
                    tenant_id,
                },
            )
            .await?;
        }
    }

    let resolved_by = tenant.tenant.as_str().to_owned();
    let updated = db::update_quarantine_disposition(
        &state.db,
        tenant_id,
        id,
        &body.disposition,
        &resolved_by,
        body.resolution_note.as_deref(),
    )
    .await?
    .ok_or_else(|| ApiError::NotFound("no such quarantine event".to_owned()))?;
    Ok(Json(QuarantineItem::from(updated)))
}

/// One policy-rule row, wire shape.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PolicyRuleItem {
    id: Uuid,
    priority: i32,
    ecosystem: Option<String>,
    name_glob: Option<String>,
    version_glob: Option<String>,
    verdict: Option<String>,
    risk_check: Option<String>,
    min_severity: Option<String>,
    action: String,
    description: Option<String>,
    enabled: bool,
    created_at: String,
    updated_at: String,
}

impl From<db::PolicyRuleRow> for PolicyRuleItem {
    fn from(r: db::PolicyRuleRow) -> Self {
        Self {
            id: r.id,
            priority: r.priority,
            ecosystem: r.ecosystem,
            name_glob: r.name_glob,
            version_glob: r.version_glob,
            verdict: r.verdict,
            risk_check: r.risk_check,
            min_severity: r.min_severity,
            action: r.action,
            description: r.description,
            enabled: r.enabled,
            created_at: r.created_at.and_utc().to_rfc3339(),
            updated_at: r.updated_at.and_utc().to_rfc3339(),
        }
    }
}

/// Create/replace request body for a policy rule.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct PolicyRuleRequest {
    #[serde(default = "default_priority")]
    priority: i32,
    ecosystem: Option<String>,
    name_glob: Option<String>,
    version_glob: Option<String>,
    verdict: Option<String>,
    risk_check: Option<String>,
    min_severity: Option<String>,
    action: String,
    description: Option<String>,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

fn default_priority() -> i32 {
    100
}

fn default_enabled() -> bool {
    true
}

fn validate_policy_rule_request(req: &PolicyRuleRequest) -> Result<(), ApiError> {
    if req.action.parse::<crate::policy::Action>().is_err() {
        return Err(ApiError::BadRequest(format!(
            "invalid action {:?}: must be allow, warn, block, or quarantine",
            req.action
        )));
    }
    if let Some(sev) = &req.min_severity
        && sev.parse::<crate::heuristics::Severity>().is_err()
    {
        return Err(ApiError::BadRequest(format!(
            "invalid min_severity {sev:?}: must be info, low, medium, high, or critical"
        )));
    }
    Ok(())
}

#[utoipa::path(
    get,
    path = "/api/v1/depgate/policy-rules",
    tag = "depgate",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Tenant's policy rules, highest priority first", body = [PolicyRuleItem]),
        (status = 401, description = "Missing or invalid authorization header", body = crate::error::ErrorResponse),
        (status = 403, description = "Missing or invalid tenant claim, or missing depgate:read scope", body = crate::error::ErrorResponse),
    ),
)]
pub(crate) async fn list_policy_rules(
    State(state): State<AppState>,
    tenant: TenantContext,
    auth: AuthedUser,
) -> Result<Json<Vec<PolicyRuleItem>>, ApiError> {
    auth.require_scope(READ_SCOPE)?;
    let tenant_id = tenant_uuid(&tenant.tenant)?;
    let rows = db::list_policy_rules(&state.db, tenant_id).await?;
    Ok(Json(rows.into_iter().map(PolicyRuleItem::from).collect()))
}

#[utoipa::path(
    post,
    path = "/api/v1/depgate/policy-rules",
    tag = "depgate",
    security(("bearer_jwt" = [])),
    request_body = PolicyRuleRequest,
    responses(
        (status = 200, description = "Created policy rule", body = PolicyRuleItem),
        (status = 400, description = "Invalid action/min_severity value", body = crate::error::ErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = crate::error::ErrorResponse),
        (status = 403, description = "Missing or invalid tenant claim, or missing depgate:admin scope", body = crate::error::ErrorResponse),
    ),
)]
pub(crate) async fn create_policy_rule(
    State(state): State<AppState>,
    tenant: TenantContext,
    auth: AuthedUser,
    Json(req): Json<PolicyRuleRequest>,
) -> Result<Json<PolicyRuleItem>, ApiError> {
    auth.require_scope(ADMIN_SCOPE)?;
    let tenant_id = tenant_uuid(&tenant.tenant)?;
    validate_policy_rule_request(&req)?;
    let row = db::insert_policy_rule(
        &state.db,
        tenant_id,
        &PolicyRuleInput {
            priority: req.priority,
            ecosystem: req.ecosystem.as_deref(),
            name_glob: req.name_glob.as_deref(),
            version_glob: req.version_glob.as_deref(),
            verdict: req.verdict.as_deref(),
            risk_check: req.risk_check.as_deref(),
            min_severity: req.min_severity.as_deref(),
            action: &req.action,
            description: req.description.as_deref(),
            enabled: req.enabled,
            created_by: Some(tenant.tenant.as_str()),
        },
    )
    .await?;
    Ok(Json(PolicyRuleItem::from(row)))
}

#[utoipa::path(
    get,
    path = "/api/v1/depgate/policy-rules/{id}",
    tag = "depgate",
    security(("bearer_jwt" = [])),
    params(("id" = Uuid, Path, description = "Policy rule id")),
    responses(
        (status = 200, description = "The policy rule", body = PolicyRuleItem),
        (status = 401, description = "Missing or invalid authorization header", body = crate::error::ErrorResponse),
        (status = 403, description = "Missing or invalid tenant claim, or missing depgate:read scope", body = crate::error::ErrorResponse),
        (status = 404, description = "No such policy rule for this tenant", body = crate::error::ErrorResponse),
    ),
)]
pub(crate) async fn get_policy_rule(
    State(state): State<AppState>,
    tenant: TenantContext,
    auth: AuthedUser,
    Path(id): Path<Uuid>,
) -> Result<Json<PolicyRuleItem>, ApiError> {
    auth.require_scope(READ_SCOPE)?;
    let tenant_id = tenant_uuid(&tenant.tenant)?;
    let row = db::get_policy_rule(&state.db, tenant_id, id)
        .await?
        .ok_or_else(|| ApiError::NotFound("no such policy rule".to_owned()))?;
    Ok(Json(PolicyRuleItem::from(row)))
}

#[utoipa::path(
    put,
    path = "/api/v1/depgate/policy-rules/{id}",
    tag = "depgate",
    security(("bearer_jwt" = [])),
    params(("id" = Uuid, Path, description = "Policy rule id")),
    request_body = PolicyRuleRequest,
    responses(
        (status = 200, description = "Updated policy rule", body = PolicyRuleItem),
        (status = 400, description = "Invalid action/min_severity value", body = crate::error::ErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = crate::error::ErrorResponse),
        (status = 403, description = "Missing or invalid tenant claim, or missing depgate:admin scope", body = crate::error::ErrorResponse),
        (status = 404, description = "No such policy rule for this tenant", body = crate::error::ErrorResponse),
    ),
)]
pub(crate) async fn update_policy_rule(
    State(state): State<AppState>,
    tenant: TenantContext,
    auth: AuthedUser,
    Path(id): Path<Uuid>,
    Json(req): Json<PolicyRuleRequest>,
) -> Result<Json<PolicyRuleItem>, ApiError> {
    auth.require_scope(ADMIN_SCOPE)?;
    let tenant_id = tenant_uuid(&tenant.tenant)?;
    validate_policy_rule_request(&req)?;
    let row = db::update_policy_rule(
        &state.db,
        tenant_id,
        id,
        &PolicyRuleInput {
            priority: req.priority,
            ecosystem: req.ecosystem.as_deref(),
            name_glob: req.name_glob.as_deref(),
            version_glob: req.version_glob.as_deref(),
            verdict: req.verdict.as_deref(),
            risk_check: req.risk_check.as_deref(),
            min_severity: req.min_severity.as_deref(),
            action: &req.action,
            description: req.description.as_deref(),
            enabled: req.enabled,
            created_by: Some(tenant.tenant.as_str()),
        },
    )
    .await?
    .ok_or_else(|| ApiError::NotFound("no such policy rule".to_owned()))?;
    Ok(Json(PolicyRuleItem::from(row)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/depgate/policy-rules/{id}",
    tag = "depgate",
    security(("bearer_jwt" = [])),
    params(("id" = Uuid, Path, description = "Policy rule id")),
    responses(
        (status = 204, description = "Policy rule deleted"),
        (status = 401, description = "Missing or invalid authorization header", body = crate::error::ErrorResponse),
        (status = 403, description = "Missing or invalid tenant claim, or missing depgate:admin scope", body = crate::error::ErrorResponse),
        (status = 404, description = "No such policy rule for this tenant", body = crate::error::ErrorResponse),
    ),
)]
pub(crate) async fn delete_policy_rule(
    State(state): State<AppState>,
    tenant: TenantContext,
    auth: AuthedUser,
    Path(id): Path<Uuid>,
) -> Result<axum::http::StatusCode, ApiError> {
    auth.require_scope(ADMIN_SCOPE)?;
    let tenant_id = tenant_uuid(&tenant.tenant)?;
    let deleted = db::delete_policy_rule(&state.db, tenant_id, id).await?;
    if deleted {
        Ok(axum::http::StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound("no such policy rule".to_owned()))
    }
}

/// Response for `GET /api/v1/depgate/stats`.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct StatsResponse {
    by_verdict: std::collections::HashMap<String, i64>,
    quarantine_count: i64,
    /// In-process (this replica, since last restart) cache lookups.
    cache_hits: u64,
    /// In-process (this replica, since last restart) cache misses.
    cache_misses: u64,
    /// `cache_hits / (cache_hits + cache_misses)`, `0.0` when there have
    /// been no lookups yet.
    cache_hit_rate: f64,
}

#[utoipa::path(
    get,
    path = "/api/v1/depgate/stats",
    tag = "depgate",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Verdict counts and cache hit-rate", body = StatsResponse),
        (status = 401, description = "Missing or invalid authorization header", body = crate::error::ErrorResponse),
        (status = 403, description = "Missing or invalid tenant claim, or missing depgate:read scope", body = crate::error::ErrorResponse),
    ),
)]
pub(crate) async fn stats(
    State(state): State<AppState>,
    tenant: TenantContext,
    auth: AuthedUser,
) -> Result<Json<StatsResponse>, ApiError> {
    auth.require_scope(READ_SCOPE)?;
    let tenant_id = tenant_uuid(&tenant.tenant)?;
    let by_verdict = db::verdict_counts(&state.db, tenant_id)
        .await?
        .into_iter()
        .collect();
    let quarantine_count = db::quarantine_count(&state.db, tenant_id).await?;
    let (hits, misses) = state.cache_stats.snapshot();
    let total = hits + misses;
    let cache_hit_rate = if total == 0 {
        0.0
    } else {
        hits as f64 / total as f64
    };
    Ok(Json(StatsResponse {
        by_verdict,
        quarantine_count,
        cache_hits: hits,
        cache_misses: misses,
        cache_hit_rate,
    }))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;

    #[test]
    fn clamp_limit_bounds_between_1_and_200() {
        assert_eq!(clamp_limit(0), 1);
        assert_eq!(clamp_limit(-5), 1);
        assert_eq!(clamp_limit(50), 50);
        assert_eq!(clamp_limit(500), 200);
    }

    #[test]
    fn clamp_offset_never_negative() {
        assert_eq!(clamp_offset(-10), 0);
        assert_eq!(clamp_offset(10), 10);
    }

    #[test]
    fn tenant_uuid_rejects_non_uuid_claim() {
        let t = skauswatch_auth::Tenant("not-a-uuid".to_owned());
        assert!(tenant_uuid(&t).is_err());
    }

    #[test]
    fn tenant_uuid_accepts_valid_claim() {
        let id = Uuid::new_v4();
        let t = skauswatch_auth::Tenant(id.to_string());
        assert_eq!(tenant_uuid(&t).expect("valid"), id);
    }
}
