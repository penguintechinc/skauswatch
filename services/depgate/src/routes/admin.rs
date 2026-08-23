//! `/api/v1/depgate` — tenant-scoped report/audit surface over the
//! `depgate_artifacts`/`depgate_quarantine` index tables (§8). Distinct
//! from the OCI proxy surface (`crate::routes::oci`): this is the
//! human/operator-facing reporting API, so unlike the proxy's shared-cache
//! lookups, every query here filters on the caller's own tenant.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use skauswatch_auth::TenantContext;
use uuid::Uuid;

use crate::db::{self, ArtifactFilters};
use crate::error::{ApiError, tenant_uuid};
use crate::state::AppState;

/// Router for `/api/v1/depgate`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/depgate/artifacts", get(list_artifacts))
        .route("/depgate/quarantine", get(list_quarantine))
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
        (status = 403, description = "Missing or invalid tenant claim", body = crate::error::ErrorResponse),
    ),
)]
pub(crate) async fn list_artifacts(
    State(state): State<AppState>,
    tenant: TenantContext,
    Query(q): Query<ListArtifactsQuery>,
) -> Result<Json<ArtifactListResponse>, ApiError> {
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
        (status = 403, description = "Missing or invalid tenant claim", body = crate::error::ErrorResponse),
    ),
)]
pub(crate) async fn list_quarantine(
    State(state): State<AppState>,
    tenant: TenantContext,
    Query(q): Query<ListQuarantineQuery>,
) -> Result<Json<QuarantineListResponse>, ApiError> {
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
        (status = 403, description = "Missing or invalid tenant claim", body = crate::error::ErrorResponse),
    ),
)]
pub(crate) async fn stats(
    State(state): State<AppState>,
    tenant: TenantContext,
) -> Result<Json<StatsResponse>, ApiError> {
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
