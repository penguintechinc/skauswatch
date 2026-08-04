//! `/threat-intel/*` — a clean, new REST surface over
//! [`crate::threat_intel::store::ThreatStore`], deliberately not a restore
//! of v1's ~15 broken routes (see `mod.rs` module docs). Read-only for this
//! pass: search/get indicators, list feed poll status. Every route requires
//! a valid tenant-bearing JWT (`skauswatch_auth::tenant_middleware`, same as
//! `crate::routes::events`) even though `threat_iocs`/`threat_feeds`
//! themselves are not tenant-scoped data (shared threat intelligence, see
//! `migrations/0001_threat_intel.sql`) — every authenticated caller with a
//! valid token may read it, matching `backend.md`'s OpenAPI auth-gating
//! rule ("not further role/scope-gated... the goal is keeping the API map
//! off the open internet").

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use skauswatch_auth::TenantContext;

use crate::error::{ApiError, ErrorResponse};
use crate::flags::flag_denied_for;
use crate::models::{Ioc, ThreatFeed, ThreatLevel};
use crate::state::AppState;
use crate::threat_intel::taxii::THREAT_INTEL_FLAG;

/// Router for `/threat-intel/*`.
pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/threat-intel/indicators", get(search_indicators))
        .route("/threat-intel/indicators/{id}", get(get_indicator))
        .route("/threat-intel/feeds", get(list_feeds))
        .layer(axum::middleware::from_fn_with_state(
            state,
            skauswatch_auth::tenant_middleware::<AppState>,
        ))
}

fn flag_check(state: &AppState) -> impl std::future::Future<Output = Option<Response>> + '_ {
    flag_denied_for(
        state,
        THREAT_INTEL_FLAG,
        "threat intelligence is not enabled for this deployment.",
    )
}

/// Query params for `GET /threat-intel/indicators`.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub(crate) struct SearchParams {
    /// Free-text match against value/description.
    #[serde(default)]
    q: String,
    /// Restrict to one IOC kind (`ip`, `domain`, `hash`, ...).
    #[serde(rename = "type", default)]
    #[param(rename = "type")]
    kind: Option<String>,
    /// Restrict to one threat level.
    #[serde(default)]
    threat_level: Option<ThreatLevel>,
    /// Page size (default 50).
    #[serde(default = "default_limit")]
    limit: i64,
    /// Page offset (default 0).
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    50
}

/// Response for `GET /threat-intel/indicators`.
#[derive(Debug, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub(crate) struct IndicatorSearchResponse {
    /// Matching indicators.
    indicators: Vec<Ioc>,
    /// Total match count (before pagination).
    total: i64,
    /// Echoed page size.
    limit: i64,
    /// Echoed page offset.
    offset: i64,
}

#[utoipa::path(
    get,
    path = "/api/v1/threat-intel/indicators",
    tag = "threat-intel",
    security(("bearer_jwt" = [])),
    params(SearchParams),
    responses(
        (status = 200, description = "Matching threat indicators", body = IndicatorSearchResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Missing tenant claim, or threat-intel not enabled for this deployment", body = ErrorResponse),
        (status = 503, description = "Threat-intel database not configured", body = ErrorResponse),
    ),
)]
pub(crate) async fn search_indicators(
    State(state): State<AppState>,
    _tenant: TenantContext,
    Query(params): Query<SearchParams>,
) -> Result<Response, ApiError> {
    if let Some(denied) = flag_check(&state).await {
        return Ok(denied);
    }
    let store = state.threat_store.as_ref().ok_or_else(|| {
        ApiError::ServiceUnavailable("threat-intel database not configured".to_owned())
    })?;
    let limit = params.limit.clamp(1, 500);
    let offset = params.offset.max(0);
    let (indicators, total) = store
        .search_indicators(
            &params.q,
            params.kind.as_deref(),
            params.threat_level,
            limit,
            offset,
        )
        .await
        .map_err(|e| ApiError::internal("threat-intel search", e))?;
    Ok(Json(IndicatorSearchResponse {
        indicators,
        total,
        limit,
        offset,
    })
    .into_response())
}

#[utoipa::path(
    get,
    path = "/api/v1/threat-intel/indicators/{id}",
    tag = "threat-intel",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Indicator id")),
    responses(
        (status = 200, description = "The indicator", body = Ioc),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Missing tenant claim, or threat-intel not enabled for this deployment", body = ErrorResponse),
        (status = 404, description = "Indicator not found", body = ErrorResponse),
        (status = 503, description = "Threat-intel database not configured", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_indicator(
    State(state): State<AppState>,
    _tenant: TenantContext,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    if let Some(denied) = flag_check(&state).await {
        return Ok(denied);
    }
    let store = state.threat_store.as_ref().ok_or_else(|| {
        ApiError::ServiceUnavailable("threat-intel database not configured".to_owned())
    })?;
    match store
        .get_ioc_by_id(&id)
        .await
        .map_err(|e| ApiError::internal("threat-intel get", e))?
    {
        Some(ioc) => Ok(Json(ioc).into_response()),
        None => Ok(ApiError::NotFound("Indicator not found".to_owned()).into_response()),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/threat-intel/feeds",
    tag = "threat-intel",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Configured TAXII feeds and their poll status", body = [ThreatFeed]),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Missing tenant claim, or threat-intel not enabled for this deployment", body = ErrorResponse),
        (status = 503, description = "Threat-intel database not configured", body = ErrorResponse),
    ),
)]
pub(crate) async fn list_feeds(
    State(state): State<AppState>,
    _tenant: TenantContext,
) -> Result<Response, ApiError> {
    if let Some(denied) = flag_check(&state).await {
        return Ok(denied);
    }
    let store = state.threat_store.as_ref().ok_or_else(|| {
        ApiError::ServiceUnavailable("threat-intel database not configured".to_owned())
    })?;
    let feeds = store
        .list_feeds()
        .await
        .map_err(|e| ApiError::internal("threat-intel list feeds", e))?;
    Ok(Json(feeds).into_response())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::routes::test_support::{dev_state, gated_state, sign_token};
    use crate::threat_intel::store::ThreatStore;
    use axum::http::StatusCode;
    use std::sync::Arc;

    const TENANT_A: &str = "tenant-a";
    const READ_SCOPE: &str = "events:read";

    fn test_server(state: AppState) -> axum_test::TestServer {
        let app = axum::Router::new()
            .merge(router(state.clone()))
            .with_state(state);
        axum_test::TestServer::new(app)
    }

    async fn state_with_threat_store() -> AppState {
        let pool =
            skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"))
                .await;
        crate::state::AppStateInner::for_tests_with_threat_store(
            skauswatch_testkit::license::dev_license("skauswatch"),
            Arc::new(ThreatStore::new(pool)),
        )
    }

    #[tokio::test]
    async fn search_indicators_without_auth_is_unauthorized() {
        let server = test_server(dev_state());
        server
            .get("/threat-intel/indicators")
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn search_indicators_flag_denied_is_forbidden() {
        let state = gated_state();
        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);
        server
            .get("/threat-intel/indicators")
            .authorization_bearer(token)
            .await
            .assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn search_indicators_without_a_store_is_service_unavailable() {
        let state = dev_state();
        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);
        server
            .get("/threat-intel/indicators")
            .authorization_bearer(token)
            .await
            .assert_status(StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn search_indicators_returns_stored_matches() {
        let state = state_with_threat_store().await;
        state
            .threat_store
            .as_ref()
            .unwrap_or_else(|| panic!("expected threat store"))
            .store_indicator(&Ioc {
                id: String::new(),
                kind: "ip".to_owned(),
                value: "203.0.113.42".to_owned(),
                description: "test".to_owned(),
                threat_level: ThreatLevel::High,
                confidence: 0.8,
                tags: vec![],
                malware_families: vec![],
                kill_chain_phases: vec![],
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                expiration: None,
                source_feed: None,
                metadata: serde_json::json!({}),
            })
            .await
            .unwrap_or_else(|e| panic!("seed: {e}"));

        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);
        let res = server
            .get("/threat-intel/indicators?q=203.0.113.42")
            .authorization_bearer(token)
            .await;
        res.assert_status_ok();
        let body: IndicatorSearchResponse = res.json();
        assert_eq!(body.total, 1);
        assert_eq!(body.indicators[0].value, "203.0.113.42");
    }

    #[tokio::test]
    async fn get_indicator_returns_404_for_unknown_id() {
        let state = state_with_threat_store().await;
        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);
        server
            .get("/threat-intel/indicators/00000000-0000-0000-0000-000000000000")
            .authorization_bearer(token)
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_indicator_flag_denied_is_forbidden() {
        let state = gated_state();
        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);
        server
            .get("/threat-intel/indicators/00000000-0000-0000-0000-000000000000")
            .authorization_bearer(token)
            .await
            .assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn get_indicator_without_a_store_is_service_unavailable() {
        let state = dev_state();
        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);
        server
            .get("/threat-intel/indicators/00000000-0000-0000-0000-000000000000")
            .authorization_bearer(token)
            .await
            .assert_status(StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn get_indicator_returns_the_stored_indicator() {
        let state = state_with_threat_store().await;
        let stored = state
            .threat_store
            .as_ref()
            .unwrap_or_else(|| panic!("expected threat store"))
            .store_indicator(&Ioc {
                id: String::new(),
                kind: "domain".to_owned(),
                value: "evil.example.test".to_owned(),
                description: "test".to_owned(),
                threat_level: ThreatLevel::Medium,
                confidence: 0.5,
                tags: vec![],
                malware_families: vec![],
                kill_chain_phases: vec![],
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                expiration: None,
                source_feed: None,
                metadata: serde_json::json!({}),
            })
            .await
            .unwrap_or_else(|e| panic!("seed: {e}"));

        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);
        let res = server
            .get(&format!("/threat-intel/indicators/{}", stored.id))
            .authorization_bearer(token)
            .await;
        res.assert_status_ok();
        let body: Ioc = res.json();
        assert_eq!(body.value, "evil.example.test");
    }

    #[tokio::test]
    async fn list_feeds_flag_denied_is_forbidden() {
        let state = gated_state();
        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);
        server
            .get("/threat-intel/feeds")
            .authorization_bearer(token)
            .await
            .assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn list_feeds_without_a_store_is_service_unavailable() {
        let state = dev_state();
        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);
        server
            .get("/threat-intel/feeds")
            .authorization_bearer(token)
            .await
            .assert_status(StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn list_feeds_returns_seeded_feeds() {
        let state = state_with_threat_store().await;
        state
            .threat_store
            .as_ref()
            .unwrap_or_else(|| panic!("expected threat store"))
            .upsert_feed(&ThreatFeed {
                id: String::new(),
                name: "Test feed".to_owned(),
                url: "https://taxii.example.test/".to_owned(),
                feed_type: "taxii".to_owned(),
                enabled: true,
                update_frequency: 3600,
                credentials: None,
                headers: None,
                certificate_verification: true,
                proxy_url: None,
                last_updated: None,
                ioc_count: 0,
                status: "unknown".to_owned(),
                metadata: serde_json::json!({}),
            })
            .await
            .unwrap_or_else(|e| panic!("seed feed: {e}"));

        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);
        let res = server
            .get("/threat-intel/feeds")
            .authorization_bearer(token)
            .await;
        res.assert_status_ok();
        let body: Vec<ThreatFeed> = res.json();
        assert_eq!(body.len(), 1);
        assert_eq!(body[0].name, "Test feed");
    }
}
