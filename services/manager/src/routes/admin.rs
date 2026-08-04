//! /api/v1/admin — super-admin-only operational controls. Currently one
//! surface: the SPIFFE SVID TTL policy (`GET`/`PUT /admin/svid-ttl`,
//! `docs/v2-port/service-auth-model.md`) that governs how long SPIRE-issued
//! X.509-SVIDs and JWT-SVIDs live before rotation. The webui's
//! `SvidTtlSettings` panel (`services/webui/src/client/components/
//! SvidTtlSettings.tsx`) is already built to this exact wire contract.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};

use crate::auth::CurrentUser;
use crate::error::{ApiError, ApiJson, ErrorResponse, ValidationErrorResponse};
use crate::state::AppState;

/// Fallback/advertised default TTL (seconds) when no row has ever been
/// persisted — matches the webui's own `FALLBACK_DEFAULT_SECONDS`.
const DEFAULT_SVID_TTL_SECONDS: i64 = 300;
/// Hard floor on either TTL field — matches the webui's
/// `FALLBACK_MIN_SECONDS`.
const MIN_SVID_TTL_SECONDS: i64 = 60;
/// Hard ceiling on either TTL field — matches the webui's
/// `FALLBACK_MAX_SECONDS`.
const MAX_SVID_TTL_SECONDS: i64 = 86_400;

/// Router for /api/v1/admin.
pub fn router() -> Router<AppState> {
    Router::new().route("/admin/svid-ttl", get(get_svid_ttl).put(update_svid_ttl))
}

fn validation(field: &str, msg: &str) -> ApiError {
    ApiError::Validation(vec![serde_json::json!({
        "loc": [field], "msg": msg, "type": "value_error"
    })])
}

/// GET/PUT wire shape — identical on both directions per the webui contract
/// (`services/webui/src/client/types/svidTtl.ts::SvidTtlSettings`).
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct SvidTtlSettings {
    x509_ttl_seconds: i64,
    jwt_ttl_seconds: i64,
    default_seconds: i64,
    min_seconds: i64,
    max_seconds: i64,
}

impl SvidTtlSettings {
    fn from_values(x509_ttl_seconds: i64, jwt_ttl_seconds: i64) -> Self {
        Self {
            x509_ttl_seconds,
            jwt_ttl_seconds,
            default_seconds: DEFAULT_SVID_TTL_SECONDS,
            min_seconds: MIN_SVID_TTL_SECONDS,
            max_seconds: MAX_SVID_TTL_SECONDS,
        }
    }
}

/// GET /admin/svid-ttl — super_admin only. Reads the singleton row if one
/// has ever been persisted, else reports the documented defaults without
/// requiring a seed migration to insert one.
#[utoipa::path(
    get,
    path = "/api/v1/admin/svid-ttl",
    tag = "admin",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Current SVID TTL policy", body = SvidTtlSettings),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions — super_admin required", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_svid_ttl(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<SvidTtlSettings>, ApiError> {
    user.require_role(&["super_admin"])?;

    let row: Option<(i32, i32)> = sqlx::query_as(
        "SELECT x509_ttl_seconds, jwt_ttl_seconds FROM svid_ttl_settings WHERE id = 1",
    )
    .fetch_optional(&state.db)
    .await?;

    let (x509_ttl_seconds, jwt_ttl_seconds) = row
        .map(|(x509, jwt)| (i64::from(x509), i64::from(jwt)))
        .unwrap_or((DEFAULT_SVID_TTL_SECONDS, DEFAULT_SVID_TTL_SECONDS));
    Ok(Json(SvidTtlSettings::from_values(
        x509_ttl_seconds,
        jwt_ttl_seconds,
    )))
}

/// PUT /admin/svid-ttl body — both fields required, each independently
/// bounds-checked against [`MIN_SVID_TTL_SECONDS`, `MAX_SVID_TTL_SECONDS`].
#[derive(serde::Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateSvidTtlRequest {
    x509_ttl_seconds: Option<i64>,
    jwt_ttl_seconds: Option<i64>,
}

/// Validates one TTL field: required, integer, in `[MIN, MAX]` seconds.
fn validate_ttl(v: Option<i64>, field: &str) -> Result<i64, ApiError> {
    let Some(v) = v else {
        return Err(validation(field, "Field required"));
    };
    if !(MIN_SVID_TTL_SECONDS..=MAX_SVID_TTL_SECONDS).contains(&v) {
        return Err(validation(
            field,
            &format!(
                "Must be an integer between {MIN_SVID_TTL_SECONDS} and \
                 {MAX_SVID_TTL_SECONDS} seconds"
            ),
        ));
    }
    Ok(v)
}

/// Applies newly-persisted SVID TTLs to SPIRE's Server Entry API
/// (`UpdateEntry` `x509SvidTtl`/`jwtSvidTtl`) — the seam a future pass wires
/// a real SPIRE Server API client into. No such client exists in this repo
/// today (the Server API is an upstream SPIRE surface, not one skauswatch
/// defines itself, and building/vendoring its proto is out of scope here);
/// this deliberately never blocks or fails the request that already
/// persisted the setting to the database (the source of truth for GET going
/// forward regardless of whether SPIRE's own registration entries have been
/// updated to match yet) — same fail-safe posture as every other
/// SPIRE/identity-adjacent fallback in this crate: log a warning, never
/// crash or 500 on an unreachable/unimplemented control plane.
async fn apply_svid_ttl_to_spire(state: &AppState, x509_ttl_seconds: i64, jwt_ttl_seconds: i64) {
    match &state.identity {
        Some(identity) if identity.has_identity() => {
            tracing::warn!(
                x509_ttl_seconds,
                jwt_ttl_seconds,
                "SVID TTL settings persisted to the database; SPIRE Server Entry \
                 API UpdateEntry apply is not yet implemented (no in-repo SPIRE \
                 Server API client) — update SPIRE's registration entries out of \
                 band until this seam is wired to a real client"
            );
        }
        _ => {
            tracing::warn!(
                x509_ttl_seconds,
                jwt_ttl_seconds,
                "no SPIFFE workload identity held — skipping SPIRE Server API apply \
                 (dev/test only; production hard-fails at startup before ever \
                 reaching this fallback)"
            );
        }
    }
}

/// PUT /admin/svid-ttl — super_admin only; validates both fields, persists
/// the singleton row (insert-or-update), and best-effort applies the change
/// to SPIRE (see [`apply_svid_ttl_to_spire`] — never blocks the response).
#[utoipa::path(
    put,
    path = "/api/v1/admin/svid-ttl",
    tag = "admin",
    security(("bearer_jwt" = [])),
    request_body = UpdateSvidTtlRequest,
    responses(
        (status = 200, description = "Updated SVID TTL policy", body = SvidTtlSettings),
        (status = 400, description = "Validation error", body = ValidationErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions — super_admin required", body = ErrorResponse),
    ),
)]
pub(crate) async fn update_svid_ttl(
    State(state): State<AppState>,
    user: CurrentUser,
    ApiJson(body): ApiJson<UpdateSvidTtlRequest>,
) -> Result<Json<SvidTtlSettings>, ApiError> {
    user.require_role(&["super_admin"])?;

    let x509_ttl_seconds = validate_ttl(body.x509_ttl_seconds, "x509_ttl_seconds")?;
    let jwt_ttl_seconds = validate_ttl(body.jwt_ttl_seconds, "jwt_ttl_seconds")?;

    sqlx::query(
        "INSERT INTO svid_ttl_settings (id, x509_ttl_seconds, jwt_ttl_seconds, updated_by, \
         updated_at) VALUES (1, $1, $2, $3, now()) \
         ON CONFLICT (id) DO UPDATE SET x509_ttl_seconds = $1, jwt_ttl_seconds = $2, \
         updated_by = $3, updated_at = now()",
    )
    .bind(x509_ttl_seconds as i32)
    .bind(jwt_ttl_seconds as i32)
    .bind(user.id)
    .execute(&state.db)
    .await?;

    apply_svid_ttl_to_spire(&state, x509_ttl_seconds, jwt_ttl_seconds).await;

    Ok(Json(SvidTtlSettings::from_values(
        x509_ttl_seconds,
        jwt_ttl_seconds,
    )))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use axum::http::StatusCode;

    use super::*;
    use crate::routes::test_support::{authed_user, db_state, seed_super_admin};

    fn dev_license() -> std::sync::Arc<penguin_licensing::LicenseClient> {
        skauswatch_testkit::license::dev_license("skauswatch")
    }

    async fn server_for(state: AppState) -> axum_test::TestServer {
        let app = axum::Router::new()
            .nest("/api/v1", router())
            .with_state(state);
        axum_test::TestServer::new(app)
    }

    #[tokio::test]
    async fn get_and_put_require_super_admin() {
        let state = db_state(dev_license()).await;
        let (_, admin_tok) = authed_user(&state, "svid-admin@example.com", "admin").await;
        let server = server_for(state).await;

        let get_res = server
            .get("/api/v1/admin/svid-ttl")
            .authorization_bearer(&admin_tok)
            .await;
        get_res.assert_status(StatusCode::FORBIDDEN);

        let put_res = server
            .put("/api/v1/admin/svid-ttl")
            .authorization_bearer(&admin_tok)
            .json(&serde_json::json!({"x509_ttl_seconds": 600, "jwt_ttl_seconds": 600}))
            .await;
        put_res.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn get_reports_defaults_before_any_write() {
        let state = db_state(dev_license()).await;
        let (_, super_tok) = seed_super_admin(&state, "svid-root@example.com").await;
        let server = server_for(state).await;

        let res = server
            .get("/api/v1/admin/svid-ttl")
            .authorization_bearer(&super_tok)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["x509_ttl_seconds"], 300);
        assert_eq!(body["jwt_ttl_seconds"], 300);
        assert_eq!(body["default_seconds"], 300);
        assert_eq!(body["min_seconds"], 60);
        assert_eq!(body["max_seconds"], 86_400);
    }

    #[tokio::test]
    async fn put_persists_then_get_reflects_it() {
        let state = db_state(dev_license()).await;
        let (_, super_tok) = seed_super_admin(&state, "svid-root2@example.com").await;
        let server = server_for(state).await;

        let put_res = server
            .put("/api/v1/admin/svid-ttl")
            .authorization_bearer(&super_tok)
            .json(&serde_json::json!({"x509_ttl_seconds": 1800, "jwt_ttl_seconds": 900}))
            .await;
        put_res.assert_status_ok();
        let body: serde_json::Value = put_res.json();
        assert_eq!(body["x509_ttl_seconds"], 1800);
        assert_eq!(body["jwt_ttl_seconds"], 900);

        let get_res = server
            .get("/api/v1/admin/svid-ttl")
            .authorization_bearer(&super_tok)
            .await;
        get_res.assert_status_ok();
        let body: serde_json::Value = get_res.json();
        assert_eq!(body["x509_ttl_seconds"], 1800);
        assert_eq!(body["jwt_ttl_seconds"], 900);

        // A second PUT (update, not insert) must overwrite cleanly.
        let put_again = server
            .put("/api/v1/admin/svid-ttl")
            .authorization_bearer(&super_tok)
            .json(&serde_json::json!({"x509_ttl_seconds": 120, "jwt_ttl_seconds": 120}))
            .await;
        put_again.assert_status_ok();
        let get_final = server
            .get("/api/v1/admin/svid-ttl")
            .authorization_bearer(&super_tok)
            .await;
        let body: serde_json::Value = get_final.json();
        assert_eq!(body["x509_ttl_seconds"], 120);
        assert_eq!(body["jwt_ttl_seconds"], 120);
    }

    #[tokio::test]
    async fn put_rejects_out_of_bounds_and_missing_fields() {
        let state = db_state(dev_license()).await;
        let (_, super_tok) = seed_super_admin(&state, "svid-root3@example.com").await;
        let server = server_for(state).await;

        for body in [
            serde_json::json!({"x509_ttl_seconds": 59, "jwt_ttl_seconds": 300}),
            serde_json::json!({"x509_ttl_seconds": 86_401, "jwt_ttl_seconds": 300}),
            serde_json::json!({"x509_ttl_seconds": 300, "jwt_ttl_seconds": 0}),
            serde_json::json!({"x509_ttl_seconds": 300}),
            serde_json::json!({}),
        ] {
            let res = server
                .put("/api/v1/admin/svid-ttl")
                .authorization_bearer(&super_tok)
                .json(&body)
                .await;
            res.assert_status(StatusCode::BAD_REQUEST);
        }

        // Bounds are inclusive.
        let ok = server
            .put("/api/v1/admin/svid-ttl")
            .authorization_bearer(&super_tok)
            .json(&serde_json::json!({"x509_ttl_seconds": 60, "jwt_ttl_seconds": 86_400}))
            .await;
        ok.assert_status_ok();
    }

    #[tokio::test]
    async fn apply_to_spire_never_panics_without_a_held_identity() {
        // Regression for the fail-safe seam: no identity at all (the default
        // test constructor) must log-and-return, never crash the request
        // that already committed the DB write above.
        let state = db_state(dev_license()).await;
        assert!(state.identity.is_none());
        apply_svid_ttl_to_spire(&state, 300, 300).await;
    }
}
