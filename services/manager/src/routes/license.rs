//! GET /api/v1/license/features — the frontend entitlement contract.
//! Returns the license tier plus every known flag's decision so the unified
//! webui can gate nav/routes (UX only; enforcement stays server-side).
//!
//! Auth: requires a valid JWT (`CurrentUser`) — the webui only calls this
//! after login, and an unauthenticated caller shouldn't be able to enumerate
//! which paid features/flags a tenant has enabled (finding #7).

use std::collections::BTreeMap;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};

use crate::auth::CurrentUser;
use crate::flags;
use crate::state::AppState;

/// Router for license/entitlement endpoints.
pub fn router() -> Router<AppState> {
    Router::new().route("/license/features", get(license_features))
}

async fn license_features(
    State(state): State<AppState>,
    _user: CurrentUser,
) -> Json<serde_json::Value> {
    let info = state.license.validate().await;
    let tier = state.license.tier().await;

    let mut flag_map: BTreeMap<&'static str, bool> = BTreeMap::new();
    for key in flags::all_flags() {
        flag_map.insert(key, state.license.flag_enabled(key).await);
    }

    let features: BTreeMap<String, bool> = info
        .features
        .iter()
        .map(|f| (f.name.clone(), f.entitled))
        .collect();

    Json(serde_json::json!({
        "status": "success",
        "data": {
            "valid": info.valid,
            "tier": tier,
            "flags": flag_map,
            "features": features,
        },
        "meta": {
            "version": 1,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }
    }))
}

#[cfg(test)]
#[allow(clippy::panic)] // tests fail loudly by design
mod tests {
    use axum::http::StatusCode;

    use crate::state::AppStateInner;
    use penguin_licensing::{LicenseClient, LicenseConfig};

    fn test_server() -> axum_test::TestServer {
        // Dev-mode client (release_mode=false) — bypass grants everything
        // without touching the network.
        let cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("config: {e}"),
        };
        let client = match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("client: {e}"),
        };
        let state = AppStateInner::for_tests(client);
        let app = crate::routes::router(state);
        axum_test::TestServer::new(app)
    }

    /// Regression for finding #7: an unauthenticated caller must not be able
    /// to enumerate license tier/flags — the route now requires `CurrentUser`
    /// exactly like every other operator endpoint.
    #[tokio::test]
    async fn features_endpoint_requires_jwt() {
        let server = test_server();
        let res = server.get("/api/v1/license/features").await;
        res.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Missing or invalid authorization header");
    }

    #[tokio::test]
    async fn features_endpoint_rejects_garbage_bearer_token() {
        let server = test_server();
        let res = server
            .get("/api/v1/license/features")
            .add_header(axum::http::header::AUTHORIZATION, "Bearer not-a-jwt")
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Invalid token");
    }

    #[tokio::test]
    async fn features_endpoint_returns_tier_flags_and_features_when_authed() {
        let license = skauswatch_testkit::license::dev_license("skauswatch");
        let state = crate::routes::test_support::db_state(license).await;
        let (_, token) =
            crate::routes::test_support::authed_user(&state, "flags@example.com", "viewer").await;
        let app = crate::routes::router(state);
        let server = axum_test::TestServer::new(app);

        let res = server
            .get("/api/v1/license/features")
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["status"], "success");
        assert_eq!(body["data"]["valid"], true);
        assert!(body["data"]["flags"].is_object());
        assert!(
            body["data"]["flags"]
                .as_object()
                .is_some_and(|m| m.contains_key("skauswatch.s3-scan"))
        );
        assert!(body["data"]["features"].is_object());
        assert_eq!(body["meta"]["version"], 1);
        assert!(body["meta"]["timestamp"].is_string());
    }
}
