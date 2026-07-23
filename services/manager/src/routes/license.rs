//! GET /api/v1/license/features — the frontend entitlement contract.
//! Returns the license tier plus every known flag's decision so the unified
//! webui can gate nav/routes (UX only; enforcement stays server-side).

use std::collections::BTreeMap;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};

use crate::flags;
use crate::state::AppState;

/// Router for license/entitlement endpoints.
pub fn router() -> Router<AppState> {
    Router::new().route("/license/features", get(license_features))
}

async fn license_features(State(state): State<AppState>) -> Json<serde_json::Value> {
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
    use crate::state::AppStateInner;
    use penguin_licensing::{LicenseClient, LicenseConfig};

    #[tokio::test]
    async fn features_endpoint_reports_tier_and_flags() {
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
        let server = axum_test::TestServer::new(app);

        let res = server.get("/api/v1/license/features").await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["status"], "success");
        assert_eq!(body["data"]["tier"], "enterprise"); // dev bypass
        assert_eq!(body["data"]["flags"]["skauswatch.icebox"], true);
        assert!(body["meta"]["timestamp"].is_string());
    }
}
