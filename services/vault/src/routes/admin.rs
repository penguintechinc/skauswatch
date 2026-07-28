//! `/api/v1/admin` — license status and Master Encryption Key rotation.
//! Rust port of `icebox/services/flask-backend/api/v1/admin.py`.
//!
//! v1's DB-driven "set license key" endpoint (`POST /admin/license`) has no
//! v2 equivalent: entitlement is now resolved centrally by
//! `penguin-licensing` from `LICENSE_KEY`/PostHog at process startup, not a
//! per-request DB write (see `state.rs::VAULT_FLAG` and
//! `license_gate.rs`) — this is an intentional architecture change, not a
//! missing port, tracked in `docs/v2-port/vault-crypto-gate.md`.

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::CurrentUser;
use crate::error::ApiError;
use crate::state::{AppState, VAULT_FLAG};

/// Router for `/api/v1/admin`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/license", get(get_license_status))
        .route("/admin/mek/rotate", post(rotate_mek))
}

async fn get_license_status(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<Value>, ApiError> {
    user.require_scope("secrets:admin")?;
    let info = state.license.validate().await;
    let tier = state.license.tier().await;
    let licensed = state.license.flag_enabled(VAULT_FLAG).await;
    Ok(Json(json!({
        "licensed": licensed,
        "bypassed": state.license.bypass_active(),
        "tier": tier,
        "validated_at": info.issued_at.map(|t| t.to_rfc3339()),
        "license_server_url": state.license.config().server_url.to_string(),
    })))
}

#[derive(Deserialize)]
struct RotateMekBody {
    new_mek_version: Option<u32>,
}

/// One rotatable table's fixed (compile-time-literal) select/update SQL —
/// sqlx 0.9 forbids building query strings from runtime data
/// (`SqlSafeStr`), so each table gets its own `&'static str` pair instead
/// of a `format!`-interpolated table name.
struct RotatableTable {
    select: &'static str,
    update: &'static str,
}

/// Tables whose `encrypted_dek`/`dek_version` are re-wrapped on rotation —
/// matches v1 `rotate_mek`'s `_collect_rows` call sites.
const ROTATABLE_TABLES: &[RotatableTable] = &[
    RotatableTable {
        select: "SELECT id, encrypted_dek, dek_version FROM vault_secrets WHERE dek_version <> $1",
        update: "UPDATE vault_secrets SET encrypted_dek = $1, dek_version = $2 WHERE id = $3",
    },
    RotatableTable {
        select: "SELECT id, encrypted_dek, dek_version FROM vault_secret_versions WHERE dek_version <> $1",
        update: "UPDATE vault_secret_versions SET encrypted_dek = $1, dek_version = $2 WHERE id = $3",
    },
    RotatableTable {
        select: "SELECT id, encrypted_dek, dek_version FROM vault_one_time_secrets WHERE dek_version <> $1",
        update: "UPDATE vault_one_time_secrets SET encrypted_dek = $1, dek_version = $2 WHERE id = $3",
    },
];

async fn rotate_mek(
    State(state): State<AppState>,
    user: CurrentUser,
    body: Option<Json<RotateMekBody>>,
) -> Result<Json<Value>, ApiError> {
    user.require_scope("secrets:admin")?;

    let new_version = body
        .and_then(|Json(b)| b.new_mek_version)
        .ok_or_else(|| ApiError::BadRequest("new_mek_version is required".to_owned()))?;

    if !state.envelope.read().await.has_mek_version(new_version) {
        return Err(ApiError::BadRequest(format!(
            "MEK version {new_version} not loaded. Set VAULT_MEK_V{new_version} env var."
        )));
    }

    #[derive(sqlx::FromRow)]
    struct DekRow {
        id: String,
        encrypted_dek: String,
        dek_version: i32,
    }

    let mut total_updated = 0usize;
    for table in ROTATABLE_TABLES {
        let rows = sqlx::query_as::<_, DekRow>(table.select)
            .bind(new_version as i32)
            .fetch_all(&state.db)
            .await?;
        if rows.is_empty() {
            continue;
        }

        let mut rotate_rows: Vec<skauswatch_vault::RotateRow> = rows
            .iter()
            .map(|r| skauswatch_vault::RotateRow {
                id: r.id.clone(),
                encrypted_dek: r.encrypted_dek.clone(),
                dek_version: r.dek_version as u32,
            })
            .collect();

        let updated = {
            let mut enc = state.envelope.write().await;
            enc.rotate_mek(new_version, &mut rotate_rows)?
        };
        total_updated += updated;

        for row in &rotate_rows {
            sqlx::query(table.update)
                .bind(&row.encrypted_dek)
                .bind(row.dek_version as i32)
                .bind(&row.id)
                .execute(&state.db)
                .await?;
        }
    }

    tracing::warn!(
        rows_updated = total_updated,
        new_version,
        actor = %user.user_id,
        "MEK rotation complete"
    );

    Ok(Json(json!({
        "rows_updated": total_updated,
        "new_version": new_version,
        "rotated_at": skauswatch_streams::py_now_isoformat(),
    })))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashSet;

    use axum_test::TestServer;
    use skauswatch_testkit::license::{dev_license, gated_license};

    use super::*;
    use crate::routes::test_support::{db_state, db_state_with_envelope, sign_token};

    #[test]
    fn admin_scope_is_required() {
        let user = CurrentUser {
            user_id: "u".into(),
            tenant_id: "default".into(),
            scopes: HashSet::new(),
            raw_token: "t".into(),
        };
        assert!(user.require_scope("secrets:admin").is_err());
    }

    fn test_server_with_state(state: crate::state::AppState) -> TestServer {
        let app = axum::Router::new()
            .nest("/api/v1", router())
            .with_state(state);
        TestServer::new(app)
    }

    /// The full merged `/api/v1` router (every route module + license
    /// gate) — needed by tests that exercise both `admin` and another
    /// module's routes (e.g. seeding a secret via `secrets::router()`
    /// before rotating its DEK). `dev_license` bypasses the gate.
    fn full_router_server(state: crate::state::AppState) -> TestServer {
        TestServer::new(crate::routes::router(state))
    }

    #[tokio::test]
    async fn get_license_status_requires_admin_scope() {
        let state = db_state(dev_license("skauswatch")).await;
        let token = sign_token(&state, "u", "secrets:read");
        let server = test_server_with_state(state);
        server
            .get("/api/v1/admin/license")
            .authorization_bearer(&token)
            .await
            .assert_status(axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn get_license_status_reflects_flag_state() {
        let licensed_state = db_state(dev_license("skauswatch")).await;
        let licensed_token = sign_token(&licensed_state, "u", "secrets:admin");
        let licensed_server = test_server_with_state(licensed_state);
        let licensed_resp = licensed_server
            .get("/api/v1/admin/license")
            .authorization_bearer(&licensed_token)
            .await;
        licensed_resp.assert_status_ok();
        let licensed_body: Value = licensed_resp.json();
        assert_eq!(licensed_body["licensed"], true);
        assert!(
            licensed_body["license_server_url"]
                .as_str()
                .unwrap_or_default()
                .starts_with("http")
        );

        let gated_state = db_state(gated_license("skauswatch")).await;
        let gated_token = sign_token(&gated_state, "u", "secrets:admin");
        let gated_server = test_server_with_state(gated_state);
        let gated_resp = gated_server
            .get("/api/v1/admin/license")
            .authorization_bearer(&gated_token)
            .await;
        gated_resp.assert_status_ok();
        assert_eq!(gated_resp.json::<Value>()["licensed"], false);
    }

    #[tokio::test]
    async fn rotate_mek_validates_request_before_touching_db() {
        let state = db_state(dev_license("skauswatch")).await;
        let token = sign_token(&state, "u", "secrets:admin");
        let server = test_server_with_state(state);

        let missing_version = server
            .post("/api/v1/admin/mek/rotate")
            .authorization_bearer(&token)
            .json(&json!({}))
            .await;
        missing_version.assert_status(axum::http::StatusCode::BAD_REQUEST);

        let unloaded_version = server
            .post("/api/v1/admin/mek/rotate")
            .authorization_bearer(&token)
            .json(&json!({"new_mek_version": 99}))
            .await;
        unloaded_version.assert_status(axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn rotate_mek_rewraps_deks_across_every_rotatable_table() {
        let state = db_state_with_envelope(
            dev_license("skauswatch"),
            crate::routes::test_support::test_envelope_two_versions(),
        )
        .await;
        let write_token = sign_token(&state, "owner-1", "secrets:write secrets:read");
        let admin_token = sign_token(&state, "owner-1", "secrets:admin");
        let server = full_router_server(state.clone());

        let created = server
            .post("/api/v1/secrets")
            .authorization_bearer(&write_token)
            .json(&json!({"name": "rotatable", "value": "top-secret"}))
            .await;
        created.assert_status(axum::http::StatusCode::CREATED);
        let secret_id = created.json::<Value>()["id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        let one_time = server
            .post("/api/v1/one-time-secrets")
            .authorization_bearer(&write_token)
            .json(&json!({"value": "share-me"}))
            .await;
        one_time.assert_status(axum::http::StatusCode::CREATED);

        let before: (i32,) = sqlx::query_as("SELECT dek_version FROM vault_secrets WHERE id = $1")
            .bind(&secret_id)
            .fetch_one(&state.db)
            .await
            .unwrap_or_else(|e| panic!("read dek_version: {e}"));
        assert_eq!(before.0, 1);

        let rotated = server
            .post("/api/v1/admin/mek/rotate")
            .authorization_bearer(&admin_token)
            .json(&json!({"new_mek_version": 2}))
            .await;
        rotated.assert_status_ok();
        let rotated_body: Value = rotated.json();
        assert_eq!(rotated_body["new_version"], 2);
        // vault_secrets (1 row) + vault_secret_versions (1 row) +
        // vault_one_time_secrets (1 row) = 3 rows rewrapped.
        assert_eq!(rotated_body["rows_updated"], 3);

        let after: (i32,) = sqlx::query_as("SELECT dek_version FROM vault_secrets WHERE id = $1")
            .bind(&secret_id)
            .fetch_one(&state.db)
            .await
            .unwrap_or_else(|e| panic!("read dek_version: {e}"));
        assert_eq!(after.0, 2);

        // The secret's ciphertext is untouched by rotation — only the DEK
        // wrapping changes — so the value must still round-trip correctly
        // through the ordinary read path after rotation.
        let value_resp = server
            .get(&format!("/api/v1/secrets/{secret_id}/value"))
            .authorization_bearer(&write_token)
            .await;
        value_resp.assert_status_ok();
        assert_eq!(value_resp.json::<Value>()["value"], "top-secret");
    }
}
