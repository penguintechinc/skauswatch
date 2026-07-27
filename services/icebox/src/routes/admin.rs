//! `/api/v1/admin` — license status and Master Encryption Key rotation.
//! Rust port of `icebox/services/flask-backend/api/v1/admin.py`.
//!
//! v1's DB-driven "set license key" endpoint (`POST /admin/license`) has no
//! v2 equivalent: entitlement is now resolved centrally by
//! `penguin-licensing` from `LICENSE_KEY`/PostHog at process startup, not a
//! per-request DB write (see `state.rs::ICEBOX_FLAG` and
//! `license_gate.rs`) — this is an intentional architecture change, not a
//! missing port, tracked in `docs/v2-port/icebox-crypto-gate.md`.

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::CurrentUser;
use crate::error::ApiError;
use crate::state::{AppState, ICEBOX_FLAG};

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
    let licensed = state.license.flag_enabled(ICEBOX_FLAG).await;
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
        select: "SELECT id, encrypted_dek, dek_version FROM icebox_secrets WHERE dek_version <> $1",
        update: "UPDATE icebox_secrets SET encrypted_dek = $1, dek_version = $2 WHERE id = $3",
    },
    RotatableTable {
        select: "SELECT id, encrypted_dek, dek_version FROM icebox_secret_versions WHERE dek_version <> $1",
        update: "UPDATE icebox_secret_versions SET encrypted_dek = $1, dek_version = $2 WHERE id = $3",
    },
    RotatableTable {
        select: "SELECT id, encrypted_dek, dek_version FROM icebox_one_time_secrets WHERE dek_version <> $1",
        update: "UPDATE icebox_one_time_secrets SET encrypted_dek = $1, dek_version = $2 WHERE id = $3",
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
            "MEK version {new_version} not loaded. Set ICEBOX_MEK_V{new_version} env var."
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

        let mut rotate_rows: Vec<skauswatch_icebox::RotateRow> = rows
            .iter()
            .map(|r| skauswatch_icebox::RotateRow {
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

    use super::*;

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
}
