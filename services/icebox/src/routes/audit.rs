//! `/api/v1/audit` — read-only audit trail, plus the shared `write_audit`
//! helper used by every mutating route. Rust port of
//! `icebox/services/flask-backend/api/v1/audit.py`.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{NaiveDateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::CurrentUser;
use crate::error::ApiError;
use crate::state::AppState;

/// Router for `/api/v1/audit`.
pub fn router() -> Router<AppState> {
    Router::new().route("/audit/log", get(get_audit_log))
}

/// Extracts the caller's address for audit logging. Every deployment sits
/// behind an ingress/Gateway, so the immediate TCP peer is always the
/// proxy — `X-Forwarded-For`'s first hop is the real client, matching what
/// v1's `request.remote_addr` observed running behind the same proxy tier.
fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .unwrap_or_default()
        .to_owned()
}

fn user_agent(headers: &HeaderMap) -> String {
    let ua = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    ua.chars().take(512).collect()
}

/// Inserts one `icebox_audit_log` row. Mirrors v1 `_write_audit`; failures
/// are logged, not propagated — an audit-write outage must never block the
/// operation it is recording (matches v1, which had no try/except here
/// only because PyDAL raised synchronously inside the same transaction as
/// the caller — this Rust port explicitly decouples the two so a slow/
/// down audit sink can't turn every mutation into a 500).
pub async fn write_audit(
    state: &AppState,
    actor_id: &str,
    action: &str,
    resource_id: &str,
    headers: &HeaderMap,
) {
    let result = sqlx::query(
        "INSERT INTO icebox_audit_log (id, actor_id, action, resource_type, resource_id, \
         ip_address, user_agent, created_at) VALUES ($1,$2,$3,'secret',$4,$5,$6,$7)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(actor_id)
    .bind(action)
    .bind(resource_id)
    .bind(client_ip(headers))
    .bind(user_agent(headers))
    .bind(Utc::now().naive_utc())
    .execute(&state.db)
    .await;
    if let Err(e) = result {
        tracing::warn!(error = %e, action, resource_id, "failed to write audit log entry");
    }
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    id: String,
    actor_id: String,
    action: String,
    resource_type: String,
    resource_id: Option<String>,
    ip_address: Option<String>,
    created_at: NaiveDateTime,
}

#[derive(Deserialize)]
struct AuditQuery {
    page: Option<i64>,
    per_page: Option<i64>,
    actor_id: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    action: Option<String>,
}

async fn get_audit_log(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(q): Query<AuditQuery>,
) -> Result<Json<Value>, ApiError> {
    user.require_scope("audit:read")?;

    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(50).clamp(1, 200);
    let offset = (page - 1) * per_page;

    let rows = sqlx::query_as::<_, AuditRow>(
        "SELECT id, actor_id, action, resource_type, resource_id, ip_address, created_at \
         FROM icebox_audit_log \
         WHERE ($1::text IS NULL OR actor_id = $1) \
           AND ($2::text IS NULL OR resource_type = $2) \
           AND ($3::text IS NULL OR resource_id = $3) \
           AND ($4::text IS NULL OR action = $4) \
         ORDER BY created_at DESC LIMIT $5 OFFSET $6",
    )
    .bind(&q.actor_id)
    .bind(&q.resource_type)
    .bind(&q.resource_id)
    .bind(&q.action)
    .bind(per_page)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM icebox_audit_log \
         WHERE ($1::text IS NULL OR actor_id = $1) \
           AND ($2::text IS NULL OR resource_type = $2) \
           AND ($3::text IS NULL OR resource_id = $3) \
           AND ($4::text IS NULL OR action = $4)",
    )
    .bind(&q.actor_id)
    .bind(&q.resource_type)
    .bind(&q.resource_id)
    .bind(&q.action)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(json!({
        "entries": rows.iter().map(|r| json!({
            "id": r.id,
            "actor_id": r.actor_id,
            "action": r.action,
            "resource_type": r.resource_type,
            "resource_id": r.resource_id,
            "ip_address": r.ip_address,
            "created_at": skauswatch_streams::py_isoformat(r.created_at),
        })).collect::<Vec<_>>(),
        "total": total,
        "page": page,
        "per_page": per_page,
    })))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn client_ip_takes_first_forwarded_hop() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.2.3.4, 5.6.7.8"),
        );
        assert_eq!(client_ip(&headers), "1.2.3.4");
    }

    #[test]
    fn client_ip_defaults_empty_without_header() {
        assert_eq!(client_ip(&HeaderMap::new()), "");
    }

    #[test]
    fn user_agent_is_truncated_to_512_chars() {
        let mut headers = HeaderMap::new();
        let long = "a".repeat(600);
        headers.insert(
            axum::http::header::USER_AGENT,
            HeaderValue::from_str(&long).expect("header value"),
        );
        assert_eq!(user_agent(&headers).len(), 512);
    }
}
