//! Common REST handlers (v1 `api/v1/common.py`): statistics, combined CA
//! info, audit log, expiring certificates, and expired-status cleanup.

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Query, State};
use chrono::{Duration, Utc};
use serde_json::Value;
use skauswatch_streams::{py_isoformat, py_isoformat_opt};
use sqlx::{QueryBuilder, Row};
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::AppState;

/// GET /api/v1/statistics — combined X.509 + SSH counts.
pub async fn statistics(State(st): State<AppState>) -> Result<Json<Value>, ApiError> {
    Ok(Json(st.manager.statistics().await?))
}

/// GET /api/v1/ca/info — info for both certificate authorities.
pub async fn all_ca_info(State(st): State<AppState>) -> Json<Value> {
    let info = st.manager.x509.info();
    Json(serde_json::json!({
        "x509": {
            "subject": info.subject,
            "issuer": info.issuer,
            "not_before": py_isoformat(info.not_before),
            "not_after": py_isoformat(info.not_after),
            "fingerprint_sha256": info.fingerprint_sha256,
            "serial_counter": st.manager.x509.serial_counter(),
            "crl_number": st.manager.x509.crl_number(),
        },
        "ssh": {
            "ca_public_key": st.manager.ssh.ca_public_key(),
            "key_type": st.manager.ssh.ca_key_type(),
            "fingerprint": st.manager.ssh.ca_fingerprint(),
            "serial_counter": st.manager.ssh.serial_counter(),
            "krl_version": st.manager.ssh.krl_version(),
        },
    }))
}

/// GET /api/v1/audit — paginated PKI audit log with filters.
pub async fn audit(
    State(st): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let page: i64 = q.get("page").and_then(|v| v.parse().ok()).unwrap_or(1);
    let page_size: i64 = q
        .get("page_size")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    let event_type = q.get("event_type").map(String::as_str);
    let cert_type = q.get("certificate_type").map(String::as_str);

    let mut count = QueryBuilder::new("SELECT COUNT(*) FROM pki_audit_log");
    push_audit_filters(&mut count, event_type, cert_type);
    let total: i64 = count.build().fetch_one(st.manager.db()).await?.try_get(0)?;

    let mut qb = QueryBuilder::new(
        "SELECT id, event_type, certificate_type, certificate_id, serial_number, subject, \
         actor_id, action, status, error_message, timestamp FROM pki_audit_log",
    );
    push_audit_filters(&mut qb, event_type, cert_type);
    qb.push(" ORDER BY timestamp DESC LIMIT ")
        .push_bind(page_size)
        .push(" OFFSET ")
        .push_bind((page - 1).max(0) * page_size);
    let rows = qb.build().fetch_all(st.manager.db()).await?;

    let audit_log: Vec<Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.try_get::<Uuid, _>("id").map(|u| u.to_string()).unwrap_or_default(),
                "event_type": r.try_get::<String, _>("event_type").unwrap_or_default(),
                "certificate_type": r.try_get::<Option<String>, _>("certificate_type").unwrap_or(None),
                "certificate_id": r.try_get::<Option<Uuid>, _>("certificate_id").ok().flatten().map(|u| u.to_string()),
                "serial_number": r.try_get::<Option<String>, _>("serial_number").unwrap_or(None),
                "subject": r.try_get::<Option<String>, _>("subject").unwrap_or(None),
                "actor_id": r.try_get::<Option<Uuid>, _>("actor_id").ok().flatten().map(|u| u.to_string()),
                "action": r.try_get::<String, _>("action").unwrap_or_default(),
                "status": r.try_get::<String, _>("status").unwrap_or_default(),
                "error_message": r.try_get::<Option<String>, _>("error_message").unwrap_or(None),
                "timestamp": py_isoformat_opt(r.try_get("timestamp").ok().flatten()),
            })
        })
        .collect();
    let pages = if page_size > 0 {
        (total + page_size - 1) / page_size
    } else {
        0
    };
    Ok(Json(serde_json::json!({
        "audit_log": audit_log,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
    })))
}

/// GET /api/v1/expiring — certificates expiring within N days.
pub async fn expiring(
    State(st): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let days: i64 = q.get("days").and_then(|v| v.parse().ok()).unwrap_or(30);
    let cert_type = q.get("type").map(String::as_str).unwrap_or("all");
    let now = Utc::now().naive_utc();
    let before = now + Duration::days(days);

    let mut result = serde_json::json!({
        "expiring_within_days": days,
        "x509": [],
        "ssh": [],
    });

    if cert_type == "x509" || cert_type == "all" {
        let rows = sqlx::query(
            "SELECT id, serial_number, subject, not_after FROM x509_certificates \
             WHERE status='active' AND not_after < $1 AND not_after > $2 ORDER BY not_after",
        )
        .bind(before)
        .bind(now)
        .fetch_all(st.manager.db())
        .await?;
        result["x509"] = rows
            .iter()
            .map(|r| {
                let na: chrono::NaiveDateTime = r.try_get("not_after").unwrap_or(now);
                serde_json::json!({
                    "id": r.try_get::<Uuid, _>("id").map(|u| u.to_string()).unwrap_or_default(),
                    "serial_number": r.try_get::<String, _>("serial_number").unwrap_or_default(),
                    "subject": r.try_get::<String, _>("subject").unwrap_or_default(),
                    "not_after": py_isoformat(na),
                    "days_until_expiry": (na - now).num_days(),
                })
            })
            .collect();
    }
    if cert_type == "ssh" || cert_type == "all" {
        let rows = sqlx::query(
            "SELECT id, serial_number, key_id, valid_before FROM ssh_certificates \
             WHERE status='active' AND valid_before < $1 AND valid_before > $2 ORDER BY valid_before",
        )
        .bind(before)
        .bind(now)
        .fetch_all(st.manager.db())
        .await?;
        result["ssh"] = rows
            .iter()
            .map(|r| {
                let vb: chrono::NaiveDateTime = r.try_get("valid_before").unwrap_or(now);
                serde_json::json!({
                    "id": r.try_get::<Uuid, _>("id").map(|u| u.to_string()).unwrap_or_default(),
                    "serial_number": r.try_get::<String, _>("serial_number").unwrap_or_default(),
                    "key_id": r.try_get::<String, _>("key_id").unwrap_or_default(),
                    "valid_before": py_isoformat(vb),
                    "days_until_expiry": (vb - now).num_days(),
                })
            })
            .collect();
    }
    Ok(Json(result))
}

/// POST /api/v1/cleanup — mark expired certificates as `expired`.
pub async fn cleanup(State(st): State<AppState>) -> Result<Json<Value>, ApiError> {
    let now = Utc::now().naive_utc();
    let x = sqlx::query(
        "UPDATE x509_certificates SET status='expired', updated_at=$1 \
         WHERE status='active' AND not_after < $1",
    )
    .bind(now)
    .execute(st.manager.db())
    .await?
    .rows_affected();
    let s = sqlx::query(
        "UPDATE ssh_certificates SET status='expired', updated_at=$1 \
         WHERE status='active' AND valid_before < $1",
    )
    .bind(now)
    .execute(st.manager.db())
    .await?
    .rows_affected();
    Ok(Json(serde_json::json!({
        "message": "Cleanup completed",
        "updated_count": x + s,
    })))
}

fn push_audit_filters(
    qb: &mut QueryBuilder<sqlx::Postgres>,
    event_type: Option<&str>,
    cert_type: Option<&str>,
) {
    let mut first = true;
    let mut sep = |qb: &mut QueryBuilder<sqlx::Postgres>| {
        qb.push(if first { " WHERE " } else { " AND " });
        first = false;
    };
    if let Some(e) = event_type {
        sep(qb);
        qb.push("event_type = ").push_bind(e.to_owned());
    }
    if let Some(c) = cert_type {
        sep(qb);
        qb.push("certificate_type = ").push_bind(c.to_owned());
    }
}
