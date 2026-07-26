//! X.509 REST handlers (v1 `api/v1/x509.py`, blueprint prefix
//! `/api/v1/certificates`).

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::Value;

use crate::error::{ApiError, ApiJson};
use crate::models::{RevokeRequest, X509CertificateRequest};
use crate::state::AppState;

use super::{page_params, user_id};

fn paginated(items: Vec<Value>, total: i64, page: i64, page_size: i64) -> Json<Value> {
    let pages = if page_size > 0 {
        (total + page_size - 1) / page_size
    } else {
        0
    };
    Json(serde_json::json!({
        "certificates": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
    }))
}

/// POST /api/v1/certificates — issue an X.509 certificate.
pub async fn issue(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: ApiJson<X509CertificateRequest>,
) -> Result<Response, ApiError> {
    let req = body.0;
    req.validate().map_err(ApiError::Validation)?;
    let params = req.into_issue_params();
    let result = st
        .manager
        .issue_x509(params, user_id(&headers).as_deref())
        .await?;
    Ok((StatusCode::CREATED, Json(result)).into_response())
}

/// GET /api/v1/certificates/{cert_id}
pub async fn get_cert(
    State(st): State<AppState>,
    Path(cert_id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let include_pk = q
        .get("include_private_key")
        .map(|v| v == "true")
        .unwrap_or(false);
    let mut cert = st
        .manager
        .get_x509(Some(&cert_id), None, true)
        .await?
        .ok_or_else(|| ApiError::NotFound("Certificate not found".into()))?;
    #[allow(clippy::collapsible_if)]
    if !include_pk {
        if let Some(o) = cert.as_object_mut() {
            o.remove("private_key_pem");
        }
    }
    Ok(Json(cert))
}

/// GET /api/v1/certificates/serial/{serial}
pub async fn get_by_serial(
    State(st): State<AppState>,
    Path(serial): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let mut cert = st
        .manager
        .get_x509(None, Some(&serial), true)
        .await?
        .ok_or_else(|| ApiError::NotFound("Certificate not found".into()))?;
    if let Some(o) = cert.as_object_mut() {
        o.remove("private_key_pem");
    }
    Ok(Json(cert))
}

/// POST /api/v1/certificates/{cert_id}/revoke
pub async fn revoke_cert(
    State(st): State<AppState>,
    Path(cert_id): Path<String>,
    headers: HeaderMap,
    body: ApiJson<RevokeRequest>,
) -> Result<Json<Value>, ApiError> {
    let ok = st
        .manager
        .revoke_x509(
            Some(&cert_id),
            None,
            &body.0.reason,
            user_id(&headers).as_deref(),
        )
        .await?;
    if !ok {
        return Err(ApiError::NotFound("Certificate not found".into()));
    }
    Ok(Json(serde_json::json!({
        "message": "Certificate revoked",
        "certificate_id": cert_id,
    })))
}

/// POST /api/v1/certificates/serial/{serial}/revoke
pub async fn revoke_by_serial(
    State(st): State<AppState>,
    Path(serial): Path<String>,
    headers: HeaderMap,
    body: ApiJson<RevokeRequest>,
) -> Result<Json<Value>, ApiError> {
    let ok = st
        .manager
        .revoke_x509(
            None,
            Some(&serial),
            &body.0.reason,
            user_id(&headers).as_deref(),
        )
        .await?;
    if !ok {
        return Err(ApiError::NotFound("Certificate not found".into()));
    }
    Ok(Json(serde_json::json!({
        "message": "Certificate revoked",
        "serial_number": serial,
    })))
}

/// GET /api/v1/certificates — list with filters.
pub async fn list(
    State(st): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let (page, page_size) = page_params(&q);
    let expires_before = q
        .get("expires_before")
        .and_then(|v| chrono::NaiveDateTime::parse_from_str(v, "%Y-%m-%dT%H:%M:%S").ok());
    let (items, total) = st
        .manager
        .list_x509(
            q.get("status").map(String::as_str),
            q.get("subject").map(String::as_str),
            expires_before,
            page,
            page_size,
        )
        .await?;
    Ok(paginated(items, total, page, page_size))
}

/// Body for POST /api/v1/certificates/search (v1 `CertificateSearchRequest`).
#[derive(Deserialize, Default)]
pub struct SearchBody {
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    expires_before: Option<String>,
    #[serde(default = "one")]
    page: i64,
    #[serde(default = "fifty")]
    page_size: i64,
}
fn one() -> i64 {
    1
}
fn fifty() -> i64 {
    50
}

/// POST /api/v1/certificates/search
pub async fn search(
    State(st): State<AppState>,
    body: ApiJson<SearchBody>,
) -> Result<Json<Value>, ApiError> {
    let b = body.0;
    let expires_before = b
        .expires_before
        .as_deref()
        .and_then(|v| chrono::NaiveDateTime::parse_from_str(v, "%Y-%m-%dT%H:%M:%S").ok());
    let (items, total) = st
        .manager
        .list_x509(
            b.status.as_deref(),
            b.subject.as_deref(),
            expires_before,
            b.page,
            b.page_size,
        )
        .await?;
    Ok(paginated(items, total, b.page, b.page_size))
}

/// GET /api/v1/certificates/crl
pub async fn get_crl(State(st): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let crl = st.manager.generate_x509_crl().await?;
    if headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) == Some("application/pkix-crl") {
        let pem = crl
            .get("crl_pem")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        return Ok((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/pkix-crl"),
                (header::CONTENT_DISPOSITION, "attachment; filename=crl.pem"),
            ],
            pem,
        )
            .into_response());
    }
    Ok(Json(crl).into_response())
}

/// POST /api/v1/certificates/ocsp — JSON OCSP status (binary → 501, per v1).
pub async fn ocsp(
    State(st): State<AppState>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Result<Response, ApiError> {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        == Some("application/ocsp-request")
    {
        return Err(ApiError::NotImplemented(
            "Binary OCSP not yet implemented".into(),
        ));
    }
    let data: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let serial = data.get("serial_number").and_then(Value::as_str);
    let Some(serial) = serial else {
        return Err(ApiError::BadRequest("serial_number required".into()));
    };
    let now = skauswatch_streams::py_now_isoformat();
    let cert = st.manager.get_x509(None, Some(serial), false).await?;
    let Some(cert) = cert else {
        return Ok(Json(serde_json::json!({
            "serial_number": serial,
            "status": "unknown",
            "this_update": now,
            "next_update": now,
        }))
        .into_response());
    };
    let (status, rev_time, rev_reason) =
        if cert.get("status").and_then(Value::as_str) == Some("revoked") {
            (
                "revoked",
                cert.get("revoked_at").cloned().unwrap_or(Value::Null),
                cert.get("revocation_reason")
                    .cloned()
                    .unwrap_or(Value::Null),
            )
        } else {
            ("good", Value::Null, Value::Null)
        };
    Ok(Json(serde_json::json!({
        "serial_number": serial,
        "status": status,
        "this_update": now,
        "next_update": now,
        "revocation_time": rev_time,
        "revocation_reason": rev_reason,
    }))
    .into_response())
}

/// GET /api/v1/certificates/ca — CA info + PEM.
pub async fn ca_info(State(st): State<AppState>) -> Json<Value> {
    let info = st.manager.x509.info();
    Json(serde_json::json!({
        "subject": info.subject,
        "issuer": info.issuer,
        "not_before": skauswatch_streams::py_isoformat(info.not_before),
        "not_after": skauswatch_streams::py_isoformat(info.not_after),
        "fingerprint_sha256": info.fingerprint_sha256,
        "serial_counter": st.manager.x509.serial_counter(),
        "crl_number": st.manager.x509.crl_number(),
        "ca_certificate_pem": st.manager.x509.ca_certificate_pem(),
    }))
}

/// GET /api/v1/certificates/ca/certificate — download CA cert PEM.
pub async fn download_ca_cert(State(st): State<AppState>) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-pem-file"),
            (header::CONTENT_DISPOSITION, "attachment; filename=ca.crt"),
        ],
        st.manager.x509.ca_certificate_pem().to_owned(),
    )
        .into_response()
}

/// GET /api/v1/certificates/{cert_id}/status
pub async fn cert_status(
    State(st): State<AppState>,
    Path(cert_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let cert = st
        .manager
        .get_x509(Some(&cert_id), None, false)
        .await?
        .ok_or_else(|| ApiError::NotFound("Certificate not found".into()))?;
    let na = cert
        .get("not_after")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let is_expired = chrono::NaiveDateTime::parse_from_str(na, "%Y-%m-%dT%H:%M:%S%.f")
        .map(|d| d < chrono::Utc::now().naive_utc())
        .unwrap_or(false);
    Ok(Json(serde_json::json!({
        "certificate_id": cert_id,
        "serial_number": cert.get("serial_number"),
        "status": cert.get("status"),
        "is_expired": is_expired,
        "not_before": cert.get("not_before"),
        "not_after": cert.get("not_after"),
        "revoked_at": cert.get("revoked_at"),
        "revocation_reason": cert.get("revocation_reason"),
    })))
}
