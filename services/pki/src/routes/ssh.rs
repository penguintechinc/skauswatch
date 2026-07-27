//! SSH REST handlers (v1 `api/v1/ssh.py`, blueprint prefix `/api/v1/ssh`).

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use serde_json::Value;

use crate::ca::ssh::SshIssueParams;
use crate::error::{ApiError, ApiJson};
use crate::models::{
    AuthorizedKeysRequest, RevokeRequest, SshCertificateRequest, SshConfigRequest,
};
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

fn map_to_pairs(m: std::collections::BTreeMap<String, String>) -> Vec<(String, String)> {
    m.into_iter().collect()
}

/// POST /api/v1/ssh/certificates — issue an SSH certificate.
pub async fn issue(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: ApiJson<SshCertificateRequest>,
) -> Result<Response, ApiError> {
    let req = body.0;
    req.validate().map_err(ApiError::Validation)?;
    let extensions = if req.certificate_type == "host" {
        None
    } else {
        req.extensions.map(map_to_pairs)
    };
    let critical_options = req.critical_options.map(map_to_pairs);
    let params = SshIssueParams {
        public_key: req.public_key,
        certificate_type: req.certificate_type,
        key_id: Some(req.key_id),
        principals: req.principals,
        validity_seconds: req.validity_seconds,
        extensions,
        critical_options,
        source_addresses: req.source_addresses,
        force_command: req.force_command,
        hostname: req.hostname,
    };
    let result = st
        .manager
        .issue_ssh(params, user_id(&headers).as_deref())
        .await?;
    Ok((StatusCode::CREATED, Json(result)).into_response())
}

/// GET /api/v1/ssh/certificates/{cert_id}
pub async fn get_cert(
    State(st): State<AppState>,
    Path(cert_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    st.manager
        .get_ssh(Some(&cert_id), None, true)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::NotFound("Certificate not found".into()))
}

/// GET /api/v1/ssh/certificates/serial/{serial}
pub async fn get_by_serial(
    State(st): State<AppState>,
    Path(serial): Path<String>,
) -> Result<Json<Value>, ApiError> {
    st.manager
        .get_ssh(None, Some(&serial), true)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::NotFound("Certificate not found".into()))
}

/// POST /api/v1/ssh/certificates/{cert_id}/revoke
pub async fn revoke_cert(
    State(st): State<AppState>,
    Path(cert_id): Path<String>,
    headers: HeaderMap,
    body: ApiJson<RevokeRequest>,
) -> Result<Json<Value>, ApiError> {
    let ok = st
        .manager
        .revoke_ssh(
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

/// GET /api/v1/ssh/certificates — list with filters.
pub async fn list(
    State(st): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let (page, page_size) = page_params(&q);
    let (items, total) = st
        .manager
        .list_ssh(
            q.get("status").map(String::as_str),
            q.get("type").map(String::as_str),
            q.get("principal").map(String::as_str),
            page,
            page_size,
        )
        .await?;
    Ok(paginated(items, total, page, page_size))
}

/// GET /api/v1/ssh/krl
pub async fn get_krl(State(st): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let krl = st.manager.generate_ssh_krl().await?;
    if headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) == Some("application/octet-stream")
    {
        let b64 = krl
            .get("krl_binary")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| ApiError::internal("krl decode", e))?;
        return Ok((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=revoked_keys",
                ),
            ],
            bytes,
        )
            .into_response());
    }
    Ok(Json(krl).into_response())
}

/// GET /api/v1/ssh/ca — SSH CA info.
pub async fn ca_info(State(st): State<AppState>) -> Json<Value> {
    Json(serde_json::json!({
        "ca_public_key": st.manager.ssh.ca_public_key(),
        "key_type": st.manager.ssh.ca_key_type(),
        "fingerprint": st.manager.ssh.ca_fingerprint(),
        "serial_counter": st.manager.ssh.serial_counter(),
        "krl_version": st.manager.ssh.krl_version(),
    }))
}

/// GET /api/v1/ssh/ca/public-key
pub async fn ca_public_key(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let key = st.manager.ssh.ca_public_key().to_owned();
    if headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) == Some("text/plain") {
        return (StatusCode::OK, [(header::CONTENT_TYPE, "text/plain")], key).into_response();
    }
    Json(serde_json::json!({ "ca_public_key": key })).into_response()
}

/// POST /api/v1/ssh/config/known-hosts
pub async fn known_hosts(
    State(st): State<AppState>,
    body: ApiJson<Value>,
) -> Result<Json<Value>, ApiError> {
    let hostnames: Vec<String> = body
        .0
        .get("hostnames")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if hostnames.is_empty() {
        return Err(ApiError::BadRequest("hostnames required".into()));
    }
    Ok(Json(serde_json::json!({
        "known_hosts": st.manager.ssh.known_hosts_entry(&hostnames, true),
        "hostnames": hostnames,
    })))
}

/// POST /api/v1/ssh/config/authorized-keys
pub async fn authorized_keys(
    State(st): State<AppState>,
    body: ApiJson<AuthorizedKeysRequest>,
) -> Json<Value> {
    let req = body.0;
    let options = map_to_pairs(req.options);
    let entry = st
        .manager
        .ssh
        .authorized_keys_entry(&req.principals, &options);
    Json(serde_json::json!({
        "authorized_keys": entry,
        "trustedUserCAKeys": st.manager.ssh.ca_public_key(),
        "principals": req.principals,
    }))
}

/// POST /api/v1/ssh/config/ssh-config
pub async fn ssh_config(
    State(st): State<AppState>,
    body: ApiJson<SshConfigRequest>,
) -> Json<Value> {
    let req = body.0;
    let cfg = st.manager.ssh.ssh_config(
        &req.hostname,
        req.port,
        req.user.as_deref(),
        req.identity_file.as_deref(),
    );
    let kh = st
        .manager
        .ssh
        .known_hosts_entry(std::slice::from_ref(&req.hostname), true);
    Json(serde_json::json!({
        "ssh_config": cfg,
        "known_hosts_entry": kh,
        "ca_public_key": st.manager.ssh.ca_public_key(),
    }))
}

/// GET /api/v1/ssh/certificates/{cert_id}/status
pub async fn cert_status(
    State(st): State<AppState>,
    Path(cert_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let cert = st
        .manager
        .get_ssh(Some(&cert_id), None, false)
        .await?
        .ok_or_else(|| ApiError::NotFound("Certificate not found".into()))?;
    let vb = cert
        .get("valid_before")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let is_expired = chrono::NaiveDateTime::parse_from_str(vb, "%Y-%m-%dT%H:%M:%S%.f")
        .map(|d| d < chrono::Utc::now().naive_utc())
        .unwrap_or(false);
    Ok(Json(serde_json::json!({
        "certificate_id": cert_id,
        "serial_number": cert.get("serial_number"),
        "key_id": cert.get("key_id"),
        "status": cert.get("status"),
        "is_expired": is_expired,
        "valid_after": cert.get("valid_after"),
        "valid_before": cert.get("valid_before"),
        "revoked_at": cert.get("revoked_at"),
        "revocation_reason": cert.get("revocation_reason"),
    })))
}

/// POST /api/v1/ssh/verify — parse + verify an SSH certificate.
pub async fn verify(
    State(st): State<AppState>,
    body: ApiJson<Value>,
) -> Result<Response, ApiError> {
    let cert = body
        .0
        .get("certificate")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let Some(cert) = cert else {
        return Err(ApiError::BadRequest("certificate required".into()));
    };
    let ssh = st.manager.ssh.clone();
    let cert_for_task = cert.clone();
    let mut info = tokio::task::spawn_blocking(move || ssh.check_certificate(&cert_for_task))
        .await
        .map_err(|e| ApiError::internal("verify join", e))?
        .map_err(ApiError::from)?;

    // Overlay revocation status from the DB when the serial is known.
    #[allow(clippy::collapsible_if)]
    if let Some(serial) = info
        .get("serial")
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        if let Some(row) = st.manager.get_ssh(None, Some(&serial), false).await? {
            if row.get("status").and_then(Value::as_str) == Some("revoked") {
                info["status"] = Value::String("revoked".into());
            }
            info["revoked_at"] = row.get("revoked_at").cloned().unwrap_or(Value::Null);
        }
    }
    Ok(Json(info).into_response())
}
