//! /api/v1 router assembly for the PKI service. Paths mirror the v1 Quart
//! blueprints exactly (`/certificates`, `/ssh`, and the bare common routes),
//! with no trailing-slash variance.

pub mod common;
pub mod ssh;
pub mod x509;

use std::collections::HashMap;

use axum::Router;
use axum::http::HeaderMap;
use axum::routing::{get, post};

use crate::state::AppState;

/// Extracts the `X-User-ID` requester header (v1 `request.headers.get`).
pub fn user_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// Parses `page`/`page_size` query params (v1 defaults 1 / 50).
pub fn page_params(q: &HashMap<String, String>) -> (i64, i64) {
    let page = q.get("page").and_then(|v| v.parse().ok()).unwrap_or(1);
    let page_size = q
        .get("page_size")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    (page, page_size)
}

/// Builds the full /api/v1 application router.
pub fn router(state: AppState) -> Router {
    let api = Router::new()
        // ---- X.509 (/api/v1/certificates) ----
        .route("/certificates", post(x509::issue).get(x509::list))
        .route("/certificates/search", post(x509::search))
        .route("/certificates/crl", get(x509::get_crl))
        .route("/certificates/ocsp", post(x509::ocsp))
        .route("/certificates/ca", get(x509::ca_info))
        .route("/certificates/ca/certificate", get(x509::download_ca_cert))
        .route("/certificates/serial/{serial}", get(x509::get_by_serial))
        .route(
            "/certificates/serial/{serial}/revoke",
            post(x509::revoke_by_serial),
        )
        .route("/certificates/{cert_id}", get(x509::get_cert))
        .route("/certificates/{cert_id}/revoke", post(x509::revoke_cert))
        .route("/certificates/{cert_id}/status", get(x509::cert_status))
        // ---- SSH (/api/v1/ssh) ----
        .route("/ssh/certificates", post(ssh::issue).get(ssh::list))
        .route("/ssh/certificates/serial/{serial}", get(ssh::get_by_serial))
        .route("/ssh/certificates/{cert_id}", get(ssh::get_cert))
        .route("/ssh/certificates/{cert_id}/revoke", post(ssh::revoke_cert))
        .route("/ssh/certificates/{cert_id}/status", get(ssh::cert_status))
        .route("/ssh/krl", get(ssh::get_krl))
        .route("/ssh/ca", get(ssh::ca_info))
        .route("/ssh/ca/public-key", get(ssh::ca_public_key))
        .route("/ssh/config/known-hosts", post(ssh::known_hosts))
        .route("/ssh/config/authorized-keys", post(ssh::authorized_keys))
        .route("/ssh/config/ssh-config", post(ssh::ssh_config))
        .route("/ssh/verify", post(ssh::verify))
        // ---- Common (/api/v1) ----
        .route("/statistics", get(common::statistics))
        .route("/ca/info", get(common::all_ca_info))
        .route("/audit", get(common::audit))
        .route("/expiring", get(common::expiring))
        .route("/cleanup", post(common::cleanup));

    Router::new().nest("/api/v1", api).with_state(state)
}
