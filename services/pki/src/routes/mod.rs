//! /api/v1 router assembly for the PKI service. Paths mirror the v1 Quart
//! blueprints exactly (`/certificates`, `/ssh`, and the bare common routes),
//! with no trailing-slash variance.
//!
//! AUTH (hardened, finding #1): every route in this router requires a valid
//! `Authorization: Bearer <jwt>` — an HS256 access token signed with the
//! shared `JWT_SECRET_KEY` — enforced as a single router-wide layer via
//! `skauswatch_auth::AuthenticatedCaller` (no local user DB here, so this is
//! signature/expiry/type only, unlike the manager's `CurrentUser`). Before
//! this pass every one of these endpoints — including certificate issuance
//! and private-key retrieval — was open to anyone on the network. `/healthz`
//! `/readyz` (mounted separately in `main.rs`, merged in after this router)
//! are not covered by this layer.

pub mod common;
pub mod ssh;
pub mod x509;

/// Shared DB-backed test wiring, per `docs/v2-port/testing-pattern.md`'s
/// fan-out pattern — one `db_state()`/`bearer()` pair reused by every route
/// module's (and `manager.rs`'/`grpc/pki_service.rs`'s) success-path tests,
/// instead of each hand-rolling its own real-Postgres `AppState`.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::state::{AppState, AppStateInner};

    /// Real X.509 + SSH CA engines (see `AppStateInner::for_tests_with_db`)
    /// wired to a fresh, migrated Postgres schema — a genuine end-to-end
    /// stack for DB-backed success-path tests (no `migrations/` directory
    /// means this is the *only* way to exercise the "found"/list/CRL/KRL/
    /// statistics/audit-log code paths at all).
    pub(crate) async fn db_state() -> AppState {
        let pool =
            skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"))
                .await;
        AppStateInner::for_tests_with_db(pool)
    }

    /// Mints a bearer token for the fixed `for_tests`/`for_tests_with_db`
    /// JWT secret (`"test-secret"`).
    #[allow(clippy::panic)] // test-only helper fails loudly by design
    pub(crate) fn bearer() -> String {
        match skauswatch_auth::issue_service_token("tester", "admin", "test-secret", 300) {
            Ok(t) => format!("Bearer {t}"),
            Err(e) => panic!("issue test token: {e}"),
        }
    }
}

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
        .route("/cleanup", post(common::cleanup))
        .layer(axum::middleware::from_extractor_with_state::<
            skauswatch_auth::AuthenticatedCaller,
            AppState,
        >(state.clone()));

    Router::new().nest("/api/v1", api).with_state(state)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)] // tests fail loudly by design
mod tests {
    use axum::http::StatusCode;

    use crate::state::AppStateInner;

    use super::{page_params, user_id};

    #[test]
    fn user_id_reads_x_user_id_header_case_insensitively() {
        let mut headers = axum::http::HeaderMap::new();
        assert_eq!(user_id(&headers), None);
        headers.insert("x-user-id", "abc-123".parse().unwrap());
        assert_eq!(user_id(&headers), Some("abc-123".to_owned()));
    }

    #[test]
    fn page_params_defaults_and_parses_overrides() {
        let empty = std::collections::HashMap::new();
        assert_eq!(page_params(&empty), (1, 50));

        let mut q = std::collections::HashMap::new();
        q.insert("page".to_owned(), "3".to_owned());
        q.insert("page_size".to_owned(), "10".to_owned());
        assert_eq!(page_params(&q), (3, 10));

        // Unparseable values fall back to defaults.
        let mut bad = std::collections::HashMap::new();
        bad.insert("page".to_owned(), "not-a-number".to_owned());
        assert_eq!(page_params(&bad), (1, 50));
    }

    fn test_server() -> axum_test::TestServer {
        axum_test::TestServer::new(super::router(AppStateInner::for_tests()))
    }

    fn bearer(server_secret: &str) -> String {
        match skauswatch_auth::issue_service_token("tester", "admin", server_secret, 300) {
            Ok(t) => format!("Bearer {t}"),
            Err(e) => panic!("issue test token: {e}"),
        }
    }

    /// Regression for finding #1: every one of these previously-open
    /// endpoints (issuance, listing, CRL, CA cert download, SSH config
    /// helpers, statistics, audit) must now reject an unauthenticated
    /// caller with 401 before touching any CA/DB logic.
    #[tokio::test]
    async fn every_route_requires_jwt() {
        let server = test_server();
        for (method, path) in [
            ("GET", "/api/v1/certificates"),
            ("POST", "/api/v1/certificates"),
            ("POST", "/api/v1/certificates/search"),
            ("GET", "/api/v1/certificates/crl"),
            ("POST", "/api/v1/certificates/ocsp"),
            ("GET", "/api/v1/certificates/ca"),
            ("GET", "/api/v1/certificates/ca/certificate"),
            ("GET", "/api/v1/certificates/serial/abc"),
            ("POST", "/api/v1/certificates/serial/abc/revoke"),
            ("GET", "/api/v1/certificates/x/status"),
            ("GET", "/api/v1/ssh/certificates"),
            ("POST", "/api/v1/ssh/certificates"),
            ("GET", "/api/v1/ssh/krl"),
            ("GET", "/api/v1/ssh/ca"),
            ("GET", "/api/v1/ssh/ca/public-key"),
            ("POST", "/api/v1/ssh/config/known-hosts"),
            ("POST", "/api/v1/ssh/verify"),
            ("GET", "/api/v1/statistics"),
            ("GET", "/api/v1/ca/info"),
            ("GET", "/api/v1/audit"),
            ("GET", "/api/v1/expiring"),
            ("POST", "/api/v1/cleanup"),
        ] {
            let res = match method {
                "GET" => server.get(path).await,
                _ => server.post(path).await,
            };
            res.assert_status(StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn valid_bearer_token_passes_the_auth_gate() {
        let server = test_server();
        // Auth passes; the request proceeds to the handler (which 400s on
        // the empty body) — proving this is a real gate, not a stub that
        // always rejects.
        let res = server
            .get("/api/v1/statistics")
            .add_header(axum::http::header::AUTHORIZATION, bearer("test-secret"))
            .await;
        assert_ne!(res.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn token_signed_with_wrong_secret_is_rejected() {
        let server = test_server();
        let res = server
            .get("/api/v1/statistics")
            .add_header(axum::http::header::AUTHORIZATION, bearer("wrong-secret"))
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }
}
