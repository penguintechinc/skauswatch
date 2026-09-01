//! /api/v1 router assembly for the PKI service. Paths mirror the v1 Quart
//! blueprints exactly (`/certificates`, `/ssh`, and the bare common routes),
//! with no trailing-slash variance.
//!
//! AUTH (hardened, finding #1; ES256 per audit finding H1b): every route in
//! this router requires a valid `Authorization: Bearer <jwt>` — an ES256
//! access token verifiable with the shared `JWT_VERIFY_KEY` — enforced as a
//! single router-wide layer via
//! `skauswatch_auth::AuthenticatedCaller` (no local user DB here, so this is
//! signature/expiry/type only, unlike the manager's `CurrentUser`). Before
//! this pass every one of these endpoints — including certificate issuance
//! and private-key retrieval — was open to anyone on the network. `/healthz`
//! `/readyz` (mounted separately in `main.rs`, merged in after this router)
//! are not covered by this layer.

pub mod common;
pub mod openapi;
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
    /// verify key (`skauswatch_testkit::jwt::verify_key`).
    #[allow(clippy::panic)] // test-only helper fails loudly by design
    pub(crate) fn bearer() -> String {
        match skauswatch_auth::issue_service_token(
            "tester",
            "admin",
            skauswatch_testkit::jwt::signing_key(),
            300,
        ) {
            Ok(t) => format!("Bearer {t}"),
            Err(e) => panic!("issue test token: {e}"),
        }
    }

    /// A fixed tenant id for DB-backed tests that don't specifically
    /// exercise cross-tenant isolation — pair with [`bearer`] and the
    /// `crate::tenant::TENANT_HEADER` header.
    #[allow(clippy::panic)] // test-only helper fails loudly by design
    pub(crate) fn tenant() -> uuid::Uuid {
        match uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111") {
            Ok(u) => u,
            Err(e) => panic!("fixed test tenant: {e}"),
        }
    }

    /// A [`skauswatch_identity::IdentityProvider`] holding no identity at
    /// all — via the crate's `testutil`-feature test seam
    /// (`IdentityProvider::degraded_for_test`), not by asking a real
    /// `connect()` to degrade. Deliberately does not reuse `from_env`'s
    /// production bootstrap path here at all: since the identity
    /// prod-hard-fail bypass fix, there is no deployment-domain argument
    /// left to coax `connect()` into degrading, and there shouldn't be —
    /// forcing degrade via a real connect would mean re-introducing
    /// exactly the kind of domain-based override this fix removed. Used by
    /// `grpc`/`maintenance` tests that need to exercise the "identity held
    /// but degraded" branch specifically, distinct from the `identity:
    /// None` shortcut every other test constructor uses.
    pub(crate) fn degraded_identity() -> std::sync::Arc<skauswatch_identity::IdentityProvider> {
        let provider = skauswatch_identity::IdentityProvider::degraded_for_test();
        assert!(!provider.has_identity());
        std::sync::Arc::new(provider)
    }
}

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use penguin_licensing::axum::{FlagGate, flag_gate};
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;

use crate::state::AppState;

/// PostHog flag gating certificate/SSH-certificate *issuance* — default
/// OFF until validated (see `general.md` Feature Toggling & License
/// Enforcement). Independent of `openapi::OPENAPI_FLAG`. This is a
/// separate concern from tenant isolation: a disabled flag blocks issuance
/// for every tenant; `crate::tenant::TenantId` still governs which
/// tenant's data an *enabled* request can touch.
pub const ISSUANCE_FLAG: &str = "skauswatch.pki";

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
///
/// Cert-issuance routes (`POST /certificates`, `POST /ssh/certificates`)
/// are split into their own sub-router so `ISSUANCE_FLAG` can gate them
/// without affecting the read/list/revoke routes on the same paths —
/// `Router::merge` combines method routers registered for the same path
/// across two routers, so `GET /certificates` (ungated) and
/// `POST /certificates` (gated) coexist normally once merged. The flag
/// layer is applied to `issuance` before it merges into `api`, so it sits
/// *innermost* relative to the outer `AuthenticatedCaller` layer below —
/// auth runs first, then the flag check, matching this crate's
/// auth → feature layering (this service has no per-request tenant scope
/// to gate on between the two, unlike the manager's tenant → scope →
/// feature contract).
pub fn router(state: AppState) -> Router {
    // Security audit finding — real authorization, not just authentication
    // (see `crate::authz` module docs): every sub-router below carries its
    // own `crate::authz::ScopeGate` requiring the `pki:*` capability that
    // matches what it actually does, layered *innermost* relative to the
    // outer router-wide `AuthenticatedCaller` applied to `api` below — so
    // ordering is auth (401) → scope (403) → feature flag (404, issuance
    // only), matching `crates/skauswatch-auth`'s documented layering
    // contract adapted to this machine-token surface.
    let issuance = Router::new()
        .route("/certificates", post(x509::issue))
        .route("/ssh/certificates", post(ssh::issue))
        .layer(axum::middleware::from_fn_with_state(
            FlagGate::new(state.license.clone(), ISSUANCE_FLAG),
            flag_gate,
        ))
        .layer(axum::middleware::from_fn_with_state(
            crate::authz::ScopeGate::new(state.clone(), crate::authz::PKI_ISSUE),
            crate::authz::scope_gate,
        ));

    // Certificate revocation (X.509 + SSH) — `pki:revoke`.
    let revoke = Router::new()
        .route(
            "/certificates/serial/{serial}/revoke",
            post(x509::revoke_by_serial),
        )
        .route("/certificates/{cert_id}/revoke", post(x509::revoke_cert))
        .route("/ssh/certificates/{cert_id}/revoke", post(ssh::revoke_cert))
        .layer(axum::middleware::from_fn_with_state(
            crate::authz::ScopeGate::new(state.clone(), crate::authz::PKI_REVOKE),
            crate::authz::scope_gate,
        ));

    // Audit log — `pki:admin` (more sensitive than routine lookups).
    let admin = Router::new().route("/audit", get(common::audit)).layer(
        axum::middleware::from_fn_with_state(
            crate::authz::ScopeGate::new(state.clone(), crate::authz::PKI_ADMIN),
            crate::authz::scope_gate,
        ),
    );

    // Everything else: lookup/list/search/CRL/OCSP/CA-info/statistics/SSH
    // config helpers, and the OpenAPI spec — `pki:read`.
    let read = Router::new()
        // ---- X.509 (/api/v1/certificates) ----
        .route("/certificates", get(x509::list))
        .route("/certificates/search", post(x509::search))
        .route("/certificates/crl", get(x509::get_crl))
        .route("/certificates/ocsp", post(x509::ocsp))
        .route("/certificates/ca", get(x509::ca_info))
        .route("/certificates/ca/certificate", get(x509::download_ca_cert))
        .route("/certificates/serial/{serial}", get(x509::get_by_serial))
        .route("/certificates/{cert_id}", get(x509::get_cert))
        .route("/certificates/{cert_id}/status", get(x509::cert_status))
        // ---- SSH (/api/v1/ssh) ----
        .route("/ssh/certificates", get(ssh::list))
        .route("/ssh/certificates/serial/{serial}", get(ssh::get_by_serial))
        .route("/ssh/certificates/{cert_id}", get(ssh::get_cert))
        .route("/ssh/certificates/{cert_id}/status", get(ssh::cert_status))
        .route("/ssh/krl", get(ssh::get_krl))
        .route("/ssh/ca", get(ssh::ca_info))
        .route("/ssh/ca/public-key", get(ssh::ca_public_key))
        .route("/ssh/config/known-hosts", post(ssh::known_hosts))
        .route("/ssh/config/authorized-keys", post(ssh::authorized_keys))
        .route("/ssh/config/ssh-config", post(ssh::ssh_config))
        .route("/ssh/verify", post(ssh::verify))
        // ---- Common (/api/v1) ----
        // NOTE: `/expiring` and `/cleanup` are deliberately NOT mounted here
        // — they moved to the dedicated mTLS-required maintenance listener
        // (`crate::maintenance`) so their cross-tenant access is
        // cryptographically enforced (SPIFFE `endpoint-agent-maintenance`
        // identity) instead of relying on this ES256-bearer-gated listener's
        // network reachability. See `crate::maintenance` module docs and
        // `docs/v2-port/service-auth-model.md` §3.
        .route("/statistics", get(common::statistics))
        .route("/ca/info", get(common::all_ca_info))
        // ---- OpenAPI (/api/v1/openapi.json) ----
        .merge(openapi::router())
        .layer(axum::middleware::from_fn_with_state(
            crate::authz::ScopeGate::new(state.clone(), crate::authz::PKI_READ),
            crate::authz::scope_gate,
        ));

    let api =
        read.merge(issuance).merge(revoke).merge(admin).layer(
            axum::middleware::from_extractor_with_state::<
                skauswatch_auth::AuthenticatedCaller,
                AppState,
            >(state.clone()),
        );

    let app = Router::new().nest("/api/v1", api).with_state(state);

    // Per-IP rate limiting (security audit finding), outermost layer so it
    // also throttles unauthenticated/invalid-token flooding, not just
    // successfully-authenticated traffic. Requires the listener to be
    // served via `.into_make_service_with_connect_info::<SocketAddr>()`
    // (see `main.rs`) for `crate::ratelimit::PeerIpOrGlobalKeyExtractor` to
    // see the real TCP peer address — see that module's docs for why it's
    // a custom extractor rather than the crate default. Never panics: an
    // invalid computed config (should not happen — inputs are always
    // positive integers, see `crate::ratelimit`) logs loudly and serves
    // without rate limiting rather than crashing the service.
    let per_sec = crate::ratelimit::per_second();
    let burst = crate::ratelimit::burst_size();
    match GovernorConfigBuilder::default()
        .key_extractor(crate::ratelimit::PeerIpOrGlobalKeyExtractor)
        .per_second(per_sec)
        .burst_size(burst)
        .finish()
    {
        Some(conf) => app.layer(GovernorLayer::new(Arc::new(conf))),
        None => {
            tracing::error!(
                per_sec,
                burst,
                "rate limit config could not be constructed; serving without rate limiting"
            );
            app
        }
    }
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

    fn bearer(signing_key: &jsonwebtoken::EncodingKey) -> String {
        bearer_with_role("admin", signing_key)
    }

    /// Same as [`bearer`] but with a caller-chosen `ServiceClaims.role`, for
    /// exercising `crate::authz`'s scope gates with a role that carries
    /// less than every capability.
    fn bearer_with_role(role: &str, signing_key: &jsonwebtoken::EncodingKey) -> String {
        match skauswatch_auth::issue_service_token("tester", role, signing_key, 300) {
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
        // A fresh server per path (not one shared instance for all of
        // these) — otherwise this exceeds `crate::ratelimit`'s default
        // burst (20) partway through the 21-entry list below, since the
        // rate-limit layer runs outermost, ahead of the auth check this
        // test exercises, and would start returning 429 instead of 401.
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
            ("GET", "/api/v1/openapi.json"),
        ] {
            let server = test_server();
            let res = match method {
                "GET" => server.get(path).await,
                _ => server.post(path).await,
            };
            res.assert_status(StatusCode::UNAUTHORIZED);
        }
    }

    /// Regression for R3-1 (`docs/v2-port/service-auth-model.md` §3):
    /// `/expiring` and `/cleanup` must no longer be reachable on the
    /// primary, ES256-bearer-gated listener at all — not even behind the
    /// auth layer — since they now live exclusively on the dedicated
    /// mTLS-required maintenance listener (`crate::maintenance`). A bare
    /// 404 here (not 401) proves the route was actually removed, not just
    /// re-gated.
    #[tokio::test]
    async fn expiring_and_cleanup_are_no_longer_served_on_the_primary_router() {
        let server = test_server();
        for (method, path) in [("GET", "/api/v1/expiring"), ("POST", "/api/v1/cleanup")] {
            let request = match method {
                "GET" => server.get(path),
                _ => server.post(path),
            };
            let res = request
                .add_header(
                    axum::http::header::AUTHORIZATION,
                    bearer(skauswatch_testkit::jwt::signing_key()),
                )
                .await;
            res.assert_status(StatusCode::NOT_FOUND);
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
            .add_header(
                axum::http::header::AUTHORIZATION,
                bearer(skauswatch_testkit::jwt::signing_key()),
            )
            .await;
        assert_ne!(res.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn token_signed_with_wrong_secret_is_rejected() {
        let server = test_server();
        let res = server
            .get("/api/v1/statistics")
            .add_header(
                axum::http::header::AUTHORIZATION,
                bearer(skauswatch_testkit::jwt::other_signing_key()),
            )
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }

    /// `release_mode = true` license client (flags default OFF, no dev
    /// bypass) — mirrors `openapi::tests::gated_license`.
    fn gated_license() -> std::sync::Arc<penguin_licensing::LicenseClient> {
        let mut cfg = match penguin_licensing::LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        cfg.release_mode = true;
        match penguin_licensing::LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        }
    }

    /// Regression: cert issuance (both CAs) must be denied while
    /// `ISSUANCE_FLAG` evaluates disabled, even for an authenticated,
    /// correctly-tenanted caller — read/list/revoke routes on the same
    /// paths are unaffected by the flag.
    #[tokio::test]
    async fn issuance_is_denied_when_the_flag_is_disabled() {
        let state = AppStateInner::for_tests_with_license(gated_license());
        let server = axum_test::TestServer::new(super::router(state));
        let tenant = uuid::Uuid::new_v4().to_string();

        let x509_res = server
            .post("/api/v1/certificates")
            .add_header(
                axum::http::header::AUTHORIZATION,
                bearer(skauswatch_testkit::jwt::signing_key()),
            )
            .add_header(crate::tenant::TENANT_HEADER, tenant.clone())
            .json(&serde_json::json!({ "subject": "CN=flag-off.example.com" }))
            .await;
        x509_res.assert_status(StatusCode::FORBIDDEN);
        let x509_body: serde_json::Value = x509_res.json();
        assert_eq!(x509_body["error"], "feature_disabled");
        assert_eq!(x509_body["flag"], super::ISSUANCE_FLAG);

        let ssh_res = server
            .post("/api/v1/ssh/certificates")
            .add_header(
                axum::http::header::AUTHORIZATION,
                bearer(skauswatch_testkit::jwt::signing_key()),
            )
            .add_header(crate::tenant::TENANT_HEADER, tenant)
            .json(&serde_json::json!({
                "certificate_type": "user",
                "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdefghij",
                "key_id": "k",
                "principals": ["alice"],
            }))
            .await;
        ssh_res.assert_status(StatusCode::FORBIDDEN);
        let ssh_body: serde_json::Value = ssh_res.json();
        assert_eq!(ssh_body["error"], "feature_disabled");

        // Read routes on the same paths are unaffected by the flag —
        // proves the split targets POST only, not the whole path.
        let list_res = server
            .get("/api/v1/certificates")
            .add_header(
                axum::http::header::AUTHORIZATION,
                bearer(skauswatch_testkit::jwt::signing_key()),
            )
            .add_header(
                crate::tenant::TENANT_HEADER,
                uuid::Uuid::new_v4().to_string(),
            )
            .await;
        assert_ne!(list_res.status_code(), StatusCode::FORBIDDEN);
    }

    /// Security audit finding #1 (authorization): issuance must require
    /// `pki:issue`, not just "any valid token" — a `viewer`-role machine
    /// token (read-only) is denied 403 naming the missing capability, while
    /// an `admin`-role token (every capability) passes the scope gate and
    /// proceeds to the real handler.
    #[tokio::test]
    async fn issuance_requires_the_issue_scope() {
        let server = test_server();
        let tenant = uuid::Uuid::new_v4().to_string();

        let denied = server
            .post("/api/v1/certificates")
            .add_header(
                axum::http::header::AUTHORIZATION,
                bearer_with_role("viewer", skauswatch_testkit::jwt::signing_key()),
            )
            .add_header(crate::tenant::TENANT_HEADER, tenant.clone())
            .json(&serde_json::json!({ "subject": "CN=no-issue-scope.example.com" }))
            .await;
        denied.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = denied.json();
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains(crate::authz::PKI_ISSUE)
        );

        let allowed = server
            .post("/api/v1/certificates")
            .add_header(
                axum::http::header::AUTHORIZATION,
                bearer_with_role("admin", skauswatch_testkit::jwt::signing_key()),
            )
            .add_header(crate::tenant::TENANT_HEADER, tenant)
            .json(&serde_json::json!({ "subject": "CN=has-issue-scope.example.com" }))
            .await;
        // Passed the scope gate — proceeds to real crypto, then 500s for
        // lack of a DB (see `x509::tests::issue_valid_body_runs_real_crypto_
        // then_500s_on_unreachable_db`), never 403.
        assert_ne!(allowed.status_code(), StatusCode::FORBIDDEN);
    }

    /// Revocation requires `pki:revoke` — an issue-only role is denied even
    /// though it can create certificates.
    #[tokio::test]
    async fn revocation_requires_the_revoke_scope() {
        let server = test_server();
        let denied = server
            .post(&format!(
                "/api/v1/certificates/{}/revoke",
                uuid::Uuid::new_v4()
            ))
            .add_header(
                axum::http::header::AUTHORIZATION,
                bearer_with_role("pki-issuer", skauswatch_testkit::jwt::signing_key()),
            )
            .await;
        denied.assert_status(StatusCode::FORBIDDEN);

        let allowed = server
            .post(&format!(
                "/api/v1/certificates/{}/revoke",
                uuid::Uuid::new_v4()
            ))
            .add_header(
                axum::http::header::AUTHORIZATION,
                bearer_with_role("pki-revoker", skauswatch_testkit::jwt::signing_key()),
            )
            .add_header(
                crate::tenant::TENANT_HEADER,
                uuid::Uuid::new_v4().to_string(),
            )
            .await;
        assert_ne!(allowed.status_code(), StatusCode::FORBIDDEN);
    }

    /// Read endpoints require `pki:read` — fails closed for a role with no
    /// mapped capabilities at all, passes for a read-only role.
    #[tokio::test]
    async fn read_endpoints_require_the_read_scope() {
        let server = test_server();
        let denied = server
            .get("/api/v1/statistics")
            .add_header(
                axum::http::header::AUTHORIZATION,
                bearer_with_role("unmapped-role", skauswatch_testkit::jwt::signing_key()),
            )
            .await;
        denied.assert_status(StatusCode::FORBIDDEN);

        let allowed = server
            .get("/api/v1/statistics")
            .add_header(
                axum::http::header::AUTHORIZATION,
                bearer_with_role("pki-reader", skauswatch_testkit::jwt::signing_key()),
            )
            .add_header(
                crate::tenant::TENANT_HEADER,
                uuid::Uuid::new_v4().to_string(),
            )
            .await;
        // Passed the scope gate — proceeds to the real (tenant-scoped)
        // handler, never 403.
        assert_ne!(allowed.status_code(), StatusCode::FORBIDDEN);
    }

    /// The audit log requires `pki:admin` specifically — a read-only role
    /// is not enough, unlike every other lookup endpoint.
    #[tokio::test]
    async fn audit_requires_the_admin_scope_not_just_read() {
        let server = test_server();
        let denied = server
            .get("/api/v1/audit")
            .add_header(
                axum::http::header::AUTHORIZATION,
                bearer_with_role("pki-reader", skauswatch_testkit::jwt::signing_key()),
            )
            .await;
        denied.assert_status(StatusCode::FORBIDDEN);

        let allowed = server
            .get("/api/v1/audit")
            .add_header(
                axum::http::header::AUTHORIZATION,
                bearer_with_role("admin", skauswatch_testkit::jwt::signing_key()),
            )
            .add_header(
                crate::tenant::TENANT_HEADER,
                uuid::Uuid::new_v4().to_string(),
            )
            .await;
        // Passed the scope gate — proceeds to the real (tenant-scoped)
        // handler, never 403.
        assert_ne!(allowed.status_code(), StatusCode::FORBIDDEN);
    }

    /// Rate limiting (security audit finding): firing more requests than
    /// the default burst (20 — see `crate::ratelimit::burst_size`) in a
    /// tight loop must eventually trip `tower_governor`'s 429, well before
    /// the per-second replenishment (10/s = one token per 100ms) can add
    /// one back.
    #[tokio::test]
    async fn requests_exceeding_the_burst_are_rate_limited() {
        let server = test_server();
        let auth = bearer(skauswatch_testkit::jwt::signing_key());
        let mut saw_429 = false;
        for _ in 0..30 {
            let res = server
                .get("/api/v1/statistics")
                .add_header(axum::http::header::AUTHORIZATION, auth.clone())
                .await;
            if res.status_code() == StatusCode::TOO_MANY_REQUESTS {
                saw_429 = true;
                break;
            }
        }
        assert!(
            saw_429,
            "expected at least one 429 after exceeding the rate limit burst"
        );
    }
}
