//! Per-IP rate limiting (`tower_governor`) for the two exposure classes on
//! this service's production router: the pull-through proxy (`/v2/*`,
//! `/npm/*`, `/pypi/*`, `/crates/*`, `/go/*` — the abuse/egress-cost
//! surface, so it tolerates a higher burst) and the JWT-gated admin/report
//! API (`/api/v1/depgate/*` — a human or CI caller, not a package manager,
//! so it stays tighter). Both are env-overridable so operators can tune
//! per deployment without a rebuild.
//!
//! [`SmartIpKeyExtractor`] (not the crate default `PeerIpKeyExtractor`) is
//! used throughout: this service runs behind a Cilium ingress/gateway in
//! every real deployment (`security.md` Kubernetes Network Security), so
//! the raw TCP peer IP as seen by the pod is always the ingress's own IP —
//! rate limiting on peer IP alone would bucket every real client together,
//! defeating the point. `SmartIpKeyExtractor` reads
//! `x-forwarded-for`/`x-real-ip`/`forwarded` first and only falls back to
//! the connection's peer IP (`ConnectInfo`).
//!
//! WHY THIS IS ONLY WIRED INTO `crate::routes::rate_limited_router`, NOT
//! THE PLAIN `crate::routes::router` EVERY UNIT TEST IN THIS CRATE BUILDS
//! ON: `tower_governor`'s key extractor needs either a forwarded-IP header
//! or a populated `ConnectInfo<SocketAddr>` request extension to succeed;
//! `axum-test`'s default mock transport (what every existing
//! `test_server()` helper in this crate uses) provides neither, so it
//! would fail every request with `GovernorError::UnableToExtractKey` (500)
//! rather than exercising the route under test. Keeping rate limiting out
//! of the shared `router()` isolates that requirement to `main.rs::serve()`
//! (which wires `into_make_service_with_connect_info` as a defense-in-depth
//! fallback) and to this module's own focused tests below, which set the
//! forwarded-for header directly instead.

use axum::Router;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::SmartIpKeyExtractor;

/// Proxy surface defaults (req/s, burst) — `DEPGATE_RATE_LIMIT_PROXY_PER_SECOND`
/// / `DEPGATE_RATE_LIMIT_PROXY_BURST`.
const PROXY_DEFAULT_PER_SECOND: u64 = 20;
const PROXY_DEFAULT_BURST: u32 = 40;

/// Admin/report API defaults — `DEPGATE_RATE_LIMIT_ADMIN_PER_SECOND` /
/// `DEPGATE_RATE_LIMIT_ADMIN_BURST`.
const ADMIN_DEFAULT_PER_SECOND: u64 = 5;
const ADMIN_DEFAULT_BURST: u32 = 10;

/// Applies the pull-through proxy's per-IP rate limit to `router`.
pub fn proxy<S>(router: Router<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let per_second = env_u64(
        "DEPGATE_RATE_LIMIT_PROXY_PER_SECOND",
        PROXY_DEFAULT_PER_SECOND,
    );
    let burst = env_u32("DEPGATE_RATE_LIMIT_PROXY_BURST", PROXY_DEFAULT_BURST);
    apply_with(router, per_second, burst, "proxy")
}

/// Applies the admin/report API's per-IP rate limit to `router`.
pub fn admin<S>(router: Router<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let per_second = env_u64(
        "DEPGATE_RATE_LIMIT_ADMIN_PER_SECOND",
        ADMIN_DEFAULT_PER_SECOND,
    );
    let burst = env_u32("DEPGATE_RATE_LIMIT_ADMIN_BURST", ADMIN_DEFAULT_BURST);
    apply_with(router, per_second, burst, "admin")
}

/// Builds and applies a `SmartIpKeyExtractor`-keyed [`GovernorLayer`] with
/// an explicit rate/burst — the seam [`proxy`]/[`admin`] read env vars
/// into, and the seam this module's own tests exercise directly with a
/// tiny burst (`unsafe_code = "deny"` at the workspace level rules out
/// `std::env::set_var` in tests, so tests can't override the env-read
/// path). Construction never panics: an invalid (zero) rate or burst
/// degrades to "no rate limiting" for this router, logged at `error`,
/// rather than crashing the service on a config typo.
pub(crate) fn apply_with<S>(
    router: Router<S>,
    per_second: u64,
    burst: u32,
    label: &str,
) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let mut builder = GovernorConfigBuilder::default();
    builder.per_second(per_second).burst_size(burst);
    let mut builder = builder.key_extractor(SmartIpKeyExtractor);
    match builder.finish() {
        Some(cfg) => router.layer(GovernorLayer::new(cfg)),
        None => {
            tracing::error!(
                label,
                per_second,
                burst,
                "invalid rate limit config (per_second/burst must be non-zero); rate limiting disabled"
            );
            router
        }
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use axum::Router;
    use axum::http::StatusCode;
    use axum::routing::get;

    use super::apply_with;

    async fn ok() -> &'static str {
        "ok"
    }

    /// A one-route router with a burst of exactly one request per 60s —
    /// long enough that the quota never refills mid-test.
    fn burst_one_router() -> Router {
        apply_with(Router::new().route("/", get(ok)), 60, 1, "test")
    }

    #[tokio::test]
    async fn a_second_request_from_the_same_ip_within_the_burst_gets_429() {
        let server = axum_test::TestServer::new(burst_one_router());
        server
            .get("/")
            .add_header("x-forwarded-for", "203.0.113.9")
            .await
            .assert_status_ok();
        server
            .get("/")
            .add_header("x-forwarded-for", "203.0.113.9")
            .await
            .assert_status(StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn a_different_source_ip_gets_its_own_independent_burst() {
        let server = axum_test::TestServer::new(burst_one_router());
        server
            .get("/")
            .add_header("x-forwarded-for", "203.0.113.9")
            .await
            .assert_status_ok();
        server
            .get("/")
            .add_header("x-forwarded-for", "203.0.113.10")
            .await
            .assert_status_ok();
    }

    #[tokio::test]
    async fn a_zero_burst_disables_rate_limiting_instead_of_panicking() {
        let router = apply_with(Router::new().route("/", get(ok)), 60, 0, "test");
        let server = axum_test::TestServer::new(router);
        // No burst was configured (invalid), so the layer was never
        // attached — every request just reaches the handler.
        server
            .get("/")
            .add_header("x-forwarded-for", "203.0.113.9")
            .await
            .assert_status_ok();
        server
            .get("/")
            .add_header("x-forwarded-for", "203.0.113.9")
            .await
            .assert_status_ok();
    }
}
