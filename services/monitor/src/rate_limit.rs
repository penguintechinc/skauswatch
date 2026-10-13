//! Per-IP rate limiting (`tower_governor`) for the production router —
//! env-overridable via `MONITOR_RATE_LIMIT_PER_SECOND` /
//! `MONITOR_RATE_LIMIT_BURST` so operators can tune per deployment without
//! a rebuild.
//!
//! [`SmartIpKeyExtractor`] (not the crate default `PeerIpKeyExtractor`) is
//! used: this service runs behind a Cilium ingress/gateway in every real
//! deployment (`security.md` Kubernetes Network Security), so the raw TCP
//! peer IP as seen by the pod is always the ingress's own IP — rate
//! limiting on peer IP alone would bucket every real client together,
//! defeating the point. `SmartIpKeyExtractor` reads
//! `x-forwarded-for`/`x-real-ip`/`forwarded` first and only falls back to
//! the connection's peer IP (`ConnectInfo`).
//!
//! WHY THIS IS APPLIED IN `main.rs::serve()` ONLY, NOT INSIDE
//! `crate::routes::router` ITSELF: `tower_governor`'s key extractor needs
//! either a forwarded-IP header or a populated `ConnectInfo<SocketAddr>`
//! request extension to succeed; `axum-test`'s default mock transport
//! (what every existing `TestServer::new(...)` call in this crate uses)
//! provides neither, so it would fail every request with
//! `GovernorError::UnableToExtractKey` (500) rather than exercising the
//! route under test. Wrapping only the fully-assembled production app in
//! `main.rs` keeps `routes::router` (and every test built on it) unchanged;
//! `main.rs` also wires `into_make_service_with_connect_info` as a
//! defense-in-depth fallback. This module's own tests below set the
//! forwarded-for header directly instead of needing either of those.

use axum::Router;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::SmartIpKeyExtractor;

/// Default requests/second — `MONITOR_RATE_LIMIT_PER_SECOND`.
const DEFAULT_PER_SECOND: u64 = 10;
/// Default burst size — `MONITOR_RATE_LIMIT_BURST`.
const DEFAULT_BURST: u32 = 20;

/// Applies the per-IP rate limit to `router`, reading
/// `MONITOR_RATE_LIMIT_PER_SECOND`/`MONITOR_RATE_LIMIT_BURST` (falling back
/// to [`DEFAULT_PER_SECOND`]/[`DEFAULT_BURST`] when unset, empty, or
/// unparsable).
pub fn apply<S>(router: Router<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let per_second = env_u64("MONITOR_RATE_LIMIT_PER_SECOND", DEFAULT_PER_SECOND);
    let burst = env_u32("MONITOR_RATE_LIMIT_BURST", DEFAULT_BURST);
    apply_with(router, per_second, burst)
}

/// Builds and applies a `SmartIpKeyExtractor`-keyed [`GovernorLayer`] with
/// an explicit rate/burst — the seam [`apply`] reads env vars into, and the
/// seam this module's own tests exercise directly with a tiny burst
/// (`unsafe_code = "deny"` at the workspace level rules out
/// `std::env::set_var` in tests, so tests can't override the env-read
/// path). Construction never panics: an invalid (zero) rate or burst
/// degrades to "no rate limiting", logged at `error`, rather than crashing
/// the service on a config typo.
pub(crate) fn apply_with<S>(router: Router<S>, per_second: u64, burst: u32) -> Router<S>
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

    use super::{apply, apply_with};

    async fn ok() -> &'static str {
        "ok"
    }

    /// A one-route router with a burst of exactly one request per 60s —
    /// long enough that the quota never refills mid-test.
    fn burst_one_router() -> Router {
        apply_with(Router::new().route("/", get(ok)), 60, 1)
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
        let router = apply_with(Router::new().route("/", get(ok)), 60, 0);
        let server = axum_test::TestServer::new(router);
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
    /// Exercises `apply` (the real `main.rs::serve()` entrypoint), not just
    /// the `apply_with` seam the tests above use — covers the `env_u64`/
    /// `env_u32` env-read lines, which `apply_with`-only tests never touch.
    /// `MONITOR_RATE_LIMIT_PER_SECOND`/`MONITOR_RATE_LIMIT_BURST` are unset
    /// in the test process, so this also proves the unset -> default
    /// fallback path never panics and still serves traffic.
    #[tokio::test]
    async fn apply_reads_env_defaults_and_the_production_entrypoint_serves_requests() {
        let server = axum_test::TestServer::new(apply(Router::new().route("/", get(ok))));
        server
            .get("/")
            .add_header("x-forwarded-for", "203.0.113.99")
            .await
            .assert_status_ok();
    }

    /// Regression test for the first-run microk8s deploy bug: `GET
    /// /health` used to be merged into `routes::router`'s business route
    /// set, so it sat inside the same governed router `main.rs::serve()`
    /// wraps in `rate_limit::apply` — the tower_governor limiter 429'd it
    /// under probe frequency once the burst was exhausted by other traffic
    /// sharing the bucket. This reconstructs `main.rs`'s exact assembly
    /// (business routes governed, `routes::health::router()` merged in
    /// separately, unguarded) with an artificially tiny burst so the
    /// governor is provably active, then proves `/health` never 429s on
    /// the very same source IP that trips the governor on a business
    /// route.
    #[tokio::test]
    async fn health_router_is_exempt_from_the_rate_limiter_that_governs_business_routes() {
        let state = crate::routes::test_support::dev_state();
        let api = apply_with(crate::routes::router(state.clone()), 60, 1).with_state(state.clone());
        let health = crate::routes::health::router().with_state(state);
        let app = Router::new().merge(api).merge(health);
        let server = axum_test::TestServer::new(app);

        // Five requests, well past the burst=1 governor limit applied to
        // the business routes below — `/health` must never see a 429,
        // with no Authorization header sent (k8s probes carry none).
        for _ in 0..5 {
            server
                .get("/health")
                .add_header("x-forwarded-for", "203.0.113.9")
                .await
                .assert_status(StatusCode::SERVICE_UNAVAILABLE); // dev_state has no event store — still not a 429
        }

        // Sanity: the same source IP genuinely trips the governor on the
        // governed surface — proving this test would have caught the
        // original bug rather than passing vacuously.
        server
            .get("/metrics/dashboard")
            .add_header("x-forwarded-for", "203.0.113.9")
            .await
            .assert_status_ok();
        server
            .get("/metrics/dashboard")
            .add_header("x-forwarded-for", "203.0.113.9")
            .await
            .assert_status(StatusCode::TOO_MANY_REQUESTS);
    }
}
