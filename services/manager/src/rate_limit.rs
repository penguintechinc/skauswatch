//! Rate limiting (security hardening Fix 2): `tower_governor`-backed
//! token-bucket limiting keyed on the caller's IP. This service sits behind
//! a K8s ingress, so [`SmartIpKeyExtractor`] is used everywhere — it reads
//! `X-Forwarded-For`/`X-Real-Ip`/`Forwarded` (in that order) before falling
//! back to the raw peer address, per `security.md`'s reverse-proxy caveat.
//!
//! Two independent tiers:
//!   - [`apply_global`]: a generous, app-wide default — blunts generic
//!     request floods. Wired at the OUTERMOST layer in `main.rs::serve()`,
//!     never inside `routes::router()` — so the many per-module and
//!     full-router unit tests that build their own `axum_test::TestServer`
//!     directly from a `Router` (never through `serve()`, never setting a
//!     forwarded-for header) stay completely unaffected.
//!   - [`apply_auth`]: a much stricter limit scoped to `auth::public_router()`
//!     alone (`/auth/login`, `/auth/register`, `/auth/refresh`) — blunts
//!     credential-stuffing / bcrypt-CPU-DoS against the unauthenticated
//!     login surface specifically. Wired in `routes::router()` at the point
//!     `auth::public_router()` is built, since that router carries only
//!     those three routes (no collateral blast radius onto any other
//!     endpoint).
//!
//! Both are env-overridable with sane defaults, and both degrade
//! gracefully rather than panicking on a bad config:
//! `GovernorConfigBuilder::finish()` returns `None` for a zero burst/period
//! (e.g. a misconfigured env override) instead of panicking, and [`apply`]
//! treats that as a logged config error, serving that tier without a rate
//! limit rather than refusing to start the whole service.

use std::time::Duration;

use axum::Router;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::SmartIpKeyExtractor;

/// Burst capacity for the app-wide default limiter (per client IP).
const DEFAULT_GLOBAL_BURST: u32 = 50;
/// Replenish period (ms) for the app-wide default limiter — one element
/// every 200ms once the burst is spent, i.e. ~5 req/s sustained per caller.
const DEFAULT_GLOBAL_PERIOD_MS: u64 = 200;
/// Burst capacity for the `/auth/*` credential-surface limiter.
const DEFAULT_AUTH_BURST: u32 = 5;
/// Replenish period (seconds) for the `/auth/*` limiter — one element every
/// 12s once the burst is spent, i.e. ~5 req/min sustained per caller: low
/// enough to blunt credential-stuffing/bcrypt-CPU-DoS while still letting a
/// real user retype a mistyped password a few times in a row.
const DEFAULT_AUTH_PERIOD_SECS: u64 = 12;

/// `RATE_LIMIT_GLOBAL_BURST` env var name.
const ENV_GLOBAL_BURST: &str = "RATE_LIMIT_GLOBAL_BURST";
/// `RATE_LIMIT_GLOBAL_PERIOD_MS` env var name.
const ENV_GLOBAL_PERIOD_MS: &str = "RATE_LIMIT_GLOBAL_PERIOD_MS";
/// `RATE_LIMIT_AUTH_BURST` env var name.
const ENV_AUTH_BURST: &str = "RATE_LIMIT_AUTH_BURST";
/// `RATE_LIMIT_AUTH_PERIOD_SECS` env var name.
const ENV_AUTH_PERIOD_SECS: &str = "RATE_LIMIT_AUTH_PERIOD_SECS";

fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Wraps `router` in the app-wide default rate limiter. Burst/period are
/// overridable via [`ENV_GLOBAL_BURST`]/[`ENV_GLOBAL_PERIOD_MS`], defaulting
/// to [`DEFAULT_GLOBAL_BURST`]/[`DEFAULT_GLOBAL_PERIOD_MS`]. Intended call
/// site: `main.rs::serve()`, wrapping the fully assembled app — see module
/// docs for why it must never sit inside `routes::router()`.
pub(crate) fn apply_global<S>(router: Router<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    apply(
        router,
        env_u32(ENV_GLOBAL_BURST, DEFAULT_GLOBAL_BURST),
        Duration::from_millis(env_u64(ENV_GLOBAL_PERIOD_MS, DEFAULT_GLOBAL_PERIOD_MS)),
        "global",
    )
}

/// Wraps `router` (intended: `auth::public_router()` alone, before it
/// merges into the app-wide router) in a much stricter limiter. Burst/
/// period are overridable via [`ENV_AUTH_BURST`]/[`ENV_AUTH_PERIOD_SECS`],
/// defaulting to [`DEFAULT_AUTH_BURST`]/[`DEFAULT_AUTH_PERIOD_SECS`] — see
/// module docs for why this sits on the credential-facing surface
/// specifically rather than only at the global layer.
pub(crate) fn apply_auth<S>(router: Router<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    apply(
        router,
        env_u32(ENV_AUTH_BURST, DEFAULT_AUTH_BURST),
        Duration::from_secs(env_u64(ENV_AUTH_PERIOD_SECS, DEFAULT_AUTH_PERIOD_SECS)),
        "auth",
    )
}

/// Shared builder: constructs a [`SmartIpKeyExtractor`]-keyed governor
/// config from `(burst, period)` and layers it onto `router`. `tier` is
/// log-only context (`"global"`/`"auth"`/a test name), never part of the
/// rate-limiting decision itself.
///
/// A `None` from `GovernorConfigBuilder::finish()` (only possible if
/// `burst`/`period` end up zero — e.g. a misconfigured env override) is a
/// config error, not a crash: logged, and `router` is returned unwrapped so
/// the service still starts and serves traffic without that tier's rate
/// limit rather than refusing to boot.
fn apply<S>(router: Router<S>, burst: u32, period: Duration, tier: &'static str) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let mut builder = GovernorConfigBuilder::default();
    let mut builder = builder.key_extractor(SmartIpKeyExtractor);
    match builder.period(period).burst_size(burst).finish() {
        Some(config) => router.layer(GovernorLayer::new(config)),
        None => {
            tracing::error!(
                tier,
                burst,
                period_ms = period.as_millis() as u64,
                "invalid rate limit config (zero burst or period) — serving this tier \
                 without a rate limit rather than failing to start"
            );
            router
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use axum::routing::post;

    use super::*;

    async fn ok_handler() -> StatusCode {
        StatusCode::OK
    }

    fn test_router(burst: u32, period: Duration) -> Router {
        apply(
            Router::new().route("/probe", post(ok_handler)),
            burst,
            period,
            "test",
        )
    }

    #[tokio::test]
    async fn allows_requests_within_burst_then_429s() {
        let server = axum_test::TestServer::new(test_router(2, Duration::from_secs(60)));
        for _ in 0..2 {
            let res = server
                .post("/probe")
                .add_header("x-forwarded-for", "203.0.113.7")
                .await;
            res.assert_status_ok();
        }
        let res = server
            .post("/probe")
            .add_header("x-forwarded-for", "203.0.113.7")
            .await;
        res.assert_status(StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn distinct_callers_get_independent_buckets() {
        let server = axum_test::TestServer::new(test_router(1, Duration::from_secs(60)));
        let a = server
            .post("/probe")
            .add_header("x-forwarded-for", "203.0.113.10")
            .await;
        a.assert_status_ok();
        // A different caller's own untouched bucket — not blocked by `a`'s
        // burst, proving the key is per-IP, not global.
        let b = server
            .post("/probe")
            .add_header("x-forwarded-for", "203.0.113.11")
            .await;
        b.assert_status_ok();
    }

    #[tokio::test]
    async fn zero_burst_degrades_to_unlimited_instead_of_panicking() {
        // GovernorConfigBuilder::finish() returns None for a zero burst —
        // `apply` must fall back to the unwrapped router (no rate limit
        // installed at all), never panic. Proven by sending well more than
        // any real burst would allow and observing every request succeeds.
        let server = axum_test::TestServer::new(test_router(0, Duration::from_secs(1)));
        for _ in 0..10 {
            let res = server
                .post("/probe")
                .add_header("x-forwarded-for", "203.0.113.20")
                .await;
            res.assert_status_ok();
        }
    }
    /// Exercises `apply_global` (the real `main.rs::serve()` entrypoint for
    /// the app-wide tier), not just the `apply` seam the tests above use —
    /// covers the `ENV_GLOBAL_BURST`/`ENV_GLOBAL_PERIOD_MS` env-read lines,
    /// which `apply`-only tests never touch. Both are unset in the test
    /// process, so this also proves the unset -> default fallback path
    /// never panics and still serves traffic.
    #[tokio::test]
    async fn apply_global_reads_env_defaults_and_the_production_entrypoint_serves_requests() {
        let server = axum_test::TestServer::new(apply_global(
            Router::new().route("/probe", post(ok_handler)),
        ));
        server
            .post("/probe")
            .add_header("x-forwarded-for", "203.0.113.30")
            .await
            .assert_status_ok();
    }

    /// Same as above for `apply_auth` (the real `routes::router()` entrypoint
    /// wrapping `auth::public_router()`) — covers `ENV_AUTH_BURST`/
    /// `ENV_AUTH_PERIOD_SECS`, unset here as well.
    #[tokio::test]
    async fn apply_auth_reads_env_defaults_and_the_production_entrypoint_serves_requests() {
        let server =
            axum_test::TestServer::new(apply_auth(Router::new().route("/probe", post(ok_handler))));
        server
            .post("/probe")
            .add_header("x-forwarded-for", "203.0.113.31")
            .await
            .assert_status_ok();
    }

    /// Dev-bypass license state, backed by a lazily-connected pool
    /// pointed at the real local test Postgres (`make db-test-up`'s
    /// `postgres://postgres:postgres@localhost:5432/postgres` — same
    /// credentials `skauswatch-testkit::db` assumes elsewhere in this
    /// suite). Deliberately NOT `crate::state::AppStateInner::for_tests`
    /// (whose lazy pool points at the dead `127.0.0.1:1`): `/healthz`'s
    /// real `SELECT 1` probe against that address only fails after sqlx's
    /// ~30s `acquire_timeout`, and this test calls `/healthz` twice —
    /// pointing at a reachable Postgres instead keeps the regression test
    /// itself fast.
    #[allow(clippy::panic)] // test-only constructor fails loudly by design
    fn dev_state() -> crate::state::AppState {
        let cfg = match penguin_licensing::LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        let license = match penguin_licensing::LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        };
        let db = match sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://postgres:postgres@localhost:5432/postgres")
        {
            Ok(p) => p,
            Err(e) => panic!("lazy test pool: {e}"),
        };
        crate::state::AppStateInner::for_tests_with_db(license, db)
    }

    /// Regression test for the first-run microk8s deploy bug: `health::
    /// router` (`/healthz`, `/readyz`, `/version`) used to be merged into
    /// the same `Router` passed to `apply_global`, so k8s probe traffic (no
    /// JWT, high frequency) shared the same governed bucket as ordinary API
    /// traffic and could be 429'd once the global burst was exhausted.
    /// This reconstructs `main.rs`'s exact assembly — business routes
    /// governed via `apply` (an artificially tiny burst so the governor is
    /// provably active), `health::router` merged in separately, unguarded —
    /// then proves `/healthz` never 429s while `/api/v1/openapi/login.json`
    /// (a real, unauthenticated, zero-I/O business route — deliberately
    /// not `/siem/health`, which makes a real `LOGS_URL` network probe and
    /// would make this test slow/flaky on a DNS-less runner), on the very
    /// same source IP, does.
    #[tokio::test]
    async fn health_router_is_exempt_from_the_rate_limiter_that_governs_business_routes() {
        let state = dev_state();
        let api = apply(
            crate::routes::router(state.clone()),
            1,
            Duration::from_secs(60),
            "test",
        );
        let health = crate::health::router(state, skauswatch_telemetry::Readiness::new());
        let app = Router::new().merge(api).merge(health);
        let server = axum_test::TestServer::new(app);

        // Two requests from the same source IP — already past the
        // burst=1 governor limit applied to `/api/v1/openapi/login.json`
        // below — `/healthz` must never see a 429, with no Authorization
        // header sent (k8s probes carry none).
        for _ in 0..2 {
            let res = server
                .get("/healthz")
                .add_header("x-forwarded-for", "203.0.113.50")
                .await;
            assert_ne!(res.status_code(), StatusCode::TOO_MANY_REQUESTS);
        }

        // Sanity: the same source IP genuinely trips the governor on the
        // governed surface — proving this test would have caught the
        // original bug rather than passing vacuously. `routes::router`
        // nests everything under `/api/v1`.
        server
            .get("/api/v1/openapi/login.json")
            .add_header("x-forwarded-for", "203.0.113.50")
            .await
            .assert_status_ok();
        server
            .get("/api/v1/openapi/login.json")
            .add_header("x-forwarded-for", "203.0.113.50")
            .await
            .assert_status(StatusCode::TOO_MANY_REQUESTS);
    }
}
