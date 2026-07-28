//! Shared test helpers for the `routes::*` test modules: dev/gated license
//! states, event-store injection, a dev-auth-bypass state, and Bearer-JWT
//! signing matching `crate::auth::decode_bearer`'s expected OIDC claim
//! shape. See `docs/v2-port/testing-pattern.md`.

use std::sync::Arc;

use jsonwebtoken::{EncodingKey, Header};
use penguin_licensing::LicenseClient;
use skauswatch_auth::Claims;

use crate::config::Config;
use crate::es::EventStore;
use crate::state::{AppState, AppStateInner};

/// Broadcast capacity for test states — small on purpose, tests never
/// publish more than a handful of events.
const TEST_EVENT_BUS_CAPACITY: usize = 64;

fn build_state(
    config: Config,
    license: Arc<LicenseClient>,
    event_store: Option<Arc<dyn EventStore>>,
) -> AppState {
    let (event_bus, _rx) = tokio::sync::broadcast::channel(TEST_EVENT_BUS_CAPACITY);
    Arc::new(AppStateInner {
        config,
        license,
        event_store,
        event_bus,
    })
}

/// Dev-bypass license (flags/features pass), no event store — matches
/// `AppStateInner::for_tests`, built the same way so route tests that don't
/// need a store keep exercising the `None`-store paths.
pub(crate) fn dev_state() -> AppState {
    build_state(
        Config::from_env(),
        skauswatch_testkit::license::dev_license("skauswatch"),
        None,
    )
}

/// Gated license (`release_mode = true`) — flags/features denied, for
/// exercising `crate::flags::flag_denied`'s 403 path.
pub(crate) fn gated_state() -> AppState {
    build_state(
        Config::from_env(),
        skauswatch_testkit::license::gated_license("skauswatch"),
        None,
    )
}

/// Dev-bypass license with `store` wired in as the active event store —
/// exercises the search/get routes' real (`wiremock`-backed) path instead
/// of the `None` 503 short-circuit.
pub(crate) fn state_with_store(store: impl EventStore + 'static) -> AppState {
    build_state(
        Config::from_env(),
        skauswatch_testkit::license::dev_license("skauswatch"),
        Some(Arc::new(store)),
    )
}

/// Dev-bypass license, `auth_enabled` forced false — exercises
/// `crate::auth::AuthedUser`'s dev-mode bypass. Built by hand rather than
/// via a `MONITOR_AUTH_ENABLED` env override: mutating process env is an
/// `unsafe fn` call on this toolchain, and `unsafe_code = "deny"` at the
/// workspace level rules that out even in tests.
pub(crate) fn dev_bypass_state() -> AppState {
    let mut config = Config::from_env();
    config.security.auth_enabled = false;
    build_state(
        config,
        skauswatch_testkit::license::dev_license("skauswatch"),
        None,
    )
}

/// Signs a Bearer JWT in `crate::auth`'s expected OIDC claim shape
/// (`tenant`/`scope` set, everything else fixed), using `state`'s
/// configured secret.
pub(crate) fn sign_token(state: &AppState, tenant: &str, scope: &str) -> String {
    sign_claims(
        state,
        &Claims {
            sub: "test-user".to_owned(),
            iss: "https://auth.skauswatch.app".to_owned(),
            aud: "skauswatch".to_owned(),
            iat: 0,
            exp: i64::MAX,
            scope: scope.to_owned(),
            tenant: tenant.to_owned(),
            teams: vec![],
            roles: vec![],
        },
    )
}

/// Signs arbitrary claims with `state`'s configured secret — for tests that
/// need to control fields `sign_token` fixes (expiry, empty tenant, ...).
#[allow(clippy::panic)]
pub(crate) fn sign_claims(state: &AppState, claims: &Claims) -> String {
    match jsonwebtoken::encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(state.config.security.secret_key.as_bytes()),
    ) {
        Ok(t) => t,
        Err(e) => panic!("skauswatch-monitor test_support: sign_claims: {e}"),
    }
}
