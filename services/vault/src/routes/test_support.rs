//! Shared test helpers for the /api/v1 route test modules.

use std::collections::HashMap;
use std::sync::Arc;

use jsonwebtoken::{EncodingKey, Header};
use penguin_licensing::LicenseClient;
use serde::Serialize;
use skauswatch_vault::{EnvelopeEncryption, MekVersion};

use crate::state::{AppState, AppStateInner};

/// Fixed tenant UUID used by [`sign_token`] for handler tests that don't
/// exercise tenant isolation itself (the large majority) — a real UUID is
/// required now that `CurrentUser::tenant_uuid()` parses the claim before
/// every tenant-scoped query.
pub(crate) const TEST_TENANT: &str = "11111111-1111-1111-1111-111111111111";
/// A second, distinct tenant id for cross-tenant-isolation tests (tenant A's
/// token must never see/mutate tenant B's rows).
pub(crate) const OTHER_TENANT: &str = "22222222-2222-2222-2222-222222222222";

#[derive(Serialize)]
struct TestClaims<'a> {
    sub: &'a str,
    exp: i64,
    scope: &'a str,
    tenant: &'a str,
}

/// Signs a Vault-shaped bearer token (`sub`/`exp`/`scope`/`tenant`) using
/// the given state's configured JWT secret — for exercising `CurrentUser`.
/// Always stamped with [`TEST_TENANT`]; use [`sign_token_for_tenant`] for
/// tests that need a specific (or second) tenant.
#[allow(clippy::panic)]
pub(crate) fn sign_token(state: &AppState, sub: &str, scope: &str) -> String {
    sign_token_for_tenant(state, sub, scope, TEST_TENANT)
}

/// Like [`sign_token`], but with a caller-chosen `tenant` claim — for
/// cross-tenant-isolation tests.
#[allow(clippy::panic)]
pub(crate) fn sign_token_for_tenant(
    state: &AppState,
    sub: &str,
    scope: &str,
    tenant: &str,
) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = TestClaims {
        sub,
        exp: now + 300,
        scope,
        tenant,
    };
    match jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.auth.jwt_secret.as_bytes()),
    ) {
        Ok(t) => t,
        Err(e) => panic!("sign test token: {e}"),
    }
}

/// A single-MEK (version 1) envelope engine for tests that need real
/// encrypt/decrypt round trips — `EnvelopeEncryption::default()` has no
/// loaded MEK and cannot en/decrypt anything.
pub(crate) fn test_envelope() -> EnvelopeEncryption {
    let mut versions = HashMap::new();
    versions.insert(
        1,
        MekVersion {
            version: 1,
            key_bytes: [9u8; 32],
        },
    );
    EnvelopeEncryption::new(versions, 1)
}

/// A two-MEK (versions 1 and 2, current = 1) envelope engine for MEK
/// rotation tests (`admin::rotate_mek`).
pub(crate) fn test_envelope_two_versions() -> EnvelopeEncryption {
    let mut versions = HashMap::new();
    versions.insert(
        1,
        MekVersion {
            version: 1,
            key_bytes: [9u8; 32],
        },
    );
    versions.insert(
        2,
        MekVersion {
            version: 2,
            key_bytes: [11u8; 32],
        },
    );
    EnvelopeEncryption::new(versions, 1)
}

/// Builds an `AppState` backed by a real, migrated Postgres pool (a fresh
/// isolated schema per call, via `skauswatch_testkit::db::test_pool`) and a
/// working single-MEK envelope engine — for handler tests that issue real
/// queries and/or real encrypt/decrypt round trips rather than only
/// exercising the pre-DB auth/license/validation gates.
pub(crate) async fn db_state(license: Arc<LicenseClient>) -> AppState {
    db_state_with_envelope(license, test_envelope()).await
}

/// Like [`db_state`], but with a caller-supplied envelope engine — for
/// tests (MEK rotation) that need more than one loaded MEK version.
pub(crate) async fn db_state_with_envelope(
    license: Arc<LicenseClient>,
    envelope: EnvelopeEncryption,
) -> AppState {
    let pool =
        skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")).await;
    AppStateInner::for_tests_with_db(license, envelope, pool)
}

/// Like [`db_state`], but wired to a caller-supplied real `StreamProducer`
/// instead of `None` — for tests that must verify what `trigger_sync`
/// actually publishes to Redis (`routes::sync`'s payload-plumbing
/// regression tests), not just what it writes to Postgres.
pub(crate) async fn db_state_with_streams(
    license: Arc<LicenseClient>,
    streams: skauswatch_streams::StreamProducer,
) -> AppState {
    let pool =
        skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")).await;
    std::sync::Arc::new(AppStateInner {
        license,
        db: pool,
        auth: crate::state::AuthSettings {
            jwt_secret: "test-secret".to_owned(),
        },
        envelope: tokio::sync::RwLock::new(test_envelope()),
        streams: Some(streams),
    })
}
