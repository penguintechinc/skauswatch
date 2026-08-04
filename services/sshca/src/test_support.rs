//! Shared test-only Postgres pool helpers, used by `store`, `routes`, and
//! `routes::openapi`'s test modules.
//!
//! sshca now persists into the same `ssh_certificates`/`crl_entries`
//! tables `services/pki` owns (see `crate::store`'s module doc for the
//! consolidation decision) but ships no migrations of its own — schema
//! authority stays entirely with pki. Tests that need a real, migrated
//! schema apply pki's migrations directly via
//! `skauswatch_testkit::db::test_pool_multi`, the same helper
//! `docs/v2-port/testing-pattern.md` documents for "handlers query tables
//! owned by another service".

use std::path::Path;

use sqlx::PgPool;

/// A pool that never successfully connects — for tests that only exercise
/// validation/auth/CA-signing paths that fail (or short-circuit) before
/// ever touching the store.
#[allow(clippy::panic)] // test-infra bootstrap: fail loudly, not silently skip coverage
pub(crate) fn lazy_pool() -> PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://test:test@127.0.0.1:1/test")
        .unwrap_or_else(|e| panic!("lazy test pool: {e}"))
}

/// A real, freshly migrated Postgres pool using pki's
/// `ssh_certificates`/`crl_entries` schema (`services/pki/migrations/`) —
/// for DB-backed success-path tests. Panics (test-infra fault, not a case
/// under test) if the database is unreachable — see `skauswatch_testkit::
/// db::test_pool_multi`'s own docs for the expected local/CI Postgres.
pub(crate) async fn db_pool() -> PgPool {
    skauswatch_testkit::db::test_pool_multi(&[Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../pki/migrations"
    ))])
    .await
}
